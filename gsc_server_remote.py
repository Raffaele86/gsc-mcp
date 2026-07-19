import os
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

"""
GSC MCP Server — Google Search Console via Model Context Protocol
Uses MCP SDK built-in OAuth 2.1 framework for Cowork/Claude.ai compatibility.
"""

import asyncio
import json
import secrets
import sqlite3
import time
import logging
from datetime import datetime, timedelta
from uuid import uuid4

from dotenv import load_dotenv
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route
from starlette.middleware.cors import CORSMiddleware
from basic_auth import BasicAuthMiddleware

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    AuthorizationParams,
    OAuthClientInformationFull,
    OAuthToken,
    AuthorizationCode,
    AccessToken,
    RefreshToken,
    ProviderTokenVerifier,
    construct_redirect_uri,
)
from mcp.server.auth.routes import ClientRegistrationOptions, RevocationOptions
from mcp.server.auth.middleware.auth_context import get_access_token

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------

load_dotenv()
DASHBOARD_USER = os.getenv("DASHBOARD_USER", "")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS", "")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))
DB_PATH = os.getenv("DB_PATH", "gsc_mcp.db")
TOKEN_EXPIRY = 3600  # 1 hour

GOOGLE_SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/webmasters",
    "https://www.googleapis.com/auth/indexing",
]

GOOGLE_CLIENT_CONFIG = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [GOOGLE_REDIRECT_URI],
    }
}

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gsc-mcp")


# ---------------------------------------------------------------------------
# 2. SQLite Database
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT,
            api_key TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS google_credentials (
            user_id TEXT PRIMARY KEY,
            credentials_json TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_info_json TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS oauth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT,
            user_id TEXT,
            scopes TEXT,
            expires_at REAL,
            code_challenge TEXT,
            redirect_uri TEXT,
            redirect_uri_provided_explicitly INTEGER DEFAULT 0,
            resource TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            token TEXT PRIMARY KEY,
            token_type TEXT,
            client_id TEXT,
            user_id TEXT,
            scopes TEXT,
            expires_at REAL,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS google_oauth_states (
            state TEXT PRIMARY KEY,
            google_code_verifier TEXT,
            mcp_params_json TEXT,
            created_at TEXT
        );
    """)
    conn.commit()
    conn.close()
    log.info("Database initialized")


def db_execute(sql: str, params: tuple = ()) -> None:
    conn = _get_db()
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def db_fetchone(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    conn = _get_db()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3. Google API Helpers
# ---------------------------------------------------------------------------

def _load_credentials(user_id: str) -> Credentials:
    row = db_fetchone(
        "SELECT credentials_json FROM google_credentials WHERE user_id=?", (user_id,)
    )
    if not row:
        raise ValueError(f"No Google credentials for user {user_id}")
    creds_data = json.loads(row["credentials_json"])
    creds = Credentials(
        token=creds_data.get("token"),
        refresh_token=creds_data.get("refresh_token"),
        token_uri=creds_data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=creds_data.get("client_id", GOOGLE_CLIENT_ID),
        client_secret=creds_data.get("client_secret", GOOGLE_CLIENT_SECRET),
        scopes=creds_data.get("scopes", GOOGLE_SCOPES),
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleAuthRequest())
        creds_data["token"] = creds.token
        db_execute(
            "UPDATE google_credentials SET credentials_json=?, updated_at=? WHERE user_id=?",
            (json.dumps(creds_data), datetime.utcnow().isoformat(), user_id),
        )
    return creds


def get_gsc_service(user_id: str):
    return build("searchconsole", "v1", credentials=_load_credentials(user_id), cache_discovery=False)


def get_indexing_service(user_id: str):
    return build("indexing", "v3", credentials=_load_credentials(user_id), cache_discovery=False)


async def _run_batch(items: list, worker, user_id: str, concurrency: int) -> list:
    """Esegue worker(item, http) in thread paralleli con cap di concorrenza.

    httplib2 non è thread-safe: ogni task usa un AuthorizedHttp dedicato
    (stesse credenziali, passato a request.execute(http=...)). Risultati in
    ordine di input."""
    import httplib2
    import google_auth_httplib2

    creds = _load_credentials(user_id)
    sem = asyncio.Semaphore(concurrency)

    async def one(item):
        async with sem:
            http = google_auth_httplib2.AuthorizedHttp(creds, http=httplib2.Http())
            return await asyncio.to_thread(worker, item, http)

    return list(await asyncio.gather(*(one(i) for i in items)))


def _get_user_id() -> str:
    """Get user_id - uses the most recent user (no MCP auth needed)."""
    user = db_fetchone("SELECT user_id FROM users ORDER BY created_at DESC LIMIT 1")
    if user:
        return user["user_id"]
    raise ValueError("No user found - authenticate via /oauth/login first")

def _query_gsc(service, site_url: str, start_date: str, end_date: str,
               dimensions: list[str], row_limit: int = 25000,
               dimension_filters: list[dict] | None = None) -> list[dict]:
    """Helper to query GSC Search Analytics with optional filters."""
    body = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": dimensions,
        "rowLimit": row_limit,
    }
    if dimension_filters:
        body["dimensionFilterGroups"] = [{
            "filters": dimension_filters
        }]
    result = service.searchanalytics().query(siteUrl=site_url, body=body).execute()
    return result.get("rows", [])


def _date_ago(days: int) -> str:
    """Return date string N days ago in YYYY-MM-DD format."""
    return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# 4. OAuth Authorization Server Provider
# ---------------------------------------------------------------------------

class GscOAuthProvider:
    """Implements MCP SDK's OAuthAuthorizationServerProvider protocol."""

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = db_fetchone(
            "SELECT client_info_json FROM oauth_clients WHERE client_id=?",
            (client_id,),
        )
        if not row:
            return None
        return OAuthClientInformationFull.model_validate_json(row["client_info_json"])

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        db_execute(
            "INSERT INTO oauth_clients (client_id, client_info_json, created_at) VALUES (?, ?, ?)",
            (client_info.client_id, client_info.model_dump_json(), datetime.utcnow().isoformat()),
        )
        log.info(f"DCR: registered client '{client_info.client_name}' ({client_info.client_id})")

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        log.info(f"Authorize: client_id={client.client_id}, redirect_uri={params.redirect_uri}, state={params.state[:20] if params.state else 'None'}")
        user = db_fetchone("SELECT user_id FROM users ORDER BY created_at DESC LIMIT 1")
        if user:
            creds = db_fetchone(
                "SELECT user_id FROM google_credentials WHERE user_id=?",
                (user["user_id"],),
            )
            if creds:
                code = secrets.token_urlsafe(32)
                db_execute(
                    "INSERT INTO oauth_codes (code, client_id, user_id, scopes, expires_at, code_challenge, redirect_uri, redirect_uri_provided_explicitly, resource, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        code, client.client_id, user["user_id"],
                        json.dumps(params.scopes or []), time.time() + 300,
                        params.code_challenge, str(params.redirect_uri),
                        1 if params.redirect_uri_provided_explicitly else 0,
                        params.resource, datetime.utcnow().isoformat(),
                    ),
                )
                log.info(f"Authorize: auto-approved for user {user['user_id']}")
                return construct_redirect_uri(
                    str(params.redirect_uri), code=code, state=params.state
                )

        mcp_params = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "scopes": params.scopes,
            "state": params.state,
            "resource": params.resource,
        }

        flow = Flow.from_client_config(
            GOOGLE_CLIENT_CONFIG, scopes=GOOGLE_SCOPES, redirect_uri=GOOGLE_REDIRECT_URI,
        )
        authorization_url, google_state = flow.authorization_url(
            access_type="offline", prompt="consent",
        )
        google_code_verifier = getattr(flow, "code_verifier", None) or ""

        db_execute(
            "INSERT INTO google_oauth_states (state, google_code_verifier, mcp_params_json, created_at) VALUES (?, ?, ?, ?)",
            (google_state, google_code_verifier, json.dumps(mcp_params), datetime.utcnow().isoformat()),
        )
        log.info("Authorize: no Google creds, redirecting to Google OAuth")
        return str(authorization_url)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        row = db_fetchone("SELECT * FROM oauth_codes WHERE code=?", (authorization_code,))
        if not row:
            return None
        scopes_raw = row["scopes"]
        scopes = json.loads(scopes_raw) if scopes_raw else []
        return AuthorizationCode(
            code=row["code"],
            scopes=scopes if scopes is not None else [],
            expires_at=float(row["expires_at"]),
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=AnyHttpUrl(row["redirect_uri"]),
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            resource=row["resource"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        code_row = db_fetchone(
            "SELECT user_id FROM oauth_codes WHERE code=?", (authorization_code.code,)
        )
        user_id = code_row["user_id"] if code_row else "unknown"

        db_execute("DELETE FROM oauth_codes WHERE code=?", (authorization_code.code,))

        access_token = secrets.token_urlsafe(48)
        refresh_token = secrets.token_urlsafe(48)
        expires_at = time.time() + TOKEN_EXPIRY
        scopes_json = json.dumps(authorization_code.scopes)

        db_execute(
            "INSERT INTO oauth_tokens (token, token_type, client_id, user_id, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (access_token, "access", client.client_id, user_id, scopes_json, expires_at, datetime.utcnow().isoformat()),
        )
        db_execute(
            "INSERT INTO oauth_tokens (token, token_type, client_id, user_id, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (refresh_token, "refresh", client.client_id, user_id, scopes_json, 0, datetime.utcnow().isoformat()),
        )

        log.info(f"Token exchange: issued tokens for user {user_id}")
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=TOKEN_EXPIRY,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = db_fetchone(
            "SELECT * FROM oauth_tokens WHERE token=? AND token_type='refresh'",
            (refresh_token,),
        )
        if not row:
            return None
        return RefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=int(row["expires_at"]) if row["expires_at"] else None,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull,
        refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        old_row = db_fetchone(
            "SELECT user_id FROM oauth_tokens WHERE token=?", (refresh_token.token,)
        )
        user_id = old_row["user_id"] if old_row else "unknown"

        db_execute("DELETE FROM oauth_tokens WHERE token=?", (refresh_token.token,))

        new_access = secrets.token_urlsafe(48)
        new_refresh = secrets.token_urlsafe(48)
        expires_at = time.time() + TOKEN_EXPIRY
        use_scopes = scopes if scopes else refresh_token.scopes
        scopes_json = json.dumps(use_scopes)

        db_execute(
            "INSERT INTO oauth_tokens (token, token_type, client_id, user_id, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_access, "access", client.client_id, user_id, scopes_json, expires_at, datetime.utcnow().isoformat()),
        )
        db_execute(
            "INSERT INTO oauth_tokens (token, token_type, client_id, user_id, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_refresh, "refresh", client.client_id, user_id, scopes_json, 0, datetime.utcnow().isoformat()),
        )

        log.info(f"Token refresh: issued new tokens for user {user_id}")
        return OAuthToken(
            access_token=new_access, token_type="Bearer",
            expires_in=TOKEN_EXPIRY, refresh_token=new_refresh,
            scope=" ".join(use_scopes) if use_scopes else None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        # Check API key first (for Claude Code CLI)
        user = db_fetchone("SELECT user_id FROM users WHERE api_key=?", (token,))
        if user:
            return AccessToken(
                token=token, client_id="cli-api-key",
                scopes=["mcp:read", "mcp:write"], expires_at=None,
            )

        # Normal OAuth token validation (for Cowork)
        row = db_fetchone(
            "SELECT * FROM oauth_tokens WHERE token=? AND token_type='access'",
            (token,),
        )
        if not row:
            return None
        if row["expires_at"] and float(row["expires_at"]) < time.time():
            return None
        return AccessToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=int(row["expires_at"]) if row["expires_at"] else None,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        db_execute("DELETE FROM oauth_tokens WHERE token=?", (token.token,))
        log.info(f"Token revoked: {token.token[:8]}...")


# ---------------------------------------------------------------------------
# 5. MCP Server + Tools
# ---------------------------------------------------------------------------

init_db()

oauth_provider = GscOAuthProvider()

mcp_server = FastMCP(
    "GSC MCP Server",
    streamable_http_path="/sse",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)


# =====================================================================
# TOOL ORIGINALI
# =====================================================================

@mcp_server.tool()
async def list_sites() -> str:
    """Elenca tutte le proprietà Google Search Console dell'utente."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    result = service.sites().list().execute()
    return json.dumps(result.get("siteEntry", []), indent=2, default=str)


@mcp_server.tool()
async def search_analytics(
    site_url: str,
    start_date: str,
    end_date: str,
    dimensions: list[str] = ["query"],
    row_limit: int = 10,
) -> str:
    """Query Search Analytics: click, impression, ctr, position per le dimensioni richieste.
    Dimensioni disponibili: query, page, country, device, searchAppearance, date."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    body = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": dimensions,
        "rowLimit": row_limit,
    }
    result = service.searchanalytics().query(siteUrl=site_url, body=body).execute()
    return json.dumps(result, indent=2, default=str)


@mcp_server.tool()
async def inspect_url(site_url: str, inspection_url: str) -> str:
    """Ispeziona un URL tramite la URL Inspection API di Google Search Console."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    body = {"inspectionUrl": inspection_url, "siteUrl": site_url}
    result = service.urlInspection().index().inspect(body=body).execute()
    return json.dumps(result, indent=2, default=str)


@mcp_server.tool()
async def list_sitemaps(site_url: str) -> str:
    """Elenca tutte le sitemap di un sito in Google Search Console."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    result = service.sitemaps().list(siteUrl=site_url).execute()
    return json.dumps(result.get("sitemap", []), indent=2, default=str)


@mcp_server.tool()
async def submit_sitemap(site_url: str, sitemap_url: str) -> str:
    """Invia una sitemap a Google Search Console."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    service.sitemaps().submit(siteUrl=site_url, feedpath=sitemap_url).execute()
    return json.dumps({"status": "submitted", "sitemap_url": sitemap_url})


@mcp_server.tool()
async def request_indexing(url: str) -> str:
    """Richiedi l'indicizzazione di un URL tramite la Google Indexing API."""
    uid = _get_user_id()
    service = get_indexing_service(uid)
    body = {"url": url, "type": "URL_UPDATED"}
    result = service.urlNotifications().publish(body=body).execute()
    return json.dumps(result, indent=2, default=str)


# =====================================================================
# ANALISI PERFORMANCE
# =====================================================================

@mcp_server.tool()
async def top_queries(
    site_url: str, start_date: str = "", end_date: str = "",
    row_limit: int = 25, order_by: str = "clicks"
) -> str:
    """Top query per click o impression. order_by: clicks, impressions, ctr, position. Default ultimi 28 giorni."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["query"], row_limit=25000)
    sort_key = {"clicks": "clicks", "impressions": "impressions", "ctr": "ctr", "position": "position"}.get(order_by, "clicks")
    reverse = sort_key != "position"
    rows.sort(key=lambda r: r.get(sort_key, 0), reverse=reverse)
    result = []
    for r in rows[:row_limit]:
        result.append({
            "query": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    return json.dumps({"period": f"{start_date} → {end_date}", "order_by": order_by, "rows": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def top_pages(
    site_url: str, start_date: str = "", end_date: str = "",
    row_limit: int = 25, order_by: str = "clicks"
) -> str:
    """Top pagine per click o impression. order_by: clicks, impressions, ctr, position. Default ultimi 28 giorni."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["page"], row_limit=25000)
    sort_key = {"clicks": "clicks", "impressions": "impressions", "ctr": "ctr", "position": "position"}.get(order_by, "clicks")
    reverse = sort_key != "position"
    rows.sort(key=lambda r: r.get(sort_key, 0), reverse=reverse)
    result = []
    for r in rows[:row_limit]:
        result.append({
            "page": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    return json.dumps({"period": f"{start_date} → {end_date}", "order_by": order_by, "rows": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def query_trend(
    site_url: str, query: str, days: int = 90
) -> str:
    """Trend giornaliero di una query specifica negli ultimi N giorni (default 90)."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    start_date = _date_ago(days)
    end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["date"], row_limit=25000,
                       dimension_filters=[{"dimension": "query", "expression": query, "operator": "equals"}])
    result = []
    for r in rows:
        result.append({
            "date": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    result.sort(key=lambda x: x["date"])
    return json.dumps({"query": query, "days": days, "data": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def page_trend(
    site_url: str, page_url: str, days: int = 90
) -> str:
    """Trend giornaliero di una pagina specifica negli ultimi N giorni (default 90)."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    start_date = _date_ago(days)
    end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["date"], row_limit=25000,
                       dimension_filters=[{"dimension": "page", "expression": page_url, "operator": "equals"}])
    result = []
    for r in rows:
        result.append({
            "date": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    result.sort(key=lambda x: x["date"])
    return json.dumps({"page": page_url, "days": days, "data": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def compare_periods(
    site_url: str, period1_start: str, period1_end: str,
    period2_start: str, period2_end: str, dimension: str = "query",
    row_limit: int = 50
) -> str:
    """Confronta due periodi: mostra delta di click, impression, CTR e posizione per ogni elemento.
    Utile per confrontare mese vs mese o settimana vs settimana."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    rows1 = _query_gsc(service, site_url, period1_start, period1_end, [dimension], row_limit=25000)
    rows2 = _query_gsc(service, site_url, period2_start, period2_end, [dimension], row_limit=25000)
    data1 = {r["keys"][0]: r for r in rows1}
    data2 = {r["keys"][0]: r for r in rows2}
    all_keys = set(data1.keys()) | set(data2.keys())
    comparisons = []
    for key in all_keys:
        r1 = data1.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
        r2 = data2.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
        comparisons.append({
            dimension: key,
            "period1_clicks": r1["clicks"], "period2_clicks": r2["clicks"],
            "delta_clicks": r2["clicks"] - r1["clicks"],
            "period1_impressions": r1["impressions"], "period2_impressions": r2["impressions"],
            "delta_impressions": r2["impressions"] - r1["impressions"],
            "period1_position": round(r1["position"], 1) if r1["position"] else None,
            "period2_position": round(r2["position"], 1) if r2["position"] else None,
            "delta_position": round(r1["position"] - r2["position"], 1) if r1["position"] and r2["position"] else None,
        })
    comparisons.sort(key=lambda x: abs(x["delta_clicks"]), reverse=True)
    return json.dumps({
        "period1": f"{period1_start} → {period1_end}",
        "period2": f"{period2_start} → {period2_end}",
        "dimension": dimension,
        "rows": comparisons[:row_limit],
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def country_performance(
    site_url: str, start_date: str = "", end_date: str = "", row_limit: int = 30
) -> str:
    """Performance per paese: click, impression, CTR e posizione media. Default ultimi 28 giorni."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["country"], row_limit=25000)
    rows.sort(key=lambda r: r["clicks"], reverse=True)
    result = []
    for r in rows[:row_limit]:
        result.append({
            "country": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    return json.dumps({"period": f"{start_date} → {end_date}", "rows": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def device_performance(
    site_url: str, start_date: str = "", end_date: str = ""
) -> str:
    """Confronto performance MOBILE vs DESKTOP vs TABLET. Default ultimi 28 giorni."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["device"])
    result = []
    for r in rows:
        result.append({
            "device": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    return json.dumps({"period": f"{start_date} → {end_date}", "devices": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def search_appearance(
    site_url: str, start_date: str = "", end_date: str = ""
) -> str:
    """Performance per tipo di risultato in SERP (rich snippet, video, FAQ, ecc). Default ultimi 28 giorni."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["searchAppearance"])
    result = []
    for r in rows:
        result.append({
            "type": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    result.sort(key=lambda x: x["clicks"], reverse=True)
    return json.dumps({"period": f"{start_date} → {end_date}", "appearances": result}, indent=2, ensure_ascii=False)


# =====================================================================
# OPPORTUNITA' SEO
# =====================================================================

@mcp_server.tool()
async def keyword_opportunities(
    site_url: str, start_date: str = "", end_date: str = "",
    min_impressions: int = 50, max_position: float = 20, min_position: float = 5,
    row_limit: int = 50
) -> str:
    """Query con alte impression ma basso CTR in posizione 5-20: opportunità di ottimizzazione.
    Queste keyword hanno visibilità ma non cliccano — migliorare title/meta description."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["query"], row_limit=25000)
    opportunities = []
    for r in rows:
        pos = r["position"]
        if min_position <= pos <= max_position and r["impressions"] >= min_impressions:
            opportunities.append({
                "query": r["keys"][0],
                "clicks": r["clicks"], "impressions": r["impressions"],
                "ctr": round(r["ctr"] * 100, 2), "position": round(pos, 1),
                "potential_clicks": round(r["impressions"] * 0.10 - r["clicks"]),
            })
    opportunities.sort(key=lambda x: x["potential_clicks"], reverse=True)
    return json.dumps({
        "period": f"{start_date} → {end_date}",
        "criteria": f"position {min_position}-{max_position}, min {min_impressions} impressions",
        "rows": opportunities[:row_limit],
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def declining_queries(
    site_url: str, days: int = 28, row_limit: int = 30
) -> str:
    """Query che stanno perdendo click/posizioni: confronta ultimi N giorni vs periodo precedente equivalente."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    p2_end = _date_ago(1)
    p2_start = _date_ago(days)
    p1_end = _date_ago(days + 1)
    p1_start = _date_ago(days * 2)
    rows_before = _query_gsc(service, site_url, p1_start, p1_end, ["query"], row_limit=25000)
    rows_after = _query_gsc(service, site_url, p2_start, p2_end, ["query"], row_limit=25000)
    before = {r["keys"][0]: r for r in rows_before}
    after = {r["keys"][0]: r for r in rows_after}
    declining = []
    for query, r1 in before.items():
        r2 = after.get(query)
        if not r2:
            if r1["clicks"] >= 3:
                declining.append({
                    "query": query, "before_clicks": r1["clicks"], "after_clicks": 0,
                    "delta_clicks": -r1["clicks"],
                    "before_position": round(r1["position"], 1), "after_position": None,
                    "status": "disappeared",
                })
            continue
        delta_clicks = r2["clicks"] - r1["clicks"]
        delta_pos = r1["position"] - r2["position"]
        if delta_clicks < -2 or delta_pos < -2:
            declining.append({
                "query": query,
                "before_clicks": r1["clicks"], "after_clicks": r2["clicks"],
                "delta_clicks": delta_clicks,
                "before_position": round(r1["position"], 1),
                "after_position": round(r2["position"], 1),
                "delta_position": round(delta_pos, 1),
                "status": "declining",
            })
    declining.sort(key=lambda x: x["delta_clicks"])
    return json.dumps({
        "period_before": f"{p1_start} → {p1_end}",
        "period_after": f"{p2_start} → {p2_end}",
        "rows": declining[:row_limit],
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def rising_queries(
    site_url: str, days: int = 28, row_limit: int = 30
) -> str:
    """Query in crescita: confronta ultimi N giorni vs periodo precedente equivalente."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    p2_end = _date_ago(1)
    p2_start = _date_ago(days)
    p1_end = _date_ago(days + 1)
    p1_start = _date_ago(days * 2)
    rows_before = _query_gsc(service, site_url, p1_start, p1_end, ["query"], row_limit=25000)
    rows_after = _query_gsc(service, site_url, p2_start, p2_end, ["query"], row_limit=25000)
    before = {r["keys"][0]: r for r in rows_before}
    after = {r["keys"][0]: r for r in rows_after}
    rising = []
    for query, r2 in after.items():
        r1 = before.get(query)
        if not r1:
            if r2["clicks"] >= 3:
                rising.append({
                    "query": query, "before_clicks": 0, "after_clicks": r2["clicks"],
                    "delta_clicks": r2["clicks"],
                    "before_position": None, "after_position": round(r2["position"], 1),
                    "status": "new",
                })
            continue
        delta_clicks = r2["clicks"] - r1["clicks"]
        delta_pos = r1["position"] - r2["position"]
        if delta_clicks > 2 or delta_pos > 2:
            rising.append({
                "query": query,
                "before_clicks": r1["clicks"], "after_clicks": r2["clicks"],
                "delta_clicks": delta_clicks,
                "before_position": round(r1["position"], 1),
                "after_position": round(r2["position"], 1),
                "delta_position": round(delta_pos, 1),
                "status": "rising",
            })
    rising.sort(key=lambda x: x["delta_clicks"], reverse=True)
    return json.dumps({
        "period_before": f"{p1_start} → {p1_end}",
        "period_after": f"{p2_start} → {p2_end}",
        "rows": rising[:row_limit],
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def cannibalization_check(
    site_url: str, start_date: str = "", end_date: str = "",
    min_impressions: int = 20, row_limit: int = 30
) -> str:
    """Trova query con più pagine che competono (cannibalizzazione). Mostra query con 2+ pagine posizionate."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["query", "page"], row_limit=25000)
    query_pages: dict[str, list] = {}
    for r in rows:
        query = r["keys"][0]
        page = r["keys"][1]
        if r["impressions"] >= min_impressions:
            query_pages.setdefault(query, []).append({
                "page": page,
                "clicks": r["clicks"], "impressions": r["impressions"],
                "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
            })
    cannibalized = []
    for query, pages in query_pages.items():
        if len(pages) >= 2:
            pages.sort(key=lambda x: x["clicks"], reverse=True)
            total_clicks = sum(p["clicks"] for p in pages)
            cannibalized.append({
                "query": query,
                "num_pages": len(pages),
                "total_clicks": total_clicks,
                "pages": pages,
            })
    cannibalized.sort(key=lambda x: x["total_clicks"], reverse=True)
    return json.dumps({
        "period": f"{start_date} → {end_date}",
        "cannibalized_queries": cannibalized[:row_limit],
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def low_hanging_fruit(
    site_url: str, start_date: str = "", end_date: str = "",
    min_impressions: int = 30, row_limit: int = 50
) -> str:
    """Query in posizione 3-10 con alto volume di impression: piccole ottimizzazioni possono portarle in top 3.
    Ordinate per potenziale di click aggiuntivi."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["query"], row_limit=25000)
    fruits = []
    for r in rows:
        pos = r["position"]
        if 3 <= pos <= 10 and r["impressions"] >= min_impressions:
            estimated_top3_ctr = 0.15
            potential = round(r["impressions"] * estimated_top3_ctr - r["clicks"])
            fruits.append({
                "query": r["keys"][0],
                "clicks": r["clicks"], "impressions": r["impressions"],
                "ctr": round(r["ctr"] * 100, 2), "position": round(pos, 1),
                "potential_extra_clicks": max(0, potential),
            })
    fruits.sort(key=lambda x: x["potential_extra_clicks"], reverse=True)
    return json.dumps({
        "period": f"{start_date} → {end_date}",
        "criteria": "position 3-10, easy wins",
        "rows": fruits[:row_limit],
    }, indent=2, ensure_ascii=False)


# =====================================================================
# FILTRI AVANZATI
# =====================================================================

@mcp_server.tool()
async def search_analytics_filtered(
    site_url: str, start_date: str, end_date: str,
    dimensions: list[str] = ["query"],
    query_contains: str = "", query_regex: str = "",
    page_contains: str = "", page_regex: str = "",
    country: str = "", device: str = "",
    row_limit: int = 100
) -> str:
    """Search Analytics con filtri avanzati. Filtri: query_contains, query_regex, page_contains, page_regex, country (es: 'ita'), device (MOBILE/DESKTOP/TABLET)."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    filters = []
    if query_contains:
        filters.append({"dimension": "query", "operator": "contains", "expression": query_contains})
    if query_regex:
        filters.append({"dimension": "query", "operator": "includingRegex", "expression": query_regex})
    if page_contains:
        filters.append({"dimension": "page", "operator": "contains", "expression": page_contains})
    if page_regex:
        filters.append({"dimension": "page", "operator": "includingRegex", "expression": page_regex})
    if country:
        filters.append({"dimension": "country", "operator": "equals", "expression": country})
    if device:
        filters.append({"dimension": "device", "operator": "equals", "expression": device})
    rows = _query_gsc(service, site_url, start_date, end_date, dimensions, row_limit=row_limit,
                       dimension_filters=filters if filters else None)
    result = []
    for r in rows:
        entry = {"clicks": r["clicks"], "impressions": r["impressions"],
                 "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1)}
        for i, dim in enumerate(dimensions):
            entry[dim] = r["keys"][i]
        result.append(entry)
    return json.dumps({"period": f"{start_date} → {end_date}", "filters_applied": len(filters), "rows": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def pages_for_query(
    site_url: str, query: str, start_date: str = "", end_date: str = ""
) -> str:
    """Quali pagine si posizionano per una query specifica? Mostra tutte le pagine con dati di performance."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["page"], row_limit=25000,
                       dimension_filters=[{"dimension": "query", "expression": query, "operator": "equals"}])
    result = []
    for r in rows:
        result.append({
            "page": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    result.sort(key=lambda x: x["clicks"], reverse=True)
    return json.dumps({"query": query, "period": f"{start_date} → {end_date}", "pages": result}, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def queries_for_page(
    site_url: str, page_url: str, start_date: str = "", end_date: str = "",
    row_limit: int = 50
) -> str:
    """Quali query portano traffico a una pagina specifica? Mostra tutte le keyword con dati di performance."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["query"], row_limit=25000,
                       dimension_filters=[{"dimension": "page", "expression": page_url, "operator": "equals"}])
    result = []
    for r in rows:
        result.append({
            "query": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    result.sort(key=lambda x: x["clicks"], reverse=True)
    return json.dumps({"page": page_url, "period": f"{start_date} → {end_date}", "queries": result[:row_limit]}, indent=2, ensure_ascii=False)


# =====================================================================
# INDICIZZAZIONE AVANZATA
# =====================================================================

@mcp_server.tool()
async def bulk_inspect_urls(site_url: str, urls: list[str]) -> str:
    """Ispeziona più URL in batch tramite la URL Inspection API. Max 50 URL per chiamata."""
    uid = _get_user_id()
    service = get_gsc_service(uid)

    def inspect(url, http):
        try:
            body = {"inspectionUrl": url, "siteUrl": site_url}
            result = service.urlInspection().index().inspect(body=body).execute(http=http)
            inspection = result.get("inspectionResult", {})
            index_status = inspection.get("indexStatusResult", {})
            return {
                "url": url,
                "verdict": index_status.get("verdict", "UNKNOWN"),
                "coverageState": index_status.get("coverageState", ""),
                "robotsTxtState": index_status.get("robotsTxtState", ""),
                "indexingState": index_status.get("indexingState", ""),
                "lastCrawlTime": index_status.get("lastCrawlTime", ""),
                "pageFetchState": index_status.get("pageFetchState", ""),
                "crawledAs": index_status.get("crawledAs", ""),
            }
        except Exception as e:
            return {"url": url, "error": str(e)}

    results = await _run_batch(urls[:50], inspect, uid, concurrency=4)
    return json.dumps({"inspected": len(results), "results": results}, indent=2, default=str)


@mcp_server.tool()
async def bulk_request_indexing(urls: list[str]) -> str:
    """Richiedi indicizzazione per più URL tramite la Google Indexing API. Max 50 URL.
    ATTENZIONE: Google ha un limite giornaliero di ~200 richieste."""
    uid = _get_user_id()
    service = get_indexing_service(uid)

    def publish(url, http):
        try:
            body = {"url": url, "type": "URL_UPDATED"}
            result = service.urlNotifications().publish(body=body).execute(http=http)
            return {"url": url, "status": "submitted", "response": result}
        except Exception as e:
            return {"url": url, "status": "error", "error": str(e)}

    # concorrenza bassa: il vincolo vero è la quota giornaliera (~200/die)
    results = await _run_batch(urls[:50], publish, uid, concurrency=3)
    return json.dumps({"submitted": len([r for r in results if r["status"] == "submitted"]),
                        "errors": len([r for r in results if r["status"] == "error"]),
                        "results": results}, indent=2, default=str)


@mcp_server.tool()
async def delete_sitemap(site_url: str, sitemap_url: str) -> str:
    """Rimuovi una sitemap da Google Search Console."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    service.sitemaps().delete(siteUrl=site_url, feedpath=sitemap_url).execute()
    return json.dumps({"status": "deleted", "sitemap_url": sitemap_url})


@mcp_server.tool()
async def indexing_status_summary(site_url: str, urls: list[str]) -> str:
    """Riepilogo stato indicizzazione di più URL: quanti indicizzati, quanti no, quanti con errori."""
    uid = _get_user_id()
    service = get_gsc_service(uid)

    def inspect(url, http):
        try:
            body = {"inspectionUrl": url, "siteUrl": site_url}
            result = service.urlInspection().index().inspect(body=body).execute(http=http)
            verdict = result.get("inspectionResult", {}).get("indexStatusResult", {}).get("verdict", "UNKNOWN")
            return {"url": url, "verdict": verdict}
        except Exception as e:
            return {"url": url, "verdict": "ERROR", "error": str(e)}

    details = await _run_batch(urls[:50], inspect, uid, concurrency=4)
    indexed = sum(1 for d in details if d["verdict"] == "PASS")
    errors = sum(1 for d in details if d["verdict"] == "ERROR")
    not_indexed = len(details) - indexed - errors
    return json.dumps({
        "total": len(urls[:50]), "indexed": indexed,
        "not_indexed": not_indexed, "errors": errors,
        "details": details,
    }, indent=2, default=str)


# =====================================================================
# DASHBOARD / REPORTISTICA
# =====================================================================

@mcp_server.tool()
async def daily_stats(
    site_url: str, days: int = 30
) -> str:
    """Statistiche giornaliere aggregate del sito: click, impression, CTR, posizione media per ogni giorno."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    start_date = _date_ago(days)
    end_date = _date_ago(1)
    rows = _query_gsc(service, site_url, start_date, end_date, ["date"], row_limit=25000)
    result = []
    for r in rows:
        result.append({
            "date": r["keys"][0],
            "clicks": r["clicks"], "impressions": r["impressions"],
            "ctr": round(r["ctr"] * 100, 2), "position": round(r["position"], 1),
        })
    result.sort(key=lambda x: x["date"])
    total_clicks = sum(r["clicks"] for r in result)
    total_impressions = sum(r["impressions"] for r in result)
    avg_position = round(sum(r["position"] for r in result) / len(result), 1) if result else 0
    return json.dumps({
        "site": site_url, "days": days,
        "totals": {"clicks": total_clicks, "impressions": total_impressions, "avg_position": avg_position},
        "daily": result,
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def weekly_report(
    site_url: str
) -> str:
    """Report settimanale automatico: metriche ultime 7 giorni vs 7 giorni precedenti con delta e top query/pagine."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    this_week_start = _date_ago(7)
    this_week_end = _date_ago(1)
    last_week_start = _date_ago(14)
    last_week_end = _date_ago(8)

    # Totali questa settimana
    tw_rows = _query_gsc(service, site_url, this_week_start, this_week_end, ["date"], row_limit=7)
    tw_clicks = sum(r["clicks"] for r in tw_rows)
    tw_impressions = sum(r["impressions"] for r in tw_rows)
    tw_avg_pos = round(sum(r["position"] for r in tw_rows) / len(tw_rows), 1) if tw_rows else 0

    # Totali settimana scorsa
    lw_rows = _query_gsc(service, site_url, last_week_start, last_week_end, ["date"], row_limit=7)
    lw_clicks = sum(r["clicks"] for r in lw_rows)
    lw_impressions = sum(r["impressions"] for r in lw_rows)
    lw_avg_pos = round(sum(r["position"] for r in lw_rows) / len(lw_rows), 1) if lw_rows else 0

    # Top 10 query questa settimana
    tw_queries = _query_gsc(service, site_url, this_week_start, this_week_end, ["query"], row_limit=25000)
    tw_queries.sort(key=lambda r: r["clicks"], reverse=True)
    top_queries_list = [{"query": r["keys"][0], "clicks": r["clicks"], "position": round(r["position"], 1)} for r in tw_queries[:10]]

    # Top 10 pagine questa settimana
    tw_pages = _query_gsc(service, site_url, this_week_start, this_week_end, ["page"], row_limit=25000)
    tw_pages.sort(key=lambda r: r["clicks"], reverse=True)
    top_pages_list = [{"page": r["keys"][0], "clicks": r["clicks"], "position": round(r["position"], 1)} for r in tw_pages[:10]]

    return json.dumps({
        "this_week": {"period": f"{this_week_start} → {this_week_end}", "clicks": tw_clicks, "impressions": tw_impressions, "avg_position": tw_avg_pos},
        "last_week": {"period": f"{last_week_start} → {last_week_end}", "clicks": lw_clicks, "impressions": lw_impressions, "avg_position": lw_avg_pos},
        "delta": {
            "clicks": tw_clicks - lw_clicks,
            "clicks_pct": round((tw_clicks - lw_clicks) / lw_clicks * 100, 1) if lw_clicks else 0,
            "impressions": tw_impressions - lw_impressions,
            "impressions_pct": round((tw_impressions - lw_impressions) / lw_impressions * 100, 1) if lw_impressions else 0,
            "position": round(lw_avg_pos - tw_avg_pos, 1),
        },
        "top_queries": top_queries_list,
        "top_pages": top_pages_list,
    }, indent=2, ensure_ascii=False)


@mcp_server.tool()
async def content_gap_analysis(
    site_url: str, competitor_url: str, start_date: str = "", end_date: str = "",
    row_limit: int = 50
) -> str:
    """Analisi content gap: query dove il competitor si posiziona ma tu no (o sei molto indietro).
    Richiede che il competitor sia verificato in GSC oppure si usa la stessa property."""
    uid = _get_user_id()
    service = get_gsc_service(uid)
    if not start_date:
        start_date = _date_ago(28)
    if not end_date:
        end_date = _date_ago(1)

    my_rows = _query_gsc(service, site_url, start_date, end_date, ["query"], row_limit=25000)
    my_queries = {r["keys"][0]: r for r in my_rows}

    try:
        comp_rows = _query_gsc(service, competitor_url, start_date, end_date, ["query"], row_limit=25000)
    except Exception as e:
        return json.dumps({"error": f"Impossibile accedere ai dati del competitor: {e}. Assicurati che la property sia verificata nel tuo GSC."}, ensure_ascii=False)

    gaps = []
    for r in comp_rows:
        query = r["keys"][0]
        my_data = my_queries.get(query)
        if not my_data:
            gaps.append({
                "query": query, "competitor_clicks": r["clicks"],
                "competitor_position": round(r["position"], 1),
                "your_clicks": 0, "your_position": None,
                "gap_type": "missing",
            })
        elif my_data["position"] > r["position"] + 5:
            gaps.append({
                "query": query, "competitor_clicks": r["clicks"],
                "competitor_position": round(r["position"], 1),
                "your_clicks": my_data["clicks"],
                "your_position": round(my_data["position"], 1),
                "gap_type": "behind",
            })
    gaps.sort(key=lambda x: x["competitor_clicks"], reverse=True)
    return json.dumps({
        "site": site_url, "competitor": competitor_url,
        "period": f"{start_date} → {end_date}",
        "gaps": gaps[:row_limit],
    }, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 6. Custom Routes (Google OAuth + Homepage)
# ---------------------------------------------------------------------------

async def google_oauth_callback(request: Request):
    """Handle Google OAuth callback, store credentials, complete MCP auth if needed."""
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    error = request.query_params.get("error", "")

    if error:
        return HTMLResponse(f"<h1>Errore</h1><p>{error}</p>", status_code=400)
    if not code or not state:
        return HTMLResponse("<h1>Errore</h1><p>Parametri mancanti</p>", status_code=400)

    state_row = db_fetchone("SELECT * FROM google_oauth_states WHERE state=?", (state,))
    if not state_row:
        return HTMLResponse("<h1>Errore</h1><p>State non valido o scaduto</p>", status_code=400)

    google_code_verifier = state_row["google_code_verifier"] or ""
    mcp_params_json = state_row["mcp_params_json"] or ""

    db_execute("DELETE FROM google_oauth_states WHERE state=?", (state,))

    flow = Flow.from_client_config(
        GOOGLE_CLIENT_CONFIG, scopes=GOOGLE_SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI, state=state,
    )
    if google_code_verifier:
        flow.code_verifier = google_code_verifier
    flow.fetch_token(code=code)
    credentials = flow.credentials

    email = "unknown"
    if hasattr(credentials, "id_token") and isinstance(credentials.id_token, dict):
        email = credentials.id_token.get("email", "unknown")
    if email == "unknown":
        try:
            from google.oauth2 import id_token as google_id_token
            id_info = google_id_token.verify_oauth2_token(
                credentials.token, GoogleAuthRequest(),
                GOOGLE_CLIENT_ID, clock_skew_in_seconds=10,
            )
            email = id_info.get("email", "unknown")
        except Exception:
            pass

    existing = db_fetchone("SELECT user_id FROM users WHERE email=?", (email,))
    if existing:
        user_id = existing["user_id"]
    elif email == "unknown":
        existing_any = db_fetchone("SELECT user_id FROM users ORDER BY created_at DESC LIMIT 1")
        if existing_any:
            user_id = existing_any["user_id"]
        else:
            user_id = str(uuid4())
            db_execute(
                "INSERT INTO users (user_id, email, created_at) VALUES (?, ?, ?)",
                (user_id, email, datetime.utcnow().isoformat()),
            )
    else:
        user_id = str(uuid4())
        db_execute(
            "INSERT INTO users (user_id, email, created_at) VALUES (?, ?, ?)",
            (user_id, email, datetime.utcnow().isoformat()),
        )

    creds_json = json.dumps({
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": list(credentials.scopes) if credentials.scopes else GOOGLE_SCOPES,
    })

    existing_creds = db_fetchone("SELECT user_id FROM google_credentials WHERE user_id=?", (user_id,))
    if existing_creds:
        db_execute(
            "UPDATE google_credentials SET credentials_json=?, updated_at=? WHERE user_id=?",
            (creds_json, datetime.utcnow().isoformat(), user_id),
        )
    else:
        db_execute(
            "INSERT INTO google_credentials (user_id, credentials_json, updated_at) VALUES (?, ?, ?)",
            (user_id, creds_json, datetime.utcnow().isoformat()),
        )

    log.info(f"Google callback: user {email} ({user_id}) credentials saved")

    if mcp_params_json:
        mcp_params = json.loads(mcp_params_json)
        mcp_code = secrets.token_urlsafe(32)
        db_execute(
            "INSERT INTO oauth_codes (code, client_id, user_id, scopes, expires_at, code_challenge, redirect_uri, redirect_uri_provided_explicitly, resource, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                mcp_code, mcp_params["client_id"], user_id,
                json.dumps(mcp_params.get("scopes") or []), time.time() + 300,
                mcp_params["code_challenge"], mcp_params["redirect_uri"],
                1 if mcp_params.get("redirect_uri_provided_explicitly") else 0,
                mcp_params.get("resource"), datetime.utcnow().isoformat(),
            ),
        )
        redirect_url = construct_redirect_uri(
            mcp_params["redirect_uri"], code=mcp_code, state=mcp_params.get("state"),
        )
        log.info("Google callback: completing MCP auth, redirecting to Cowork")
        return RedirectResponse(redirect_url, status_code=302)

    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GSC MCP - Login OK</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #f5f5f5; }}
.card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
h1 {{ color: #1a73e8; }}
.info {{ background: #e8f5e9; padding: 15px; border-radius: 8px; margin: 15px 0; }}
</style></head>
<body><div class="card">
<h1>Login riuscito!</h1>
<div class="info">
<p><strong>Email:</strong> {email}</p>
<p><strong>User ID:</strong> {user_id}</p>
</div>
<p>URL SSE: <code>{BASE_URL}/sse</code></p>
<p><a href="/">Torna alla home</a></p>
</div></body></html>""")


async def google_login(request: Request):
    """Redirect user to Google consent screen (standalone login)."""
    flow = Flow.from_client_config(
        GOOGLE_CLIENT_CONFIG, scopes=GOOGLE_SCOPES, redirect_uri=GOOGLE_REDIRECT_URI,
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline", prompt="consent",
    )
    code_verifier = getattr(flow, "code_verifier", None) or ""
    db_execute(
        "INSERT INTO google_oauth_states (state, google_code_verifier, mcp_params_json, created_at) VALUES (?, ?, ?, ?)",
        (state, code_verifier, "", datetime.utcnow().isoformat()),
    )
    log.info("Google login: redirecting to Google")
    return RedirectResponse(str(authorization_url))


async def homepage(request: Request):
    """Show homepage with status and setup instructions."""
    user = db_fetchone("SELECT * FROM users ORDER BY created_at DESC LIMIT 1")
    if user:
        creds = db_fetchone(
            "SELECT user_id FROM google_credentials WHERE user_id=?", (user["user_id"],)
        )
        has_creds = creds is not None
        return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GSC MCP Server</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; background: #f5f5f5; }}
.card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
h1 {{ color: #1a73e8; }}
.status {{ padding: 15px; border-radius: 8px; margin: 15px 0; }}
.ok {{ background: #e8f5e9; border-left: 4px solid #4caf50; }}
code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 14px; word-break: break-all; }}
</style></head>
<body><div class="card">
<h1>GSC MCP Server</h1>
<div class="status ok">
<p><strong>Utente:</strong> {user['email']}</p>
<p><strong>Google Credentials:</strong> {'Collegate' if has_creds else 'Non collegate'}</p>
</div>
<h3>Setup Claude.ai / Cowork</h3>
<ol>
<li>Vai su Claude.ai - Settings - Connectors</li>
<li>Aggiungi connettore MCP</li>
<li>URL: <code>{BASE_URL}/sse</code></li>
<li>Il flusso OAuth si completa automaticamente</li>
</ol>
<p><a href="/oauth/login">Ricollega Google Account</a></p>
</div></body></html>""")
    else:
        return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GSC MCP Server</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #f5f5f5; }}
.card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
h1 {{ color: #1a73e8; }}
.btn {{ display: inline-block; padding: 12px 30px; background: #1a73e8; color: white; text-decoration: none; border-radius: 8px; font-size: 16px; margin-top: 20px; }}
</style></head>
<body><div class="card">
<h1>GSC MCP Server</h1>
<p>Server MCP per Google Search Console</p>
<p>Collega il tuo account Google per iniziare.</p>
<a href="/oauth/login" class="btn">Login with Google</a>
</div></body></html>""")


# ---------------------------------------------------------------------------
# 7. ASGI App Assembly
# ---------------------------------------------------------------------------

starlette_app = mcp_server.streamable_http_app()

starlette_app.routes.insert(0, Route("/", homepage))
starlette_app.routes.insert(0, Route("/oauth/login", google_login))
starlette_app.routes.insert(0, Route("/oauth/callback", google_oauth_callback))

auth_app = BasicAuthMiddleware(starlette_app, DASHBOARD_USER, DASHBOARD_PASS)
app = CORSMiddleware(
    auth_app,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
    allow_headers=["*"],
    allow_credentials=False,
    expose_headers=["mcp-session-id"],
)


# ---------------------------------------------------------------------------
# 8. Main Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    log.info(f"Starting GSC MCP Server at {BASE_URL}")
    log.info(f"SSE endpoint: {BASE_URL}/sse")
    log.info(f"Google OAuth callback: {GOOGLE_REDIRECT_URI}")

    uvicorn.run(app, host="0.0.0.0", port=8000)
