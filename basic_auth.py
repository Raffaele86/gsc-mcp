"""Basic Auth middleware per dashboard MCP. Protegge tutto tranne endpoint MCP/OAuth."""
import base64
import hmac
import logging

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger("mcp-auth")

PUBLIC_PREFIXES = (
    "/sse",
    "/mcp",
    "/messages",
    "/oauth",
    "/.well-known",
    "/callback",
    "/health",
)


class BasicAuthMiddleware:
    def __init__(self, app: ASGIApp, user: str, password: str):
        self.app = app
        self.enabled = bool(user and password)
        self._expected = (
            base64.b64encode(f"{user}:{password}".encode()).decode()
            if self.enabled
            else ""
        )
        if not self.enabled:
            log.warning("Basic Auth disabilitato (DASHBOARD_USER/PASS vuoti)")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in PUBLIC_PREFIXES):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()

        if auth.startswith("Basic "):
            if hmac.compare_digest(auth[6:].strip(), self._expected):
                await self.app(scope, receive, send)
                return

        resp = Response(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="MCP Dashboard"'},
        )
        await resp(scope, receive, send)
