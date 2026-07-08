import sqlite3
conn = sqlite3.connect("gsc_mcp.db")
conn.row_factory = sqlite3.Row
print("=== USERS ===")
for r in conn.execute("SELECT * FROM users"):
    print(dict(r))
print("=== GOOGLE_CREDENTIALS ===")
for r in conn.execute("SELECT user_id, updated_at FROM google_credentials"):
    print(dict(r))
print("=== OAUTH_CLIENTS ===")
for r in conn.execute("SELECT client_id, client_name, redirect_uris FROM oauth_clients"):
    print(dict(r))
print("=== OAUTH_CODES ===")
for r in conn.execute("SELECT * FROM oauth_codes"):
    print(dict(r))
print("=== OAUTH_TOKENS ===")
for r in conn.execute("SELECT access_token, user_id, scope, expires_at FROM oauth_tokens"):
    print(dict(r))
conn.close()
