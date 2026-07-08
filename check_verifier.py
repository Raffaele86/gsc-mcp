import inspect
from mcp.server.auth.provider import ProviderTokenVerifier
print(inspect.getsource(ProviderTokenVerifier))
print()
from mcp.server.auth.routes import build_resource_metadata_url
print("=== build_resource_metadata_url ===")
print(inspect.getsource(build_resource_metadata_url))
print()
from mcp.server.auth.provider import construct_redirect_uri
print("=== construct_redirect_uri ===")
print(inspect.getsource(construct_redirect_uri))
