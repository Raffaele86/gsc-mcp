import inspect
from mcp.server.auth.routes import create_auth_routes, create_protected_resource_routes, cors_middleware
print("=== create_protected_resource_routes ===")
print(inspect.getsource(create_protected_resource_routes))
print()

# Check how FastMCP handles auth
from mcp.server.fastmcp import FastMCP
print("=== FastMCP.__init__ signature ===")
print(inspect.signature(FastMCP.__init__))
print()

# Check if there's an http_app method
if hasattr(FastMCP, 'http_app'):
    print("=== FastMCP.http_app ===")
    print(inspect.getsource(FastMCP.http_app))
elif hasattr(FastMCP, 'sse_app'):
    print("=== FastMCP.sse_app ===")
    print(inspect.getsource(FastMCP.sse_app))

# Check streamable http
from mcp.server.streamable_http import StreamableHTTPServerTransport
print()
print("=== StreamableHTTPServerTransport.__init__ signature ===")
print(inspect.signature(StreamableHTTPServerTransport.__init__))
