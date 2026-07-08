import inspect
from mcp.server.auth.routes import RegistrationHandler
src = inspect.getsource(RegistrationHandler)
print(src)
print()

# Also check AuthSettings
try:
    from mcp.server.fastmcp.server import AuthSettings
    print("=== AuthSettings ===")
    print(inspect.getsource(AuthSettings))
except ImportError:
    try:
        from mcp.server.fastmcp import AuthSettings
        print("=== AuthSettings ===")
        print(inspect.getsource(AuthSettings))
    except ImportError:
        print("AuthSettings not found directly, checking FastMCP module")
        import mcp.server.fastmcp.server as fms
        for name in dir(fms):
            if 'auth' in name.lower() or 'setting' in name.lower():
                print(f"  {name}")
