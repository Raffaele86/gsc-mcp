import inspect
from mcp.server.auth.routes import build_metadata, MetadataHandler, AuthorizationHandler, TokenHandler, RegistrationHandler

print("=== build_metadata ===")
print(inspect.getsource(build_metadata))
print()
print("=== MetadataHandler ===")
print(inspect.getsource(MetadataHandler))
print()
print("=== AuthorizationHandler ===")
print(inspect.getsource(AuthorizationHandler))
print()
print("=== TokenHandler ===")
src = inspect.getsource(TokenHandler)
print(src[:3000])
print()
print("=== RegistrationHandler ===")
src = inspect.getsource(RegistrationHandler)
print(src[:3000])
