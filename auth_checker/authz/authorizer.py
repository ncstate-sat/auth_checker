from auth_checker.util import settings
from auth_checker.util.interfaces import AuthorizerPluginRegistry


class Authorizer:
    def __new__(cls, *args, **kwargs):
        # Load all plugins
        authorizer = settings.AUTHORIZER
        for k, v in AuthorizerPluginRegistry.get_registry().items():
            if authorizer == v.name:
                return v(*args, **kwargs)
