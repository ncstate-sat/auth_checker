from typing import Dict, Any


class AuthorizerPluginRegistry(type):
    REGISTRY: Dict[str, "AuthorizerPluginRegistry"] = {}

    def __new__(cls, name, bases, attrs):
        new_cls = type.__new__(cls, name, bases, attrs)
        cls.REGISTRY[new_cls.__name__.lower()] = new_cls
        return new_cls

    @classmethod
    def get_registry(cls):
        return dict(cls.REGISTRY)


class AuthorizerPlugin(metaclass=AuthorizerPluginRegistry):
    name = "__authorize_plugin__"


class BaseAuthorizer(AuthorizerPlugin):
    name = "__base_authorizer__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def authorize(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    def roles_for_user(self, *args, **kwargs) -> list[str]:
        raise NotImplementedError

    def permissions_for_user(self, *args, **kwargs) -> list[Any]:
        raise NotImplementedError
