import os
from pathlib import Path
import casbin
from auth_checker.util.interfaces import BaseAuthorizer
from auth_checker.util.settings import CASBIN_RBAC_MODEL
from casbin.model import Model

# For V1 of the Casbin model, we will use a model defined in the settings
# TODO: Add support for loading a model from a file that whose path is defined in the settings
model = Model()
model.load_model_from_text(CASBIN_RBAC_MODEL)

CASBIN_AUTHORIZER_POLICY_ADAPTER = os.getenv("CASBIN_AUTHORIZER_POLICY_ADAPTER")
CASBIN_POLICY_FILE = os.getenv("CASBIN_POLICY_FILE", None)


def _redis_adapter():  # pragma: no cover
    casbin_redis_host = os.getenv("CASBIN_REDIS_HOST", "localhost")
    casbin_redis_port = os.getenv("CASBIN_REDIS_PORT", 6379)
    casbin_redis_password = os.getenv("CASBIN_REDIS_PASSWORD", None)
    casbin_redis_db = os.getenv("CASBIN_REDIS_DB", 0)
    try:
        from casbin_redis_adapter.adapter import Adapter
    except ImportError:
        raise ImportError("casbin_redis_adapter is not installed")
    adapter = Adapter(host=casbin_redis_host, port=casbin_redis_port, db=casbin_redis_db)
    if casbin_redis_password:
        adapter.password = casbin_redis_password
    return adapter


def _file_adapter():  # pragma: no cover
    if not Path(CASBIN_POLICY_FILE).exists():
        raise FileNotFoundError(f"File {CASBIN_POLICY_FILE} not found")
    adapter = casbin.FileAdapter(CASBIN_POLICY_FILE)
    return adapter


def _mongo_adapter():  # pragma: no cover
    try:
        from casbin_pymongo_adapter.adapter import Adapter
    except ImportError:
        raise ImportError("casbin_mongo_adapter is not installed")
    adapter = Adapter(
        os.getenv("CASBIN_AUTH_URI"),
        os.getenv("CASBIN_AUTH_DB"),
    )
    return adapter


def _sqlite_adapter():  # pragma: no cover
    try:
        import casbin_sqlalchemy_adapter
        import casbin
    except ImportError as e:
        raise ImportError(f"A dependency is not installed: {e}")
    db_file = Path(os.getenv("CASBIN_SQLITE_DB_FILE", "./"))
    if not db_file.exists():
        db_file.touch()
    adapter = casbin_sqlalchemy_adapter.Adapter(f"sqlite:///{db_file.absolute()}")
    return adapter


ADAPTER_MAP = {
    "redis": _redis_adapter,
    "mongo": _mongo_adapter,
    "file": _file_adapter,
    "sqlite": _sqlite_adapter,
}


class CasbinAuthorizer(BaseAuthorizer):
    name = "casbin_authorizer"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        adapter = kwargs.get("adapter", ADAPTER_MAP[CASBIN_AUTHORIZER_POLICY_ADAPTER]())
        self.enforcer = casbin.Enforcer(model=model, adapter=adapter, enable_log=False)

    def authorize(self, *args) -> bool:
        """
        Authorize a user to perform an action on an object
        kwargs are not supported for casbin authorize
        :param args:
        :return:
        """
        if args:
            subject, _object, action = args
            return self.enforcer.enforce(subject, _object, action)
        return False

    def roles_for_user(self, *args) -> list[str]:
        if args:
            subject = args[0]
            return self.enforcer.get_implicit_roles_for_user(subject)
        return []

    def permissions_for_user(self, *args, **kwargs):
        raise NotImplementedError
