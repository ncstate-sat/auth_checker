import os
from pathlib import Path

import casbin

from auth_service.util.interfaces import BaseAuthorizer

CASBIN_AUTHORIZER_MODEL = os.getenv("CASBIN_AUTHORIZER_MODEL")
CASBIN_AUTHORIZER_POLICY_ADAPTER = os.getenv("CASBIN_AUTHORIZER_POLICY_ADAPTER")


def _redis_adapter():
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


def _file_adapter():
    if not Path(CASBIN_AUTHORIZER_POLICY_ADAPTER).exists():
        raise FileNotFoundError(f"File {CASBIN_AUTHORIZER_POLICY_ADAPTER} not found")
    adapter = casbin.FileAdapter(CASBIN_AUTHORIZER_POLICY_ADAPTER)
    return adapter


def _mongo_adapter():
    try:
        from casbin_pymongo_adapter.adapter import Adapter
    except ImportError:
        raise ImportError("casbin_mongo_adapter is not installed")
    adapter = Adapter(
        os.getenv("MONGODB_URI"),
        os.getenv("MONGODB_DB"),
    )
    return adapter


ADAPTER_MAP = {
    "redis": _redis_adapter,
    "mongo": _mongo_adapter,
    "file": _file_adapter,
}


class CasbinAuthorizer(BaseAuthorizer):
    name = "casbin_authorizer"

    def __init__(self, *args, **kwargs):
        model = kwargs.get("model", CASBIN_AUTHORIZER_MODEL)
        adapter = kwargs.get("adapter", ADAPTER_MAP[CASBIN_AUTHORIZER_POLICY_ADAPTER]())
        self.enforcer = casbin.Enforcer(model=model, adapter=adapter, enable_log=True)
        super().__init__(*args, **kwargs)
