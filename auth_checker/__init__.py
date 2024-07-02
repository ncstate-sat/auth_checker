from auth_checker.authz.authorizer import Authorizer
from sat.logs import SATLogger
import importlib
import pkgutil
import auth_checker.plugins.authorize

logger = SATLogger(__name__)


def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    logger.debug(f"{ns_pkg.__path__}, {ns_pkg.__name__ + '.'}")
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in iter_namespace(auth_checker.plugins.authorize)
}
