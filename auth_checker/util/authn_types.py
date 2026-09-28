from enum import Enum


class AuthNTypes(Enum):
    """The AuthNTypes Enum
    1 = OAUTH2
    2 = X509
    """

    OAUTH2 = 1
    X509 = 2
