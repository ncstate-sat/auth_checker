import pytest
import jwt
from auth_checker.models.models import Account, AuthnTokenRequestBody
from auth_checker.util.settings import JWT_SECRET, JWT_ALGORITHM

USER_ACCOUNT = {
    "name": "Test User",
    "email": "user@example.com",
}

SERVICE_ACCOUNT = {"client_email": "nonhuman_service@example.com"}

DATE_IN_FUTURE = 17529325008


@pytest.fixture
def account():
    def _account(data=None):
        if data:
            return Account(data)
        return Account(USER_ACCOUNT)

    return _account


@pytest.fixture
def user_to_token(account):
    def _user_to_token(
        expires=DATE_IN_FUTURE, signature=JWT_SECRET, algo=JWT_ALGORITHM, refresh=False
    ):
        acct = {}
        if refresh:
            acct["account"] = account().render()
        else:
            acct = account().render()
        acct["exp"] = expires
        return jwt.encode(acct, signature, algorithm=algo)

    return _user_to_token


@pytest.fixture
def service_to_token(account):
    acct = account(SERVICE_ACCOUNT).render()
    acct["exp"] = DATE_IN_FUTURE
    return jwt.encode(acct, JWT_SECRET, algorithm=JWT_ALGORITHM)


@pytest.fixture
def user_token_request_body(user_to_token):
    return AuthnTokenRequestBody(token=user_to_token(refresh=True))


@pytest.fixture
def service_token_request_body(service_to_token):
    return AuthnTokenRequestBody(token=service_to_token, authn_type=2)
