import pytest
import jwt
from auth_checker.models.models import Account
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
    acct = account(USER_ACCOUNT).render()
    acct["exp"] = DATE_IN_FUTURE
    return jwt.encode(acct, JWT_SECRET, algorithm=JWT_ALGORITHM)


@pytest.fixture
def service_to_token(account):
    acct = account(SERVICE_ACCOUNT).render()
    acct["exp"] = DATE_IN_FUTURE
    return jwt.encode(acct, JWT_SECRET, algorithm=JWT_ALGORITHM)
