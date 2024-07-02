"""verify that AuthChecker allows and blocks the correct requests"""
import pytest
import os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from auth_checker.models.models import Account
from auth_checker.authn.routes import router as authn_router


def get_account(d: dict):
    return Account(d)


@pytest.fixture
def patch_google_oauth(monkeypatch, account):
    def _patch_google_oauth(authenticate=True):
        if authenticate:
            monkeypatch.setattr(
                "auth_checker.models.models.GoogleJWTAuthenticator.authenticate", lambda x: True
            )
            monkeypatch.setattr(
                "auth_checker.models.models.GoogleJWTAuthenticator.account", account()
            )
        else:
            monkeypatch.setattr(
                "auth_checker.models.models.GoogleJWTAuthenticator.authenticate", lambda x: False
            )

    return _patch_google_oauth


@pytest.fixture
def patch_authorizer(monkeypatch):
    return monkeypatch.setattr(
        "auth_checker.plugins.authorize.casbin_pl.CasbinAuthorizer.roles_for_user",
        lambda x, y: ["tester"],
    )


app_to_test = FastAPI()
app_to_test.include_router(authn_router, prefix="/auth")
client = TestClient(app_to_test)


def test_authenticate_pass(patch_google_oauth, patch_authorizer, account):
    patch_google_oauth()
    response = client.post("/auth/token", json={"token": "dummytoken", "authn_type": 1})
    assert response.status_code == 200
    assert "token" in response.json()
    assert "refresh_token" in response.json()
    account = response.json()["account"]
    assert account["name"] == "Test User"
    assert account["email"] == "user@example.com"
    assert account["client_email"] is None
    assert account["roles"] == ["tester"]


def test_authenticate_fail(patch_google_oauth, patch_authorizer):
    patch_google_oauth(authenticate=False)
    response = client.post("/auth/token", json={"token": "dummytoken", "authn_type": 1})
    assert response.status_code == 401
    assert "Your login could not be authenticated." in response.json()["detail"]


def test_refresh_token(user_to_token):
    response = client.post("/auth/token/refresh", json={"token": user_to_token(), "authn_type": 1})
    assert response.status_code == 200
    assert "refresh_token" in response.json()
    account = response.json()["account"]
    assert account["name"] == "Test User"
    assert account["email"] == "user@example.com"
    assert account["client_email"] is None


def test_token_validation_w_bearer_token(user_to_token):
    response = client.post(
        "/auth/token/refresh", headers={"Authorization": f"Bearer {user_to_token()}"}
    )
    assert response.status_code == 200
    assert "refresh_token" in response.json()


def test_token_validation_w_x_token(user_to_token):
    response = client.post("/auth/token/refresh", headers={"X-Token": user_to_token()})
    assert response.status_code == 200
    assert "refresh_token" in response.json()


def test_token_validation_w_bearer_no_token(user_to_token):
    response = client.post("/auth/token/refresh", headers={"Authorization": "Bearer"})
    assert response.status_code == 401


def test_token_validation_no_token(user_to_token):
    response = client.post("/auth/token/refresh", json={"token": "", "authn_type": 1})
    assert response.status_code == 401
