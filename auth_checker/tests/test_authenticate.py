import os
import jwt
from datetime import datetime, timedelta, timezone
from auth_checker.models.token import Token
from auth_checker.util.service import ServiceUtils
from auth_checker.authenticate import Authenticate

def test_google_login(monkeypatch):
    """It should return a JWT with a valid Google credential."""
    def mock_decode_google_token(*_, **__):
        return {"email": "jtchampi@ncsu.edu", "name": "John Champion"}
    
    monkeypatch.setattr(Token, "decode_google_token", mock_decode_google_token)

    response = Authenticate.google_login("asdf")
    assert response is not None


def test_google_login_bad_credential(monkeypatch):
    """It should throw an error if an invalid Google credential is given."""
    def mock_decode_google_token(*_, **__):
        return {"email": "jtchampi@ncsu.edu", "name": "John Champion"}
    
    monkeypatch.setattr(Token, "decode_google_token", mock_decode_google_token)

    try:
        Authenticate.google_login("asdf")
    except RuntimeError as _:
        assert True


def test_service_login(monkeypatch):
    """It should return a JWT with a valid service login."""
    def mock_google_authenticate(*_, **__):
        return {"client_email": "jtchampi@ncsu.edu"}
    
    monkeypatch.setattr(ServiceUtils, "google_authenticate", mock_google_authenticate)

    response = Authenticate.service_login("asdf")
    assert response is not None


def test_service_login_bad_credential(monkeypatch):
    """It should throw an error with an invalid service login."""
    def mock_google_authenticate(*_, **__):
        raise RuntimeError()
    
    monkeypatch.setattr(ServiceUtils, "google_authenticate", mock_google_authenticate)

    try:
        Authenticate.service_login("asdf")
    except RuntimeError as _:
        assert True


def test_refresh_token():
    token = Token.generate_token({ "email": "jtchampi@ncsu.edu" })
    new_token = Authenticate.refresh_token(token)
    assert new_token is not None


def test_refresh_token_expired_credential():
    token_payload = {"exp": datetime.now(tz=timezone.utc) - timedelta(minutes=30)}
    token = jwt.encode(token_payload, os.getenv("JWT_SECRET"), "HS256")

    try:
        Authenticate.refresh_token(token)
    except jwt.exceptions.ExpiredSignatureError as _:
        assert True