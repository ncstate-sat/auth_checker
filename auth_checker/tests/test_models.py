import pytest
from auth_checker.models.models import (
    GoogleJWTAuthenticator,
    get_authn_token,
    _encode_jwt,
)
from auth_checker.util.authn_types import AuthNTypes
from fastapi.exceptions import HTTPException
from auth_checker.models.models import AuthnTokenRequestBody, RefreshTokenValidator


def test_errors_no_client_id(mocker, user_token_request_body):
    mocker.patch("auth_checker.models.models.GOOGLE_CLIENT_ID", None)
    with pytest.raises(AttributeError) as e:
        GoogleJWTAuthenticator(user_token_request_body)
    assert "Google Client ID is not set" in str(e.value)


def test_oauth2_default_value(mocker, user_token_request_body):
    mocked = mocker.patch(
        "auth_checker.models.models.GoogleJWTAuthenticator._oauth2", return_value=True
    )
    GoogleJWTAuthenticator(user_token_request_body).authenticate()
    mocked.assert_called_once()


def test_x509_is_called(mocker, service_token_request_body):
    # Test the code path when a service token is used.
    # The validation and decoding logic isn't really testable, so we'll just
    # make sure the method is called.
    mocked = mocker.patch(
        "auth_checker.models.models.GoogleJWTAuthenticator._x509", return_value=True
    )
    GoogleJWTAuthenticator(service_token_request_body).authenticate()
    mocked.assert_called_once()


def test_token_validator_valid(user_token_request_body):
    token_validator = RefreshTokenValidator(user_token_request_body)
    assert token_validator
    assert token_validator.account
    assert token_validator.account.name == "Test User"


def test_token_validator_invalid_expired(user_to_token):
    with pytest.raises(HTTPException) as e:
        utoken = user_to_token(expires=0)
        RefreshTokenValidator(AuthnTokenRequestBody(token=utoken, authn_type=AuthNTypes.OAUTH2))
    assert e.value.status_code == 401
    assert "Token is expired" in e.value.detail


def test_token_validator_invalid_bad_signature(user_to_token):
    with pytest.raises(HTTPException) as e:
        utoken = user_to_token(signature="badsecret")
        RefreshTokenValidator(AuthnTokenRequestBody(token=utoken, authn_type=AuthNTypes.OAUTH2))
    assert e.value.status_code == 400
    assert "Token has an invalid signature. Check the JWT_SECRET variable." in e.value.detail


def test_encode_jwt_x509(account):
    assert get_authn_token(account(), AuthNTypes.X509)


def test_encode_jwt_oauth2(account):
    assert get_authn_token(account(), AuthNTypes.OAUTH2)


def test_encode_jwt_invalid_algorithm(account):
    with pytest.raises(HTTPException) as e:
        _encode_jwt(account().render(), "TEST_SECRET", "")
    assert e.value.status_code == 401
    assert "Algorithm not supported" in e.value.detail


def test_encode_jwt_unknown_error(account):
    with pytest.raises(HTTPException) as e:
        _encode_jwt(account(), "TEST_SECRET", "HS256")
    assert e.value.status_code == 500
    assert "An unknown error has occurred" in e.value.detail
