"""verify that AuthChecker allows and blocks the correct requests"""

import os
import time
import jwt
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from auth_checker.auth_checker import AuthChecker


app_to_test = FastAPI()


@app_to_test.get("/normal-auth", dependencies=[Depends(AuthChecker("auth1:read"))])
def normal_auth_route():
    """Requires an auth that the user has"""
    return "Success"


@app_to_test.get("/multiple-auths", dependencies=[Depends(AuthChecker("auth1:read", "auth2:read"))])
def multiple_auths_route():
    """Requires multiple auths"""
    return "Success"


@app_to_test.get(
    "/not-enough-permissions", dependencies=[Depends(AuthChecker("auth1:read", "auth2:write"))]
)
def not_enough_permissions_route():
    """Requires an auth that's not in the user's permissions"""
    return "Success"


@app_to_test.get("/no-permissions", dependencies=[Depends(AuthChecker("auth3:read"))])
def no_permissions_route():
    """Requires an auth that doesn't appear in the user's permissions"""
    return "Success"


client = TestClient(app_to_test)
JWT_SECRET = "TEST_SECRET"
os.environ["JWT_SECRET"] = JWT_SECRET


def generate_token(permissions=None, exp=None, secret=JWT_SECRET, email="lmena@ncsu.edu"):
    """
    Build a JWT for testing.
    :param list permissions: overrides the payload's "permissions" list.
    :param int exp: unix timestamp for the payload's "exp". Defaults to one
        hour from now. Pass a timestamp in the past to produce an expired
        token.
    :param str secret: the secret used to sign the token. Use a value other
        than JWT_SECRET to produce a token with an invalid signature.
    :param str email: overrides the payload's "email" field.
    """
    payload = dict(
        {
            "exp": exp if exp is not None else int(time.time()) + 3600,
            "email": email,
            "roles": ["test-user"],
            "inherited_roles": [],
            "permissions": permissions,
        }
    )
    return jwt.encode(payload, secret, algorithm="HS256")


USER_JWT = generate_token(permissions=["auth1:read", "auth1:write", "auth2:read"])
ALL_PERMISSIONS_JWT = generate_token(
    permissions=[
        "auth1:read",
        "auth1:write",
        "auth2:read",
        "auth2:write",
        "auth3:read",
        "auth3:write",
    ]
)
EXPIRED_JWT = generate_token(
    permissions=["auth1:read", "auth1:write", "auth2:read"], exp=int(time.time()) - 3600
)
INVALID_SIGNATURE_JWT = generate_token(
    permissions=["auth1:read", "auth1:write", "auth2:read"], secret="WRONG_SECRET"
)
MISSING_EMAIL_JWT = jwt.encode(
    {
        "exp": int(time.time()) + 3600,
        "roles": ["test-user"],
        "inherited_roles": [],
        "permissions": ["auth1:read"],
    },
    JWT_SECRET,
    algorithm="HS256",
)


def test_one_requirement():
    """User can access a route that requires one auth"""
    response = client.get("/normal-auth", headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 200
    assert "Success" in response.text


def test_multiple_requirements():
    """User can access a route that requires multiple auths"""
    response = client.get("/multiple-auths", headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 200
    assert "Success" in response.text


def test_expired_token():
    """User can't access a route with an expired token"""
    response = client.get("/normal-auth", headers={"Authorization": "Bearer " + EXPIRED_JWT})
    assert response.status_code == 401
    assert "Success" not in response.text


def test_invalid_signature_token():
    """User can't access a route using the wrong JWT_SECRET"""
    response = client.get(
        "/normal-auth", headers={"Authorization": "Bearer " + INVALID_SIGNATURE_JWT}
    )
    assert response.status_code == 400
    assert "Success" not in response.text


def test_malformed_token():
    """User can't access a route with a malformed (non-JWT) token"""
    response = client.get("/normal-auth", headers={"Authorization": "Bearer not-a-real-jwt"})
    assert response.status_code == 400
    assert "Success" not in response.text


def test_no_token_provided():
    """User should get a 401 if no token is provided."""
    response = client.get("/normal-auth", headers={"Authorization": ""})
    assert response.status_code == 401
    assert "Success" not in response.text


def test_no_header_provided():
    """User should get a 401 if no header is provided."""
    response = client.get("/normal-auth")
    assert response.status_code == 401
    assert "Success" not in response.text


def test_unauthorized_requirement():
    """
    User can't access a route with a required auth that isn't in their
    permissions. A user with that permission can still access the route.
    """
    response = client.get(
        "/not-enough-permissions", headers={"Authorization": "Bearer " + USER_JWT}
    )
    assert response.status_code == 403
    assert "Success" not in response.text

    response = client.get(
        "/not-enough-permissions", headers={"Authorization": "Bearer " + ALL_PERMISSIONS_JWT}
    )
    assert response.status_code == 200
    assert "Success" in response.text


def test_payload_missing_required_field():
    """User can't access a route with a token payload missing a required field"""
    response = client.get("/normal-auth", headers={"Authorization": "Bearer " + MISSING_EMAIL_JWT})
    assert response.status_code == 400
    assert "Success" not in response.text


def test_nonexistant_requirement():
    """
    User can't access a route that requires an auth user doesn't have.
    A user with that permission can still access the route.
    """
    response = client.get("/no-permissions", headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 403
    assert "Success" not in response.text

    response = client.get(
        "/no-permissions", headers={"Authorization": "Bearer " + ALL_PERMISSIONS_JWT}
    )
    assert response.status_code == 200
    assert "Success" in response.text
