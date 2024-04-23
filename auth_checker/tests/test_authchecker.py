"""verify that AuthChecker allows and blocks the correct requests"""

import os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from auth_checker import AuthChecker


app_to_test = FastAPI()


@app_to_test.get(
    "/1",
    dependencies=[Depends(AuthChecker("auth1"))]
)
def route1():
    """Requires an auth that the user has"""
    return "Success"


@app_to_test.get(
    "/12",
    dependencies=[Depends(AuthChecker("auth1", "auth2"))]
)
def route12():
    """Requires multiple auths"""
    return "Success"


@app_to_test.get(
    "/13",
    dependencies=[Depends(AuthChecker("auth1", "auth3"))]
)
def route13():
    """Requires an auth that's set to False"""
    return "Success"


@app_to_test.get(
    "/4",
    dependencies=[Depends(AuthChecker("auth4"))]
)
def route4():
    """Requires an auth that doesn't appear in the user's authorizations"""
    return "Success"


client = TestClient(app_to_test)
os.environ["JWT_SECRET"] = "TEST_SECRET"

# all tokens have auth1: True, auth2: True, auth3: False
USER_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTQxOTQ4ODA3LCJlbWFpbC"
    "I6ImxtZW5hQG5jc3UuZWR1IiwiY2FtcHVzX2lkIjoiMDAxMTMyODA4Iiwicm9sZXMiOlsid"
    "GVzdF91c2VyIl0sImF1dGhvcml6YXRpb25zIjp7ImF1dGgxIjp0cnVlLCJhdXRoMiI6dHJ1"
    "ZSwiYXV0aDMiOmZhbHNlLCJfcmVhZCI6W10sIl93cml0ZSI6W119fQ.TK96nuYGlBExPSqG"
    "ngI_7I2DQNrGgtaRFDhN1NJyfio"
)
ROOT_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTQxOTQ4ODA3LCJlbWFpbC"
    "I6ImxtZW5hQG5jc3UuZWR1IiwiY2FtcHVzX2lkIjoiMDAxMTMyODA4Iiwicm9sZXMiOlsid"
    "GVzdF91c2VyIl0sImF1dGhvcml6YXRpb25zIjp7ImF1dGgxIjp0cnVlLCJhdXRoMiI6dHJ1"
    "ZSwiYXV0aDMiOmZhbHNlLCJyb290Ijp0cnVlLCJfcmVhZCI6W10sIl93cml0ZSI6W119fQ."
    "8R2uFboSK7FiHtuw8If94pgoNdiWRHuj-yPsl-8sV1U"
)
EXPIRED_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2Njg3MDU2NzMsImVtYWlsIj"
    "oibG1lbmFAbmNzdS5lZHUiLCJjYW1wdXNfaWQiOiIwMDExMzI4MDgiLCJyb2xlcyI6WyJ0Z"
    "XN0X3VzZXIiXSwiYXV0aG9yaXphdGlvbnMiOnsiYXV0aDEiOnRydWUsImF1dGgyIjp0cnVl"
    "LCJhdXRoMyI6ZmFsc2UsIl9yZWFkIjpbXSwiX3dyaXRlIjpbXX19.UmLWB6Pf-hwQaHBdrg"
    "Iq662_H1ZwAT1fWBzL1sfApIo"
)
INVALID_SIGNATURE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQwOTk3Mzc4MDAsImVtYWlsIj"
    "oibG1lbmFAbmNzdS5lZHUiLCJjYW1wdXNfaWQiOiIwMDExMzI4MDgiLCJyb2xlcyI6WyJ0Z"
    "XN0X3VzZXIiXSwiYXV0aG9yaXphdGlvbnMiOnsiYXV0aDEiOnRydWUsImF1dGgyIjp0cnVl"
    "LCJhdXRoMyI6ZmFsc2UsInJvb3QiOnRydWUsIl9yZWFkIjpbXSwiX3dyaXRlIjpbXX19.qo"
    "4DfBZaP-rHptkcwNqh4Lcmhn14ClJ4NK1sKC499pY"
)


def test_one_requirement():
    """User can access a route that requires one auth"""
    response = client.get("/1",
                          headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 200
    assert "Success" in response.text


def test_multiple_requirements():
    """User can access a route that requires multiple auths"""
    response = client.get("/12",
                          headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 200
    assert "Success" in response.text


def test_expired_token():
    """User can't access a route with an expired token"""
    response = client.get("/1",
                          headers={"Authorization": "Bearer " + EXPIRED_JWT})
    assert response.status_code == 401
    assert "Success" not in response.text


def test_invalid_signature_token():
    """User can't access a route using the wrong JWT_SECRET"""
    response = client.get(
        "/1", headers={"Authorization": "Bearer " + INVALID_SIGNATURE_JWT}
    )
    assert response.status_code == 400
    assert "Success" not in response.text


def test_no_token_provided():
    """User should get a 401 if no token is provided."""
    response = client.get("/1",
                          headers={"Authorization": ""})
    assert response.status_code == 401
    assert "Success" not in response.text


def test_no_header_provided():
    """User should get a 401 if no header is provided."""
    response = client.get("/1")
    assert response.status_code == 401
    assert "Success" not in response.text


def test_unauthorized_requirement():
    """
    User can't access a route with a required auth set to False.
    Root user can still access the route.
    """
    response = client.get("/13",
                          headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 403
    assert "Success" not in response.text

    response = client.get("/13",
                          headers={"Authorization": "Bearer " + ROOT_JWT})
    assert response.status_code == 200
    assert "Success" in response.text


def test_nonexistant_requirement():
    """
    User can't access a route that requires an auth user doesn't have.
    Root user can still access the route.
    """
    response = client.get("/4",
                          headers={"Authorization": "Bearer " + USER_JWT})
    assert response.status_code == 403
    assert "Success" not in response.text

    response = client.get("/4",
                          headers={"Authorization": "Bearer " + ROOT_JWT})
    assert response.status_code == 200
    assert "Success" in response.text
