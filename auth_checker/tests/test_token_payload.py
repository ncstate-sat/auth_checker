"""verify that TokenPayload models a decoded JWT's claims correctly"""

import pytest
from pydantic import ValidationError
from auth_checker.token_payload import TokenPayload


def test_token_payload_from_full_claims():
    """TokenPayload can be built from a fully-populated set of claims"""
    payload = TokenPayload(
        email="lmena@ncsu.edu",
        roles=["test-user"],
        inherited_roles=["base-user"],
        permissions=["auth1:read"],
    )
    assert payload.email == "lmena@ncsu.edu"
    assert payload.roles == ["test-user"]
    assert payload.inherited_roles == ["base-user"]
    assert payload.permissions == ["auth1:read"]


def test_token_payload_defaults_list_fields():
    """roles, inherited_roles, and permissions default to empty lists"""
    payload = TokenPayload(email="lmena@ncsu.edu")
    assert payload.roles == []
    assert payload.inherited_roles == []
    assert payload.permissions == []


def test_token_payload_requires_email():
    """TokenPayload raises a ValidationError if email is missing"""
    with pytest.raises(ValidationError):
        TokenPayload(roles=["test-user"], inherited_roles=[], permissions=[])
