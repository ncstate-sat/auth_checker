"""Contains the TokenPayload model, representing the payload of a decoded JWT"""

from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """
    TokenPayload models the claims contained in a JWT issued by the Auth
    Service, once decoded by AuthChecker.
    """

    email: str
    roles: list[str] = Field(default_factory=list)
    inherited_roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
