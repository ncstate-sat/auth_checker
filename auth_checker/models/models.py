from typing import Mapping, Annotated, Union
from fastapi import Header, Depends
from fastapi.exceptions import HTTPException
import requests
from google.auth import jwt
import jwt as jot
from google.auth.exceptions import InvalidValue, MalformedError
import json
from google.auth.transport import requests as google_auth_requests
from google.oauth2.id_token import verify_oauth2_token as v_oauth2
from datetime import timedelta, datetime, timezone
from auth_checker.util.settings import (
    JWT_SECRET,
    GOOGLE_CLIENT_ID,
    JWT_ALGORITHM,
    ACCOUNT_TOKEN_EXP_TIME as TOKEN_EXP_TIME,
    SERVICE_TOKEN_EXP_TIME as SERVICE_EXP_TIME,
    REFRESH_TOKEN_EXP_TIME as REFRESH_EXP_TIME,
)

from auth_checker.util.authn_types import AuthNTypes
from sat.logs import SATLogger
from pydantic import BaseModel, Field


logger = SATLogger(__name__)

TOKEN_HEADER_ANNOTATION = Annotated[Union[str, None], Header()]


class AuthnTokenRequestBody(BaseModel):
    """
    The primary model for tracking the information need to authenticate with a
    token.
    """

    token: str
    authn_type: int = Field(default=AuthNTypes.OAUTH2.value)


class Authenticator:
    def authenticate(self) -> bool:
        raise NotImplementedError


class GoogleJWTAuthenticator(Authenticator):
    account = None

    def __init__(self, body: AuthnTokenRequestBody):
        self.token = body.token
        self.auth_type = body.authn_type
        self.client_id = GOOGLE_CLIENT_ID
        if not self.client_id:
            raise AttributeError("Google Client ID is not set")

    def _oauth2(self) -> bool:
        """Decodes a token from Google Identity Services."""
        try:
            if token := v_oauth2(self.token, google_auth_requests.Request(), self.client_id):
                self.account = Account(token)
                return True
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e))

    def _x509(self) -> bool:  # pragma: no cover
        """
        Takes a jwt payload signed by a google service account, and authenticates the
        signature. The signed_jwt payload must include the `client_x509_cert_url`  and the
        `client_email` for the service. This can be found in the service account key
        (https://cloud.google.com/iam/docs/keys-list-get)
        :returns bool
        """
        # Get the cert url from the jwt before verification
        unverified_claims = jwt.decode(self.token, verify=False)
        if url := unverified_claims.get("client_x509_cert_url"):
            # Get the public certs for the client

            # This part of the code is essentially untestable because it requires real
            # google services to be running, a real service account, and a real jwt token
            # from google.
            certs = requests.get(url, timeout=3)
            if certs.status_code != 200:
                logger.error(f"Could not get public certs for {url}")
                return False
            elif certs.content:
                public_certs = json.loads(certs.content)
                try:
                    result = dict(jwt.decode(self.token, certs=public_certs))
                    self.account = Account(result)
                    return True
                except MalformedError as e:
                    logger.error(f"{e}")
                    return False
                except InvalidValue as e:
                    logger.error(f"{e}")
                    return False
        else:
            logger.error("The jwt supplied payload is missing the client_x509_cert_url")
            raise HTTPException(
                status_code=400,
                detail="The jwt supplied payload is missing the client_x509_cert_url",
            )

    def authenticate(self) -> bool:
        if self.auth_type == AuthNTypes.OAUTH2.value:
            return self._oauth2()
        if self.auth_type == AuthNTypes.X509.value:
            return self._x509()


class Account:
    """The Account Model"""

    name = None
    email = None
    client_email = None
    roles = []

    def __init__(self, config: Mapping[str, str]):
        for k, v in config.items():
            if hasattr(self, k):
                setattr(self, k, v)

    def render(self):
        return {
            "name": self.name,
            "email": self.email,
            "client_email": self.client_email,
            "roles": self.roles,
        }

    @property
    def get_email(self):
        if self.email:
            return self.email
        if self.client_email:
            return self.client_email


class BaseTokenValidator:
    def __init__(self, *args, **kwargs):
        self.account = None
        self.token = None

    def _validate(self) -> bool:
        """
        Validates a JSON Web Token for this app.
        :returns tuple: (bool, Account)
        """
        if not self.token:
            raise HTTPException(401, detail="Token is missing.")
        try:
            if token_map := jot.decode(self.token, JWT_SECRET, algorithms=[JWT_ALGORITHM]):
                logger.debug(f"Token map: {token_map}")
                if account := token_map.get("account"):
                    self.account = Account(account)
                else:
                    self.account = Account(token_map)
                if not self.account:
                    raise HTTPException(401, detail="Account information is missing")
                return True
        except jot.exceptions.ExpiredSignatureError:
            raise HTTPException(401, detail="Token is expired")
        except jot.exceptions.InvalidSignatureError:
            raise HTTPException(
                400, detail="Token has an invalid signature. Check the JWT_SECRET variable."
            )


class RefreshTokenValidator(BaseTokenValidator):
    def __init__(self, body: AuthnTokenRequestBody):
        super().__init__()
        if token := body.token:
            self.token = token
            self._validate()
        else:
            raise HTTPException(401, detail="Token is missing")


class TokenValidator(BaseTokenValidator):
    def __init__(
        self,
        authorization: TOKEN_HEADER_ANNOTATION = None,
        x_token: TOKEN_HEADER_ANNOTATION = None,
    ):
        """
        :param authorization: Captures the Authorization key in the HTTP Header. Populated in GET requests.
            Should be sent in the format:
                Authorization: Bearer <STR>
        :param x_token: This is a custom header that can be used to pass a token. Added primarily for Swagger docs testing.
            Should be in the format:
                X-Token: Bearer <STR>
        """
        super().__init__()
        if authorization:
            try:
                self.token = authorization.split(" ")[1]
            except IndexError:
                raise HTTPException(401, detail="Token is missing")
        elif x_token:
            self.token = x_token
        if not self.token:
            raise HTTPException(401, detail="Token is missing")
        self.account = None
        self._validate()


class TokenAuthorizer:
    def __init__(self, roles: list[str]):
        self.authorized_roles = roles
        self.token = None

    def __call__(self, token: Annotated[TokenValidator, Depends(TokenValidator)]):
        if not token.account:
            raise HTTPException(401, detail="No account can be found in the token")
        if not token.account.roles:
            raise HTTPException(401, detail="User has no roles")
        if not any(role in self.authorized_roles for role in token.account.roles):
            raise HTTPException(403, detail="User is not authorized to perform this action")
        self.token = token.token
        return self


def _encode_jwt(payload: dict, secret: str, algorithm: str) -> str:
    try:
        return jot.encode(payload, secret, algorithm)
    except NotImplementedError as e:
        raise HTTPException(401, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=f"An unknown error has occurred: {e}")


def get_token(account: Account, expiry: timedelta = REFRESH_EXP_TIME):
    """Generates a JWT given an email address, with a given duration. The default is 2 days, for
    a refresh token.
    :param account: An Account object.
    :param expiry: An expiry expressed as a timedelta. Defaults to 2 days.
    """
    payload = {"account": account.render(), "exp": datetime.now(tz=timezone.utc) + expiry}
    return _encode_jwt(payload, JWT_SECRET, JWT_ALGORITHM)


def get_authn_token(payload: Account, token_type: AuthNTypes):
    payload = payload.render()
    if token_type == AuthNTypes.OAUTH2:
        payload["exp"] = datetime.now(tz=timezone.utc) + TOKEN_EXP_TIME
    if token_type == AuthNTypes.X509:
        payload["exp"] = datetime.now(tz=timezone.utc) + SERVICE_EXP_TIME
    return _encode_jwt(payload, JWT_SECRET, JWT_ALGORITHM)
