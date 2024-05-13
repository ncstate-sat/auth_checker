from typing import Mapping

import requests
from google.auth import jwt
import jwt as jot
from google.auth.exceptions import InvalidValue, MalformedError
import json
from google.auth.transport import requests as google_auth_requests
from google.oauth2.id_token import verify_oauth2_token as v_oauth2
from datetime import timedelta, datetime, timezone
from auth_checker.util.settings import JWT_SECRET, GOOGLE_CLIENT_ID
from auth_checker.util.authn_types import AuthNgsTypes
from auth_checker.util.exceptions import HTTPException
from sat.logs import SATLogger

logger = SATLogger(__name__)


TOKEN_EXP_TIME = timedelta(minutes=15)
SERVICE_EXP_TIME = timedelta(hours=8)
REFRESH_TOKEN_EXP_TIME = timedelta(days=2)


class JWTAuthenticator:
    def authenticate(self) -> bool:
        raise NotImplementedError


class GoogleJWTAuthenticator(JWTAuthenticator):
    def __init__(self, token, auth_type=AuthNTypes.OAUTH2):
        self.token = token
        self.auth_type = auth_type
        self.client_id = GOOGLE_CLIENT_ID
        if not self.client_id:
            raise AttributeError("Google Client ID is not set")

    def _oauth2(self) -> bool:
        """Decodes a token from Google Identity Services.
        :param token: The token from Google.
        """
        try:
            if token := v_oauth2(self.token, google_auth_requests.Request(), self.client_id):
                self.account = Account(token)
                return True
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e))

    def _x509(self) -> bool:
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

    def authenticate(self) -> bool:
        if self.auth_type == AuthNTypes.OAUTH2:
            return self._oauth2()
        if self.auth_type == AuthNTypes.X509:
            return self._x509()


class Account:
    """The Account Model"""

    name = None
    email = None
    client_email = None

    def __init__(self, config: Mapping[str, str]):
        for k, v in config.items():
            if hasattr(self, k):
                setattr(self, k, v)

    def render(self):
        return {"name": self.name, "email": self.email, "client_email": self.client_email}


class Token:
    def __init__(self, token: str):
        self.token = token

    def decode_token(self):
        """Decodes a JSON Web Token from this Auth Service.
        :param token: The token from this service.
        """
        try:
            return Account(jot.decode(self.token, JWT_SECRET, "HS256"))
        except jot.exceptions.ExpiredSignatureError:
            raise HTTPException(401, detail="Token is expired")
        except jot.exceptions.InvalidSignatureError:
            raise HTTPException(
                400, detail="Token has an invalid signature. Check the JWT_SECRET variable."
            )

    @staticmethod
    def get_token(payload: Account, token_type: AuthNTypes):
        payload = payload.render()
        if token_type == AuthNTypes.OAUTH2:
            payload["exp"] = datetime.now(tz=timezone.utc) + TOKEN_EXP_TIME
        if token_type == AuthNTypes.X509:
            payload["exp"] = datetime.now(tz=timezone.utc) + SERVICE_EXP_TIME
        return jot.encode(payload, JWT_SECRET, "HS256")

    @staticmethod
    def generate_refresh_token(email, refresh: timedelta = REFRESH_TOKEN_EXP_TIME):
        """Generates a refresh JWT given an email address.
        :param email: The email address of the user, which will be encoded in the token.
        :param refresh: A refresh expiry expressed as a timedelta. Defaults to 2 days.
        """
        payload = {"email": email, "exp": datetime.now(tz=timezone.utc) + refresh}
        return jot.encode(payload, JWT_SECRET, "HS256")
