import os
import requests
import json
from google.auth import jwt
from google.oauth2.id_token import verify_oauth2_token as v_oauth2
from google.auth.transport import requests as google_auth_requests
from google.auth.exceptions import InvalidValue, MalformedError
from auth_checker.models.account import Account
from auth_checker.util.auth_types import AuthTypes
from auth_checker.util.exceptions import HTTPException
from sat.logs import SATLogger

logger = SATLogger(__name__)


class JWTAuthenticator:
    def authenticate(self) -> bool:
        raise NotImplementedError


class GoogleJWTAuthenticator(JWTAuthenticator):
    def __init__(self, token, auth_type=AuthTypes.OAUTH2):
        self.token = token
        self.auth_type = auth_type
        self.client_id = os.getenv("GOOGLE_CLIENT_ID")
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
        if self.auth_type == AuthTypes.OAUTH2:
            return self._oauth2()
        if self.auth_type == AuthTypes.X509:
            return self._x509()
