import json

import requests
from google.auth import jwt
from google.auth.exceptions import InvalidValue, MalformedError
from sat.logs import SATLogger

logger = SATLogger(__name__)


class ServiceUtils:
    def google_authenticate(signed_jwt: str) -> dict:
        """google_authenticate
        Takes a jwt payload signed by a google service account, and authenticates the
        signature. The signed_jwt payload must include the `client_x509_cert_url`  and the
        `client_email` for the service. This can be found in the service account key
        (https://cloud.google.com/iam/docs/keys-list-get)

        :param signed_jwt
        :returns dict: Either empty if the signature cannot be verified or with validated claims
        """
        # Get the cert url from the jwt before verification
        unverified_claims = jwt.decode(signed_jwt, verify=False)
        if url := unverified_claims.get("client_x509_cert_url"):
            # Get the public certs for the client
            certs = requests.get(url, timeout=3)
            if certs.status_code != 200:
                logger.error(f"Could not get public certs for {url}")
            elif certs.content:
                public_certs = json.loads(certs.content)
                try:
                    return dict(jwt.decode(signed_jwt, certs=public_certs))
                except MalformedError as e:
                    logger.error(f"{e}")
                except InvalidValue as e:
                    logger.error(f"{e}")
        else:
            logger.error("The jwt supplied payload is missing the client_x509_cert_url")
        return {}
