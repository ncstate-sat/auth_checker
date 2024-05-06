import os
from datetime import datetime, timedelta, timezone

import jwt
from google.auth.transport import requests as google_auth_requests
from google.oauth2 import id_token

TOKEN_EXP_TIME = timedelta(minutes=15)
SERVICE_EXP_TIME = timedelta(hours=8)
REFRESH_TOKEN_EXP_TIME = timedelta(days=2)


class Token:
    @staticmethod
    def decode_google_token(token):
        """Decodes a token from Google Identity Services.
        :param token: The token from Google.
        """
        return id_token.verify_oauth2_token(
            token, google_auth_requests.Request(), os.getenv("GOOGLE_CLIENT_ID")
        )

    @staticmethod
    def decode_token(token):
        """Decodes a JSON Web Token from this Auth Service.
        :param token: The token from this service.
        """
        try:
            return jwt.decode(token, os.getenv("JWT_SECRET"), ["HS256"])
        except jwt.exceptions.ExpiredSignatureError:
            raise HTTPException(401, detail="Token is expired")
        except jwt.exceptions.InvalidSignatureError:
            raise HTTPException(
                400, detail=("Token has an invalid signature. " "Check the JWT_SECRET variable.")
            )

    @staticmethod
    def generate_token(payload: dict):
        """Generates a JSON Web Token given a payload.
        :param payload: The object which will be encoded in the token.
        """
        token_payload = {"exp": datetime.now(tz=timezone.utc) + TOKEN_EXP_TIME}
        token_payload.update(payload)

        return jwt.encode(token_payload, os.getenv("JWT_SECRET"), "HS256")

    @staticmethod
    def service_account_token(payload: dict):
        """Generates a JWT for service accounts which often need much longer
        expiry times.
        """
        token_payload = {"exp": datetime.now(tz=timezone.utc) + SERVICE_EXP_TIME}
        token_payload.update(payload)

        return jwt.encode(token_payload, os.getenv("JWT_SECRET"), "HS256")

    @staticmethod
    def generate_refresh_token(email, refresh: timedelta = REFRESH_TOKEN_EXP_TIME):
        """Generates a refresh JWT given an email address.
        :param email: The email address of the user, which will be encoded in the token.
        :param refresh: A refresh expiry expressed as a timedelta. Defaults to 2 days.
        """
        return jwt.encode(
            {"email": email, "exp": datetime.now(tz=timezone.utc) + refresh},
            os.getenv("JWT_SECRET"),
            "HS256",
        )

    @classmethod
    def decode_refresh_token(cls, token):
        """Decodes a refresh JWT from this Auth Service.
        :param token: The refresh token from this service.
        """
        return cls.decode_token(token)
