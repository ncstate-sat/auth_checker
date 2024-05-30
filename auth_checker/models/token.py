import os
from datetime import datetime, timedelta, timezone

import jwt
from google.auth.transport import requests as google_auth_requests
from google.oauth2 import id_token
from auth_checker.util.auth_types import AuthTypes
from auth_checker.models.account import Account

TOKEN_EXP_TIME = timedelta(minutes=15)
SERVICE_EXP_TIME = timedelta(hours=8)
REFRESH_TOKEN_EXP_TIME = timedelta(days=2)


class Token:
    @staticmethod
    def decode_token(token):
        """Decodes a JSON Web Token from this Auth Service.
        :param token: The token from this service.
        """
        decoded_token = jwt.decode(token, os.getenv("JWT_SECRET"), ["HS256"])
        return Account(decoded_token)

    @staticmethod
    def generate_token(account: Account, token_type: AuthTypes):
        """Generates a JSON Web Token given a payload.
        :param payload: The object which will be encoded in the token.
        """
        token_payload = account.render()

        if token_type == AuthTypes.OAUTH2:
            token_payload["exp"] = datetime.now(tz=timezone.utc) + TOKEN_EXP_TIME
        if token_type == AuthTypes.X509:
            token_payload["exp"] = datetime.now(tz=timezone.utc) + SERVICE_EXP_TIME

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
