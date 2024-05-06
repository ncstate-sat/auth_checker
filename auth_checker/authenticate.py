from auth_checker.models.account import Account
from auth_checker.models.token import Token
from auth_checker.util.service import ServiceUtils

class Authenticate:
    def google_login(token: str):
        """Authenticates with Google Identity Services.

        The token, supplied by Google Identity Services, is passed in. Returned is a new token
        that can be used with other services.
        """
        google_info = Token.decode_google_token(token)
        user_email = google_info["email"]
        user_name = google_info["name"]
        account = Account.get_account(user_email, user_name)

        new_token = Token.generate_token(account.__dict__)
        new_refresh_token = Token.generate_refresh_token(user_email)

        return {"token": new_token, "refresh_token": new_refresh_token, "payload": account.__dict__}

    def service_login(token: str):
        error_message = ""
        if claims := ServiceUtils.google_authenticate(token):
            if account := Account.get_service_account(claims.get("client_email")):
                auth_token = Token.service_account_token(account.__dict__)
                return {"auth_token": auth_token}
            else:
                error_message = f"Could not authorize. Account not found. {claims.get('client_email')}"
        else:
            error_message = "The service could not be authenticated."
        raise RuntimeError(error_message)

    def refresh_token(token: str):
        """Returns a new token and refresh token.

        The JWT used for authentication expires 15 minutes after it's generated.
        The refresh token can be used to extend the user's session with the app
        without asking them to sign back in. This function takes a refresh token,
        and it returns a new auth token (expires in 15 minutes) and a new refresh token.
        """
        payload = Token.decode_token(token)
        email = payload["email"]
        account = Account.get_account(email)

        new_token = Token.generate_token(account.__dict__)
        new_refresh_token = Token.generate_refresh_token(email)

        return {"token": new_token, "refresh_token": new_refresh_token, "payload": account.__dict__}

