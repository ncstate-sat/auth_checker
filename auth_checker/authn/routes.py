from auth_checker.models import GoogleJWTAuthenticator, Token
from auth_checker.util.authn_types import AuthNTypes
from auth_checker.util.exceptions import HTTPException
from fastapi import APIRouter, Response, status
from pydantic import BaseModel

router = APIRouter()


class TokenRequestBody(BaseModel):
    token: str
    token_type: AuthNTypes


@router.post("/token", tags=["Authentication"])
def authenticate(response: Response, body: TokenRequestBody):
    """Authenticates with Google Identity Services.

    The token, supplied by Google Identity Services, is passed in. Returned is a new token
    that can be used with other services.
    """
    try:
        ga = GoogleJWTAuthenticator(body.token)
        if ga.authenticate():
            new_token = Token.get_token(ga.account, AuthNTypes.OAUTH2)
            new_refresh_token = Token.generate_refresh_token(ga.account.email)
            return {
                "token": new_token,
                "refresh_token": new_refresh_token,
                "payload": ga.account.render(),
            }
        else:
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return {"message": "Your login could not be authenticated."}
    except HTTPException as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"message": "There was an error decoding the Google token.", "error": e}
    except AttributeError as ae:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"message": "There was a problem with the server configuration", "error": ae}


@router.post("/token/refresh", tags=["Authentication"])
def refresh_token(response: Response, body: TokenRequestBody):
    """Returns a new token and refresh token.

    The JWT used for authentication expires 15 minutes after it's generated.
    The refresh token can be used to extend the user's session with the app
    without asking them to sign back in. This function takes a refresh token,
    and it returns a new auth token (expires in 15 minutes) and a new refresh token.
    """
    token = Token(body.token)
    try:
        account = token.decode_token()
        new_token = token.get_token(account, AuthNTypes.OAUTH2)
        new_refresh_token = token.generate_refresh_token(account.email)
        return {"token": new_token, "refresh_token": new_refresh_token, "payload": account.render()}
    except HTTPException:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Your login could not be authenticated."}
