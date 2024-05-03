from auth_checker import GoogleJWTAuthenticator, Token, AuthNTypes
from auth_checker.util import HTTPException
from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel

router = APIRouter()


class TokenRequestBody(BaseModel):
    token: str


@router.post("", tags=["Authentication"])
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
