from typing import Annotated

from auth_checker.models import GoogleJWTAuthenticator, Account, validate_token, get_authn_token, get_refresh_token
from auth_checker.util.authn_types import AuthNTypes
from auth_checker.util.exceptions import HTTPException
from fastapi import APIRouter, Response, status
from fastapi import Depends
from fastapi.security import HTTPBearer

auth_scheme = HTTPBearer()

router = APIRouter()


@router.post("/token", tags=["Authentication"])
def authenticate(response: Response, authn: Annotated[GoogleJWTAuthenticator, Depends(GoogleJWTAuthenticator)]):
    """Authenticates with Google Identity Services.

    The token, supplied by Google Identity Services, is passed in. Returned is a new token
    that can be used with other services.
    """
    try:
        if authn.authenticate():
            return {
                "token": authn.get_authn_token(authn.account, AuthNTypes.OAUTH2),
                "refresh_token": Token.generate_refresh_token(authn.account.email),
                "payload": authn.account.render(),
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
def refresh_token(response: Response, bearer: Annotated[auth_scheme, Depends(auth_scheme)]):
    """Returns a new token and refresh token.

    The JWT used for authentication expires 15 minutes after it's generated.
    The refresh token can be used to extend the user's session with the app
    without asking them to sign back in.
    """
    breakpoint()
    try:
        account = Account(token)
        new_refresh_token = token.get_refresh_token()
        return {"refresh_token": new_refresh_token, "payload": account.render()}
    except HTTPException:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Your login could not be authenticated."}
