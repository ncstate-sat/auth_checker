from typing import Annotated

from auth_checker.models import (
    GoogleJWTAuthenticator,
    get_authn_token,
    get_refresh_token,
    TokenValidator,
)
from auth_checker.util.exceptions import HTTPException
from auth_checker.authz.authorizer import Authorizer
from fastapi import APIRouter, Response, status
from fastapi import Depends


router = APIRouter()


@router.post("/token", tags=["Authentication"])
def authenticate(
    response: Response, authn: Annotated[GoogleJWTAuthenticator, Depends(GoogleJWTAuthenticator)]
):
    """Authenticates with Google Identity Services.

    The token, supplied by Google Identity Services, is passed in. Returned is a new token
    that can be used with other services.
    """
    authz = Authorizer()
    try:
        if authn.authenticate():
            return {
                "token": get_authn_token(authn.account, authn.auth_type),
                "refresh_token": get_refresh_token(authn.account),
                "account": authn.account.render(),
                "roles": authz.roles_for_user(authn.account.email),
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
def refresh_token(response: Response, token: Annotated[TokenValidator, Depends(TokenValidator)]):
    """Returns a new token and refresh token.

    The JWT used for authentication expires 15 minutes after it's generated.
    The refresh token can be used to extend the user's session with the app
    without asking them to sign back in.
    """
    try:
        account = token.account
        new_refresh_token = get_refresh_token(token.account)
        return {"refresh_token": new_refresh_token, "payload": account.render()}
    except HTTPException:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Your login could not be authenticated."}
