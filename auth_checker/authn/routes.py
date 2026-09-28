from typing import Annotated

from auth_checker.models.models import (
    GoogleJWTAuthenticator,
    get_authn_token,
    get_token,
    RefreshTokenValidator,
)
from fastapi import HTTPException
from auth_checker.authz.authorizer import Authorizer
from auth_checker.util.settings import ACCOUNT_TOKEN_EXP_TIME
from fastapi import APIRouter, status
from fastapi import Depends
from sat.logs import SATLogger

logger = SATLogger(__name__)


router = APIRouter()
authz = Authorizer()


@router.post("/token", tags=["Authentication"])
def authenticate(authn: Annotated[GoogleJWTAuthenticator, Depends(GoogleJWTAuthenticator)]):
    """Authenticates with Google Identity Services.

    The token, supplied by Google Identity Services, is passed in. Returned is a new token
    that can be used with other services.

    :returns: A new token, refresh token, and account information.
    """
    authz.enforcer.load_policy()
    try:
        if authn.authenticate():
            authn.account.roles = authz.roles_for_user(authn.account.get_email)
            return {
                "token": get_authn_token(authn.account, authn.auth_type),
                "refresh_token": get_token(authn.account),
                "account": authn.account.render(),
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Your login could not be authenticated.",
            )
    except AttributeError as ae:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"There was a problem with the server configuration: {ae}",
        )


@router.post("/token/refresh", tags=["Authentication"])
def refresh_token(token: Annotated[RefreshTokenValidator, Depends(RefreshTokenValidator)]):
    """Returns a new token and refresh token.

    The JWT used for authentication expires 15 minutes after it's generated.
    The refresh token can be used to extend the user's session with the app
    without asking them to sign back in.

    :returns: A new long-lived token, a new short-lived token, and plain text account information.
    """
    authz.enforcer.load_policy()
    logger.debug(f"Token refresh request for {token.account.render()}")
    token.account.roles = authz.roles_for_user(token.account.email)
    logger.debug(f"Roles for {token.account.email}: {token.account.roles}")
    new_refresh_token = get_token(token.account)
    new_token = get_token(token.account, expiry=ACCOUNT_TOKEN_EXP_TIME)
    return {
        "token": new_token,
        "refresh_token": new_refresh_token,
        "account": token.account.render(),
    }
