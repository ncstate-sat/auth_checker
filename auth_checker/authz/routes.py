from typing import Annotated
from fastapi import APIRouter, status, Depends, HTTPException
from auth_checker.models.models import TokenValidator
from auth_checker.authz.authorizer import Authorizer

router = APIRouter()
authz = Authorizer()


@router.get("/casbin", tags=["Authorization"])
def authorize(
    resource: str, action: str, valid: Annotated[TokenValidator, Depends(TokenValidator)]
):
    """Authorizes a user to perform an action on a resource. Auth service uses CASBIN for authorization.

    :param resource: The resource to be acted upon. For example, the liaison.
    :param action: The action to be performed on the resource. For example, read.
    :param valid: The token validator dependency. Contains the user's account information.
    :returns: A boolean indicating whether the user is authorized to perform the action.
    """
    try:
        if not authz.authorize(valid.account.email, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not authorized to perform this action.",
            )
    except AttributeError as ae:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"There was a problem with the server configuration: {ae}",
        )


@router.get("/roles", tags=["Authorization"])
def get_roles(valid: Annotated[TokenValidator, Depends(TokenValidator)]):
    """Returns the roles assigned to a user.

    :param valid: The token validator dependency. Contains the user's account information.
    :returns: A list of roles assigned to the user.
    """
    try:
        return {"roles": authz.roles_for_user(valid.account.email)}
    except AttributeError as ae:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"There was a problem with the server configuration: {ae}",
        )
