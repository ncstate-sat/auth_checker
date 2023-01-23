"""Contains the AuthChecker class, verifying user authorizations"""

import os
from fastapi import Header, HTTPException
import jwt


class AuthChecker:
    """
    AuthChecker verifies that the user is authorized to access a given route
    when added to the route's dependencies, using the jwt token
    in the request header.
    An HTTP Exception is raised if the user is not authorized.
    """

    def __init__(self, *required_authorizations):
        """
        :param strings required_authorizations: Each string given is the
        title of an authorization required by the function.
        """
        self.required_authorizations = required_authorizations

    def __call__(self, authorization=Header(default="")):
        """
        When an AuthChecker object is called, get the 'Authorization'
        header from the request and check the user's permissions from the jwt.
        """
        self.check_authorization(authorization_header=authorization)

    def check_authorization(self, authorization_header):
        """
        Get the jwt from the header, decode to get the user's authorizations.
        Throw HTTP Exception if the user doesn't have all of the function's
        required authorizations.
        :param str authorization_header: the request's Authorization header.
            The header value is a JWT.
        """
        token = authorization_header.lstrip("Bearer").strip()
        if not token:
            raise HTTPException(
                401,
                detail="No token provided in 'Authorization' header"
            )
        try:
            secret = os.getenv("JWT_SECRET")
            if not secret:
                raise HTTPException(
                    400,
                    detail="No environment variable JWT_SECRET found"
                )
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.exceptions.ExpiredSignatureError:
            raise HTTPException(401, detail="Token is expired")
        except jwt.exceptions.InvalidSignatureError:
            raise HTTPException(400, detail=("Token has an invalid signature. "
                                             "Check the JWT_SECRET variable."))

        user_authorizations = payload.get("authorizations", {})
        if user_authorizations.get("root") is True:
            # Then the user is authorized. Continue without any exceptions.
            return
        for required_auth in self.required_authorizations:
            # Throw a 403 if the authorization isn't there or is set to False:
            if user_authorizations.get(required_auth, False) is False:
                raise HTTPException(
                    403,
                    detail=f"{required_auth} authorization is required."
                )
