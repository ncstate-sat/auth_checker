"""Contains the AuthChecker class, verifying user permissions"""

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

    def __init__(self, *required_permissions):
        """
        :param strings required_authorizations: Each string given is a
        permission required by the function.
        """
        self.required_permissions = required_permissions

    def __call__(self, authorization=Header(default="")):
        """
        When an AuthChecker object is called, get the 'Authorization'
        header from the request and check the user's permissions from the jwt.
        """
        self.check_authorization(authorization_header=authorization)

    def check_authorization(self, authorization_header):
        """
        Get the jwt from the header, decode to get the user's permissions.
        Throw HTTP Exception if the user doesn't have all of the function's
        required permissions.
        :param str authorization_header: the request's Authorization header.
            The header value is a JWT.
        """
        token = authorization_header.lstrip("Bearer").strip()
        if not token:
            raise HTTPException(401, detail="No token provided in 'Authorization' header")
        try:
            secret = os.getenv("JWT_SECRET")
            if not secret:
                raise HTTPException(400, detail="No environment variable JWT_SECRET found")
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.exceptions.ExpiredSignatureError:
            raise HTTPException(401, detail="Token is expired")
        except jwt.exceptions.InvalidSignatureError:
            raise HTTPException(
                400, detail=("Token has an invalid signature. " "Check the JWT_SECRET variable.")
            )

        user_permissions = payload.get("permissions", [])
        for required_permission in self.required_permissions:
            # Throw a 403 if the user doesn't have the required permission:
            if required_permission not in user_permissions:
                raise HTTPException(403, detail=f"{required_permission} permission is required.")
