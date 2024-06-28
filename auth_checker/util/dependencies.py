from fastapi import Depends
from auth_checker.models.models import TokenValidator
from typing import Annotated


# TokenValidator Dependency
TokenValidatorDepends = Annotated[TokenValidator, Depends(TokenValidator)]
