# Auth Checker

<p align="left">
<a href="https://pypi.org/project/auth_checker/">
    <img src="https://img.shields.io/pypi/v/auth_checker.svg"
        alt = "Release Status">
</a>

A library for authorizing users based on their assigned roles, parsed from their JWT payload.

</p>

- Free software: MIT

## Usage

#### Authorize a read operation

```python
from auth_checker import AuthChecker
from fastapi import APIRouter, Depends

# authorize a user with "personnel:read" permissions to look up personnel
@router.get("", tags=["Personnel"], dependencies=[Depends(AuthChecker("personnel:read"))])
```

#### Authorize an update operation

```python
from auth_checker import AuthChecker
from fastapi import APIRouter, Depends

# authorize a user with "personnel:write" permissions to disable personnel
@router.post("/disable", tags=["Personnel"], dependencies=[Depends(AuthChecker("personnel:write"))])
```

#### Model the JWT payload

`TokenPayload` models the claims of a decoded JWT: `email`, `roles`, `inherited_roles`, and `permissions`.

```python
from auth_checker import TokenPayload

payload = TokenPayload(**decoded_jwt)
```
