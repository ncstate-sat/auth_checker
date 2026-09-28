# Auth Checker

A library that provides both authentication and authorization functionalities.

## Installation

```bash
  pip install auth-checker
```

## Authentication

Currently, there is only a single authentication method available, which is token based via Google Authentication. But
the library is designed to be extensible, by extending the `Authenticator` class and implementing the `authenticate` method.

The library provides two FastAPI routes that provide initial authentication and token refresh functionalities.

* /token/
* /token/refresh/

You can bring them into your FastAPI app by using the `auth_checker.authn.routes.router`.

```python
from auth_checker.authn.routes import router as auth_router
from fastapi import FastAPI
app = FastAPI()

...

app.include_router(auth_router, prefix="/auth")
```

## Authorization

The library provides a plugin system for authorization. You can create your own authorization plugins by inheriting from
the `BaseAuthorizer` class and implementing the required methods.

At this time this library provides a primary authorization plugin (`casbin_pl`) that is based on the [Casbin Authorization Library](https://casbin.org/).

There is a `satauth_pl` plugin that is provided, but it is primarily meant as a demo port of the original
`Authorization Service`.  It can be used as a reference for creating your own plugins.

### Routes

The library provides two fastapi routes for authorization:

* `/casbin` The root route provides casbin enforcer authorization route.
* `/roles` The roles route provides roles route for the user. This endpoint is not casbin specific.

### Usage

```python
from auth_checker.authz.authorizer import Authorizer

authz = Authorizer()

# Check if a user is authorized to perform an action
if authz.authorize("user@company.com", "my_app", "read"):
    print("User is authorized")
else:
    print("User is not authorized")
```


### Environment Variables / Settings

In projects that use this library the following environment variables should be set:
The `AUTHORIZER` tells the system which of the installed plugins to use. In this case, use the `casbin_authorizer`.

```bash
export AUTHORIZER=casbin_authorizer
```

After that refer to the plugins themselves for the required environment variables.

#### Casbin Authorization Plugin

##### Environment Variables

* CASBIN_AUTHORIZER_POLICY_ADAPTER

The `CASBIN_AUTHORIZER_POLICY_ADAPTER` tells the plugin which policy store to use. There are three initial options:

* `file` - This stores the policy in a file.
* `mongo` - This stores the policy in a MongoDB database.
* `redis` - This stores the policy in a Redis database.

The `file` Policy Adapter requires the following environment variables:

* CASBIN_POLICY_FILE

The `mongo` Policy Adapter requires the following environment variables:

* CASBIN_AUTH_URI
* CASBIN_AUTH_DB

The `redis` Policy Adapter requires the following environment variables:

* CASBIN_REDIS_HOST
* CASBIN_REDIS_PORT (optional) - Default is 6379
* CASBIN_REDIS_PASSWORD (optional) - Default is None
* CASBIN_REDIS_DB (optional) - Default is 0

##### Adding Policies

Right now there is no frontend for adding policies. You can add policies by using the Casbin library directly.
The functions required to manage the policy store can be found here: [Casbin Policy Management](https://github.com/casbin/pycasbin/blob/master/casbin/enforcer.py)

```python
from auth_checker.authz.authorizer import Authorizer

authz = Authorizer()

# First lets create a staff role for an application called `my_app`
authz.enforcer.add_policy("staff", "my_app", "read")
authz.enforcer.add_policy("staff", "my_app", "write")

# Now let's add a user to the staff role
authz.enforcer.add_role_for_user("user@company.com", "staff")
```
There are more examples of how to organize the policy structure in `notebooks/setup_casbin_policy_store.ipynb`.

To use the notebook, you will need to make sure the required environment variables are set. Then bring up jupyter lab
and open the notebook.

```shell
$> make lab
```
