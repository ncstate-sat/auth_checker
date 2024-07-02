import os
from datetime import timedelta

AUTHORIZER = os.getenv("AUTHORIZER", "casbin_authorizer")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# TOKEN EXPIRY TIMES
# An integer for number of minutes
ACCOUNT_TOKEN_EXP_TIME = timedelta(minutes=os.getenv("ACCOUNT_TOKEN_EXP_TIME", 15))
# An integer for number of hours
SERVICE_TOKEN_EXP_TIME = timedelta(hours=os.getenv("SERVICE_TOKEN_EXP_TIME", 8))
# An integer for number of days
REFRESH_TOKEN_EXP_TIME = timedelta(days=os.getenv("REFRESH_TOKEN_EXP_TIME", 2))

CASBIN_RBAC_MODEL = """
    [request_definition]
    r = sub, obj, act

    [policy_definition]
    p = sub, obj, act

    [role_definition]
    g = _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""
