import os

AUTHORIZER = os.getenv("AUTHORIZER", "casbin_authorizer")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
JWT_SECRET = os.getenv("JWT_SECRET")
