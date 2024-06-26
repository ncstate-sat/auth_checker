import os
from typing import Any

from pymongo import MongoClient

from auth_checker.util.interfaces import BaseAuthorizer

# Not covered by tests as this is a plugin that is not used in the current implementation
# and is meant more as a demonstration of how to create a plugin for the authorizer.


class ExampleMongoAuthorizer(BaseAuthorizer):  # pragma: no cover
    name = "example_mongo_authorizer"
    account_collection = None
    role_collection = None

    def __init__(self, *args, **kwargs):
        if self.account_collection is None or self.role_collection is None:
            client = MongoClient(os.getenv("MONGODB_URL"))
            self.account_collection = client["Accounts"].get_collection("accounts")
            self.role_collection = client["Accounts"].get_collection("roles")
        super().__init__(*args, **kwargs)

    def authorize(self, *args, **kwargs) -> list[dict] | dict:
        return self.roles_for_user(*args, **kwargs)

    def roles_for_user(self, *args, **kwargs) -> list[dict] | dict:
        account_data: dict = self.account_collection.find_one({"email": args[0]})
        if account_data:
            authorization_data = self.role_collection.find(
                {"name": {"$in": account_data.get("roles", [])}}
            )

            authorizations = {}
            read_roles = []
            write_roles = []
            for data in authorization_data:
                data_read_roles = data.get("authorizations", {}).get("_read", [])
                data_write_roles = data.get("authorizations", {}).get("_write", [])
                data["authorizations"].pop("_read")
                data["authorizations"].pop("_write")
                data.pop("_id")
                authorizations.update(data["authorizations"])
                read_roles = read_roles + data_read_roles
                write_roles = write_roles + data_write_roles

            account_data.pop("_id")
            authorizations["_read"] = read_roles
            authorizations["_write"] = write_roles
            account_data["authorizations"] = authorizations

        return account_data

    def users_for_role(self, *args, **kwargs) -> list[dict] | dict:
        account_data: list[dict] = self.account_collection.aggregate(
            [
                {"$match": {"roles": args[0]}},
                {
                    "$lookup": {
                        "from": "roles",
                        "localField": "roles",
                        "foreignField": "name",
                        "as": "authorizations",
                    }
                },
            ]
        )

        transformed_account_data = []
        for data in account_data:
            authorizations = {}
            read_roles = []
            write_roles = []
            for auth in data["authorizations"]:
                data_read_roles = auth.get("authorizations", {}).get("_read", [])
                data_write_roles = auth.get("authorizations", {}).get("_write", [])
                auth["authorizations"].pop("_read")
                auth["authorizations"].pop("_write")
                authorizations.update(auth.get("authorizations", {}))
                read_roles = read_roles + data_read_roles
                write_roles = write_roles + data_write_roles

            data.pop("_id")
            authorizations["_read"] = read_roles
            authorizations["_write"] = write_roles
            data["authorizations"] = authorizations
            transformed_account_data.append(data)

        return transformed_account_data

    def permissions_for_user(self, *args, **kwargs) -> list[Any]:
        return self.roles_for_user(*args, **kwargs)
