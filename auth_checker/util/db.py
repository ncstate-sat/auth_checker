"""
CRUD functions for the database.
"""
import os

from pymongo import MongoClient


class AuthDB:
    """Helper class for database functions."""

    account_collection = None
    role_collection = None

    @classmethod
    def __setup_database(cls):
        """Gets 'accounts' and 'roles' collections from MongoDB."""
        if cls.account_collection is None or cls.role_collection is None:
            client = MongoClient(os.getenv("MONGODB_URL"))
            cls.account_collection = client["Accounts"].get_collection("accounts")
            cls.role_collection = client["Accounts"].get_collection("roles")

    @classmethod
    def update_account(cls, account: dict):
        """
        Updates an account in the database.

        Parameters:
            account: The account data.
        """
        cls.__setup_database()

        # the only fields we need to store in the Accounts collection:
        accounts_fields = ("email", "roles")
        updated_account = {field: account.get(field) for field in accounts_fields}
        return cls.account_collection.update_one(
            {"email": account["email"]}, {"$set": updated_account}
        )

    @classmethod
    def delete_account(cls, account: dict):
        """
        Deletes an account from the mongo database.

        Parameters:
            account: The account data.
        """
        cls.__setup_database()
        return cls.account_collection.delete_one({"email": account["email"]})

    @classmethod
    def create_account(cls, account_data: dict):
        """
        Creates an account in the mongo database.

        Parameters
            account_data: The account data.
        """
        cls.__setup_database()
        return cls.account_collection.insert_one(account_data)
