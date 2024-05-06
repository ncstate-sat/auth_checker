"""A model to handle account CRUD."""

from sat.logs import SATLogger

logger = SATLogger(__name__)

PLACEHOLDER_ACCOUNT = {
    "email": "jtchampi@ncsu.edu",
    "name": "John Champion",
    "roles": [],
    "authorizations": {
        "_read": [],
        "_write": []
    }
}

def get_account_placeholder(email: str):
    if email == "jtchampi@ncsu.edu":
        return PLACEHOLDER_ACCOUNT
    else:
        return None


class Account:
    """The Account model handles CRUD functions for accounts."""

    name = None
    email = None
    roles = []
    authorizations = {}

    def __init__(self, config):
        if "email" in config:
            self.email = config["email"]
        if "name" in config:
            self.name = config["name"]
        if "roles" in config:
            self.roles = list(set(config["roles"]))
        if "authorizations" in config:
            self.authorizations = config["authorizations"]
        if "id" in config:
            self.id = config["id"]

    def update(self):
        """Updates this instance in the database."""
        return # AuthDB.update_account(self.__dict__)

    def add_role(self, role):
        """Adds a role to this user if it is not already added."""
        if role not in self.roles:
            self.roles.append(role)

    def remove_role(self, role):
        """Removes a role from this user, if they have it."""
        if role in self.roles:
            self.roles.remove(role)

    def delete(self):
        """Deletes this instance from the database."""
        return # AuthDB.delete_account(self.__dict__)

    @staticmethod
    def get_account(email, name=None):
        """
        Finds an account in the database by its email address.
        Creates an account if one isn't found.

        Parameters:
            email: The email address of the account.
            name: The name associated with the Google account.
        """
        db_account = get_account_placeholder(email) # AuthDB.get_account_by_email(email)
        if db_account:
            user_account = Account(config=db_account)
        else:
            user_account = Account.create_account(email, roles=[])

        if name is not None and len(name) > 0 and user_account.name != name:
            user_account.name = name
            user_account.update()

        user_account.id = email.split("@")[0]

        return user_account

    @staticmethod
    def get_service_account(email, name=""):
        if db_account := [PLACEHOLDER_ACCOUNT]: # AuthDB.get_account_by_email(email):
            logger.info(f"Service account found: {email}")
            service_account = Account(config=db_account)
            service_account.name = name or email
            return service_account
        logger.info(f"Service account not found: {email}")

    @staticmethod
    def find_by_role(role):
        """
        Finds accounts given authorization data.

        :param filter: The attribute that should be searched.
        """
        db_accounts = [PLACEHOLDER_ACCOUNT] # AuthDB.get_accounts_by_role(role)

        accounts = []
        for account_config in db_accounts:
            account = Account(config=account_config)
            account.id = account.email.split("@")[0]
            accounts.append(account)

        return accounts

    @staticmethod
    def create_account(email, roles=None):
        """
        Creates a new account in the database.

        :param email: The email address of the account.
        :param authorizations: The authorization data of the account.
        """
        if roles is None:
            roles = []
        account_data = {"email": email, "roles": roles}
        # AuthDB.create_account(account_data)
        return Account(config=account_data)
