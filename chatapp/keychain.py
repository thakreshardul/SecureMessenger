from crypto import *


# The Keychain is used by Client to store pub keys and AES Keys
class ClientKeyChain:
    def __init__(self, server_priv_file, server_pub_file):
        self.public_key, self.private_key = generate_rsa_pair()  # Ephemeral RSA Keys
        self.server_pub_key, self.server_priv_key = load_rsa_pair(
            server_priv_file, server_pub_file)  # Server RSA Keys

        self.server_dh_key = None  # Server DH Private Key
        self.addrs = {}  # Dictionary for users where address is Key
        self.usernames = {}  # Dictionary for users where username is Key

    # Add User Object
    def add_user(self, user):
        self.addrs[user.addr] = user
        self.usernames[user.username] = user

    # Get User with address or None
    def get_user_with_addr(self, addr):
        try:
            return self.addrs[addr]
        except KeyError:
            return None

    # Get User with username or None
    def get_user_with_username(self, username):
        try:
            return self.usernames[username]
        except KeyError:
            return None

    # Remove User Object
    def remove_user(self, user):
        self.addrs.pop(user.addr, None)
        self.usernames.pop(user.username, None)


# The Keychain is used by Server to store pub keys and AES Keys
class ServerKeyChain:
    def __init__(self, priv_file, pub_file):
        self.public_key, self.private_key = load_rsa_pair(priv_file,
                                                          pub_file)  # Server's RSA Keys
        self.addrs = {}  # Dictionary for users where address is Key
        self.usernames = {}  # Dictionary for users where username is Key

    # Add User Object
    def add_user(self, user):
        self.addrs[user.addr] = user
        self.usernames[user.username] = user

    # Get User with address or None
    def get_user_with_addr(self, addr):
        try:
            return self.addrs[addr]
        except KeyError:
            return None

    # Get User with username or None
    def get_user_with_username(self, username):
        try:
            return self.usernames[username]
        except KeyError:
            return None

    # Remove User Object
    def remove_user(self, user):
        self.addrs.pop(user.addr, None)
        self.usernames.pop(user.username, None)

    # Returns usernames dict
    def list_users(self):
        return self.usernames
