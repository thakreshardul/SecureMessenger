from crypto import *


class ClientKeyChain:
    def __init__(self, server_priv_file, server_pub_file):
        self.public_key, self.private_key = generate_rsa_pair()
        self.server_pub_key, self.server_priv_key = load_rsa_pair(
            server_priv_file, server_pub_file)

        self.dh_keys = {}
        self.addrs = {}
        self.usernames = {}

    def add_user(self, user):
        self.addrs[user.addr] = user
        self.usernames[user.username] = user

    def get_user_with_addr(self, addr):
        try:
            return self.addrs[addr]
        except KeyError:
            return None

    def get_user_with_username(self, username):
        try:
            return self.usernames[username]
        except KeyError:
            return None

    def remove_user(self, user):
        self.addrs.pop(user.addr, None)
        self.usernames.pop(user.username, None)


class ServerKeyChain:
    def __init__(self, priv_file, pub_file):
        self.public_key, self.private_key = load_rsa_pair(priv_file, pub_file)
        self.usernames = {}
        self.addrs = {}

    def add_user(self, user):
        self.addrs[user.addr] = user
        self.usernames[user.username] = user

    def get_user_with_addr(self, addr):
        try:
            return self.addrs[addr]
        except KeyError:
            return None

    def get_user_with_username(self, username):
        try:
            return self.usernames[username]
        except KeyError:
            return None

    def remove_user(self, user):
        self.addrs.pop(user.addr, None)
        self.usernames.pop(user.username, None)

    def list_user(self):
        return self.usernames
