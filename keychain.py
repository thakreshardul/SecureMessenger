from crypto import *


class ClientKeyChain:
    def __init__(self, server_priv_file, server_pub_file):
        self.public_key, self.private_key = generate_rsa_pair()
        self.server_pub_key, self.server_priv_key = load_rsa_pair(
            server_priv_file, server_pub_file)

        self.dh_keys = {}
        self.users = {}

    def add_user(self, user):
        self.users[user.ip] = user

    def get_user(self, user):
        return self.users[user.ip]


class ServerKeyChain:
    def __init__(self, priv_file, pub_file):
        self.public_key, self.private_key = load_rsa_pair(priv_file, pub_file)
        self.users = {}

    def add_user(self, user):
        self.users[user.ip] = user

    def get_user(self, user):
        return self.users[user.ip]
