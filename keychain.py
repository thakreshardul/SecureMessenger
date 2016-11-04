from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class ClientKeyChain:
    def __init__(self, p_exp, key_size):
        self.private_key = rsa.generate_private_key(public_exponent=p_exp,
                                                    key_size=key_size,
                                                    backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.users = {}

    def add_user(self, user):
        self.users[user.ip] = user

    def get_user(self, user):
        return self.users[user.ip]


class ServerKeyChain:
    def __init__(self, priv_file, pub_file):
        self.private_key = serialization.load_der_private_key(priv_file.read(),
                                                              None,
                                                              default_backend())
        self.public_key = serialization.load_der_public_key(pub_file.read(),
                                                            default_backend())
        self.users = {}

    def add_user(self, user):
        self.users[user.ip] = user

    def get_user(self, user):
        return self.users[user.ip]
