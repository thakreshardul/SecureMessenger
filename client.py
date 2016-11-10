from keychain import ClientKeyChain
from message import MessageGenerator
from network import *


class ChatClient:
    def __init__(self, sip, sport):
        self.sip = sip
        self.sport = sport
        self.keychain = ClientKeyChain(65537, 2048)
        self.socket = create_socket()
        self.msg_gen = MessageGenerator(self.keychain.public_key,
                                        self.keychain.private_key)

    def login(self, username, password):
        self.socket.sendto(str(self.msg_gen.generate_login_packet()),("127.0.0.1", 6000))

    def list(self):
        pass

    def send(self, destination, message):
        pass


if __name__ == "__main__":
    client = ChatClient("127.0.0.1", 6000)
    for i in xrange(100000):
        client.login("", "")
