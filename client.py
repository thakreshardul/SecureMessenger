import os

import constants
from crypto import *
from keychain import ClientKeyChain
from message import MessageGenerator
from network import *

udp = Udp("127.0.0.1", 5000, 1)


class ChatClient:
    def __init__(self, sip, sport):
        self.sip = sip
        self.sport = sport
        self.keychain = ClientKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'r'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'r'))
        self.socket = udp.socket
        self.msg_gen = MessageGenerator(self.keychain.server_pub_key,
                                        self.keychain.private_key)

    def login(self, username, password):
        self.username = username
        self.password = generate_client_hash_password(username, password)
        self.socket.sendto(str(self.msg_gen.generate_login_packet()),
                           ("127.0.0.1", 6000))

    @udp.endpoint("Puzzle")
    def find_solution(self, msg_addr):
        import struct
        msg = msg_addr[0]
        i = 5
        t = []
        while i < len(msg):
            l = struct.unpack("!H", msg[i:i + 2])[0]
            t.append(msg[i + 2:i + 2 + l])
            i += 2 + l

        ns = t[2]
        nc = os.urandom(16)
        d = ord(t[1])
        # Above Should be Replaced by Parser Code
        x = solve_puzzle(ns, nc, d)
        pub, priv = generate_dh_pair()
        # Should Save Private Key
        self.keychain.dh_keys[''] = priv
        serialized_public = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.socket.sendto(
            str(self.msg_gen.generate_solution_packet(x, self.username,
                                                  serialized_public,
                                                  os.urandom(16))),
            (self.sip, self.sport))

    def list(self):
        pass

    def send(self, destination, message):
        pass


if __name__ == "__main__":
    client = ChatClient("127.0.0.1", 6000)
    udp.start(client)
    for i in xrange(100000):
        client.login("", "")
