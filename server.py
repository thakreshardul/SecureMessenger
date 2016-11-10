import os
import struct
import threading
import time

from crypto import *
from keychain import ServerKeyChain
from message import MessageGenerator
from network import Udp

udp = Udp("127.0.0.1", 6000, 5)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = udp.socket
        self.keychain = ServerKeyChain(open("priv.der", 'r'),
                                       open("pub.der", "r"))
        self.msg_gen = MessageGenerator(self.keychain.public_key,
                                        self.keychain.private_key)
        self.certificate = None
        self.puz_thread = threading.Thread(
            target=self.__generate_puz_certificate)
        self.puz_thread.start()

    def __generate_puz_certificate(self):
        while True:
            t1 = time.time()
            ns = os.urandom(16)
            d = chr(2)
            t = long(t1 + 60)
            packed_t = struct.pack("!L", t)
            sign = sign_stuff(self.keychain.private_key,
                              packed_t + d + ns)
            self.certificate = (packed_t, d, ns, sign)
            time.sleep(60)

    @udp.endpoint("Login")
    def got_login_packet(self, msg):
        ret_msg = self.msg_gen.generate_puzzle_response(self.certificate)
        self.socket.sendto(str(ret_msg), msg[1])


if __name__ == "__main__":
    server = Server("127.0.0.1", 6000)
    udp.start(server)
