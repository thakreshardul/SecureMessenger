import os
import struct
import threading
import time

import constants
from crypto import sign_stuff
from keychain import ServerKeyChain
from message import MessageGenerator
from message import MessageParser
from network import Udp

udp = Udp("127.0.0.1", 6000, 5)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = udp.socket
        self.keychain = ServerKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'r'),
            open(constants.SERVER_PUBLIC_DER_FILE, "r"))
        self.msg_gen = MessageGenerator(self.keychain.public_key,
                                        self.keychain.private_key)
        self.msg_ver = MessageParser(self.keychain.public_key)
        self.certificate = None
        self.puz_thread = threading.Thread(
            target=self.__generate_puz_certificate)
        self.puz_thread.start()

    def __generate_puz_certificate(self):
        while True:
            t1 = time.time()
            ns = os.urandom(16)
            d = chr(2)
            expiry_time = long(t1 + 60)
            packed_t = struct.pack("!L", expiry_time)
            sign = sign_stuff(self.keychain.private_key,
                              packed_t + d + ns)
            self.certificate = (packed_t, d, ns, sign)
            time.sleep(60)

    @udp.endpoint("Login")
    def got_login_packet(self, msg_addr):
        ret_msg = self.msg_gen.generate_puzzle_response(self.certificate)
        self.socket.sendto(str(ret_msg), msg_addr[1])

    @udp.endpoint("Solution")
    def got_solution(self, msg_addr):
        msg = msg_addr[0]
        self.msg_ver.verify_timestamp(msg)
        self.msg_ver.verify_solution(msg)
        # print len(msg)


if __name__ == "__main__":
    server = Server("127.0.0.1", 6000)
    udp.start(server)
