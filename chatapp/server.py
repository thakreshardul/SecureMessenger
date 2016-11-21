import threading
import time

from chatapp.utilities import send_msg
from constants import message_type
from db import UserDatabase
from keychain import ServerKeyChain
from message import *
from network import Udp

udp = Udp("127.0.0.1", 6000, 5)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = udp.socket
        self.keychain = ServerKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'r'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'r'))
        self.msg_parser = MessageParser()
        self.converter = MessageConverter()
        self.processor = MessageProcessor()
        self.verifier = MessageVerifer()
        self.certificate = None
        UserDatabase().create_db()
        self.puz_thread = threading.Thread(
            target=self.__generate_puz_certificate)
        self.puz_thread.start()

    def __generate_puz_certificate(self):
        while True:
            t1 = time.time()
            ns = os.urandom(16)
            d = chr(1)
            expiry_time = long(t1 + 60)
            packed_t = struct.pack("!L", expiry_time)
            sign = sign_stuff(self.keychain.private_key, packed_t + d + ns)
            self.certificate = Certificate(packed_t, d, ns, sign)
            time.sleep(60)

    @udp.endpoint("Login")
    def got_login_packet(self, msg, addr):
        msg = Message(message_type["Puzzle"],
                      payload=self.certificate)
        msg = self.converter.nokey_nosign(msg)
        send_msg(self.socket, addr, msg)

    @udp.endpoint("Solution")
    def got_solution(self, msg, addr):
        try:
            msg = self.msg_parser.parse_key_asym_ans(msg)
            self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
            msg = self.processor.process_ans(msg, self.certificate.nonce_s,
                                             ord(self.certificate.difficulty),
                                             self.keychain.private_key)
            username, gamodp, n1 = msg.payload
            gamodp = convert_bytes_to_public_key(gamodp)

            gbmodp, b = generate_dh_pair()
            gbmodp = convert_public_key_to_bytes(gbmodp)
            n2 = os.urandom(constants.NONCE_LENGTH)
            key = derive_symmetric_key(b, gamodp, n1, n2)

            with UserDatabase() as db:
                usr = db.get_user(username)
                usr.key = key
                usr.addr = addr
                self.keychain.add_user(usr)

            msg = Message(message_type["Server_DH"], payload=(gbmodp, n2))
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)
        except exception.ChatException as e:
            print str(e)
            msg = Message(message_type["Reject"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)

    @udp.endpoint("Password")
    def got_password(self, msg, addr):
        try:
            msg = self.msg_parser.parse_key_sym(msg)

            self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
            usr = self.keychain.get_user(addr)
            msg = self.processor.process_sym_key(msg, usr.key)

            ts, pass_hash, pub_key = msg.payload

            ts = struct.unpack("!L", ts)[0]

            if addr != usr.addr:
                raise exception.InvalidTimeStampException()  # Should Be More Specific

            if ts != msg.timestamp:
                raise exception.InvalidTimeStampException()

            verify_hash_password(pass_hash, usr.pass_hash, usr.salt)
            pub_key = convert_bytes_to_public_key(pub_key)
            usr.public_key = pub_key

            msg = Message(message_type["Accept"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, usr.addr, msg)
        except exception.ChatException as e:
            print str(e)
            msg = Message(message_type["Reject"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)


if __name__ == "__main__":
    server = Server("127.0.0.1", 6000)
    udp.start(server)
