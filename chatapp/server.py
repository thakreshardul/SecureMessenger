import threading
import time

from chatapp.utilities import send_msg, convert_addr_to_bytes, \
    convert_bytes_to_addr
from constants import message_type
from db import UserDatabase
from keychain import ServerKeyChain
from message import *
from network import Udp
from user import ServerUser

udp = Udp("127.0.0.1", 6000, 5)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = udp.socket
        self.keychain = ServerKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'rb'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'rb'))
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

            usr = ServerUser()
            usr.username = username
            usr.key = key
            usr.addr = addr
            self.keychain.add_user(usr)

            msg = Message(message_type["Server_DH"], payload=(gbmodp, n2))
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)
        except exception.SecurityException as e:
            print str(e)
            msg = Message(message_type["Reject"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)

    @udp.endpoint("Password")
    def got_password(self, msg, addr):
        try:
            msg = self.msg_parser.parse_key_sym(msg)
            self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
            usr = self.keychain.get_user_with_addr(addr)
            msg = self.processor.process_sym_key(msg, usr.key)

            ts, pass_hash, pub_key = msg.payload

            ts = struct.unpack("!L", ts)[0]

            if addr != usr.addr:
                raise exception.InvalidTimeStampException()  # Should Be More Specific

            if ts != msg.timestamp:
                raise exception.InvalidTimeStampException()

            with UserDatabase() as db:
                user = db.get_user(usr.username)
                if user is None:
                    self.keychain.remove_user(usr)
                    raise exception.InvalidTimeStampException()  # Should be More Specific
                usr.pass_hash = user.pass_hash
                usr.salt = user.salt

            verify_hash_password(pass_hash, usr.pass_hash, usr.salt)
            pub_key = convert_bytes_to_public_key(pub_key)
            usr.public_key = pub_key

            msg = Message(message_type["Accept"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, usr.addr, msg)
        except exception.SecurityException as e:
            print str(e)
            msg = Message(message_type["Reject"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)

    @udp.endpoint("Logout")
    def got_logout_packet(self, msg, addr):
        try:
            msg = self.msg_parser.parse_key_sym_sign(msg)
            self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
            usr = self.keychain.get_user_with_addr(addr)
            if usr is None:
                print "Exception"  # Raise exception
            self.verifier.verify_signature(msg, usr.public_key)
            msg = self.processor.process_sym_key(msg, usr.key)
            if msg.payload[1] == "LOGOUT":
                self.keychain.remove_user(usr)
                payload = str_to_tuple("OK")
                msg = Message(message_type["OK"], payload=payload)
                msg = self.converter.sign(msg)
                send_msg(self.socket, addr, msg)
                # self.keychain.remove_user(usr)
                payload = (usr.username, "logged out")
                msg = Message(message_type["Broadcast"], payload=payload)
                for client in self.keychain.list_user():
                    msg = self.converter.sym_key_with_sign(
                        msg, client.key, self.keychain.private_key)
                    send_msg(self.socket, client.addr, msg)

        except exception.SecurityException as e:
            print str(e)

    @udp.endpoint("List")
    def got_list_request(self, msg, addr):
        msg = self.msg_parser.parse_key_sym_sign(msg)
        usr = self.keychain.get_user_with_addr(addr)
        self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
        if usr.public_key is None:
            # Should Remove Signature or can ignore to return something
            msg = Message(message_type["Reject"])
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)
            return

        self.verifier.verify_signature(msg, usr.public_key)

        msg = self.processor.process_sym_key(msg, usr.key)
        request = msg.payload
        if request[0] != usr.username:
            pass  # Raise HELL!!
        if request[1] == "*":
            payload = []
            users = self.keychain.usernames
            for v in users.itervalues():
                if v.username != usr.username:
                    username = v.username
                    payload.append(username)
            payload = tuple(payload)
        else:
            if request[2] == "0":
                user = self.keychain.get_user_with_username(request[1])
            else:
                user = self.keychain.get_user_with_addr(
                    convert_bytes_to_addr(request[1]))
            username = user.username
            pk = convert_public_key_to_bytes(user.public_key)
            payload = (username, convert_addr_to_bytes(user.addr), pk)

        msg = Message(message_type["List"], payload=payload)
        msg = self.converter.sym_key_with_sign(msg, usr.key,
                                               self.keychain.private_key)
        send_msg(self.socket, usr.addr, msg)


if __name__ == "__main__":
    server = Server("127.0.0.1", 6000)
    udp.start(server)
