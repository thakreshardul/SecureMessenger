import threading

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
            open(constants.SERVER_PUBLIC_DER_FILE, "r"))
        self.msg_gen = MessageGenerator(self.keychain.public_key,
                                        self.keychain.private_key)
        self.msg_ver = MessageParser()
        self.certificate = None  # Named Tuple
        UserDatabase().create_db()
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
        msg = self.msg_ver.parse_key_asym_ans(msg)
        verifier = MessageVerifer(None, self.keychain.private_key)
        verifier.verify_solution(self.certificate[2], ord(self.certificate[1]),
                                 msg.sign[0], msg.sign[1])
        username, user_dh_key, n1 = verifier.decrypt_payload(msg.key,
                                                             msg.payload)
        user_dh_key = serialization.load_der_public_key(user_dh_key,
                                                        backend=default_backend())
        server_pub, server_priv = generate_dh_pair()
        server_pub = server_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        n2 = os.urandom(constants.NONCE_LENGTH)
        key = derive_symmetric_key(server_priv, user_dh_key, n1, n2)
        with UserDatabase() as db:
            usr = db.get_user(username)
            usr.key = key
            usr.addr = msg_addr[1]
            self.keychain.add_user(usr)
        print "Shared Key", repr(key)
        self.socket.sendto(
            str(self.msg_gen.generate_server_dh_packet(server_pub, n2)),
            msg_addr[1])

    @udp.endpoint("Password")
    def got_password(self, msg_addr):
        msg = msg_addr[0]
        msg = self.msg_ver.parse_key_sym(msg)
        print "length", len(msg.key)
        iv = msg.key[:constants.AES_IV_LENGTH]
        tag = msg.key[constants.AES_IV_LENGTH:]
        usr = self.keychain.get_user(msg_addr[1])
        ts, pass_hash, pub_key = Message.parse_payload(
            decrypt_payload(usr.key, iv, tag, msg.payload))
        verify_hash_password(pass_hash, usr.pass_hash, usr.salt)


if __name__ == "__main__":
    server = Server("127.0.0.1", 6000)
    udp.start(server)
