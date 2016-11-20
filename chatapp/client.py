from chatapp.keychain import ClientKeyChain
from chatapp.message import *
from chatapp.network import *
from chatapp.ds import ClientUser
import config
config.load()
conf = config.get_config()
udp = Udp(conf.clientip, conf.clientport, 1)


class ChatClient:
    def __init__(self, sip, sport):
        self.sip = sip
        self.sport = sport
        self.keychain = ClientKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'rb'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'rb'))
        self.socket = udp.socket
        self.msg_gen = MessageGenerator(self.keychain.server_pub_key,
                                        self.keychain.private_key)
        self.msg_parser = MessageParser()

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
        n1 = os.urandom(16)
        # Should Save Private Key
        self.keychain.dh_keys[''] = (priv, n1)
        serialized_public = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        msg = self.msg_gen.generate_solution_packet((nc, bytes(x)),
                                                    self.username,
                                                    serialized_public,
                                                    n1)
        self.socket.sendto(
            str(msg),
            (self.sip, self.sport))

    @udp.endpoint("Server_DH")
    def server_dh(self, msg_addr):
        msg = msg_addr[0]
        msg = self.msg_parser.parse_sign(msg)
        ## Verify Signature
        server_dh, n2, = Message.str_to_tuple(msg.payload)
        server_dh = convert_bytes_to_public_key(server_dh)
        dh_priv, n1 = self.keychain.dh_keys['']
        key = derive_symmetric_key(dh_priv, server_dh, n1, n2)
        print "Shared Key", repr(key)
        self.keychain.dh_keys[''] = None
        user = ClientUser()
        user.username = ""
        user.key = key
        user.addr = (self.sip, self.sport)
        self.keychain.add_user(user)
        serialized = convert_public_key_to_bytes(self.keychain.public_key)
        self.socket.sendto(
            str(self.msg_gen.generate_password_packet(key, self.password,
                                                      serialized)), msg_addr[1])

    def list(self):
        pass

    def send(self, destination, message):
        pass


if __name__ == "__main__":
    client = ChatClient("127.0.0.1", 6000)
    udp.start(client)
    # for i in xrange(100000):
    client.login("secure", "secret1")
