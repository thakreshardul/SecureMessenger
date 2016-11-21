from chatapp.ds import ClientUser
from chatapp.keychain import ClientKeyChain
from chatapp.message import *
from chatapp.network import *
from chatapp.utilities import send_msg
from constants import client_stats, message_type

udp = Udp("127.0.0.1", 5000, 1)


class ChatClient:
    def __init__(self, saddr):
        self.saddr = saddr
        self.keychain = ClientKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'r'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'r'))
        self.socket = udp.socket
        self.msg_parser = MessageParser()
        self.converter = MessageConverter()
        self.verifier = MessageVerifer()
        self.processor = MessageProcessor()
        self.username = ""
        self.passhash = ""
        self.state = client_stats["Not_Logged_In"]

    def login(self, username, password):
        self.state = client_stats["Not_Logged_In"]
        self.username = username
        msg = self.converter.nokey_nosign(Message(message_type['Login']))
        send_msg(self.socket, self.saddr, msg)
        self.passhash = generate_client_hash_password(self.username, password)
        while self.state == client_stats["Not_Logged_In"]:
            pass
        if self.state == client_stats["Log_In_Failed"]:
            return False
        else:
            return True

    @udp.endpoint("Puzzle")
    def find_solution(self, msg, addr):

        msg = self.msg_parser.parse_nokey_nosign(msg)
        msg = self.processor.process_certificate(msg)

        self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
        self.verifier.verify_certificate(msg, self.keychain.server_pub_key)

        ns = msg.payload.nonce_s
        nc = os.urandom(16)
        d = ord(msg.payload.difficulty)
        x = solve_puzzle(ns, nc, d)
        pub, priv = generate_dh_pair()
        n1 = os.urandom(16)
        self.keychain.dh_keys[''] = (priv, n1)
        gamodp = convert_public_key_to_bytes(pub)

        msg = Message(message_type['Solution'], sign=(nc, bytes(x)),
                      payload=(self.username, gamodp, n1))
        self.converter.asym_key(msg, self.keychain.server_pub_key)
        print "Done"
        send_msg(self.socket, self.saddr, msg)

    @udp.endpoint("Server_DH")
    def server_dh(self, msg, addr):
        print msg
        return
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

        # Trying to improve experience by calculating pass_hash during auth
        while self.passhash == "":
            pass

        self.socket.sendto(
            str(self.msg_gen.generate_password_packet(key, self.passhash,
                                                      serialized)), msg_addr[1])

    def list(self):
        pass

    def send(self, destination, message):
        pass


if __name__ == "__main__":
    client = ChatClient(("127.0.0.1", 6000))
    udp.start(client)
    # for i in xrange(100000):
    client.login("secure", "secret1")
