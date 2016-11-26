import config
from chatapp.keychain import ClientKeyChain
from chatapp.message import *
from chatapp.network import *
from chatapp.user import ClientUser
from chatapp.utilities import send_msg, send_recv_msg, convert_bytes_to_addr, \
    convert_addr_to_bytes
from constants import client_stats, message_type

conf = config.get_config()
udp = Udp(conf.clientip, conf.clientport, 1)


class ChatClient:
    def __init__(self, saddr):
        self.saddr = saddr
        self.keychain = ClientKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'rb'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'rb'))
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
        self.passhash = generate_client_hash_password(self.username,
                                                      password)  # Separate Thread
        msg = self.converter.nokey_nosign(Message(message_type['Login']))
        msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
        msg = self.find_solution(msg, addr)
        msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
        msg = self.server_dh(msg, addr)
        msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
        if MessageParser.get_message_type(msg) == "Accept":
            self.got_accept(msg, addr)
            self.state = client_stats["Logged_In"]
            self.passhash = ""
            return True
        elif MessageParser.get_message_type(msg) == "Reject":
            self.got_reject(msg, addr)
            self.state = client_stats["Log_In_Failed"]
            return False
        else:
            pass  # Should Handle

    def logout(self):
        if self.state == client_stats["Logged_In"]:
            msg = Message(message_type['Logout'], payload=("LOGOUT"))
            usr = self.keychain.get_user_with_addr(self.saddr)
            msg = self.converter.sym_key_with_sign(msg, usr.key,
                                                   self.keychain.private_key)
            send_msg(self.socket, self.saddr, msg)

    def find_solution(self, msg, addr):
        try:
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
            # send_msg(self.socket, self.saddr, msg)
            return msg
        except exception.SecurityException as e:
            print str(e)
            self.state = client_stats["Log_In_Failed"]

    def server_dh(self, msg, addr):
        try:
            msg = self.msg_parser.parse_sign(msg)
            self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
            self.verifier.verify_signature(msg, self.keychain.server_pub_key)
            msg.payload = str_to_tuple(msg.payload)

            gbmodp, n2, = msg.payload
            gbmodp = convert_bytes_to_public_key(gbmodp)
            a, n1 = self.keychain.dh_keys['']
            key = derive_symmetric_key(a, gbmodp, n1, n2)

            self.keychain.dh_keys[''] = None

            user = ClientUser()
            user.username = ""
            user.key = key
            user.addr = self.saddr
            self.keychain.add_user(user)

            serialized = convert_public_key_to_bytes(self.keychain.public_key)

            ts = get_timestamp()
            msg = Message(message_type["Password"],
                          payload=(
                              struct.pack("!L", ts), self.passhash,
                              serialized))
            msg = self.converter.sym_key(msg, key)
            msg.timestamp = ts
            return msg
        except exception.SecurityException as e:
            print str(e)
            self.state = client_stats["Log_In_Failed"]

    def got_accept(self, msg, addr):
        try:
            if addr == self.saddr:
                msg = self.msg_parser.parse_sign(msg)
                self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
                self.verifier.verify_signature(msg,
                                               self.keychain.server_pub_key)
        except exception.SecurityException as e:
            print str(e)
            self.state = client_stats["Log_In_Failed"]

    def got_reject(self, msg, addr):
        try:
            if self.state == client_stats[
                "Not_Logged_In"] and self.saddr == addr:
                msg = self.msg_parser.parse_sign(msg)
                self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
                self.verifier.verify_signature(msg,
                                               self.keychain.server_pub_key)
        except exception.SecurityException as e:
            print str(e)
            self.state = client_stats["Log_In_Failed"]

    def got_list_response(self, msg, addr):
        msg = self.msg_parser.parse_key_sym_sign(msg)
        self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
        self.verifier.verify_signature(msg, self.keychain.server_pub_key)
        server = self.keychain.get_user_with_addr(self.saddr)
        msg = self.processor.process_sym_key(msg, server.key)
        return msg.payload

    @udp.endpoint("Sender_Client_DH")
    def got_sender_client_dh(self, msg, addr):
        msg = self.msg_parser.parse_key_asym_sign(msg)

        user = self.keychain.get_user_with_addr(addr)

        if user is None:
            user = self.__get_missing_user_with_addr(addr)

        self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
        self.verifier.verify_signature(msg, user.public_key)

        msg = self.processor.process_asym_key(msg, self.keychain.private_key)
        sender, dest, n1, gamodp = msg.payload

        gamodp = convert_bytes_to_public_key(gamodp)

        if sender != user.username:
            pass  # Raise Hell!!

        if self.username != dest:
            pass  # Raise HELL!!

        n2 = os.urandom(constants.NONCE_LENGTH)
        public_key, private_key = generate_dh_pair()
        key = derive_symmetric_key(private_key, gamodp, n1, n2)
        user.key = key

        msg = Message(message_type["Dest_Client_DH"], payload=(
            self.username, sender, n2, convert_public_key_to_bytes(public_key)))

        msg = self.converter.asym_key_with_sign(msg, user.public_key,
                                                self.keychain.private_key)

        send_msg(self.socket, user.addr, msg)

    @udp.endpoint("Message")
    def got_message(self, msg, addr):
        msg = self.msg_parser.parse_key_sym_sign(msg)

        user = self.keychain.get_user_with_addr(addr)

        self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
        self.verifier.verify_signature(msg, user.public_key)

        msg = self.processor.process_sym_key(msg, user.key)
        sender, dest, message = msg.payload
        if self.username != dest:
            pass  # Raise Hell

        print sender+" -> "+message

    def __get_missing_user_with_username(self, username):
        utuple = self.list(username)
        # Should Raise Exception
        if utuple[0] == username:
            user = ClientUser()
            user.username = username
            user.addr = convert_bytes_to_addr(utuple[1])
            user.public_key = convert_bytes_to_public_key(utuple[2])
            self.keychain.add_user(user)
            return user

    def __get_missing_user_with_addr(self, addr):
        utuple = self.list(addr, is_ip=True)
        # Should Raise Exception
        paddr = convert_bytes_to_addr(utuple[1])
        if paddr == addr:
            user = ClientUser()
            user.username = utuple[0]
            user.addr = paddr
            user.public_key = convert_bytes_to_public_key(utuple[2])
            self.keychain.add_user(user)
            return user

    def __setup_client_shared_key(self, dest_user):
        public_key, private_key = generate_dh_pair()
        n1 = os.urandom(constants.NONCE_LENGTH)
        # dest_user.dh_private_key = (private_key, n1)
        msg = Message(message_type["Sender_Client_DH"],
                      payload=(
                          self.username, dest_user.username, n1,
                          convert_public_key_to_bytes(public_key)))
        msg = self.converter.asym_key_with_sign(msg, dest_user.public_key,
                                                self.keychain.private_key)
        msg, addr = send_recv_msg(self.socket, udp, dest_user.addr, msg)

        msg = self.msg_parser.parse_key_asym_sign(msg)

        self.verifier.verify_timestamp(msg, get_timestamp() - 5000)
        self.verifier.verify_signature(msg, dest_user.public_key)

        msg = self.processor.process_asym_key(msg, self.keychain.private_key)
        sender, dest, n2, gbmodp = msg.payload

        gbmodp = convert_bytes_to_public_key(gbmodp)

        if sender != dest_user.username:
            pass  # Raise Hell!!

        if self.username != dest:
            pass  # Raise HELL!!

        key = derive_symmetric_key(private_key, gbmodp, n1, n2)
        dest_user.key = key

    def list(self, username="*", is_ip=False):
        if is_ip:
            is_ip = "1"
            username = convert_addr_to_bytes(username)
        else:
            is_ip = "0"

        msg = Message(message_type["List"],
                      payload=(self.username, username, is_ip))
        usr = self.keychain.get_user_with_addr(self.saddr)
        self.converter.sym_key_with_sign(msg, usr.key,
                                         self.keychain.private_key)
        msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
        return self.got_list_response(msg, addr)

    def send(self, destination, message):
        user = self.keychain.get_user_with_username(destination)
        if user is None:
            user = self.__get_missing_user_with_username(destination)

        if user.key is None:
            self.__setup_client_shared_key(user)

        # Check Length of Message
        msg = Message(message_type["Message"],
                      payload=(self.username, destination, message))
        msg = self.converter.sym_key_with_sign(msg, user.key,
                                               self.keychain.private_key)
        # Should Get Ack Back
        send_msg(self.socket, user.addr, msg)


if __name__ == "__main__":
    client = ChatClient(("127.0.0.1", 6000))
    udp.start(client)
    # for i in xrange(100000):
    print client.login("secure", "secret")
