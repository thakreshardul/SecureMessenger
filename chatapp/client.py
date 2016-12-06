"""This file implements the client side code"""
import time

from chatapp.keychain import ClientKeyChain
from chatapp.message import *
from chatapp.network import *
from chatapp.user import ClientUser
from chatapp.utilities import send_msg, send_recv_msg, convert_bytes_to_addr, \
    convert_addr_to_bytes
from chatapp.constants import message_type

udp = Udp()


class ChatClient:
    def __init__(self, saddr):
        self.saddr = saddr
        self.keychain = ClientKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'rb'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'rb'))
        user = ClientUser()
        user.username = ""
        user.addr = self.saddr
        self.keychain.add_user(user)
        self.socket = udp.socket
        self.msg_parser = MessageParser()
        self.converter = MessageConverter()
        self.verifier = MessageVerifer()
        self.processor = MessageProcessor()
        self.username = ""
        self.passhash = ""
        self.heartbeat_thread = threading.Thread(target=self.heartbeat)
        self.heartbeat_thread.daemon = True
        self.passwd_thread = None

    # Generates the hash of password
    def compute_hash(self, password):
        self.passhash = generate_client_hash_password(self.username, password)

    def login(self, username, password):

        if len(username) == 0:  # blank username provided
            raise exception.InvalidUsernameException()

        if len(password) == 0:  # blank username provided
            raise exception.InvalidPasswordException()

        self.username = username
        self.passhash = ""
        if self.passwd_thread is not None and self.passwd_thread.isAlive():
            self.passwd_thread.join()
        # Password hash is computed on a separate thread
        self.passwd_thread = threading.Thread(target=self.compute_hash,
                                              args=(password,))
        self.passwd_thread.daemon = True
        self.passwd_thread.start()
        # Generate a packet that is not signed nor encrypted
        msg = self.converter.nokey_nosign(Message(message_type['Login']))
        try:
            # Send login and get Puzzle from the server
            msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
            # Compute solution to the puzzle
            msg = self.find_solution(msg, addr)
            # Send solution and get Server side DH part of the symmetric key
            msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
            # Compute the Client side DH and the symmetric key and encrypt password with symmetric key
            msg = self.server_dh(msg, addr)
            # Send password hash encrypted with symmetric key to the server and wait for accept or reject
            msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
            # process accept or reject fro the server
            self.got_login_result(msg, addr)
            return True
        except socket.timeout:
            print "Socket Timed Out, Try Again Later"
            return False
        except exception.SecurityException as e:
            print str(e)
            return False

    # Handles the logging out of the client
    def logout(self):
        try:
            msg = Message(message_type['Logout'],
                          payload=(self.username, "LOGOUT"))
            usr = self.keychain.get_user_with_addr(self.saddr)

            msg = self.converter.sym_key_with_sign(msg, usr.key,
                                                   self.keychain.private_key)
            # Send logout packet and wait for Accept
            msg, addr = send_recv_msg(self.socket, udp, self.saddr, msg)
            if MessageParser.get_message_type(msg) == "Accept":
                self.got_accept(msg, addr, self.keychain.server_pub_key,
                                self.saddr)
                return True
            else:
                raise exception.InvalidMessageTypeException()
        except socket.timeout:
            print "Socket Timed Out, Try Again Later"
        except exception.SecurityException as e:
            print str(e)
            return False

    # Handles the broadcast message from the server about logging out of a
    # client from the system
    @udp.endpoint("Logout")
    def got_broadcast(self, msg, addr):
        try:

            if addr != self.saddr:
                raise exception.InvalidSendersAddressException()

            msg = self.msg_parser.parse_sign(msg)
            self.verifier.verify_timestamp(msg,
                                           get_timestamp() - constants.TIMESTAMP_GAP)
            self.verifier.verify_signature(msg, self.keychain.server_pub_key)
            msg.payload = str_to_tuple(msg.payload)
            if msg.payload[1] == "LOGOUT":
                usr = self.keychain.get_user_with_addr(
                    convert_bytes_to_addr(msg.payload[0]))
                if usr is not None:
                    self.keychain.remove_user(usr)
            else:
                raise exception.InvalidPayloadException()
        except exception.SecurityException as e:
            print str(e)

    # computes the solution to the puzzle
    def find_solution(self, msg, addr):

        if MessageParser.get_message_type(msg) != "Puzzle":
            raise exception.InvalidMessageTypeException()

        if addr != self.saddr:
            raise exception.InvalidSendersAddressException()

        msg = self.msg_parser.parse_nokey_nosign(msg)
        msg = self.processor.process_certificate(msg)

        self.verifier.verify_timestamp(msg,
                                       get_timestamp() - constants.TIMESTAMP_GAP)
        self.verifier.verify_certificate(msg, self.keychain.server_pub_key)

        ns = msg.payload.nonce_s
        nc = os.urandom(16)
        d = ord(msg.payload.difficulty)
        x = solve_puzzle(ns, nc, d)
        pub, priv = generate_dh_pair()
        n1 = os.urandom(16)
        self.keychain.server_dh_key = (priv, n1)
        gamodp = convert_public_key_to_bytes(pub)

        msg = Message(message_type['Solution'], sign=(nc, bytes(x)),
                      payload=(self.username, gamodp, n1))
        self.converter.asym_key(msg, self.keychain.server_pub_key)
        return msg

    # After getting server DH part, compute client DH and the symmetric key
    def server_dh(self, msg, addr):

        if addr != self.saddr:
            raise exception.InvalidSendersAddressException()

        if MessageParser.get_message_type(msg) == "Reject":
            self.got_reject(msg, addr, self.keychain.server_pub_key, self.saddr)
            self.passhash = ""
            raise exception.UserAlreadyLoggedInException()
        elif MessageParser.get_message_type(msg) != "Server_DH":
            raise exception.InvalidMessageTypeException()

        msg = self.msg_parser.parse_sign(msg)
        self.verifier.verify_timestamp(msg,
                                       get_timestamp() - constants.TIMESTAMP_GAP)
        self.verifier.verify_signature(msg, self.keychain.server_pub_key)
        msg.payload = str_to_tuple(msg.payload)

        gbmodp, n2, = msg.payload
        gbmodp = convert_bytes_to_public_key(gbmodp)
        a, n1 = self.keychain.server_dh_key
        key = derive_symmetric_key(a, gbmodp, n1, n2)

        self.keychain.server_dh_key = None

        server = self.keychain.get_user_with_addr(self.saddr)
        server.key = key
        serialized = convert_public_key_to_bytes(self.keychain.public_key)

        while self.passhash == "":
            time.sleep(0)

        ts = get_timestamp()
        msg = Message(message_type["Password"],
                      payload=(
                          struct.pack("!L", ts), self.passhash,
                          serialized))
        msg = self.converter.sym_key(msg, key)
        msg.timestamp = ts
        return msg

    # Process Accept or reject from the server
    def got_login_result(self, msg, addr):
        if MessageParser.get_message_type(msg) == "Accept":
            self.got_accept(msg, addr, self.keychain.server_pub_key, self.saddr)
            self.passhash = ""
            self.heartbeat_thread.start()
        elif MessageParser.get_message_type(msg) == "Reject":
            self.got_reject(msg, addr, self.keychain.server_pub_key, self.saddr)
            raise exception.WrongCredentialsException()
        else:
            raise exception.InvalidMessageTypeException()

    # Accept message payload should have OK as the payload
    def got_accept(self, msg, addr, pk, aaddr):

        if addr != aaddr:
            raise exception.InvalidSendersAddressException()

        msg = self.msg_parser.parse_sign(msg)
        self.verifier.verify_timestamp(msg,
                                       get_timestamp() - constants.TIMESTAMP_GAP)
        self.verifier.verify_signature(msg, pk)
        msg.payload = str_to_tuple(msg.payload)
        if msg.payload[0] != "OK":
            raise exception.InvalidPayloadException()

    # Reject message payload should have Reject as the payload
    def got_reject(self, msg, addr, pk, aaddr):

        if addr != aaddr:
            raise exception.InvalidSendersAddressException()

        msg = self.msg_parser.parse_sign(msg)
        self.verifier.verify_timestamp(msg,
                                       get_timestamp() - constants.TIMESTAMP_GAP)
        self.verifier.verify_signature(msg, pk)
        msg.payload = str_to_tuple(msg.payload)
        if msg.payload[0] != "Reject":
            raise exception.InvalidPayloadException()

    # Response of the list command send to the server to list all the clients
    def got_list_response(self, msg, addr):
        if MessageParser.get_message_type(msg) != "List":
            raise exception.InvalidMessageTypeException()

        if addr != self.saddr:
            raise exception.InvalidSendersAddressException()

        msg = self.msg_parser.parse_key_sym_sign(msg)
        self.verifier.verify_timestamp(msg,
                                       get_timestamp() - constants.TIMESTAMP_GAP)
        self.verifier.verify_signature(msg, self.keychain.server_pub_key)
        server = self.keychain.get_user_with_addr(self.saddr)
        msg = self.processor.process_sym_key(msg, server.key)
        return msg.payload

    # Start of the Message protocol after send command, the initiator sends its,
    # DH contribution
    @udp.endpoint("Sender_Client_DH")
    def got_sender_client_dh(self, msg, addr):
        try:
            msg = self.msg_parser.parse_key_asym_sign(msg)
            # Check if user's sym key is already present
            user = self.keychain.get_user_with_addr(addr)
            # If key not present, contact server to get the public key
            if user is None:
                user = self.__get_missing_user_with_addr(addr)

            self.verifier.verify_timestamp(msg,
                                           get_timestamp() - constants.TIMESTAMP_GAP)
            self.verifier.verify_signature(msg, user.public_key)

            msg = self.processor.process_asym_key(msg,
                                                  self.keychain.private_key)
            sender, dest, n1, gamodp = msg.payload

            gamodp = convert_bytes_to_public_key(gamodp)
            # sender and the user identity in the message differ
            if sender != user.username:
                raise exception.InvalidUsernameException()

            if self.username != dest:
                raise exception.InvalidUsernameException()

            n2 = os.urandom(constants.NONCE_LENGTH)
            public_key, private_key = generate_dh_pair()
            key = derive_symmetric_key(private_key, gamodp, n1, n2)
            user.key = key

            msg = Message(message_type["Dest_Client_DH"], payload=(
                self.username, sender, n2,
                convert_public_key_to_bytes(public_key)))

            msg = self.converter.asym_key_with_sign(msg, user.public_key,
                                                    self.keychain.private_key)
            # After successful verification generate this client's DH contribution
            # and send it to the initiator
            send_msg(self.socket, user.addr, msg)
        except exception.SecurityException as e:
            print str(e)

    # Process a message encrypted with symmetric key
    @udp.endpoint("Message")
    def got_message(self, msg, addr):
        try:
            if MessageParser.get_message_type(msg) != "Message":
                raise exception.InvalidMessageTypeException()
            msg = self.msg_parser.parse_key_sym_sign(msg)
            user = self.keychain.get_user_with_addr(addr)
            # sender's symmetric key is not present in the keychain
            if user is None:
                # msg = Message(message_type["Reject"], payload=("Reject",))
                # self.converter.sign(msg, self.keychain.private_key)
                # send_msg(self.socket, addr, msg)
                raise exception.InvalidUserException()
            # Check for replay
            self.verifier.verify_timestamp(msg, user.last_recv_msg)
            self.verifier.verify_signature(msg, user.public_key)

            msg = self.processor.process_sym_key(msg, user.key)
            sender, dest, message = msg.payload
            if self.username != dest:
                raise exception.InvalidUsernameException()

            user.last_recv_msg = msg.timestamp
            # ACK for message
            msg = Message(message_type["Accept"], payload=("OK",))
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)
            print sender + " -> " + message

        except exception.SecurityException as e:
            print str(e)

    # Contact server to get the public of the user
    def __get_missing_user_with_username(self, username):
        utuple = self.list(username)
        if utuple is None:  # Malicious user caught!!!
            raise exception.ListFailedException()

        if utuple[0] == username:
            user = ClientUser()
            user.username = username
            user.addr = convert_bytes_to_addr(utuple[1])
            user.public_key = convert_bytes_to_public_key(utuple[2])
            self.keychain.add_user(user)
            return user
        else:
            raise exception.InvalidUsernameException()

    # Contact server to get the public of the user
    def __get_missing_user_with_addr(self, addr):
        utuple = self.list(addr, is_ip=True)
        if utuple is None:  # Malicious user caught!!!
            exception.ListFailedException()
        paddr = convert_bytes_to_addr(utuple[1])
        if paddr == addr:
            user = ClientUser()
            user.username = utuple[0]
            user.addr = paddr
            user.public_key = convert_bytes_to_public_key(utuple[2])
            self.keychain.add_user(user)
            return user
        else:
            raise exception.InvalidSendersAddressException()

    # Generate a the client shared symmetric key used for further communication
    def __setup_client_shared_key(self, dest_user):
        public_key, private_key = generate_dh_pair()
        n1 = os.urandom(constants.NONCE_LENGTH)
        msg = Message(message_type["Sender_Client_DH"],
                      payload=(
                          self.username, dest_user.username, n1,
                          convert_public_key_to_bytes(public_key)))
        msg = self.converter.asym_key_with_sign(msg, dest_user.public_key,
                                                self.keychain.private_key)
        msg, addr = send_recv_msg(self.socket, udp, dest_user.addr, msg)

        msg = self.msg_parser.parse_key_asym_sign(msg)

        self.verifier.verify_timestamp(msg,
                                       get_timestamp() - constants.TIMESTAMP_GAP)
        self.verifier.verify_signature(msg, dest_user.public_key)

        msg = self.processor.process_asym_key(msg, self.keychain.private_key)
        sender, dest, n2, gbmodp = msg.payload

        gbmodp = convert_bytes_to_public_key(gbmodp)

        if sender != dest_user.username:
            raise exception.InvalidUsernameException()

        if self.username != dest:
            raise exception.InvalidUsernameException()

        key = derive_symmetric_key(private_key, gbmodp, n1, n2)
        dest_user.key = key

    # The user enters list command.
    def list(self, username="*", is_ip=False):
        try:
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
        except socket.timeout:
            print "Socket Timed Out, Try Again Later"
            return None
        except exception.SecurityException as e:
            print str(e)
            return None

    # send the message to a specific client
    def send(self, destination, message):
        try:

            if len(destination) == 0:
                raise exception.InvalidUsernameException()
            # Checks if user already communicated in the past
            user = self.keychain.get_user_with_username(destination)
            # If not get user info from server
            if user is None:
                user = self.__get_missing_user_with_username(destination)
            # If yes, but key is not present, the set up the DH shared key
            if user.key is None:
                self.__setup_client_shared_key(user)

            if len(message) > 1000 or len(message) == 0:
                raise exception.InvalidMessageLengthException()

            msg = Message(message_type["Message"],
                          payload=(self.username, destination, message))
            msg = self.converter.sym_key_with_sign(msg, user.key,
                                                   self.keychain.private_key)
            msg, addr = send_recv_msg(self.socket, udp, user.addr, msg)

            # if MessageParser.get_message_type(msg) == "Reject":
            #     self.got_reject(msg, addr, user.public_key, user.addr)
            #     user = self.keychain.get_user_with_username(destination)
            #     self.keychain.remove_user(user)
            #     # self.send(destination, message)
            #     raise exception.SendFailedException()
            if MessageParser.get_message_type(msg) == "Accept":
                self.got_accept(msg, addr, user.public_key, user.addr)
                print "Sent Successfully"
            else:
                raise exception.InvalidMessageTypeException()

        except socket.timeout:
            print "Socket Timed Out, Try Again Later"
        except exception.SecurityException as e:
            print str(e)

    # Generate periodic heartbeats and forward to server indicating the client
    # is still in the network
    def heartbeat(self):
        while True:
            msg = Message(message_type["Heartbeat"], payload=(self.username,
                                                              "HEARTBEAT"))
            usr = self.keychain.get_user_with_addr(self.saddr)
            msg = self.converter.sym_key_with_sign(msg, usr.key,
                                                   self.keychain.private_key)
            send_msg(self.socket, self.saddr, msg)
            time.sleep(constants.SEND_HEARTBEAT_TIMEOUT)
