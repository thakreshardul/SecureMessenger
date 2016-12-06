import sys
import threading
import time

import config
from chatapp.utilities import send_msg, convert_addr_to_bytes, \
    convert_bytes_to_addr
from constants import message_type
from db import UserDatabase
from ds import Solution
from keychain import ServerKeyChain
from message import *
from network import Udp
from user import ServerUser

# Create Udp Object for Endpoints
udp = Udp()

# Represents the Server
class Server:
    def __init__(self):
        # Socket which will be used
        self.socket = udp.socket

        # Servers Keychain which stores keys
        self.keychain = ServerKeyChain(
            open(constants.SERVER_PRIVATE_DER_FILE, 'rb'),
            open(constants.SERVER_PUBLIC_DER_FILE, 'rb'))

        # Message Related Objects
        self.msg_parser = MessageParser()
        self.converter = MessageConverter()
        self.processor = MessageProcessor()
        self.verifier = MessageVerifer()

        # Puzzle Certificate and client nonce dict
        self.certificate = None
        self.nc_list = {}

        # Create DB If it doesnt exist
        UserDatabase().create_db()

        # Start Puzzle Generator Thread
        self.puz_thread = threading.Thread(
            target=self.__generate_puz_certificate)
        self.puz_thread.daemon = True
        self.puz_thread.start()

        # Start Check Heartbeat Thread
        self.check_heartbeat_thread = threading.Thread(
            target=self.check_heartbeat)
        self.check_heartbeat_thread.daemon = True
        self.check_heartbeat_thread.start()

    # Generates Puzzle Every PUZZLE_TIMEOUT seconds
    # empties nonce_c dict
    def __generate_puz_certificate(self):
        while True:
            t1 = time.time()
            ns = os.urandom(16)
            d = chr(1)
            expiry_time = long(t1 + 60)
            packed_t = struct.pack("!L", expiry_time)
            sign = sign_stuff(self.keychain.private_key, packed_t + d + ns)
            self.certificate = Certificate(packed_t, d, ns, sign)
            self.nc_list = {}
            time.sleep(constants.PUZZLE_TIMEOUT)

    # Endpoint for Login
    # Returns Puzzle Certificate
    @udp.endpoint("Login")
    def got_login_packet(self, msg, addr):
        msg = Message(message_type["Puzzle"],
                      payload=self.certificate)
        msg = self.converter.nokey_nosign(msg)
        send_msg(self.socket, addr, msg)

    # Endpoint for Solution
    @udp.endpoint("Solution")
    def got_solution(self, msg, addr):
        try:
            # Parse Message
            msg = self.msg_parser.parse_key_asym_ans(msg)

            # Verify Message
            self.verifier.verify_timestamp(msg,
                                           get_timestamp() - constants.TIMESTAMP_GAP)
            solution = Solution._make(msg.sign)
            if solution.nonce_c in self.nc_list:
                raise exception.InvalidSolutionException()

            # Process Solution
            msg = self.processor.process_ans(msg, solution,
                                             self.certificate.nonce_s,
                                             ord(self.certificate.difficulty),
                                             self.keychain.private_key)
            self.nc_list[solution.nonce_c] = True

            username, gamodp, n1 = msg.payload

            # If User is already logged in
            if self.keychain.get_user_with_username(username) is not None:
                msg = Message(message_type["Reject"], payload=("Reject",))
                self.converter.sign(msg, self.keychain.private_key)
                send_msg(self.socket, addr, msg)
                return

            # Generate Server's DH Contribution
            gamodp = convert_bytes_to_public_key(gamodp)
            gbmodp, b = generate_dh_pair()
            gbmodp = convert_public_key_to_bytes(gbmodp)
            n2 = os.urandom(constants.NONCE_LENGTH)
            key = derive_symmetric_key(b, gamodp, n1, n2)

            # Store Key
            usr = ServerUser()
            usr.username = username
            usr.key = key
            usr.addr = addr
            self.keychain.add_user(usr)

            # Send DH to Client
            msg = Message(message_type["Server_DH"], payload=(gbmodp, n2))
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, addr, msg)
        except exception.SecurityException as e:
            print str(e)

    @udp.endpoint("Password")
    def got_password(self, msg, addr):
        try:
            # Parse Message
            msg = self.msg_parser.parse_key_sym(msg)

            # Verify Message
            self.verifier.verify_timestamp(msg,
                                           get_timestamp() - constants.TIMESTAMP_GAP)
            usr = self.keychain.get_user_with_addr(addr)
            if usr is None:
                raise exception.InvalidUserException()

            # Process Message
            msg = self.processor.process_sym_key(msg, usr.key)
            ts, pass_hash, pub_key = msg.payload
            ts = struct.unpack("!L", ts)[0]

            # Verify Payload
            if ts != msg.timestamp:
                raise exception.InvalidTimeStampException()

            # Get User Details From DB
            with UserDatabase() as db:
                user = db.get_user(usr.username)
                # Send Reject if username is wrong
                if user is None:
                    self.keychain.remove_user(usr)
                    msg = Message(message_type["Reject"], payload=("Reject",))
                    self.converter.sign(msg, self.keychain.private_key)
                    send_msg(self.socket, addr, msg)
                    raise exception.InvalidUsernameException()
                usr.pass_hash = user.pass_hash
                usr.salt = user.salt

            # Verify Password Hash
            try:
                verify_hash_password(pass_hash, usr.pass_hash, usr.salt)
            except exception.PasswordMismatchException as e:
                self.keychain.remove_user(usr)
                msg = Message(message_type["Reject"], payload=("Reject",))
                self.converter.sign(msg, self.keychain.private_key)
                send_msg(self.socket, addr, msg)
                print str(e)
                return

            # Add Pub Key to User Obj
            pub_key = convert_bytes_to_public_key(pub_key)
            usr.public_key = pub_key
            usr.timestamp = get_timestamp() + constants.HEARTBEAT_TIMEOUT

            # Send Accept
            msg = Message(message_type["Accept"], payload=("OK",))
            msg = self.converter.sign(msg, self.keychain.private_key)
            send_msg(self.socket, usr.addr, msg)
        except exception.SecurityException as e:
            print str(e)

    # Endpoint for Logout
    @udp.endpoint("Logout")
    def got_logout_packet(self, msg, addr):
        try:
            # Parse Message
            msg = self.msg_parser.parse_key_sym_sign(msg)

            # Verify Message
            self.verifier.verify_timestamp(msg,
                                           get_timestamp() - constants.TIMESTAMP_GAP)
            usr = self.keychain.get_user_with_addr(addr)
            if usr is None or usr.public_key is None:
                raise exception.InvalidUserException()

            if addr != usr.addr:
                raise exception.InvalidSendersAddressException()

            self.verifier.verify_signature(msg, usr.public_key)

            # Process Message
            msg = self.processor.process_sym_key(msg, usr.key)
            if msg.payload[1] == "LOGOUT":
                # Remove User and Broadcast
                self.keychain.remove_user(usr)
                msg = Message(message_type["Accept"], payload=("OK",))
                msg = self.converter.sign(msg, self.keychain.private_key)
                send_msg(self.socket, addr, msg)
                self.__send_logout_broadcast(usr)
            else:
                raise exception.InvalidPayloadException()
        except exception.SecurityException as e:
            print str(e)

    # Helper to send logout broadcast
    def __send_logout_broadcast(self, usr):
        ip = convert_addr_to_bytes(usr.addr)
        payload = (ip, "LOGOUT")
        msg = Message(message_type["Logout"], payload=payload)
        msg = self.converter.sign(msg, self.keychain.private_key)
        for client in self.keychain.list_users().itervalues():
            send_msg(self.socket, client.addr, msg)

    # Endpoint for List
    @udp.endpoint("List")
    def got_list_request(self, msg, addr):
        try:
            # Parse Message
            msg = self.msg_parser.parse_key_sym_sign(msg)

            # Verify Message
            usr = self.keychain.get_user_with_addr(addr)
            if usr is None or usr.public_key is None:
                raise exception.InvalidUserException()

            self.verifier.verify_timestamp(msg, usr.last_list_recv)
            self.verifier.verify_signature(msg, usr.public_key)

            # Process Message
            msg = self.processor.process_sym_key(msg, usr.key)
            request = msg.payload
            if request[0] != usr.username:
                raise exception.InvalidUserException()

            # Get Data depending on Request
            # * Gets all usernames
            if request[1] == "*":
                payload = []
                users = self.keychain.usernames
                for v in users.itervalues():
                    if v.username != usr.username:
                        username = v.username
                        payload.append(username)
                payload = tuple(payload)

            # Returns Details of specfic user
            # is_ip = 0 gives user with username
            # if 1 then with IP:PORT
            else:
                if request[2] == "0":
                    user = self.keychain.get_user_with_username(request[1])
                else:
                    user = self.keychain.get_user_with_addr(
                        convert_bytes_to_addr(request[1]))
                if user is None:
                    raise exception.InvalidUserException()
                username = user.username
                pk = convert_public_key_to_bytes(user.public_key)
                payload = (username, convert_addr_to_bytes(user.addr), pk)

            # To Prevent DOS
            usr.last_list_recv = msg.timestamp

            # Send Response
            msg = Message(message_type["List"], payload=payload)
            msg = self.converter.sym_key_with_sign(msg, usr.key,
                                                   self.keychain.private_key)
            send_msg(self.socket, usr.addr, msg)
        except exception.SecurityException as e:
            print str(e)

    # Endpoint for Heartbeat
    @udp.endpoint("Heartbeat")
    def got_heartbeat(self, msg, addr):
        try:
            # Parse Message
            msg = self.msg_parser.parse_key_sym_sign(msg)

            # Verify Message
            usr = self.keychain.get_user_with_addr(addr)
            if usr is None or usr.public_key is None:
                raise exception.InvalidUserException()

            self.verifier.verify_timestamp(msg,
                                           get_timestamp() - constants.TIMESTAMP_GAP)
            if msg.timestamp == usr.timestamp:
                raise exception.InvalidTimeStampException()
            self.verifier.verify_signature(msg, usr.public_key)

            # Process Message
            msg = self.processor.process_sym_key(msg, usr.key)
            if msg.payload[1] == "HEARTBEAT":
                usr.timestamp = msg.timestamp + constants.HEARTBEAT_TIMEOUT
        except exception.SecurityException as e:
            print str(e)

    # Checks All Users and Removes Users with expired timestamps
    def check_heartbeat(self):
        while True:
            logged_out = []
            t1 = get_timestamp()
            for user in self.keychain.list_users().itervalues():
                if user.timestamp is not None and get_timestamp() >= user.timestamp:
                    logged_out.append(user)
                    print "Logged out", user.username

            for user in logged_out:
                self.keychain.remove_user(user)
                self.__send_logout_broadcast(user)

            t2 = get_timestamp()
            sleep_time = constants.HEARTBEAT_PAUSE - (t2 - t1)
            if sleep_time > 0:
                time.sleep(sleep_time)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            config.load_server(sys.argv[1])
        else:
            raise exception.ConfigFileMissingException()
        conf = config.get_server_config()
        server = Server()
        udp.start(server, conf.serverip, conf.serverport, conf.num_threads)
        print "Server Running!!"
        server.check_heartbeat_thread.join()
    except (exception.SecurityException, IOError) as e:
        print str(e)
