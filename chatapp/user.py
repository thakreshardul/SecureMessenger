# This class is used by Server
class ServerUser:
    def __init__(self):
        self.username = None  # The Client's Username
        self.pass_hash = None  # The Server Password Hash
        self.salt = None  # The Salt stored on Server
        self.public_key = None  # The Public Key given during Login
        self.key = None  # The AES Key Setup during Login
        self.addr = None  # The Network Address of the User
        self.last_heartbeat_recv = None  # The Timestamp of the Last Heartbeat Received
        self.last_list_recv = 0  # The Timestamp of the Last List Received


# This class is used by Client
class ClientUser:
    def __init__(self):
        self.username = None  # The Client's Username
        self.public_key = None  # The Public Key given by Server
        self.dh_private_key = None  # The DH Private Key used
        self.key = None # The AES Key Setup before messaging
        self.addr = None # The Network Address of User
        self.last_recv_msg = 0 # The Timestamp of the last msg recved
