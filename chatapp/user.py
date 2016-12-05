class ServerUser:
    def __init__(self):
        self.username = None
        self.pass_hash = None
        self.salt = None
        self.public_key = None
        self.key = None
        self.addr = None
        self.timestamp = None
        self.last_list_recv = 0


class ClientUser:
    def __init__(self):
        self.username = None
        self.public_key = None
        self.dh_private_key = None
        self.key = None
        self.addr = None
        self.last_recv_msg = 0
