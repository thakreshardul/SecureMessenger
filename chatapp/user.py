class ServerUser:
    def __init__(self):
        self.username = None
        self.pass_hash = None
        self.salt = None
        self.public_key = None
        self.key = None
        self.addr = None
        self.ref_count = None


class ClientUser:
    def __init__(self):
        self.username = None
        self.public_key = None
        self.dh_private_key = None
        self.key = None
        self.addr = None
