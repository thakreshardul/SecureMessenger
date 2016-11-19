class ServerUser:
    def __init__(self):
        self.username = None
        self.password = None
        self.salt = None
        self.public_key = None
        self.key = None
        self.addr = None


class ClientUser:
    def __init__(self):
        self.username = None
        self.public_key = None
        self.dh_public_key = None
        self.key = None
        self.addr = None

