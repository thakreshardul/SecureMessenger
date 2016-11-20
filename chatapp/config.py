import json
import constants


class Configuration:
    def __init__(self):
        self.serverip = None
        self.serverport = None
        self.clientip = None
        self.clientport = None
        self.filename = constants.CONFIG_FILE

    def readfile(self):
        fp = open(self.filename)
        json_dict = json.load(fp)
        self.serverip = json_dict["server-ip"]
        self.serverport = json_dict["server-port"]
        self.clientip = json_dict["client-ip"]
        self.clientport = json_dict["client-port"]

__config = None


def load():
    global __config
    __config = Configuration()
    __config.readfile()


def get_config():
    global __config
    return __config

if __name__ == "__main__":
    load()
    get_config()
    pass

