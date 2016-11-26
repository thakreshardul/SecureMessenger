import json

import constants


class Configuration:
    def __init__(self):
        self.serverip = None
        self.serverport = None
        self.clientip = None
        self.clientport = None

    def readfile(self, file):
        fp = open(file)
        json_dict = json.load(fp)
        self.serverip = json_dict["server-ip"]
        self.serverport = json_dict["server-port"]
        self.clientip = json_dict["client-ip"]
        self.clientport = json_dict["client-port"]
        print file, self.clientport


__config = None


def load(file=constants.CONFIG_FILE):
    global __config
    __config = Configuration()
    __config.readfile(file)


def get_config():
    global __config
    return __config


if __name__ == "__main__":
    load()
    get_config()
    pass
