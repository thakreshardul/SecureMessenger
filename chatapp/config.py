import json

import constants
import exception


class ClientConfig:
    def __init__(self):
        self.serverip = None
        self.serverport = None
        self.clientip = None
        self.clientport = None

    def readfile(self, file):
        fp = open(file)
        try:
            json_dict = json.load(fp)
            self.serverip = json_dict["server-ip"]
            self.serverport = json_dict["server-port"]
            self.clientip = json_dict["client-ip"]
            self.clientport = json_dict["client-port"]
        except (KeyError, ValueError):
            raise exception.ConfigFileMissingException()


class ServerConfig:
    def __init__(self):
        self.serverip = None
        self.serverport = None
        self.num_threads = None

    def readfile(self, file):
        fp = open(file)
        try:
            json_dict = json.load(fp)
            self.serverip = json_dict["server-ip"]
            self.serverport = json_dict["server-port"]
            self.num_threads = json_dict["num-threads"]
        except (KeyError, ValueError):
            raise exception.ConfigFileMissingException()


__client_config = None
__server_config = None


def load_client(file=constants.CLIENT_CONFIG_FILE):
    global __client_config
    __client_config = ClientConfig()
    __client_config.readfile(file)


def load_server(file=constants.SERVER_CONFIG_FILE):
    global __server_config
    __server_config = ServerConfig()
    __server_config.readfile(file)


def get_client_config():
    global __client_config
    return __client_config


def get_server_config():
    global __server_config
    return __server_config
