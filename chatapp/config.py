""" This file handles the methods for parsing and loading the configuration
from json files"""
import json

import chatapp.constants as constants
import chatapp.exception as exception


class ClientConfig:
    def __init__(self):
        self.serverip = None
        self.serverport = None
        self.clientip = None
        self.clientport = None

    def readfile(self, file):
        fp = open(file)
        try:
            # loads the file into a dictionary and then initialises the values
            # for client configuration
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
            # loads the file into a dictionary and then initialises the values
            # for server configuration
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
    __client_config.readfile(file)  # loads the client config into global object


def load_server(file=constants.SERVER_CONFIG_FILE):
    global __server_config
    __server_config = ServerConfig()
    __server_config.readfile(file)  # loads the server config into global object


def get_client_config():
    global __client_config  # returns the global client object
    return __client_config


def get_server_config():
    global __server_config  # returns the global server object
    return __server_config
