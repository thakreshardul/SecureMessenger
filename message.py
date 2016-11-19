import os
import struct
import time

import constants
from crypto import *

message_type = {
    "Reject": 0,
    "Login": 1,
    "Puzzle": 2,
    "Solution": 3,
    "Server_DH": 4,
    "Password": 5
}

message_dictionary = {
    0: "Reject",
    1: "Login",
    2: "Puzzle",
    3: "Solution",
    4: "Server_DH",
    5: "Password"
}


class Message:
    def __init__(self):
        self.type = 0
        self.timestamp = None
        self.key = None
        self.sign = None
        self.src = None
        self.dest = None
        self.payload = None

    def __str__(self):
        key_len = str(len(self.key))
        sign_len = str(len(self.sign))
        payload = self.str_tuple(self.payload)
        payload_len = str(len(payload))
        fmt = "!B" + key_len + "s" + sign_len + "sL" + payload_len + "s"
        return struct.pack(fmt,
                           self.type, self.key, self.sign, self.timestamp,
                           payload)

    @staticmethod
    def str_tuple(tuple):
        string = ""
        for param in tuple:
            l = struct.pack("!H", len(param))
            string += l
            string += param

        return string


class MessageGenerator:
    def __init__(self, dest_public_key, sender_private_key):
        self.dest_public_key = dest_public_key
        self.sender_private_key = sender_private_key

    def __get_timestamp(self):
        return long(time.time())

    def generate_login_packet(self):
        msg = Message()
        msg.type = message_type["Login"]
        msg.timestamp = self.__get_timestamp()
        msg.key = ""
        msg.sign = ""
        msg.payload = ""
        return msg

    def generate_puzzle_response(self, certificate):
        msg = Message()
        msg.type = message_type["Puzzle"]
        msg.timestamp = self.__get_timestamp()
        msg.key = ""
        msg.sign = ""
        msg.payload = certificate
        return msg

    def generate_solution_packet(self, solution, username, dh_public_key, n1):
        msg = Message()
        msg.type = message_type["Solution"]
        msg.sign = Message.str_tuple(solution)
        msg.payload = (username, dh_public_key, n1)
        msg = self.__encrypt_packet_with_pub(msg)
        msg.timestamp = self.__get_timestamp()
        # msg = self.__sign_packet(msg) Shouldnt Sign Solution Packet
        return msg

    def generate_server_dh_packet(self, dh_public_key, n2):
        msg = Message()
        msg.type = message_type["Server_DH"]
        msg.payload = (dh_public_key, n2)
        msg = self.__encrypt_packet_with_pub(msg)
        msg.timestamp = self.__get_timestamp()
        msg = self.__sign_packet(msg)
        return msg

    def generate_password_packet(self, key, client_password, sender_public_key):
        msg = Message()
        msg.type = message_type["Password"]
        msg.timestamp = self.__get_timestamp()
        msg.payload = (msg.timestamp, client_password, sender_public_key)
        msg = self.__encrypt_packet_with_skey(msg, key)
        msg.sign = ""
        return msg

    def __encrypt_packet_with_pub(self, msg):
        skey = os.urandom(constants.AES_KEY_LENGTH)
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv, msg.str_tuple())
        msg.payload = ciphertext
        msg.key = encrypt_key(self.dest_public_key, skey + iv + tag)
        return msg

    def __encrypt_packet_with_skey(self, msg, skey):
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv, msg.payload)
        msg.payload = ciphertext
        msg.key = iv + tag
        return msg

    def __sign_packet(self, msg):
        stuff = struct.pack("!L" + str(len(msg.payload)) + "s", msg.timestamp,
                            msg.payload)
        signature = sign_stuff(self.sender_private_key, stuff)
        msg.sign = signature
        return msg


class MessageParser:
    @staticmethod
    def get_message_type(message):
        return message_dictionary[ord(message[0])]

    def parse_nokey_nosign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = message[start_index:end_index]
        parsed_message.payload = self.parse_payload(message[end_index:])
        parsed_message.timestamp = struct.unpack("!L", parsed_message.timestamp)

        return parsed_message

    def parse_key_asym_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.EKEY_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index += constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[start_index:end_index])
        parsed_message.payload = self.parse_payload(message[end_index:])
        return parsed_message

    def parse_key_sym_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.AES_IV_LENGTH + constants.AES_TAG_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index += constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[start_index:end_index])
        parsed_message.payload = self.parse_payload(message[end_index:])
        return parsed_message

    def parse_key_asym_ans(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.AES_KEY_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index = end_index + constants.NONCE_LENGTH
        l = int(struct.unpack("!H", message[
                                    end_index:end_index + constants.LEN_LENGTH]))
        end_index += constants.LEN_LENGTH + l
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[start_index:end_index])
        parsed_message.payload = self.parse_payload(message[end_index:])
        return parsed_message

    def parse_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[start_index:end_index])
        parsed_message.payload = self.parse_payload(message[end_index:])
        return parsed_message

    def parse_key_sym(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.AES_IV_LENGTH + constants.AES_TAG_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[start_index:end_index])
        parsed_message.payload = self.parse_payload(message[end_index:])
        return parsed_message

    def parse_payload(self, payload):
        header_length = 2
        pl = []
        while True:
            header = struct.unpack("!H", payload[:header_length])[0]
            param = payload[header_length, header_length + header]
            pl.append(param)
            payload = payload[header_length+header:]
        return tuple(payload)


if __name__ == "__main__":
    msg_gen = MessageGenerator(None, None)
    print msg_gen.generate_login_packet()
    pass
