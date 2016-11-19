import os
import struct
import time

import constants
from chatapp.utlities import
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
        self.payload = None

    def __str__(self):
        type = struct.pack("!B", self.type)
        ts = struct.pack("!L", self.timestamp)
        return type + self.key + self.sign + ts + self.payload


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
        msg.payload = Message.tuple_to_str(certificate)
        return msg

    def generate_solution_packet(self, solution, username, dh_public_key, n1):
        msg = Message()
        msg.type = message_type["Solution"]
        msg.sign = Message.tuple_to_str(solution)
        msg.payload = (username, dh_public_key, n1)
        msg = self.__encrypt_packet_with_pub(msg)
        msg.timestamp = self.__get_timestamp()
        return msg

    def generate_server_dh_packet(self, dh_public_key, n2):
        msg = Message()
        msg.type = message_type["Server_DH"]
        msg.key = ""
        msg.payload = (dh_public_key, n2)
        msg.payload = Message.tuple_to_str(msg.payload)
        msg.timestamp = self.__get_timestamp()
        msg = self.__sign_packet(msg)
        return msg

    def generate_password_packet(self, key, client_password, sender_public_key):
        msg = Message()
        msg.type = message_type["Password"]
        msg.timestamp = self.__get_timestamp()
        msg.payload = (str(msg.timestamp), client_password, sender_public_key)
        msg = self.__encrypt_packet_with_skey(msg, key)
        msg.sign = ""
        return msg

    def __encrypt_packet_with_pub(self, msg):
        skey = os.urandom(constants.AES_KEY_LENGTH)
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv,
                                          Message.tuple_to_str(msg.payload))
        msg.payload = ciphertext
        msg.key = encrypt_key(self.dest_public_key, skey + iv + tag)
        return msg

    def __encrypt_packet_with_skey(self, msg, skey):
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv,
                                          Message.tuple_to_str(msg.payload))
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
        parsed_message.key = ""
        parsed_message.sign = ""
        start_index = 1
        end_index = start_index + constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = message[start_index:end_index]
        parsed_message.payload = Message.str_to_tuple(message[end_index:])
        parsed_message.timestamp = \
        struct.unpack("!L", parsed_message.timestamp)[0]

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
                                                 message[
                                                 start_index:end_index])[0]
        parsed_message.payload = message[end_index:]
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
                                                 message[
                                                 start_index:end_index])[0]
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_key_asym_ans(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.EKEY_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index = end_index + constants.NONCE_LENGTH + constants.LEN_LENGTH
        l = int(struct.unpack("!H", message[
                                    end_index:end_index + constants.LEN_LENGTH])[
                    0])
        end_index += constants.LEN_LENGTH + l
        parsed_message.sign = message[start_index:end_index]
        parsed_message.sign = Message.str_to_tuple(parsed_message.sign)
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[
                                                 start_index:end_index])[0]
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.key = ""
        start_index = 1
        end_index = start_index + constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[
                                                 start_index:end_index])[0]
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_key_sym(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        start_index = 1
        end_index = start_index + constants.AES_IV_LENGTH + constants.AES_TAG_LENGTH
        parsed_message.key = message[start_index:end_index]
        parsed_message.sign = ""
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = struct.unpack("!L",
                                                 message[
                                                 start_index:end_index])[0]
        parsed_message.payload = message[end_index:]
        return parsed_message


class MessageVerifer:
    def __init__(self, sender_public_key, private_key):
        self.sender_public_key = sender_public_key
        self.private_key = private_key

    def verify_solution(self, ns, d, nc, x):
        verify_puzzle(ns, nc, x, d)

    def decrypt_payload(self, ekey, payload):
        dkey = decrypt_key(self.private_key, ekey)
        skey = dkey[:constants.AES_KEY_LENGTH]
        iv = dkey[
             constants.AES_KEY_LENGTH:constants.AES_KEY_LENGTH + constants.AES_IV_LENGTH]
        tag = dkey[constants.AES_IV_LENGTH + constants.AES_KEY_LENGTH:]
        dpayload = decrypt_payload(skey, iv, tag, payload)
        return Message.str_to_tuple(dpayload)


if __name__ == "__main__":
    msg_gen = MessageGenerator(None, None)
    print msg_gen.generate_login_packet()
    pass
