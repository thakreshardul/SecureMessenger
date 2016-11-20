import os
import struct
import time

import chatapp.constants as constants
from chatapp.constants import message_dictionary, message_type
from chatapp.utilities import get_timestamp
from chatapp.utilities import tuple_to_str, str_to_tuple
from crypto import *


class Message:
    def __init__(self, type, timestamp="", key="", sign="", payload=""):
        self.type = type
        self.timestamp = timestamp
        self.key = key
        self.sign = sign
        self.payload = payload

    def __str__(self):
        type = struct.pack("!B", self.type)
        ts = struct.pack("!L", self.timestamp)
        return type + self.key + self.sign + ts + self.payload

    def encrypt_packet_with_pub(self, dest_public_key):
        skey = os.urandom(constants.AES_KEY_LENGTH)
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv, tuple_to_str(self.payload))
        self.payload = ciphertext
        self.key = encrypt_key(dest_public_key, skey + iv + tag)

    def encrypt_packet_with_skey(self, skey):
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv, tuple_to_str(self.payload))
        self.payload = ciphertext
        self.key = iv + tag

    def sign_packet(self, sender_private_key):
        timestamp = struct.pack("!L", self.timestamp)
        signature = sign_stuff(sender_private_key, timestamp + self.payload)
        self.sign = signature


class MessageConverter:
    def __init__(self):
        self.msg_to_str = {"Login": self.nokey_nosign,
                           "Puzzle": self.nokey_nosign}

    def convert(self, msg, dest_public_key, sender_private_key):
        return self.msg_to_str[message_dictionary[msg.type]](msg,dest_public_key,
                                                      sender_private_key)

    def nokey_nosign(self, msg, dest_public_key, sender_private_key):
        msg.timestamp = get_timestamp()
        return msg

    # Should Implement
    def asym_key_with_sign(self, msg, dest_public_key, sender_private_key):
        return msg

    def sign(self, msg, dest_public_key, sender_private_key):
        msg.payload = str_to_tuple(msg.payload)
        msg.timestamp = get_timestamp()
        msg.sign_packet(sender_private_key)
        return msg

    def sym_key(self, msg, skey, sender_private_key):
        msg.payload = str_to_tuple(msg.payload)
        msg.timestamp = get_timestamp()
        msg.encrypt_packet_with_skey(skey)
        msg.sign_packet(sender_private_key)
        return msg

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
        msg.payload = tuple_to_str(certificate)
        return msg

    def generate_solution_packet(self, solution, username, dh_public_key, n1):
        msg = Message()
        msg.type = message_type["Solution"]
        msg.sign = tuple_to_str(solution)
        msg.payload = (username, dh_public_key, n1)
        msg = self.__encrypt_packet_with_pub(msg)
        msg.timestamp = self.__get_timestamp()
        return msg

    def generate_server_dh_packet(self, dh_public_key, n2):
        msg = Message()
        msg.type = message_type["Server_DH"]
        msg.key = ""
        msg.payload = (dh_public_key, n2)
        msg.payload = tuple_to_str(msg.payload)
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
        tag, ciphertext = encrypt_payload(skey, iv, tuple_to_str(msg.payload))
        msg.payload = ciphertext
        msg.key = encrypt_key(self.dest_public_key, skey + iv + tag)
        return msg

    def __encrypt_packet_with_skey(self, msg, skey):
        iv = os.urandom(constants.AES_IV_LENGTH)
        tag, ciphertext = encrypt_payload(skey, iv, tuple_to_str(msg.payload))
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
        parsed_message.payload = str_to_tuple(message[end_index:])
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
        parsed_message.sign = str_to_tuple(parsed_message.sign)
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
        return str_to_tuple(dpayload)


if __name__ == "__main__":
    msg_gen = MessageGenerator(None, None)
    print msg_gen.generate_login_packet()
    pass
