import os
import struct

import chatapp.constants as constants
from chatapp.constants import message_dictionary
from chatapp.utilities import get_timestamp
from chatapp.utilities import tuple_to_str, str_to_tuple
from crypto import *
from ds import Solution, Certificate


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
        print len(skey), len(iv), len(tag)
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
    def nokey_nosign(self, msg):
        if msg.payload != "":
            msg.payload = tuple_to_str(msg.payload)
        msg.timestamp = get_timestamp()
        return msg

    # Should Implement
    def asym_key_with_sign(self, msg, dest_public_key, sender_private_key):
        return msg

    def asym_key(self, msg, dest_public_key):
        msg.sign = tuple_to_str(msg.sign)
        msg.encrypt_packet_with_pub(dest_public_key)
        msg.timestamp = get_timestamp()
        return msg

    def sign(self, msg, sender_private_key):
        msg.payload = tuple_to_str(msg.payload)
        msg.timestamp = get_timestamp()
        msg.sign_packet(sender_private_key)
        return msg

    def sym_key_with_sign(self, msg, skey, sender_private_key):
        msg.payload = tuple_to_str(msg.payload)
        msg.encrypt_packet_with_skey(skey)
        msg.timestamp = get_timestamp()
        msg.sign_packet(sender_private_key)
        return msg


class MessageParser:
    @staticmethod
    def get_message_type(message):
        return message_dictionary[ord(message[0])]

    def __parse_timestamp(self, message):
        return struct.unpack("!L", message)[0]

    def parse_nokey_nosign(self, message):
        parsed_message = Message(ord(message[0]))
        start_index = 1
        end_index = start_index + constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = self.__parse_timestamp(
            message[start_index:end_index])
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_key_asym_sign(self, message):
        parsed_message = Message(ord(message[0]))
        start_index = 1
        end_index = start_index + constants.EKEY_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index += constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        ts = message[start_index:end_index]
        parsed_message.timestamp = self.__parse_timestamp(ts)
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_key_sym_sign(self, message):
        parsed_message = Message(ord(message[0]))
        start_index = 1
        end_index = start_index + constants.AES_IV_LENGTH + constants.AES_TAG_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index += constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = self.__parse_timestamp(
            message[start_index:end_index])
        parsed_message.payload = message[end_index:]

        return parsed_message

    def parse_key_asym_ans(self, message):
        parsed_message = Message(ord(message[0]))
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
        parsed_message.timestamp = self.__parse_timestamp(
            message[start_index:end_index])
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_sign(self, message):
        parsed_message = Message(ord(message[0]))
        start_index = 1
        end_index = start_index + constants.SIGNATURE_LENGTH
        parsed_message.sign = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = self.__parse_timestamp(
            message[start_index:end_index])
        parsed_message.payload = message[end_index:]
        return parsed_message

    def parse_key_sym(self, message):
        parsed_message = Message(ord(message[0]))
        start_index = 1
        end_index = start_index + constants.AES_IV_LENGTH + constants.AES_TAG_LENGTH
        parsed_message.key = message[start_index:end_index]
        start_index = end_index
        end_index += constants.TIMESTAMP_LENGTH
        parsed_message.timestamp = self.__parse_timestamp(
            message[start_index:end_index])
        parsed_message.payload = message[end_index:]
        return parsed_message


class MessageVerifer:
    def verify_timestamp(self, msg, ts):
        if msg.timestamp <= ts:
            raise exception.InvalidTimeStampException()

    def verify_signature(self, msg, dest_public_key):
        ts = struct.pack("!L", msg.timestamp)
        verify_sign(msg.sign, ts + msg.payload, dest_public_key)

    def verify_certificate(self, msg, dest_public_key):
        cert = msg.payload
        ts = get_timestamp()
        cert_ts = struct.unpack("!L", cert.timestamp)[0]
        if cert_ts < ts:
            raise exception.InvalidCertificateException()
        # Should Raise Invalid Cert
        verify_sign(cert.sign, "".join(cert[:-1]), dest_public_key)


class MessageProcessor:
    def __separate_sym_keys(self, key):
        skey = key[:constants.AES_KEY_LENGTH]
        iv = key[
             constants.AES_KEY_LENGTH:constants.AES_KEY_LENGTH + constants.AES_IV_LENGTH]
        tag = key[constants.AES_KEY_LENGTH+constants.AES_IV_LENGTH:]
        return skey, iv, tag

    def process_asym_key(self, msg, sender_private_key):
        key = decrypt_key(sender_private_key, msg.key)
        skey, iv, tag = self.__separate_sym_keys(key)
        dpayload = decrypt_payload(skey, iv, tag, msg.payload)
        print repr(dpayload)
        msg.payload = str_to_tuple(dpayload)
        print msg.payload
        return msg

    def process_sym_key(self, msg, skey):
        iv = msg.key[:constants.AES_IV_LENGTH]
        tag = msg.key[constants.AES_IV_LENGTH:]
        dpayload = decrypt_payload(skey, iv, tag, msg.payload)
        msg.payload = str_to_tuple(dpayload)
        return msg

    def process_ans(self, msg, ns, d, sender_private_key):
        solution = Solution._make(msg.sign)
        verify_puzzle(ns, solution.nonce_c, solution.x, d)
        return self.process_asym_key(msg, sender_private_key)

    def process_certificate(self, msg):
        msg.payload = Certificate._make(str_to_tuple(msg.payload))
        return msg
