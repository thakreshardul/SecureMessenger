import os
import struct
import time

from crypto import *
from exceptions import *

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
        payload = self.str_payload()
        payload_len = str(len(payload))
        fmt = "!B" + key_len + "s" + sign_len + "sL" + payload_len + "s"
        return struct.pack(fmt,
                           self.type, self.key, self.sign, self.timestamp,
                           payload)

    def str_payload(self):
        payload = ""
        for param in self.payload:
            l = struct.pack("!H", len(param))
            payload += l
            payload += param
        return payload


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
        #msg.key = ""
        msg.key = "key"
        #msg.sign = ""
        msg.sign = "signature"
        #msg.payload = ""
        msg.payload = "payload"
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
        msg.sign = '0' * (256 - len(str(solution))) + bytes(
            solution[0]+solution[1])  # Possible Bug Should Probably Give Length for safe side
        payload = (username, dh_public_key, n1)
        msg.payload = payload
        msg = self.__encrypt_packet_with_pub(msg)
        msg.timestamp = self.__get_timestamp()
        # msg = self.__sign_packet(msg) Shouldnt Sign Solution Packet
        return msg

    def generate_server_dh_packet(self, dh_public_key, n2):
        msg = Message()
        msg.type = message_type["Server_DH"]
        msg.payload = dh_public_key + "#" + n2
        msg = self.__encrypt_packet_with_pub(msg)
        msg.timestamp = self.__get_timestamp()
        msg = self.__sign_packet(msg)
        return msg

    def generate_password_packet(self, key, client_password, sender_public_key):
        msg = Message()
        msg.type = message_type["Password"]
        msg.timestamp = self.__get_timestamp()
        msg.payload = msg.timestamp + "#" + client_password + "#" + sender_public_key
        msg = self.__encrypt_packet_with_skey(msg, key)
        msg.sign = ""
        return msg

    def __encrypt_packet_with_pub(self, msg):
        skey = os.urandom(32)
        iv = os.urandom(16)
        tag, ciphertext = encrypt_payload(skey, iv, msg.str_payload())
        msg.payload = ciphertext
        msg.key = encrypt_key(self.dest_public_key, skey + iv + tag)
        return msg

    def __encrypt_packet_with_skey(self, msg, skey):
        iv = os.urandom(16)
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
    def __init__(self, sender_public_key):
        self.sender_public_key = sender_public_key

    @staticmethod
    def get_message_type(message):
        return message_dictionary[ord(message[0])]

    def verify_timestamp(self, msg):
        uts = 0
        cts = 0
        if ord(msg[0]) == message_type['Solution']:
            ts = msg[513:517]

            uts = struct.unpack("!L", ts)[0]
            cts = long(time.time())

        if uts < cts - 5000:
            raise InvalidTimeStampException()

    def verify_solution(self, msg):
        solution = msg[257:513]

    def parse_nokey_nosign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.timestamp = struct.unpack("!L", message[1:5])
        parsed_message.payload = message[5:]
        return parsed_message

    def parse_key_asym_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.key = message[1:257]
        parsed_message.sign = message[257:513]
        parsed_message.timestamp = struct.unpack("!L", message[513:517])
        parsed_message.payload = message[517:]   # parse pl
        return parsed_message

    def parse_key_sym_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.key = message[1:33]
        parsed_message.sign = message[33:289]
        parsed_message.timestamp = struct.unpack("!L", message[289:293])
        parsed_message.payload = message[293:]
        return parsed_message

    def parse_key_asym_ans(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.key = message[1:257]
        ans_index = 257+16+int(struct.unpack("!H", message[257+16:257+18]))
        parsed_message.sign = message[257:ans_index]
        parsed_message.timestamp = struct.unpack("!L", message[ans_index:ans_index+4])
        parsed_message.payload = message[ans_index+4:]
        return parsed_message

    def parse_sign(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.sign = message[1:257]
        parsed_message.timestamp = struct.unpack("!L", message[257:261])
        parsed_message.payload = message[261:] #parse pl
        return parsed_message

    def parse_key_sym(self, message):
        parsed_message = Message()
        parsed_message.type = ord(message[0])
        parsed_message.key = message[1:33]
        parsed_message.timestamp = struct.unpack("!L", message[33:37])
        parsed_message.payload = message[37:]
        return parsed_message

if __name__ == "__main__":
    msg_gen = MessageGenerator(None, None)
    print msg_gen.generate_login_packet()
    pass
