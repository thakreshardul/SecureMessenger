import socket
import struct
import time

import constants


def tuple_to_str(tuple):
    string = ""
    for param in tuple:
        l = struct.pack("!H", len(param))
        # print type(string), type(l), type(param), param
        string += l
        string += param

    return string


def str_to_tuple(string):
    pl = []
    while True:
        if string == "":
            break
        header = struct.unpack("!H", string[:constants.LEN_LENGTH])[0]
        param = string[constants.LEN_LENGTH:constants.LEN_LENGTH + header]
        pl.append(param)
        string = string[constants.LEN_LENGTH + header:]
    return tuple(pl)


def send_msg(sender_socket, dest_addr, msg):
    sender_socket.sendto(str(msg), dest_addr)


def send_recv_msg(sender_socket, recv_udp, dest_addr, msg):
    recv_udp.cv_for_waiter.acquire()
    sender_socket.sendto(str(msg), dest_addr)
    return recv_udp.recv(5)


def get_timestamp():
    return long(time.time())
