import socket
import struct
import time

import constants
import exception


# Converts a tuple to string by doing the following
# (a, b, c) -> len(a)+a+len(b)+b+len(c)+c
def tuple_to_str(tuple):
    string = ""
    for param in tuple:
        l = struct.pack("!H", len(param))
        string += l
        string += param

    return string


# Converts the above string back to a tuple
def str_to_tuple(string):
    pl = []
    try:
        while True:
            if string == "":
                break
            header = struct.unpack("!H", string[:constants.LEN_LENGTH])[0]
            param = string[constants.LEN_LENGTH:constants.LEN_LENGTH + header]
            pl.append(param)
            string = string[constants.LEN_LENGTH + header:]
        return tuple(pl)
    except (IndexError, struct.error):
        raise exception.InvalidMessageException()


# Sends a message to the destination address using given socket
def send_msg(sender_socket, dest_addr, msg):
    sender_socket.sendto(str(msg), dest_addr)


# Sends Like above, but also waits for return msg
# Raises socket.timeout if it doesnt come
def send_recv_msg(sender_socket, recv_udp, dest_addr, msg):
    recv_udp.cv_for_waiter.acquire()
    sender_socket.sendto(str(msg), dest_addr)
    return recv_udp.recv(constants.SOCKET_TIMEOUT)


# Convert (ip,port) to byte string
def convert_addr_to_bytes(addr):
    ip = socket.inet_aton(addr[0])
    port = struct.pack("!H", addr[1])
    return ip + port


# Convert byte string to (ip,port)
def convert_bytes_to_addr(string):
    try:
        ip = string[:4]
        port = string[4:]
        return socket.inet_ntoa(ip), struct.unpack("!H", port)[0]
    except (IndexError, struct.error, socket.error):
        raise exception.InvalidMessageException()


# Returns Timestamp as Long
def get_timestamp():
    return long(time.time())
