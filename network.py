import socket
import struct
import threading


class Udp:
    def __init__(self, ip, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip, port))
        self.handlers = {}

    def __start_listener(self):
        threading.Thread(target=self.__recv_message)

    def __recv_message(self):
        while True:
            msg = self.socket.recv(1000)
            msg_type = msg[0]
            msg_type = struct.unpack("!B", msg_type)
            self.handlers[msg_type]()

    def endpoint(self, msg_type):
        def decorator(func):
            self.handlers[msg_type] = func
            return func

        return decorator


udp = Udp('127.0.0.1', 5000)


@udp.endpoint(1)
def test_endpoint():
    pass


print udp.handlers
