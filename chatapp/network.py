import socket
import threading

from message import MessageParser


def create_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class Udp:
    def __init__(self, ip, port, num_threads):
        self.socket = create_socket()
        self.socket.bind((ip, port))
        self.handlers = {}
        self.num_threads = num_threads
        self.threads = []
        self.current_thread = 0
        self.obj_of_handlers = None

    def start(self, self_obj):
        self.obj_of_handlers = self_obj
        for i in xrange(self.num_threads):
            cv = threading.Condition()
            q = []
            t = threading.Thread(target=self.__process_message, args=(cv, q))
            t.start()
            t_tuple = (t, cv, q)
            self.threads.append(t_tuple)

        listener_thread = threading.Thread(target=self.__recv_message)
        listener_thread.start()

    def __recv_message(self):
        while True:
            msg_addr = self.socket.recvfrom(1000)
            current_thread = self.current_thread
            t, cv, q = self.threads[current_thread]
            cv.acquire()
            q.append(msg_addr)
            cv.notify()
            cv.release()
            self.current_thread = (current_thread + 1) % self.num_threads

    def __process_message(self, cv, q):
        while True:
            cv.acquire()
            if len(q) == 0:
                cv.wait()
            msg_addr = q.pop()
            self.handlers[MessageParser.get_message_type(msg_addr[0])](
                self.obj_of_handlers, msg_addr[0], msg_addr[1])
            # self.handlers["Login"](self.obj_of_handlers, msg)
            cv.release()

    def endpoint(self, msg_type):
        def decorator(func):
            self.handlers[msg_type] = func
            return func

        return decorator

# udp = Udp('127.0.0.1', 5000, 5)
#
#
# @udp.endpoint(1)
# def test_endpoint():
#     pass
#
#
# udp.start()
# print udp.handlers
# print udp.threads
