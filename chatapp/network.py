import socket
import threading

from chatapp import exception
from message import MessageParser


def create_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class Udp:
    def __init__(self):
        self.socket = create_socket()
        self.handlers = {}
        self.num_threads = 0
        self.threads = []
        self.current_thread = 0
        self.obj_of_handlers = None
        self.msg_addr_for_waiter = ""
        self.cv_for_waiter = threading.Condition()
        self.waiting = False

    def start(self, self_obj, ip, port, num_threads):
        self.socket.bind((ip,port))
        self.num_threads = num_threads
        self.obj_of_handlers = self_obj
        for i in xrange(self.num_threads):
            cv = threading.Condition()
            q = []
            t = threading.Thread(target=self.__process_message, args=(cv, q))
            t.daemon = True
            t.start()
            t_tuple = (t, cv, q)
            self.threads.append(t_tuple)

        listener_thread = threading.Thread(target=self.__recv_message)
        listener_thread.daemon = True
        listener_thread.start()

    def recv(self, timeout):
        self.waiting = True
        self.cv_for_waiter.wait(timeout)
        self.waiting = False
        if self.msg_addr_for_waiter == "":
            self.cv_for_waiter.release()
            raise socket.timeout()
        msg_addr = self.msg_addr_for_waiter
        self.msg_addr_for_waiter = ""
        self.cv_for_waiter.release()
        return msg_addr

    def __recv_message(self):
        while True:
            msg_addr = self.socket.recvfrom(1000)
            try:
                if MessageParser.get_message_type(msg_addr[0]) in self.handlers:
                    current_thread = self.current_thread
                    t, cv, q = self.threads[current_thread]
                    cv.acquire()
                    q.append(msg_addr)
                    cv.notify()
                    cv.release()
                    self.current_thread = (current_thread + 1) % self.num_threads
                else:
                    self.cv_for_waiter.acquire()
                    if self.waiting:
                        self.msg_addr_for_waiter = msg_addr
                        self.cv_for_waiter.notify()

                    self.cv_for_waiter.release()
            except exception.SecurityException as e:
                print str(e)

    def __process_message(self, cv, q):
        while True:
            cv.acquire()
            if len(q) == 0:
                cv.wait()
            msg_addr = q.pop()
            cv.release()
            self.handlers[MessageParser.get_message_type(msg_addr[0])](
                self.obj_of_handlers, msg_addr[0], msg_addr[1])

    def endpoint(self, msg_type):
        def decorator(func):
            self.handlers[msg_type] = func
            return func

        return decorator