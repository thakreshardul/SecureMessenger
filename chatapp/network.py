import socket
import threading

import chatapp.constants as constants
import chatapp.exception as exception
from chatapp.message import MessageParser


# A Framework to add udp endpoints
# Starts Processor Threads and a Listener Thread
# Distributes Messages in Round Robin Fashion
class Udp:
    def __init__(self):
        # Socket which will be bound
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.handlers = {}  # Endpoint Handlers
        self.num_threads = 0  # Number of Processor Threads to Start

        # List of Threads, one entry is a tuple which contains
        # Thread Object
        # Condition Variable
        # Queue fo buffering incoming messages
        self.threads = []
        self.current_thread = 0  # Current Thread which will get next message
        self.obj_of_handlers = None  # client or server object that has handlers

        # Used by send_recv_msg
        # A Waiter is a thread that calls send_recv_msg
        # It waits to get a return msg
        self.msg_addr_for_waiter = ""  # Stores response (msg,addr) for waiter
        self.cv_for_waiter = threading.Condition()  # Condition Variable for Waiter
        self.waiting = False  # Set if a waiter exists

    # Starts the Framework
    # Binds to IP,PORT
    # Starts Listener and Processor Threads
    def start(self, self_obj, ip, port, num_threads):
        self.socket.bind((ip, port))
        self.num_threads = num_threads
        self.obj_of_handlers = self_obj

        # Starts Processor Threads
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

    # Called By Waiter Thread
    # It returns after timeout if no message was received
    def recv(self, timeout):
        # It waits until woken or timeout expires
        self.waiting = True
        self.cv_for_waiter.wait(timeout)

        # Checks received message and decides whether timeout or not happened
        self.waiting = False
        if self.msg_addr_for_waiter == "":
            self.cv_for_waiter.release()
            raise socket.timeout()
        msg_addr = self.msg_addr_for_waiter
        self.msg_addr_for_waiter = ""
        self.cv_for_waiter.release()
        return msg_addr

    # Run By Listener Thread
    def __recv_message(self):
        while True:
            msg_addr = self.socket.recvfrom(constants.BUFFER_SIZE) # Receive Message
            try:
                # If Handler is registered calls Handler
                if MessageParser.get_message_type(msg_addr[0]) in self.handlers:
                    current_thread = self.current_thread
                    t, cv, q = self.threads[current_thread]
                    cv.acquire()
                    q.append(msg_addr)
                    cv.notify()
                    cv.release()
                    self.current_thread = (current_thread + 1) % self.num_threads
                # or notifies waiter if any
                else:
                    self.cv_for_waiter.acquire()
                    if self.waiting:
                        self.msg_addr_for_waiter = msg_addr
                        self.cv_for_waiter.notify()

                    self.cv_for_waiter.release()
            except exception.SecurityException as e:
                print str(e)

    # Called By Processor Thread
    # Calls the handler and passes message to it
    def __process_message(self, cv, q):
        while True:
            cv.acquire()
            if len(q) == 0:
                cv.wait()
            msg_addr = q.pop()
            cv.release()
            self.handlers[MessageParser.get_message_type(msg_addr[0])](
                self.obj_of_handlers, msg_addr[0], msg_addr[1])

    # Endpoint handler used to register messages
    def endpoint(self, msg_type):
        def decorator(func):
            self.handlers[msg_type] = func
            return func

        return decorator
