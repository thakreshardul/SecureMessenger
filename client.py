from keychain import ClientKeyChain


class ChatClient:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.keychain = ClientKeyChain(65537, 2048)

    def setup_networking(self):
        pass

    def login(self, username, password):
        pass

    def list(self):
        pass

    def send(self, destination, message):
        pass


if __name__ == "__main__":
    client = ChatClient("127.0.0.1", 7050)
    # import threading
    #
    #
    # def printit():
    #     threading.Timer(1.0, printit).start()
    #     print "Hello, World!"
    #
    #
    # printit()

