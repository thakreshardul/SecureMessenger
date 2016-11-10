from network import Udp

udp = Udp("127.0.0.1", 6000, 5)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    @udp.endpoint("Login")
    def got_login_packet(self,msg):
        print "Got Login"


if __name__ == "__main__":
    server = Server("127.0.0.1", 6000)
    udp.start(server)
