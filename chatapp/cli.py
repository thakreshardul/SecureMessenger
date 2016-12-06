import getpass
import socket
import sys

import client
import config
import exception


class TextInterface:
    def __init__(self, conf):
        self.client = client.ChatClient(
            (conf.serverip, conf.serverport))
        client.udp.start(self.client, conf.clientip, conf.clientport, 1)


    def login(self):
        while True:
            usernm = raw_input("Enter your user name:\n")
            passwd = getpass.getpass("Enter your password:\n")
            print "Logging In"
            if self.client.login(usernm, passwd):
                print ("Successfully Logged in")
                break
            else:
                print ("Unsuccessful login")

    def start(self):
        print "Enter a command:\n1. list\n2. send <USER> <MESSAGE>\n3. quit\n"
        while True:
            command = raw_input()
            userinput = command.split(" ")
            if userinput[0] == "list":
                l = self.client.list()
                if len(l) > 0:
                    print " ".join(l)
                else:
                    print "Only you are logged in"
            elif userinput[0] == "send":
                self.client.send(userinput[1], userinput[2])
            elif userinput[0] == "quit":
                self.client.logout()
                print ("Quitting the application")
                break
            else:
                print ("Enter correct command")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise exception.ConfigFileMissingException()
        config.load(sys.argv[1])
        conf = config.get_config()
        txtint = TextInterface(conf)
        txtint.login()
        txtint.start()
    except (socket.error, IOError, exception.SecurityException) as e:
        print str(e)
    sys.exit(0)
