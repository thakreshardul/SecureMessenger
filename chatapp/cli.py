import getpass
import sys

import config

if len(sys.argv) == 2:
    config.load(sys.argv[1])
else:
    config.load()
conf = config.get_config()
import client


class TextInterface:
    def __init__(self):
        self.client = client.ChatClient((conf.serverip, conf.serverport))
        client.udp.start(self.client)

    def login(self):
        while True:
            usernm = raw_input("Enter your user name->\n")
            passwd = getpass.getpass("Enter your password:\n")
            if self.client.login(usernm, passwd):
                print ("Successfully Logged in")
                break
            else:
                print ("Unsuccessful login")

    def start(self):
        while True:
            command = raw_input(
                "Enter a command:\n1. list\n2. send <USER> <MESSAGE>\n3. quit\n")
            parts = command.split(" ")
            if parts[0] == "list":
                self.client.list()
            elif parts[0] == "send":
                self.client.send(parts[1], parts[2])
            elif parts[0] == "quit":
                break
            else:
                print ("Enter correct command")


if __name__ == "__main__":
    print ("Connecting to server...")
    txtint = TextInterface()
    txtint.login()
    txtint.start()
