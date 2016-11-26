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
            usernm = raw_input("Enter your user name:\n")
            passwd = getpass.getpass("Enter your password:\n")
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
                self.client.list()
            elif userinput[0] == "send":
                self.client.send(userinput[1], userinput[2])
            elif userinput[0] == "quit":
                self.client.logout()
                print ("Quitting the application\n")
                break
            else:
                print ("Enter correct command\n")


if __name__ == "__main__":
    print ("Connecting to server...")
    txtint = TextInterface()
    txtint.login()
    txtint.start()
