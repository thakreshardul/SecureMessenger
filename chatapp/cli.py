"""This is the text interface at the client side"""
import getpass
import socket
import sys

import chatapp.client as client
import chatapp.config as config
import chatapp.exception as exception


class TextInterface:
    def __init__(self, conf):
        # configure the server address from config file
        self.client = client.ChatClient((conf.serverip, conf.serverport))
        # start the client on the address specified in the config file
        client.udp.start(self.client, conf.clientip, conf.clientport, 1)

    def login(self):
        # Loop until the user is logged in to the application
        while True:
            usernm = raw_input("Enter your user name:\n")
            passwd = getpass.getpass("Enter your password:\n")
            print "Logging In"
            if self.client.login(usernm, passwd):
                print ("Successfully Logged in")
                break
            else:
                print ("Unsuccessful login")

    def show_menu(self):
        # After successful login, three commands are displayed to the user
        print "Enter a command:\n1. list\n2. send <USER> <MESSAGE>\n3. quit\n"
        while True:
            command = raw_input()
            userinput = command.split(" ", 2)  # send user has at most 3 args
            if userinput[0] == "list":
                l = self.client.list()  # obtain the entire list of logged in clients

                if l is None:  # List Failed
                    print "List Failed"
                    continue

                if len(l) > 0:  # More that 1 user logged in
                    print " ".join(l)
                else:  # Only one user i.e. self logged in to the system
                    print "Only you are logged in"
            elif userinput[0] == "send":
                if len(userinput) == 3:  # there has to be three parameters for send
                    self.client.send(userinput[1], userinput[2])
                else:
                    print "Give user and message also"
            elif userinput[0] == "quit":
                self.client.logout()  # Send the logout message to server and get back OK
                print ("Quitting the application")
                break
            else:  # Any unsupported command
                print ("Enter correct command")


def run():
    try:
        if len(sys.argv) == 2:
            config.load_client(sys.argv[1])  # load the config file
            conf = config.get_client_config()  # read the client configuration
            txtint = TextInterface(conf)
            txtint.login()
            txtint.show_menu()
        else:
            raise exception.ConfigFileMissingException()  # No config file provided
    except (socket.error, IOError, exception.SecurityException) as e:
        print str(e)
    sys.exit(0)


if __name__ == "__main__":
    run()
