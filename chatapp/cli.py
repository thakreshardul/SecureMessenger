import config
import getpass
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
            command = raw_input("""Enter a command:
             1. list
             2. send <USER> <MESSAGE>
             3. quit\n""")
            if command[0] == "list":
                self.client.list()
            elif command[0] == "send":
                self.client.send(command[1], command[2])
            elif command[0] == "quit":
                break
            else:
                print ("Enter correct command")


if __name__ == "__main__":
    print ("Connecting to server...")
    txtint = TextInterface()
    txtint.login()
    txtint.start()
