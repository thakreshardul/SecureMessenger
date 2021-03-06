import os
import sqlite3
import sys

import chatapp.constants as constants
from chatapp.crypto import *
from chatapp.user import ServerUser


class UserDatabase:
    def __init__(self):
        # get the db location from constants and connect to it
        self.conn = sqlite3.connect(constants.DB_LOCATION)
        self.c = self.conn.cursor()

    def __enter__(self):
        self.__init__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    def create_db(self):
        # create a table -- this should be a part of initial server setup
        # The db stores username, password hash and the salt
        self.c.execute(
            'CREATE TABLE IF NOT EXISTS userInfo (username TEXT PRIMARY KEY, passhash BLOB, salt BLOB)')
        self.conn.commit()

    def get_user(self, usrname):
        # Fetches the user information from the database
        cmd = "SELECT * FROM userInfo WHERE  username=?"
        self.c.execute(cmd, (usrname,))
        row = self.c.fetchone()
        if row is None:
            return None
        return self.__convert_row(row)

    def __convert_row(self, row):
        # Convert the db row to ServerUser object
        usr = ServerUser()
        usr.username = str(row[0])
        usr.pass_hash = bytes(row[1])
        usr.salt = bytes(row[2])
        return usr

    def get_users(self):
        # This is used by the list call
        self.c.execute("SELECT * FROM userInfo")
        return [self.__convert_row(x) for x in self.c.fetchall()]

    def insert_user(self, uname, phash, salt):
        # This method is used for registering the user to application
        # It should be used with the code in the add_user method only
        user_query_format = "INSERT INTO userInfo VALUES (?,?,?)"
        self.c.execute(user_query_format, [uname, sqlite3.Binary(phash),
                                           sqlite3.Binary(salt)])
        self.conn.commit()


def add_user():
    args = sys.argv
    if len(args) != 3:
        print "Enter Username and Password"
        exit(0)

    username = args[1]
    password = args[2]
    try:
        with UserDatabase() as userdb:
            userdb.create_db()
            salt = os.urandom(constants.NONCE_LENGTH)  # generate a random salt
            # generate password hash from salt
            pass_hash = generate_server_hash_password(username, password, salt)
            # insert the username, password hash and salt in the database
            userdb.insert_user(username, pass_hash, salt)
    except sqlite3.IntegrityError:
        print "Adding same user twice"

if __name__ == "__main__":
    add_user()