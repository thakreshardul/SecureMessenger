import os
import sqlite3
import sys

import constants
from crypto import *
from ds import ServerUser


# class db
#    init
#    getuser(usrnm) -> user
#    getusers() ->lou
#    insertuser(usrnm,pswdhash)

#    table
#    usrnm -- pk | passwdhash | salt

class UserDatabase:
    def __init__(self):
        self.conn = sqlite3.connect(constants.DB_LOCATION)
        self.c = self.conn.cursor()

    def __enter__(self):
        self.__init__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    def create_db(self):
        self.c.execute(
            'CREATE TABLE IF NOT EXISTS userInfo (username TEXT PRIMARY KEY, passhash BLOB, salt BLOB)')
        self.conn.commit()

    def get_user(self, usrname):
        self.c.execute(
            "SELECT * FROM userInfo WHERE  username='{0}'".format(usrname))
        return self.__convert_row(self.c.fetchone())

    def __convert_row(self, row):
        print row
        usr = ServerUser(row[0], bytes(row[1]), bytes(row[2]), None, None, None)
        return usr

    def get_users(self):
        self.c.execute("SELECT * FROM userInfo")
        return [self.__convert_row(x) for x in self.c.fetchall()]

    def insert_user(self, uname, phash, salt):
        user_query_format = "INSERT INTO userInfo VALUES (?,?,?)"
        self.c.execute(user_query_format, [uname, sqlite3.Binary(phash),
                                           sqlite3.Binary(salt)])
        self.conn.commit()


if __name__ == "__main__":
    args = sys.argv
    username = args[1]
    password = args[2]
    with UserDatabase() as userdb:
        userdb.create_db()
        salt = os.urandom(constants.NONCE_LENGTH)
        pass_hash = generate_server_hash_password(username, password, salt)
        userdb.insert_user(username, pass_hash, salt)
