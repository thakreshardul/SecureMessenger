import sqlite3
import constants
import user

#class db
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
        self.c.execute('CREATE TABLE IF NOT EXISTS userInfo (username text PRIMARY KEY, passhash text, salt text)')
        self.conn.commit()

    def get_user(self, usrname):
        self.c.execute("SELECT * FROM userInfo WHERE  username='{0}'" .format(usrname))
        return self.__convert_row(self.c.fetchone()[0])

    def __convert_row(self,row):
        usr = user.ServerUser()
        usr.username = row[0]
        usr.password = row[1]
        usr.salt = row[2]
        return user

    def get_users(self):
        self.c.execute("SELECT * FROM userInfo")
        return [self.__convert_row(x) for x in self.c.fetchall()]

    def insert_user(self, uname, phash, salt):
        user_query_format = "INSERT INTO userInfo VALUES ('{u}', '{p}', '{s}')".format(
            u=uname, p=phash, s=salt)
        self.c.execute(user_query_format)
        self.conn.commit()

if __name__ == "__main__":
    with UserDatabase() as userdb:
        userdb.create_db()
        print userdb.get_user("shardul2")
    pass
