import struct
import constants


@staticmethod
def tuple_to_str(tuple):
    string = ""
    for param in tuple:
        l = struct.pack("!H", len(param))
        string += l
        string += param

    return string

@staticmethod
def str_to_tuple(string):
    pl = []
    while True:
        if string == "":
            break
        header = struct.unpack("!H", string[:constants.LEN_LENGTH])[0]
        param = string[constants.LEN_LENGTH:constants.LEN_LENGTH + header]
        pl.append(param)
        string = string[constants.LEN_LENGTH + header:]
    return tuple(pl)
