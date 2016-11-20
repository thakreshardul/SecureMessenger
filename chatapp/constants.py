SERVER_PRIVATE_DER_FILE = "priv.der"
SERVER_PUBLIC_DER_FILE = "pub.der"

SIGNATURE_LENGTH = 256
EKEY_LENGTH = 256
NONCE_LENGTH = 16
AES_KEY_LENGTH = 32
AES_IV_LENGTH = 16
AES_TAG_LENGTH = 16
RSA_KEY_LENGTH = 2048
TIMESTAMP_LENGTH = 4
LEN_LENGTH = 2

DB_LOCATION = "user.db"

message_type = {
    "Reject": 0,
    "Login": 1,
    "Puzzle": 2,
    "Solution": 3,
    "Server_DH": 4,
    "Password": 5
}

message_dictionary = {
    0: "Reject",
    1: "Login",
    2: "Puzzle",
    3: "Solution",
    4: "Server_DH",
    5: "Password"
}



no_key_no_sign = {"Login", "Puzzle"}
asym_key_with_sign = {}
sign = {"Server_DH"}
sym_key = {"Password"}
sym_key_with_sign = {}
asym_key_ans = {"Solution"}
