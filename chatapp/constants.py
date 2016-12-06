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
SEND_HEARTBEAT_TIMEOUT = 30
HEARTBEAT_TIMEOUT = 60
HEARTBEAT_PAUSE = 5

TIMESTAMP_GAP = 5
SOCKET_TIMEOUT = 5

BUFFER_SIZE = 1000
PUZZLE_TIMEOUT = 60

DB_LOCATION = "user.db"
CLIENT_CONFIG_FILE = "client_config.json"
SERVER_CONFIG_FILE = "server_config.json"

message_type = {
    "Reject": 0,
    "Login": 1,
    "Puzzle": 2,
    "Solution": 3,
    "Server_DH": 4,
    "Password": 5,
    "Accept": 6,
    "List": 7,
    "Logout": 8,
    "Sender_Client_DH": 9,
    "Dest_Client_DH": 10,
    "Message": 11,
    "Broadcast": 12,
    "Heartbeat": 13
}

message_dictionary = {
    0: "Reject",
    1: "Login",
    2: "Puzzle",
    3: "Solution",
    4: "Server_DH",
    5: "Password",
    6: "Accept",
    7: "List",
    8: "Logout",
    9: "Sender_Client_DH",
    10: "Dest_Client_DH",
    11: "Message",
    12: "Broadcast",
    13: "Heartbeat"
}


