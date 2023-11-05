"""Defines constants"""

VERSION = 3
DB_FILE = "defensive.db"
PORT_INFO_FILE = "port.info"
DEFAULT_PORT = 1357
FILE_STORAGE_DIR = "backup"
MAX_REQUESTS_PER_SESSION = 100  # prevent infinite loop. adjust as needed
MAX_RETRY = 3  # max number of times to retry sending a file
ENDIANNESS = "little"
MAX_CONNECTIONS = 5


# Enum for field sizes in bytes
class FieldSize:
    CLIENT_ID = 16
    CLIENT_NAME = 255
    FILE_NAME = 255
    VERSION = 1
    CODE = 2
    PAYLOAD = 4
    FILE_SIZE = 4  # 4 bytes unsigned int, max file size is 2^(8*4) = 4GB
    AES_KEY = 16
    PUBLIC_KEY = 160
    CRC = 4


# Enum for request codes (client -> server)
class RequestCode:
    REGISTER = 1025
    PUBLIC_KEY = 1026
    LOGIN = 1027
    RECEIVE_FILE = 1028
    CRC_VALID = 1029
    CRC_RETRY = 1030
    CRC_FAILURE = 1031


# Enum for response codes (server -> client)
class ResponseCode:
    REGISTRATION_SUCCESS = 2100
    REGISTRATION_FAILURE = 2101
    AES_KEY_SENT = 2102
    FILE_RECEIVED = 2103
    MESSAGE_RECEIVED = 2104  # may send after 1029 or 1031
    LOGIN_SUCCESS = 2105
    LOGIN_FAILURE = 2106
    GENERAL_ERROR = 2107
