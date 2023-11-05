import re

from constants import FieldSize


def is_valid_filename(filename: str) -> bool:
    """Check if the filename is valid (length, characters, path traversal)"""
    file_size_check = 0 < len(filename) <= FieldSize.FILE_NAME
    safe_chars_check = all(unsafe_char not in filename for unsafe_char in ('..', '/', '\\'))
    valid_chars_check = bool(re.match(r'^[\w.-]+$', filename))
    return file_size_check and safe_chars_check and valid_chars_check


def pad(byte_string: bytes, block_size: int) -> bytes:
    """Pad the byte string with null bytes to the block size"""
    return byte_string.ljust(block_size, b'\0')


def unpad(byte_string: bytes) -> str:
    """Remove the null bytes from the byte string"""
    return byte_string.decode().strip("\0")
