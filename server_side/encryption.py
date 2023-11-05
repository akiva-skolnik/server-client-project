from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

from constants import FieldSize


class EncryptionWrapper:
    """Wrapper class for encryption and decryption methods"""
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate a random AES key"""
        return get_random_bytes(FieldSize.AES_KEY)

    @staticmethod
    def encrypt_aes_key(aes_key: bytes, public_key: bytes) -> bytes:
        """Encrypt the AES key using the public key"""
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
        return cipher_rsa.encrypt(aes_key)

    @staticmethod
    def decrypt_file_content(aes_key: bytes, file_content: bytes) -> bytes:
        """Decrypt the file content using the AES key"""
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=b"\x00" * FieldSize.AES_KEY)
        decrypted_data = unpad(cipher.decrypt(file_content), AES.block_size)
        return decrypted_data
