import logging
import os
import socket
import uuid
from collections import defaultdict

import crc32
import utils
from constants import (ENDIANNESS, FILE_STORAGE_DIR, MAX_REQUESTS_PER_SESSION,
                       MAX_RETRY, VERSION, FieldSize, RequestCode, ResponseCode)
from encryption import EncryptionWrapper


class ClientHandler:
    """Handles a single client connection"""
    def __init__(self, client_socket: socket.socket, server_instance) -> None:
        self.client_socket = client_socket
        self.server = server_instance
        self.tries = defaultdict(int)

    def start(self) -> None:
        """Handle requests from the client until the client closes the connection
        or the maximum number of requests is reached"""
        for request_number in range(MAX_REQUESTS_PER_SESSION):
            try:
                # Read the header of the incoming message
                try:
                    header = self.safe_recv(
                        FieldSize.CLIENT_ID + FieldSize.VERSION + FieldSize.CODE + FieldSize.PAYLOAD)
                    if not header:  # client closed the connection (sometimes raises an exception, sometimes not)
                        return
                except (ConnectionResetError, ConnectionAbortedError, TimeoutError):
                    return  # client closed the connection or timed out
                self.handle_request(header)
            except Exception as e:
                logging.error(f"Error handling request: {e}")
                self.respond(ResponseCode.GENERAL_ERROR)

        logging.warning("Closing connection with client")
        self.client_socket.close()

    @staticmethod
    def parse_header(header: bytes) -> tuple:
        """Parse the header fields from the header bytes.
        Header format: client_id (16 bytes) + version (1 byte) + code (2 bytes) + payload size (4 bytes)"""
        client_id = header[:FieldSize.CLIENT_ID]
        version = int.from_bytes(header[FieldSize.CLIENT_ID:FieldSize.CLIENT_ID + FieldSize.VERSION], ENDIANNESS)
        code = int.from_bytes(
            header[FieldSize.CLIENT_ID + FieldSize.VERSION:FieldSize.CLIENT_ID + FieldSize.VERSION + FieldSize.CODE],
            ENDIANNESS)
        payload_size = int.from_bytes(header[FieldSize.CLIENT_ID + FieldSize.VERSION + FieldSize.CODE:], ENDIANNESS)
        return client_id, version, code, payload_size

    def read_payload(self, code: int, payload_size: int) -> bytes:
        """Read the payload from the client, based on the request code"""
        if code == RequestCode.RECEIVE_FILE:
            payload = b""  # payload may be larger than payload_size, so we read it separately
        elif payload_size > FieldSize.CLIENT_NAME + FieldSize.PUBLIC_KEY:  # largest payload
            raise Exception(f"Payload size too large: {payload_size}")
        else:
            payload = self.safe_recv(payload_size)
            if len(payload) != payload_size:
                raise Exception(f"Payload size mismatch: expected {payload_size}, got {len(payload)}")
        return payload

    def handle_request(self, header: bytes) -> None:
        """Handle a single request from the client"""
        # Parse the header fields
        client_id, version, code, payload_size = self.parse_header(header)
        self.save_client_data(client_id)  # update last seen

        # Read the payload
        payload = self.read_payload(code, payload_size)

        logging.debug(f"Received request code {code} from client {client_id.hex()}. "
                      f"Payload size: {payload_size}, header size: {len(header)}")
        if version != VERSION:
            raise Exception(f"Version mismatch, expected {VERSION}, got {version}")

        # Dispatch table for handling different request codes
        handlers = {
            RequestCode.REGISTER: self.handle_register_request,
            RequestCode.LOGIN: self.handle_login_request,
            RequestCode.PUBLIC_KEY: self.handle_public_key_request,
            RequestCode.RECEIVE_FILE: self.handle_receive_file_request,
            RequestCode.CRC_VALID: self.handle_crc_valid,
            RequestCode.CRC_RETRY: self.handle_crc_retry,
            RequestCode.CRC_FAILURE: self.handle_crc_failure
        }

        # Get the handler based on the request code, or use a default handler for unknown codes
        handler = handlers.get(code, self.handle_unknown_request)

        # Call the handler with client_id and payload as arguments
        handler(client_id, payload)

    def handle_unknown_request(self, client_id: bytes, payload: bytes) -> None:
        """Handle an unknown request code"""
        logging.error(f"Error: unknown request code")
        self.respond(ResponseCode.GENERAL_ERROR)

    def respond(self, code: int, payload: bytes = b"") -> None:
        """Send a response to the client"""
        version = VERSION.to_bytes(FieldSize.VERSION, ENDIANNESS)
        bytes_code = code.to_bytes(FieldSize.CODE, ENDIANNESS)
        length = len(payload).to_bytes(FieldSize.PAYLOAD, ENDIANNESS)
        header = version + bytes_code + length
        logging.debug(f"Sending response code {code} with payload size {len(payload)} and header size {len(header)}. ")
        self.client_socket.send(header + payload)
        logging.debug("Response sent")

    def handle_register_request(self, client_id: bytes, payload: bytes) -> None:
        """Handle a register request from the client (code 1025)"""
        client_name = utils.unpad(payload)
        logging.info("Registering client " + client_name)
        if self.is_client_registered(client_name):
            logging.warning(f"Client {client_name} already registered\n")
            self.respond(ResponseCode.REGISTRATION_FAILURE)
        else:
            client_id = self.generate_unique_uuid()
            self.save_client_to_db(client_id, client_name)
            payload = utils.pad(client_id, FieldSize.CLIENT_ID)

            # Send a response to the client with the new client ID
            self.respond(ResponseCode.REGISTRATION_SUCCESS, payload)
            logging.info(f"Registered client {client_id.hex()} with name {client_name}\n")

    def handle_public_key_request(self, client_id: bytes, payload: bytes) -> None:
        """Handle a public key request from the client (code 1026)"""
        logging.info("Received public key request from client " + client_id.hex())
        client_name = utils.unpad(payload[:FieldSize.CLIENT_NAME])
        self.verify_client_name(client_id, client_name)
        public_key = payload[FieldSize.CLIENT_NAME:]

        # Generate a new AES key and encrypt it with the client's public key
        aes_key = EncryptionWrapper.generate_aes_key()
        encrypted_aes_key = EncryptionWrapper.encrypt_aes_key(aes_key, public_key)

        self.save_client_data(client_id, {"public_key": public_key, "aes_key": aes_key})

        payload = utils.pad(client_id, FieldSize.CLIENT_ID) + encrypted_aes_key

        # Send a response to the client with the AES key encrypted with the client's public key
        self.respond(ResponseCode.AES_KEY_SENT, payload)
        logging.info(f"Sent AES key to client {client_id.hex()}\n")

    def handle_login_request(self, client_id: bytes, payload: bytes) -> None:
        """Handle a login request from the client (code 1027)"""
        logging.info("Received login request from client " + client_id.hex())
        client_name = utils.unpad(payload)
        padded_client_id = utils.pad(client_id, FieldSize.CLIENT_ID)
        aes_key = self.server.clients.get(client_id, {}).get("aes_key")
        public_key = self.server.clients.get(client_id, {}).get("public_key")
        if not aes_key or not public_key:
            self.respond(ResponseCode.LOGIN_FAILURE, padded_client_id)
            logging.warning(f"Client {client_id.hex()} not registered\n")
        else:
            self.verify_client_name(client_id, client_name)

            # Generate a new AES key and encrypt it with the client's public key
            aes_key = EncryptionWrapper.generate_aes_key()
            encrypted_aes_key = EncryptionWrapper.encrypt_aes_key(aes_key, public_key)

            self.save_client_data(client_id, {"aes_key": aes_key})

            aes_payload = padded_client_id + encrypted_aes_key
            self.respond(ResponseCode.LOGIN_SUCCESS, aes_payload)
            logging.info(f"Successfully logged in and sent AES key to client {client_id.hex()}\n")

    def handle_receive_file_request(self, client_id: bytes, payload: bytes) -> None:
        """Handle a receive-file request from the client (code 1028)"""
        # Decrypt the payload using the client's AES key
        logging.info("Received save file request from client " + client_id.hex())
        aes_key = self.server.clients.get(client_id, {}).get("aes_key")
        if not aes_key:
            self.respond(ResponseCode.LOGIN_FAILURE)
            return

        # Extract the file size and name from the payload
        payload = self.safe_recv(FieldSize.FILE_SIZE + FieldSize.FILE_NAME)
        file_size = int.from_bytes(payload[:FieldSize.FILE_SIZE], ENDIANNESS)
        file_name = utils.unpad(payload[FieldSize.FILE_SIZE:FieldSize.FILE_SIZE + FieldSize.FILE_NAME])
        if not utils.is_valid_filename(file_name):
            raise Exception(f"Invalid file name: {file_name}")
        self.tries[(client_id, file_name)] = 0  # reset

        # Decrypt the file content using the client's AES key
        encrypted_data = self.safe_recv(file_size)
        decrypted_data = EncryptionWrapper.decrypt_file_content(aes_key, encrypted_data)
        logging.debug(f"Received file {file_name} from client {client_id.hex()}. Size: {file_size} bytes")
        logging.debug(f"Size of encrypted data: {len(encrypted_data)} bytes, "
                      f"size of decrypted data: {len(decrypted_data)} bytes")

        # Save the file to disk (backup/user_id/file_name)
        client_path = os.path.join(FILE_STORAGE_DIR, client_id.hex())
        if not os.path.exists(client_path):
            os.makedirs(client_path)
        file_path = os.path.join(client_path, file_name)

        try:
            with open(file_path, "wb") as file:
                file.write(decrypted_data)
        except Exception as e:
            logging.error(f"Error saving file: {e}")
            self.respond(ResponseCode.GENERAL_ERROR)
            return

        self.server.save_data_to_files(client_id, file_name, {"path_name": file_path, "verified": False})
        crc = crc32.memcrc(decrypted_data)
        logging.info(f"Saved file {file_name} from client {client_id.hex()} with CRC {crc} (not verified yet)\n")

        # payload = client_id + file size (after encryption) + file name + crc
        file_payload = utils.pad(client_id, FieldSize.CLIENT_ID) + \
            payload[:FieldSize.FILE_SIZE + FieldSize.FILE_NAME] + \
            crc.to_bytes(FieldSize.CRC, ENDIANNESS)
        self.respond(ResponseCode.FILE_RECEIVED, file_payload)

    def handle_crc_valid(self, client_id: bytes, payload: bytes) -> None:
        """Handle a CRC valid request from the client (code 1029)"""
        logging.info("Received CRC valid from client " + client_id.hex())
        file_name = utils.unpad(payload[:FieldSize.FILE_NAME])
        if (client_id, file_name) not in self.server.files:
            raise Exception(f"File {file_name} from client {client_id.hex()} not found")
        elif not utils.is_valid_filename(file_name):
            # should not happen, because otherwise the file would not be saved in self.server.files, but just in case
            raise Exception(f"Invalid file name: {file_name}")
        else:
            if self.server.files[(client_id, file_name)].get("verified"):
                logging.info(f"File {file_name} from client {client_id.hex()} already verified\n")
            self.server.save_data_to_files(client_id, file_name, {"verified": True})
            padded_client_id = utils.pad(client_id, FieldSize.CLIENT_ID)
            self.respond(ResponseCode.MESSAGE_RECEIVED, padded_client_id)
            logging.info(f"File {file_name} from client {client_id.hex()} verified\n")

    def handle_crc_retry(self, client_id: bytes, payload: bytes) -> None:
        """Handle a CRC retry request from the client (code 1030)"""
        logging.info("Received CRC retry from client " + client_id.hex())
        file_name = utils.unpad(payload[:FieldSize.FILE_NAME])
        padded_client_id = utils.pad(client_id, FieldSize.CLIENT_ID)
        if self.tries[(client_id, file_name)] < MAX_RETRY:
            self.respond(ResponseCode.MESSAGE_RECEIVED, padded_client_id)
            self.tries[(client_id, file_name)] += 1
            logging.info(f"Retry #{self.tries[(client_id, file_name)]} "
                         f"for file {file_name} from client {client_id.hex()} approved\n")
        else:
            logging.warning(f"Max tries exceeded for file {file_name} from client {client_id.hex()}\n")
            self.respond(ResponseCode.GENERAL_ERROR)
            self.tries[(client_id, file_name)] = 0

    def handle_crc_failure(self, client_id: bytes, payload: bytes) -> None:
        """Handle a CRC failure request from the client (code 1031)"""
        # delete the file
        logging.info("Received CRC failure from client " + client_id.hex())
        file_name = utils.unpad(payload[:FieldSize.FILE_NAME])
        if (client_id, file_name) not in self.server.files:
            raise Exception(f"File {file_name} from client {client_id.hex()} not found")
        elif not utils.is_valid_filename(file_name):  # should not happen
            raise Exception(f"Invalid file name: {file_name}")
        file_path = self.server.files[(client_id, file_name)].get("path_name")
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        else:
            logging.warning(f"File {file_name} from client {client_id.hex()} not found on disk")
        with self.server.lock:
            self.server.db_manager.execute_query("DELETE FROM files WHERE client_id=? AND file_name=?",
                                                 (client_id, file_name))
        del self.server.files[(client_id, file_name)]

        self.respond(ResponseCode.MESSAGE_RECEIVED, payload)
        logging.info(f"Deleted file {file_name} from client {client_id.hex()}\n")

    # helper functions:

    def safe_recv(self, size: int) -> bytes:
        """Receive the specified number of bytes from the client in chunks"""
        max_size = 2 ** (FieldSize.PAYLOAD * 8)  # max size of payload/file content
        if size > max_size:
            logging.error(f"Payload size too large: {size}, max size: {max_size}")
            raise Exception

        data = b""
        remaining_bytes = size
        chunk_size = 2 ** 12
        while remaining_bytes > 0:
            expected_size = min(chunk_size, remaining_bytes)
            try:
                chunk = self.client_socket.recv(expected_size)
            # could handle the exceptions differently, but it's not important
            except (ConnectionResetError, ConnectionAbortedError) as e:
                logging.info("Client closed the connection")
                raise e
            except TimeoutError as e:
                logging.warning("Connection timed out")
                raise e

            if not chunk:
                break
            if len(chunk) != expected_size:  # should not happen
                logging.error(f"Chunk size mismatch: expected {expected_size}, got {len(chunk)}")
                raise Exception

            data += chunk
            remaining_bytes -= len(chunk)
        return data

    def is_client_registered(self, client_name: str) -> bool:
        """Check if the client is registered"""
        clients_names = (client["client_name"] for client in self.server.clients.values())
        return client_name in clients_names

    def save_client_data(self, client_id: bytes, data: dict = None) -> None:
        """Save the client data in the database"""
        with self.server.lock:
            self.server.db_manager.save_client_data(client_id, data)
            if data:  # update the in-memory data
                self.server.clients[client_id].update(data)

    def save_client_to_db(self, client_id: bytes, client_name: str) -> None:
        """Save the client information in the database"""
        query = "INSERT INTO clients (client_id, client_name) VALUES (?, ?)"
        parameters = (client_id, client_name)
        with self.server.lock:
            self.server.db_manager.execute_query(query, parameters)
            self.server.clients[client_id] = {"client_name": client_name}

    def verify_client_name(self, client_id: bytes, client_name: str) -> None:
        """Verify that the client name matches the one in the database"""
        expected_client_name = self.server.clients.get(client_id, {}).get("client_name")
        if client_name != expected_client_name:
            raise Exception(f"Client name mismatch: {client_name} != {expected_client_name}")

    def generate_unique_uuid(self) -> bytes:
        """Generate a unique client ID"""
        client_id = uuid.uuid4().bytes
        while client_id in self.server.clients:  # ensure the key is unique
            client_id = uuid.uuid4().bytes
        return client_id
