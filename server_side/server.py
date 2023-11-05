import logging
import socket
import threading
from collections import defaultdict

from client_handler import ClientHandler
from constants import DEFAULT_PORT, MAX_CONNECTIONS, PORT_INFO_FILE
from database import DatabaseManager


class Server:
    """Server class that handles incoming connections and client requests"""
    def __init__(self) -> None:
        """Initialize the server and the DB, and load the data from it"""
        self.db_manager = DatabaseManager()
        self.clients = defaultdict(dict)
        self.files = defaultdict(dict)
        self.server_socket = self.start()
        self.lock = threading.Lock()
        self.load_from_db()

    def load_from_db(self) -> None:
        """Load all clients and files from the database"""
        # Load all clients from the database
        clients = self.db_manager.fetch_query("SELECT * FROM clients")
        for client in clients:
            client_id = client["client_id"]
            del client["client_id"]
            self.clients[client_id] = client

        # Load all files from the database
        files = self.db_manager.fetch_query("SELECT * FROM files")
        for file in files:
            key = (file["client_id"], file["file_name"])
            del file["client_id"], file["file_name"]
            self.files[key] = file

    def start(self) -> socket.socket:
        """Start the server and listen for incoming connections"""
        port = self.get_port()
        logging.info(f"Listening on port {port}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(MAX_CONNECTIONS)
        logging.info("Waiting for connections...\n")
        return server_socket

    def handle_client(self, client_socket: socket.socket) -> None:
        """Handle a single client connection"""
        client_handler = ClientHandler(client_socket, self)
        client_handler.start()

    def save_data_to_files(self, client_id: bytes, file_name: str, data: dict) -> None:
        """Save the data to the files dictionary and the database"""
        update = ",".join(f"{k}=?" for k in data.keys())
        key = (client_id, file_name)
        if client_id not in self.files:
            self.files[key] = {}
        with self.lock:
            parameters = tuple(data.values()) + tuple([client_id, file_name])
            self.db_manager.execute_query(f"UPDATE files SET {update} WHERE client_id=? AND file_name=?", parameters)
            self.files[key] = data

    @staticmethod
    def get_port() -> int:
        """Get the port from the PORT_INFO_FILE or use the default port"""
        logging.info(f"Reading port from {PORT_INFO_FILE}")
        try:
            with open(PORT_INFO_FILE, "r") as port_file:
                return int(port_file.read().strip())
        except Exception as e:
            logging.error(f"Error reading port from {PORT_INFO_FILE}: {e}\n"
                          f"Using default port {DEFAULT_PORT}")
            return DEFAULT_PORT

    def close(self) -> None:
        """Close the server and the database"""
        self.db_manager.close()
        self.server_socket.close()
        logging.info("Server closed")

    def __del__(self):
        """Close the server and the database when the object is deleted"""
        self.close()
