import logging
import threading

from server import Server


def main() -> None:
    """Main function that starts the server"""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    server = Server()
    try:
        while True:
            client_socket, client_address = server.server_socket.accept()
            logging.info(f"Connection from {client_address}")
            threading.Thread(target=server.handle_client, args=(client_socket,)).start()
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
