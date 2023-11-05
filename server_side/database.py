import logging
import sqlite3

from constants import DB_FILE, FILE_STORAGE_DIR, FieldSize


class DatabaseManager:
    """Database manager class that handles all database operations"""
    def __init__(self):
        """Initialize the database connection and create the tables if they don't exist"""
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.initiate_db()

    def initiate_db(self) -> None:
        """Create the tables if they don't exist"""
        try:
            # Create tables if they don't exist
            # No need to send parameters to the SQL query, because the field sizes are fixed
            self.cursor.execute(
                "CREATE TABLE IF NOT EXISTS clients "
                "(client_id BLOB(%d) PRIMARY KEY, "
                "client_name VARCHAR(%d), public_key BLOB(%d), last_seen DATETIME, aes_key BLOB(%d))" %
                (FieldSize.CLIENT_ID, FieldSize.CLIENT_NAME, FieldSize.PUBLIC_KEY, FieldSize.AES_KEY)
            )

            self.cursor.execute(
                "CREATE TABLE IF NOT EXISTS files "
                "(client_id BLOB(%d), file_name VARCHAR(%d), path_name VARCHAR(%d), verified BOOLEAN, "
                "PRIMARY KEY (client_id, file_name))"
                % (FieldSize.CLIENT_ID, FieldSize.FILE_NAME,
                   len(FILE_STORAGE_DIR) + FieldSize.CLIENT_ID + FieldSize.FILE_NAME + 1)
                # file name is part of the path name, so they can't have the same size.
                # the file path is FILE_STORAGE_DIR/client_id/file_name (+2 for the slashes)
            )

        except sqlite3.Error as e:
            logging.error(f"Error while creating the tables: {e}")
            raise e

    def execute_query(self, query: str, parameters: tuple = None) -> None:
        """Execute a query and commit the changes if needed"""
        try:
            self.cursor.execute(query, parameters)
            if query.startswith("INSERT") or query.startswith("UPDATE") or query.startswith("DELETE"):
                self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error while executing the query: {query}")
            raise e

    def fetch_query(self, query: str, parameters: tuple = tuple()) -> list:
        """Execute a query and return the results"""
        try:
            self.cursor.execute(query, parameters)
            column_names = [col[0] for col in self.cursor.description]
            return [dict(zip(column_names, row)) for row in self.cursor.fetchall() or []]
        except sqlite3.Error as e:
            logging.error(f"Error while executing the query: {query}")
            raise e

    def save_client_data(self, client_id: bytes, data: dict = None) -> None:
        """Save the client data to the database"""
        if not data:
            query = "UPDATE clients SET last_seen=CURRENT_TIMESTAMP WHERE client_id=?"
            parameters = (client_id,)
        else:
            update_fields = ", ".join(f"{key}=?" for key in data.keys())
            query = f"UPDATE clients SET {update_fields} WHERE client_id=?"
            parameters = tuple(data.values()) + (client_id,)

        self.execute_query(query, parameters)

    def close(self) -> None:
        """Close the database connection"""
        self.cursor.close()
        self.conn.close()

    def __del__(self):
        """Close the database connection when the object is deleted"""
        self.close()
