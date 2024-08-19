import socket
import threading
import time
import logging
import os
import mmap
from typing import Optional, Set, Tuple

# Constants
FORMAT = "utf-8"
DISCONNECT_MESSAGE = "!DISCONNECT"
MAX_MESSAGE_LENGTH = 1024
PORT = 44446

'use this path or testing FILE_PATH = "test_files/file_10000.txt"'
FILE_PATH = "/path/to/folder/with/file/containing/strings"
REREAD_ON_QUERY = False

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)


class FileSearcher:
    """
    Handles file searching operations, including loading file content and searching for strings.
    """

    def __init__(self, file_path: str, reread_on_query: bool) -> None:
        """
        Initialize the FileSearcher with file path and REREAD_ON_QUERY setting.

        Args:
            file_path (str): The path to the file to be searched.
            reread_on_query (bool): Whether to reread the file on each query.
        """
        self.file_path = file_path
        self.reread_on_query = reread_on_query
        self.file_content: Set[str] = set()  # Use a set for quick lookups
        self.mmapped_file: Optional[mmap.mmap] = None  # Type annotation
        self.load_file()  # Pre-load file content

    def load_file(self) -> None:
        """
        Load the file content into a memory-mapped file or a set.
        """
        logging.debug(f"Attempting to load file from path: {self.file_path}")
        if os.path.exists(self.file_path):
            try:
                if self.reread_on_query:
                    with open(self.file_path, 'r') as file:
                        self.mmapped_file = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
                    logging.debug(f"The file is memory-mapped at: {self.file_path}")
                else:
                    with open(self.file_path, 'r') as file:
                        self.file_content = set(line.strip() for line in file)
                    logging.debug(f"The file content is loaded into a set from: {self.file_path}")
            except Exception as e:
                logging.error(f"Error loading file: {e}")
                self.file_content = set()
                self.mmapped_file = None
        else:
            logging.error(f"The file does not exist at: {self.file_path}")
            self.file_content = set()
            self.mmapped_file = None

    def search(self, search_string: str) -> Tuple[str, float]:
        """
        Search for the string in the memory-mapped file or set.

        Args:
            search_string (str): The string to search for.

        Returns:
            Tuple[str, float]: A tuple containing the result string and the execution time.
        """
        start_time = time.time()
        if self.reread_on_query:
            if self.mmapped_file and self.mmapped_file.find(search_string.encode()) != -1:
                execution_time = time.time() - start_time
                return "STRING EXISTS\n", execution_time
        else:
            if search_string in self.file_content:
                execution_time = time.time() - start_time
                return "STRING EXISTS\n", execution_time
        execution_time = time.time() - start_time
        return "STRING NOT FOUND\n", execution_time


def handle_client(conn: socket.socket, addr: str, file_searcher: FileSearcher) -> None:
    """
    Handle client connection, receive a search string, and respond based on file content.

    Args:
        conn (socket.socket): The client socket.
        addr (str): The address of the client.
        file_searcher (FileSearcher): The file searcher instance.
    """
    logging.debug(f"[NEW CONNECTION] {addr} Connected")
    connected = True
    query_count = 0
    try:
        while connected:
            msg = conn.recv(MAX_MESSAGE_LENGTH).decode(FORMAT).strip()  # Strip \x00 characters
            if not msg:
                break

            if msg == DISCONNECT_MESSAGE:
                connected = False

            # Log the received message and client address
            logging.debug(f"[{addr}] Received message: {msg}")

            # Search the string in the file and send the response along with execution time
            response, exec_time = file_searcher.search(msg)
            logging.debug(f"Query execution time: {exec_time:.6f} seconds")
            query_count += 1

            conn.send(f"{response}Execution time: {exec_time:.6f} seconds\n".encode(FORMAT))
    finally:
        conn.close()
        logging.debug(f"[DISCONNECTED] {addr} Disconnected after handling {query_count} queries")


def start_server(file_path: str, reread_on_query: bool) -> None:
    """
    Main function to set up the server.

    Args:
        file_path (str): The path to the file to be searched.
        reread_on_query (bool): Whether to reread the file on each query.
    """
    logging.debug('[SERVER STARTED]!')
    logging.debug(f"REREAD_ON_QUERY is set to {reread_on_query}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', PORT))  # Bind to all interfaces on port 44446
    server_socket.listen()
    file_searcher = FileSearcher(file_path, reread_on_query)
    try:
        while True:
            conn, addr = server_socket.accept()
            logging.debug(f"[NEW CONNECTION] {addr} Connected")
            thread = threading.Thread(target=handle_client, args=(conn, addr, file_searcher))
            thread.start()
            logging.debug(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    except KeyboardInterrupt:
        logging.debug("Server shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server(FILE_PATH, REREAD_ON_QUERY)