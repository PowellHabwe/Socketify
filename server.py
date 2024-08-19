import time
import socket
import threading
import configparser
import logging
import ssl
from typing import Optional, Tuple, Set
from file_searcher import FileSearcher

import threading

shutdown_event = threading.Event()

# Constants
FORMAT = "utf-8"
DISCONNECT_MESSAGE = "DISCONNECT"
MAX_MESSAGE_LENGTH = 1024  # maximum message length

# Global variables for managing clients
clients: Set[socket.socket] = set()
clients_lock = threading.Lock()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

# Certificates
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'


def get_config_path(config_file: str) -> Optional[str]:
    """
    Retrieve the file path from the configuration file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        Optional[str]: The file path if found, otherwise None.
    """
    try:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config['DEFAULT'].get('linuxpath')
    except configparser.Error as e:
        logging.error(f"Error reading config file: {e}")
        return None


def get_reread_on_query(config_file: str) -> bool:
    """
    Retrieve the REREAD_ON_QUERY setting from the configuration file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        bool: The REREAD_ON_QUERY setting.
    """
    try:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config['DEFAULT'].getboolean('REREAD_ON_QUERY', False)
    except configparser.Error as e:
        logging.error(f"Error reading REREAD_ON_QUERY from config: {e}")
        return False


def use_ssl(config_file: str) -> bool:
    """
    Retrieve the USE_SSL setting from the configuration file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        bool: The USE_SSL setting.
    """
    try:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config['DEFAULT'].getboolean('USE_SSL', False)
    except configparser.Error as e:
        logging.error(f"Error reading USE_SSL from config: {e}")
        return False


def create_ssl_context() -> Optional[ssl.SSLContext]:
    """Create and configure SSL context for the server."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable older TLS versions
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        return context
    except ssl.SSLError as e:
        logging.error(f"SSL context creation failed: {e}")
    except FileNotFoundError as e:
        logging.error(f"Certificate or key file not found: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during SSL context creation: {e}")
    return None


def handle_client(
    conn: socket.socket,
    addr: Tuple[str, int],
    file_searcher: FileSearcher
) -> None:
    """
    Handle client connection, receive a search string, and respond based
    on file content, including the time taken to perform the search.

    Args:
        conn (socket.socket): The client connection socket.
        addr (Tuple[str, int]): The address of the client.
        file_searcher (FileSearcher): The FileSearcher instance to use
        for searching.
    """
    logging.debug(f"[NEW CONNECTION] {addr} Connected")
    connected = True
    try:
        while connected:
            try:
                msg = conn.recv(MAX_MESSAGE_LENGTH).decode(FORMAT).rstrip('\x00').strip()
                # If the message is empty or consists of only spaces
                if not msg:
                    response = "INVALID INPUT: Please enter a valid string.\n"
                    conn.send(response.encode(FORMAT))
                    continue

                if msg == DISCONNECT_MESSAGE:
                    connected = False
                    response = "Disconnected successfully.\n"
                    conn.send(response.encode(FORMAT))
                    break

                # Input validation
                if len(msg) > MAX_MESSAGE_LENGTH:
                    response = "INVALID REQUEST: Message too long.\n"
                    logging.debug(f"[{addr}] Invalid message length: {len(msg)}")
                    conn.send(response.encode(FORMAT))
                    continue

                logging.debug(f"[{addr}] Received message: {msg}")
                start_time = time.time()

                try:
                    if file_searcher.reread_on_query:
                        file_searcher.load_file()

                    response = file_searcher.search(msg)
                except Exception as e:
                    response = f"ERROR: {str(e)}"
                    logging.error(f"Error during file search: {e}")

                execution_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                response += f"\nSearch time: {execution_time:.2f} milliseconds"

                logging.debug(f"Execution time for search query '{msg}': {execution_time:.2f} milliseconds")
                logging.debug(f"[LOG] Response to {addr}: {response.strip()}")
                conn.send(response.encode(FORMAT))

            except ConnectionResetError:
                logging.info(f"[DISCONNECTED] {addr} Disconnected")
                break
            except socket.error as e:
                logging.error(f"Socket error with {addr}: {e}")
                break
            except Exception as e:
                logging.error(f"Unexpected error with {addr}: {e}")
                break
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()
        logging.debug(f"[DISCONNECTED] {addr} Disconnected")


def start(
    server: socket.socket,
    file_searcher: FileSearcher,
    use_ssl: bool,
    test_mode: bool = False
) -> None:
    logging.debug('[SERVER STARTED]!')
    if use_ssl:
        ssl_context = create_ssl_context()
        if not ssl_context:
            logging.error("Failed to create SSL context. Exiting.")
            return
        
        try:
            server = ssl_context.wrap_socket(server, server_side=True)
            logging.info("SSL setup successful.")
        except ssl.SSLError as e:
            logging.error(f"SSL socket wrap failed: {e}")
            return
        except Exception as e:
            logging.error(f"Unexpected error during SSL socket wrap: {e}")
            return
    else:
        logging.info('SSL is disabled.')

    server.listen()
    server.settimeout(1.0)  # Set a timeout for the accept() call
    
    try:
        while not shutdown_event.is_set():
            try:
                conn, addr = server.accept()
                with clients_lock:
                    clients.add(conn)
                logging.debug(f"[NEW CONNECTION] {addr} Connected")
                if use_ssl:
                    logging.info(f"SSL Connection from {addr}")
                    ssl_conn = conn
                    if isinstance(ssl_conn, ssl.SSLSocket):
                        logging.info(f"SSL version: {ssl_conn.version()}")
                        logging.info(f"Cipher: {ssl_conn.cipher()}")
                thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, file_searcher)
                )
                thread.start()
                logging.debug(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
                
                if test_mode:
                    break  # Exit after one iteration in test mode
                
            except socket.timeout:
                if test_mode:
                    break  # Exit on timeout in test mode
                continue  # This allows checking the shutdown_event periodically
            except ssl.SSLError as e:
                logging.error(f"SSL error during connection: {e}")
                if test_mode:
                    break
            except socket.error as e:
                logging.error(f"Socket error during connection: {e}")
                if test_mode:
                    break
            except Exception as e:
                logging.error(f"Unexpected error during connection: {e}")
                if test_mode:
                    break
    except KeyboardInterrupt:
        logging.debug("Server shutting down.")
    finally:
        shutdown_event.set()
        with clients_lock:
            for conn in clients:
                try:
                    conn.close()
                except Exception as e:
                    logging.error(f"Error closing client connection: {e}")
        server.close()

def main() -> None:
    """
    Main function to load configuration and start the server.
    """
    config_file = 'config.ini'
    file_path = get_config_path(config_file)
    reread_on_query = get_reread_on_query(config_file)
    ssl_enabled = use_ssl(config_file)

    if not file_path:
        logging.error("No file path specified in the configuration.")
        return

    try:
        file_searcher = FileSearcher(file_path, reread_on_query)
    except Exception as e:
        logging.error(f"Error initializing FileSearcher: {e}")
        return

    try:
        server_ip = socket.gethostbyname(socket.gethostname())
        server_port = 44445
        server_address = (server_ip, server_port)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(server_address)
    except socket.error as e:
        logging.error(f"Error setting up server socket: {e}")
        return
    except Exception as e:
        logging.error(f"Unexpected error during server setup: {e}")
        return

    logging.debug(f"Server listening on {server_ip}:{server_port}")

    start(server_socket, file_searcher, ssl_enabled)


if __name__ == "__main__":
    main()
