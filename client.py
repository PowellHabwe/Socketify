import socket
import ssl
import time
import signal
from typing import Optional, Tuple, Union
import configparser

FORMAT = "utf-8"
DISCONNECT_MESSAGE = "DISCONNECT"
CA_CERT_FILE = 'cert.pem'


def get_client_ip() -> str:
    """Retrieve the client's local IP address."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.gaierror as e:
        print(f"Error getting client IP: {e}")
        return "127.0.0.1"  # Fallback to localhost


def get_server_info() -> Tuple[str, int]:
    """Prompt user for server port and determine the server IP address."""
    while True:
        try:
            port = int(input('Enter server port: '))
            if 1 <= port <= 65535:
                break
            print("Port must be between 1 and 65535.")
        except ValueError:
            print("Please enter a valid integer for the port.")

    server_ip = get_client_ip()
    return server_ip, port


def use_ssl() -> bool:
    """Retrieve the USE_SSL setting from the configuration file."""
    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        return config['DEFAULT'].getboolean('USE_SSL', False)
    except configparser.Error as e:
        print(f"Error reading USE_SSL from config: {e}")
        return False


def create_ssl_context() -> Optional[ssl.SSLContext]:
    """Create and configure SSL context for the client."""
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(CA_CERT_FILE)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable older TLS versions
        context.check_hostname = False #For testing purposes
        return context
    except ssl.SSLError as e:
        print(f"SSL context creation failed: {e}")
    except FileNotFoundError as e:
        print(f"CA certificate file not found: {e}")
    except Exception as e:
        print(f"Unexpected error during SSL context creation: {e}")
    return None


def connect(server: str, port: int, use_ssl: bool) -> Optional[Union[socket.socket, ssl.SSLSocket]]:
    """Establish connection to the server."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if use_ssl:
            ssl_context = create_ssl_context()
            if not ssl_context:
                print("Failed to create SSL context. Exiting.")
                return None
            
            try:
                client = ssl_context.wrap_socket(client, server_hostname=server)
            except ssl.SSLError as e:
                print(f"SSL setup failed: {e}")
                return None
            except Exception as e:
                print(f"Unexpected error during SSL setup: {e}")
                return None

        client.connect((server, port))
        
        if use_ssl and isinstance(client, ssl.SSLSocket):
            print("SSL is enabled and connected securely.")
            print(f"Using cipher: {client.cipher()}")
            print(f"SSL version: {client.version()}")
            cert = client.getpeercert()
            print(f"SSL server certificate set successfully")
        else:
            print(f"Connected to server at {server}:{port} (unencrypted)")
        
        return client
    except ConnectionRefusedError:
        print(f"Connection refused. Make sure the server is running at {server}:{port}")
    except ssl.CertificateError as e:
        print(f"SSL certificate verification failed: {e}")
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except socket.gaierror:
        print(f"Address-related error connecting to server at {server}:{port}")
    except socket.error as e:
        print(f"Socket error connecting to server at {server}:{port}: {e}")
    except Exception as e:
        print(f"Unexpected error during connection: {e}")
    
    return None


def send(client: Union[socket.socket, ssl.SSLSocket], msg: str) -> None:
    """Send a message to the server."""
    try:
        message = msg.encode(FORMAT)
        client.send(message)
    except socket.error as e:
        print(f"Error sending message: {e}")


def signal_handler(signum, frame):
    """Handle interrupt signal (Ctrl+C)."""
    print("\nCtrl+C pressed. Disconnecting...")
    raise KeyboardInterrupt


def start() -> None:
    """Main function to handle client operations."""
    signal.signal(signal.SIGINT, signal_handler)
 
    server_ip, port = get_server_info()
    ssl_enabled = use_ssl()

    client_ip = get_client_ip()
    print(f"Connecting to server {server_ip}:{port} from client IP: {client_ip}.")
    print(f"SSL Enabled: {ssl_enabled}")

    connection = connect(server_ip, port, ssl_enabled)
    if connection is None:
        print("Failed to establish connection. Exiting.")
        return

    try:
        # Check file path validity
        file_path = 'config.ini'
        config = configparser.ConfigParser()
        config.read(file_path)
        if not config['DEFAULT'].get('linuxpath'):
            print(f"File path : '{file_path}' is incorrect or missing.")
        else:
            print(f"File path in config file '{file_path}' is correct.")

        while True:
            try:
                msg = input("Enter the string to search for (or 'q' to quit): ")

                if msg.lower() == 'q':
                    break

                send(connection, msg)

                # Receive and print the server's response
                response = connection.recv(1024).decode(FORMAT)
                print(f"Server response: {response}")
            except KeyboardInterrupt:
                print("\nCtrl+C pressed. Disconnecting...")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                break

        send(connection, DISCONNECT_MESSAGE)
        time.sleep(1)
        print('Disconnected')
    
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    finally:
        connection.close()


if __name__ == "__main__":
    start()
