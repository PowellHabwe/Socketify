import socket
import time
import threading

FORMAT = "utf-8"
DISCONNECT_MESSAGE = "!DISCONNECT"

# Hardcoded server details
SERVER_IP = '127.0.0.1'
SERVER_PORT = 44446

# Parameters for the stress test
CONCURRENT_QUERIES = 50  # Adjust as needed for the test
SEARCH_STRING = "Row 9999"  # The string to search for
TEST_DURATION = 10  # Duration of the test in seconds


def get_client_ip() -> str:
    """
    Retrieve the client's local IP address.

    Returns:
        str: The local IP address of the client.
    """
    return socket.gethostbyname(socket.gethostname())


def connect(server: str, port: int) -> socket.socket:
    """
    Establish connection to the server.

    Args:
        server (str): The server's IP address.
        port (int): The server's port number.

    Returns:
        socket.socket: The connected client socket.

    Raises:
        socket.error: If the connection to the server fails.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server, port))
        return client
    except socket.error as e:
        print(f"Could not connect to server at {server}:{port}. Error: {e}")
        raise


def send_and_receive(client: socket.socket, msg: str) -> str:
    """
    Send a message to the server and receive the response.

    Args:
        client (socket.socket): The client socket.
        msg (str): The message to send.

    Returns:
        str: The response from the server.
    """
    message = msg.encode(FORMAT)
    client.send(message)
    response = client.recv(1024).decode(FORMAT)
    return response


def stress_test() -> None:
    """
    Perform a stress test by sending multiple concurrent queries to the server.
    """
    clients = []
    total_queries = 0
    start_time = time.time()

    # Establish connections
    for _ in range(CONCURRENT_QUERIES):
        client = connect(SERVER_IP, SERVER_PORT)
        clients.append(client)

    def send_queries(client: socket.socket) -> None:
        """
        Send queries to the server until the test duration is reached.

        Args:
            client (socket.socket): The client socket.
        """
        nonlocal total_queries
        while time.time() - start_time < TEST_DURATION:
            response = send_and_receive(client, SEARCH_STRING)
            print(response)
            total_queries += 1

    threads = [threading.Thread(target=send_queries, args=(client,)) for client in clients]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for client in clients:
        send_and_receive(client, DISCONNECT_MESSAGE)
        client.close()

    duration = time.time() - start_time
    queries_per_second = total_queries / duration
    print(f"Total queries: {total_queries}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Queries per second: {queries_per_second:.2f}")


if __name__ == "__main__":
    stress_test()
