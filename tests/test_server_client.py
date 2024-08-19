import pytest
import logging
import os
import mmap
import socket
import ssl
import configparser
import threading
import time
from unittest.mock import patch, MagicMock
from pytest_mock.plugin import PytestMockWarning
import warnings
warnings.filterwarnings("ignore", category=PytestMockWarning)

from client import (
    connect, get_client_ip, get_server_info, send, start as client_start
)
from server import (
    get_config_path, get_reread_on_query, use_ssl, handle_client, main,
    start as server_start, main as server_main, create_ssl_context,CERT_FILE, KEY_FILE,
    FORMAT, DISCONNECT_MESSAGE, MAX_MESSAGE_LENGTH
)
from file_searcher import FileSearcher


@pytest.fixture
def mock_socket():
    return MagicMock(spec=socket.socket)

@pytest.fixture
def mock_file_searcher():
    return MagicMock(spec=FileSearcher)

# Constants used in the `handle_client` function
FORMAT = 'utf-8'
MAX_MESSAGE_LENGTH = 1024
DISCONNECT_MESSAGE = 'DISCONNECT'

# Mock configuration data
mock_config_data = """
[DEFAULT]
linuxpath = /path/to/file
REREAD_ON_QUERY = True
USE_SSL = False
"""


@pytest.fixture
def config_file(tmp_path):
    """Fixture to create a temporary configuration file."""
    config_file_path = tmp_path / "config.ini"
    config_file_path.write_text(mock_config_data)
    return str(config_file_path)


@pytest.fixture
def mock_config_file_no_path(tmp_path):
    """Fixture to create a temporary configuration file without 'linuxpath'."""
    config_file_path = tmp_path / "config.ini"
    config_file_path.write_text(mock_config_data)
    return str(config_file_path)


def test_get_reread_on_query(config_file):
    """Test for get_reread_on_query function."""
    assert get_reread_on_query(config_file) is True


def test_handle_client_success(mocker):
    """Test handle_client function with a successful response."""
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 44442)

    mock_file_searcher = MagicMock()
    mock_file_searcher.reread_on_query = True
    mock_file_searcher.search.return_value = "STRING EXISTS"

    mock_clients = mocker.patch('server.clients', new_callable=set)
    mock_clients.add(mock_socket)

    mock_socket.recv.side_effect = [
        b'query_string',
        DISCONNECT_MESSAGE.encode(FORMAT)
    ]

    mocker.patch('server.FORMAT', FORMAT)

    mocker.patch('server.clients_lock', MagicMock())

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    assert mock_socket.recv.called
    actual_send_calls = mock_socket.send.call_args_list
    assert actual_send_calls
    assert any(b"STRING EXISTS" in call[0][0] for call in actual_send_calls)
    assert mock_file_searcher.search.called
    assert mock_file_searcher.search.call_args[0][0] == 'query_string'
    assert mock_socket.close.called


def test_handle_client_no_data(mocker):
    """Test handle_client function with no data received."""
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 44442)

    mock_file_searcher = MagicMock()

    mock_clients = mocker.patch('server.clients', new_callable=set)
    mock_clients.add(mock_socket)

    mock_socket.recv.side_effect = [b'', DISCONNECT_MESSAGE.encode(FORMAT)]

    mocker.patch('server.FORMAT', FORMAT)

    mocker.patch('server.clients_lock', MagicMock())

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    assert mock_socket.recv.called
    assert mock_socket.send.called
    expected_response = b"INVALID INPUT: Please enter a valid string.\n"
    mock_socket.send.assert_any_call(expected_response)
    assert mock_file_searcher.search.called is False
    assert mock_socket.close.called


def test_handle_client_error(mocker):
    """Test handle_client function with an error during file search."""
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 44442)

    mock_file_searcher = MagicMock()
    mock_file_searcher.reread_on_query = True
    mock_file_searcher.search.side_effect = Exception("Test error")

    mock_clients = mocker.patch('server.clients', new_callable=set)
    mock_clients.add(mock_socket)

    mock_socket.recv.side_effect = [
        b'query_string',
        DISCONNECT_MESSAGE.encode(FORMAT)
    ]

    mocker.patch('server.FORMAT', FORMAT)

    mocker.patch('server.clients_lock', MagicMock())

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    assert mock_socket.recv.called
    assert any(b"ERROR: Test error" in call[0][0]
               for call in mock_socket.send.call_args_list)
    assert mock_file_searcher.search.called
    assert mock_socket.close.called


def test_get_server_info(mocker):
    """Test get_server_info function."""
    mocker.patch('client.get_client_ip', return_value='127.0.1.1')
    mocker.patch('builtins.input', side_effect=['44445'])
    assert get_server_info() == ('127.0.1.1', 44445)


def test_connect_success(mocker):
    """Test connect function for a successful connection."""
    mock_socket = MagicMock()
    mocker.patch('socket.socket', return_value=mock_socket)
    assert connect('127.0.0.1', 44442, use_ssl=False) == mock_socket


def test_connect_failure(mocker):
    """Test connect function when connection fails."""
    mock_socket = MagicMock()
    mock_socket.connect.side_effect = socket.error
    mocker.patch('socket.socket', return_value=mock_socket)
    assert connect('127.0.0.1', 44442, use_ssl=False) is None


def test_get_client_ip():
    """Test get_client_ip function."""
    assert get_client_ip() == socket.gethostbyname(socket.gethostname())


def test_use_ssl(config_file):
    """Test for use_ssl function."""
    assert use_ssl(config_file) is False


def test_handle_client_long_message(mocker):
    """Test handle_client function with a message longer than MAX_MESSAGE_LENGTH."""
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 44442)
    mock_file_searcher = MagicMock()

    long_message = 'a' * (MAX_MESSAGE_LENGTH + 1)
    mock_socket.recv.side_effect = [
        long_message.encode(FORMAT),
        DISCONNECT_MESSAGE.encode(FORMAT)
    ]

    mocker.patch('server.FORMAT', FORMAT)
    mocker.patch('server.MAX_MESSAGE_LENGTH', MAX_MESSAGE_LENGTH)

    mock_clients = mocker.patch('server.clients', new_callable=set)
    mock_clients.add(mock_socket)

    mocker.patch('server.clients_lock', MagicMock())

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    expected_response = b"INVALID REQUEST: Message too long.\n"
    mock_socket.send.assert_any_call(expected_response)


def test_start_server(mocker):
    """Test start function of the server."""
    mock_socket = MagicMock()
    mock_file_searcher = MagicMock()

    mocker.patch('socket.socket', return_value=mock_socket)
    mocker.patch('threading.Thread')

    mock_conn = MagicMock()
    mock_socket.accept.side_effect = [(mock_conn, 'mock_addr'), KeyboardInterrupt]

    mock_clients = mocker.patch('server.clients', new_callable=set)

    server_start(mock_socket, mock_file_searcher, use_ssl=False)

    assert mock_socket.listen.called
    assert mock_socket.accept.called
    assert mock_socket.close.called
    assert mock_conn.close.called


def test_server_main(mocker):
    """Test main function of the server."""
    mocker.patch('server.get_config_path', return_value='/mock/path')
    mocker.patch('server.get_reread_on_query', return_value=True)
    mocker.patch('server.use_ssl', return_value=False)
    mocker.patch('socket.socket')
    mock_file_searcher = mocker.patch('server.FileSearcher')
    mock_start = mocker.patch('server.start')

    server_main()

    assert mock_file_searcher.called
    assert mock_start.called


def test_client_send(mocker):
    """Test send function of the client."""
    mock_socket = MagicMock()
    test_message = "Test message"

    send(mock_socket, test_message)

    mock_socket.send.assert_called_with(test_message.encode(FORMAT))


def test_client_start(mocker):
    """Test start function of the client."""
    mocker.patch('client.get_server_info', return_value=('127.0.0.1', 44442))
    mocker.patch('client.use_ssl', return_value=False)
    mocker.patch('client.get_client_ip', return_value='127.0.0.1')
    mock_connect = mocker.patch('client.connect', return_value=MagicMock())
    mocker.patch('builtins.input', side_effect=['test_query', 'q'])

    client_start()

    assert mock_connect.called


def test_ssl_connection(mocker):
    """Test SSL connection in the client."""
    mock_socket = MagicMock()
    mock_ssl_context = MagicMock()
    mock_ssl_context.wrap_socket.return_value = mock_socket

    mocker.patch('socket.socket', return_value=mock_socket)
    mocker.patch('ssl.create_default_context', return_value=mock_ssl_context)

    result = connect('127.0.0.1', 44442, use_ssl=True)

    assert result == mock_socket
    assert mock_ssl_context.wrap_socket.called


def test_file_searcher_initialization_error(mocker):
    """Test server main function when FileSearcher initialization fails."""
    mocker.patch('server.get_config_path', return_value='/mock/path')
    mocker.patch('server.get_reread_on_query', return_value=True)
    mocker.patch('server.use_ssl', return_value=False)
    mocker.patch('socket.socket')
    mock_file_searcher = mocker.patch('server.FileSearcher', side_effect=Exception("Mocked error"))
    mock_start = mocker.patch('server.start')

    server_main()

    assert mock_file_searcher.called
    assert not mock_start.called


def test_server_socket_setup_error(mocker):
    """Test server main function when socket setup fails."""
    mocker.patch('server.get_config_path', return_value='/mock/path')
    mocker.patch('server.get_reread_on_query', return_value=True)
    mocker.patch('server.use_ssl', return_value=False)
    mocker.patch('socket.socket', side_effect=socket.error("Mocked socket error"))
    mock_file_searcher = mocker.patch('server.FileSearcher')
    mock_start = mocker.patch('server.start')

    server_main()

    assert mock_file_searcher.called
    assert not mock_start.called


def test_get_config_path(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("[DEFAULT]\nlinuxpath = /test/path\n")
    assert get_config_path(str(config_file)) == "/test/path"

def test_get_reread_on_query(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("[DEFAULT]\nREREAD_ON_QUERY = True\n")
    assert get_reread_on_query(str(config_file)) is True

def test_use_ssl(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("[DEFAULT]\nUSE_SSL = False\n")
    assert use_ssl(str(config_file)) is False

@patch('server.clients', new_callable=set)
@patch('server.clients_lock')
@patch('server.time.time', return_value=0)
def test_handle_client(mock_time, mock_lock, mock_clients, mock_socket, mock_file_searcher):
    mock_socket.recv.side_effect = [b'test', DISCONNECT_MESSAGE.encode(FORMAT)]
    mock_file_searcher.search.return_value = "STRING EXISTS\n"
    mock_file_searcher.reread_on_query = False
    mock_clients.add(mock_socket)

    handle_client(mock_socket, ('127.0.0.1', 12345), mock_file_searcher)

    assert mock_socket.send.call_count == 2
    calls = mock_socket.send.call_args_list
    assert b"STRING EXISTS\n" in calls[0][0][0]
    assert mock_socket.close.called
    assert mock_socket not in mock_clients  # Check if the socket was removed from the set


@patch('server.socket.socket')
@patch('server.threading.Thread')
def test_server_start(mock_thread, mock_socket_class, mock_file_searcher):
    mock_socket = mock_socket_class.return_value
    mock_socket.accept.side_effect = [
        (MagicMock(), ('127.0.0.1', 12345)),
        KeyboardInterrupt
    ]
    
    server_start(mock_socket, mock_file_searcher, use_ssl=False)
    
    assert mock_socket.listen.called
    assert mock_socket.close.called

@patch('server.socket.socket')
@patch('server.FileSearcher')
@patch('server.start')
def test_server_main(mock_start, mock_file_searcher, mock_socket):
    with patch('server.get_config_path', return_value='/test/path'):
        with patch('server.get_reread_on_query', return_value=True):
            with patch('server.use_ssl', return_value=False):
                server_main()
                
                assert mock_file_searcher.called
                assert mock_start.called


def test_file_searcher_init_errors():
    with pytest.raises(FileNotFoundError):
        with patch('os.path.exists', return_value=False):
            FileSearcher('/non/existent/path', False)
    
    with pytest.raises(PermissionError):
        with patch('os.path.exists', return_value=True):
            with patch('os.access', return_value=False):
                FileSearcher('/no/permission/path', False)

def test_file_searcher_load_file_errors():
    with pytest.raises(IOError):
        with patch('os.path.exists', return_value=True):
            with patch('os.access', return_value=True):
                with patch('builtins.open', side_effect=IOError):
                    FileSearcher('/test/path', False)

def test_file_searcher_search_errors():
    with patch('os.path.exists', return_value=True):
        with patch('os.access', return_value=True):
            with patch('builtins.open', MagicMock()):
                file_searcher = FileSearcher('/test/path', False)
                
                with pytest.raises(ValueError):
                    file_searcher.search("")


def test_handle_client_error_handling(mock_socket, mock_file_searcher):
    mock_socket.recv.side_effect = [b'test', socket.error("Mocked socket error")]
    mock_file_searcher.search.side_effect = Exception("Mocked search error")
    mock_file_searcher.reread_on_query = False

    with patch('server.clients', new_callable=set) as mock_clients, \
         patch('server.clients_lock', new_callable=threading.Lock):
        mock_clients.add(mock_socket)
        handle_client(mock_socket, ('127.0.0.1', 12345), mock_file_searcher)

    assert mock_socket.send.called
    assert b"ERROR: Mocked search error" in mock_socket.send.call_args[0][0]
    assert mock_socket.close.called

def test_file_searcher_init_invalid_file(tmp_path):
    invalid_path = tmp_path / "nonexistent_file.txt"
    with pytest.raises(FileNotFoundError):
        FileSearcher(str(invalid_path), False)

def test_file_searcher_search_empty_string(tmp_path):
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("test\ndata\n")
    file_searcher = FileSearcher(str(file_path), False)
    with pytest.raises(ValueError):
        file_searcher.search("")


@patch('client.socket.socket')
@patch('client.ssl.create_default_context')
def test_connect_with_ssl(mock_ssl_context, mock_socket_class):
    mock_socket = mock_socket_class.return_value
    mock_ssl_socket = MagicMock()
    mock_ssl_context.return_value.wrap_socket.return_value = mock_ssl_socket

    result = connect('127.0.0.1', 44442, use_ssl=True)

    assert result == mock_ssl_socket
    assert mock_ssl_context.called
    assert mock_ssl_context.return_value.wrap_socket.called





def test_connect_error_handling():
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.connect.side_effect = socket.error("Mocked connection error")
        result = connect('localhost', 12345, use_ssl=False)
        assert result is None

def test_file_searcher_permission_error(tmp_path):
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("test data")
    file_path.chmod(0o000)  # Remove all permissions
    with pytest.raises(PermissionError):
        FileSearcher(str(file_path), False)



# Test for a valid configuration file
def test_get_config_path_valid(tmp_path):
    """Test get_config_path with a valid configuration file."""
    config_data = """
    [DEFAULT]
    linuxpath = /valid/path
    """
    config_file = tmp_path / "config.ini"
    config_file.write_text(config_data)

    result = get_config_path(config_file)
    assert result == "/valid/path"


# Test for an error in configparser
@patch('configparser.ConfigParser.read', side_effect=configparser.Error("Mocked error"))
def test_get_config_path_configparser_error(mock_read, tmp_path):
    """Test get_config_path with configparser.Error."""
    config_file = tmp_path / "config.ini"
    config_file.write_text("[DEFAULT]\nlinuxpath = /mock/path")

    result = get_config_path(config_file)
    assert result is None
    # Check that the error was logged
    with patch('server.logging.error') as mock_logging:
        get_config_path(config_file)
        mock_logging.assert_called_with(f"Error reading config file: Mocked error")


@patch('server.ssl.SSLContext')
@patch('server.ssl.SSLContext.load_cert_chain')
def test_create_ssl_context_file_not_found(mock_load_cert_chain, mock_ssl_context):
    """Test SSL context creation with missing certificate or key file."""
    mock_ssl_context.return_value = MagicMock(ssl.SSLContext)
    mock_load_cert_chain.side_effect = FileNotFoundError

    context = create_ssl_context()
    assert context is None


def test_start_server_ssl_disabled():
    """Test server start with SSL disabled."""
    mock_server = MagicMock(socket.socket)
    file_searcher = MagicMock()
    use_ssl = False

    with patch('server.create_ssl_context', return_value=None):
        server_start(mock_server, file_searcher, use_ssl)

    # Check that create_ssl_context was not called
    with patch('server.create_ssl_context') as mock_create_ssl_context:
        server_start(mock_server, file_searcher, use_ssl)
        mock_create_ssl_context.assert_not_called()


def test_create_ssl_context(mocker):
    # Mock SSL context creation to avoid real SSL certificate loading
    mock_ssl_context = mocker.patch('ssl.SSLContext', autospec=True)
    mock_ssl_context.return_value = mocker.MagicMock()
    context = create_ssl_context()
    assert context is not None

def test_start_with_ssl(mocker):
    # Mock SSL context and server socket
    mock_ssl_context = mocker.patch('ssl.SSLContext', autospec=True)
    mock_ssl_context.return_value.wrap_socket.return_value = mocker.MagicMock()
    server_socket = mocker.MagicMock()
    file_searcher = mocker.MagicMock()
    # Ensure the server start method does not attempt real SSL setup
    server_start(server_socket, file_searcher, use_ssl=True)
    mock_ssl_context.assert_called_once()


@patch('ssl.SSLContext')
def test_create_ssl_context_failure(mock_ssl_context):
    mock_ssl_context.side_effect = ssl.SSLError("Mocked SSL Error")
    context = create_ssl_context()
    assert context is None



def test_get_reread_on_query():
    # Test successful retrieval of REREAD_ON_QUERY
    with patch('configparser.ConfigParser') as mock_parser:
        mock_parser.return_value.read.return_value = None
        mock_parser.return_value['DEFAULT'].getboolean.return_value = True
        
        result = get_reread_on_query('mock_config.ini')
        assert result is True

    # Test configparser.Error
    with patch('configparser.ConfigParser') as mock_parser:
        mock_parser.return_value.read.side_effect = configparser.Error("Mocked config error")
        
        result = get_reread_on_query('mock_config.ini')
        assert result is False

@patch('server.logging.error')
def test_get_reread_on_query_logging(mock_logging_error):
    with patch('configparser.ConfigParser') as mock_parser:
        mock_parser.return_value.read.side_effect = configparser.Error("Mocked config error")
        
        get_reread_on_query('mock_config.ini')
        mock_logging_error.assert_called_once_with("Error reading REREAD_ON_QUERY from config: Mocked config error")



@patch('ssl.SSLContext')
def test_create_ssl_context_file_not_found(mock_ssl_context):
    mock_ssl_context.return_value.load_cert_chain.side_effect = FileNotFoundError("Mocked file not found")
    
    result = create_ssl_context()
    assert result is None

@patch('server.logging.error')
def test_create_ssl_context_file_not_found_logging(mock_logging_error):
    with patch('ssl.SSLContext') as mock_ssl_context:
        mock_ssl_context.return_value.load_cert_chain.side_effect = FileNotFoundError("Mocked file not found")
        
        create_ssl_context()
        mock_logging_error.assert_called_once_with("Certificate or key file not found: Mocked file not found")

@patch('server.clients', new_callable=set)
@patch('server.clients_lock', new_callable=threading.Lock)
def test_handle_client_connection_reset(mock_lock, mock_clients):
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 12345)
    mock_file_searcher = MagicMock()
    
    mock_socket.recv.side_effect = ConnectionResetError("Mocked connection reset")
    mock_clients.add(mock_socket)

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    assert mock_socket not in mock_clients
    mock_socket.close.assert_called_once()

@patch('server.clients', new_callable=set)
@patch('server.clients_lock', new_callable=threading.Lock)
def test_handle_client_socket_error(mock_lock, mock_clients):
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 12345)
    mock_file_searcher = MagicMock()
    
    mock_socket.recv.side_effect = socket.error("Mocked socket error")
    mock_clients.add(mock_socket)

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    assert mock_socket not in mock_clients
    mock_socket.close.assert_called_once()

@patch('server.clients', new_callable=set)
@patch('server.clients_lock', new_callable=threading.Lock)
def test_handle_client_unexpected_error(mock_lock, mock_clients):
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 12345)
    mock_file_searcher = MagicMock()
    
    mock_socket.recv.side_effect = Exception("Mocked unexpected error")
    mock_clients.add(mock_socket)

    handle_client(mock_socket, mock_addr, mock_file_searcher)

    assert mock_socket not in mock_clients
    mock_socket.close.assert_called_once()

@patch('server.logging.info')
@patch('server.logging.error')
def test_handle_client_error_logging(mock_logging_error, mock_logging_info):
    mock_socket = MagicMock()
    mock_addr = ('127.0.0.1', 12345)
    mock_file_searcher = MagicMock()

    # Test ConnectionResetError logging
    mock_socket.recv.side_effect = ConnectionResetError("Mocked connection reset")
    handle_client(mock_socket, mock_addr, mock_file_searcher)
    mock_logging_info.assert_called_with("[DISCONNECTED] ('127.0.0.1', 12345) Disconnected")

    # Reset mocks
    mock_logging_info.reset_mock()
    mock_logging_error.reset_mock()

    # Test socket.error logging
    mock_socket.recv.side_effect = socket.error("Mocked socket error")
    handle_client(mock_socket, mock_addr, mock_file_searcher)
    mock_logging_error.assert_called_with("Socket error with ('127.0.0.1', 12345): Mocked socket error")

    # Reset mocks
    mock_logging_info.reset_mock()
    mock_logging_error.reset_mock()

    # Test unexpected error logging
    mock_socket.recv.side_effect = Exception("Mocked unexpected error")
    handle_client(mock_socket, mock_addr, mock_file_searcher)
    mock_logging_error.assert_called_with("Unexpected error with ('127.0.0.1', 12345): Mocked unexpected error")


def test_get_config_path_error():
    with patch('configparser.ConfigParser.read', side_effect=configparser.Error("Mocked error")):
        result = get_config_path('mock_config.ini')
        assert result is None

def test_use_ssl_error():
    with patch('configparser.ConfigParser.read', side_effect=configparser.Error("Mocked error")):
        result = use_ssl('mock_config.ini')
        assert result is False


def test_create_ssl_context_unexpected_error():
    with patch('ssl.SSLContext', side_effect=Exception("Mocked unexpected error")):
        result = create_ssl_context()
        assert result is None


@patch('server.socket.socket')
@patch('server.create_ssl_context')
@patch('logging.error')
def test_start_ssl_context_creation_failure(mock_logging, mock_create_ssl_context, mock_socket):
    mock_create_ssl_context.return_value = None
    mock_file_searcher = MagicMock()
    
    server_start(mock_socket, mock_file_searcher, use_ssl=True)
    
    mock_logging.assert_called_with("Failed to create SSL context. Exiting.")


@patch('server.get_config_path')
@patch('server.get_reread_on_query')
@patch('server.use_ssl')
@patch('server.FileSearcher')
@patch('server.socket.socket')
@patch('logging.error')
def test_main_unexpected_error(mock_logging, mock_socket, mock_file_searcher, mock_use_ssl, mock_get_reread, mock_get_config):
    mock_get_config.return_value = '/mock/path'
    mock_get_reread.return_value = False
    mock_use_ssl.return_value = False
    mock_socket.side_effect = Exception("Mocked unexpected error")
    
    server_main()
    
    mock_logging.assert_called_with("Unexpected error during server setup: Mocked unexpected error")


@patch('server.socket.socket')
@patch('server.create_ssl_context')
@patch('logging.error')
def test_start_ssl_unexpected_error(mock_logging, mock_create_ssl_context, mock_socket):
    mock_ssl_context = MagicMock()
    mock_create_ssl_context.return_value = mock_ssl_context
    mock_ssl_context.wrap_socket.side_effect = Exception("Mocked unexpected error")
    mock_file_searcher = MagicMock()
    
    server_start(mock_socket, mock_file_searcher, use_ssl=True)
    
    mock_logging.assert_called_with("Unexpected error during SSL socket wrap: Mocked unexpected error")


@patch('server.socket.socket')
@patch('server.create_ssl_context')
@patch('logging.error')
def test_start_ssl_socket_wrap_failure(mock_logging, mock_create_ssl_context, mock_socket):
    mock_ssl_context = MagicMock()
    mock_create_ssl_context.return_value = mock_ssl_context
    mock_ssl_context.wrap_socket.side_effect = ssl.SSLError("Mocked SSL error")
    mock_file_searcher = MagicMock()
    
    # Call the server_start function with SSL enabled
    server_start(mock_socket, mock_file_searcher, use_ssl=True)
    
    # Check if the logging error was called with the expected message format
    mock_logging.assert_called_with("SSL socket wrap failed: ('Mocked SSL error',)")



def test_start_with_ssl(mocker):
    mock_socket = MagicMock()
    mock_file_searcher = MagicMock()
    mock_ssl_context = MagicMock()
    
    mocker.patch('server.create_ssl_context', return_value=mock_ssl_context)
    mocker.patch('server.shutdown_event', new=threading.Event())
    
    # Simulate server accepting one connection
    mock_socket.accept.return_value = (MagicMock(), ('127.0.0.1', 12345))
    
    server_start(mock_socket, mock_file_searcher, use_ssl=True, test_mode=True)
    
    mock_ssl_context.wrap_socket.assert_called_once_with(mock_socket, server_side=True)

def test_start_ssl_errors(mocker):
    mock_socket = MagicMock()
    mock_file_searcher = MagicMock()
    mock_ssl_context = MagicMock()
    
    mocker.patch('server.create_ssl_context', return_value=mock_ssl_context)
    mocker.patch('server.shutdown_event', new=threading.Event())
    
    # Test SSLError
    mock_ssl_context.wrap_socket.side_effect = ssl.SSLError("SSL Error")
    server_start(mock_socket, mock_file_searcher, use_ssl=True, test_mode=True)
    
    # Test generic exception
    mock_ssl_context.wrap_socket.side_effect = Exception("Generic Error")
    server_start(mock_socket, mock_file_searcher, use_ssl=True, test_mode=True)

def test_start_exception_handling(mocker):
    mock_socket = MagicMock()
    mock_file_searcher = MagicMock()
    
    mocker.patch('server.shutdown_event', new=threading.Event())
    mocker.patch('server.clients', new=set())
    mocker.patch('server.clients_lock', new=threading.Lock())
    
    mock_socket.accept.side_effect = [
        ssl.SSLError("SSL Error"),
        socket.error("Socket Error"),
        Exception("Generic Error")
    ]
    
    server_start(mock_socket, mock_file_searcher, use_ssl=False, test_mode=True)

def test_start_keyboard_interrupt(mocker):
    mock_socket = MagicMock()
    mock_file_searcher = MagicMock()
    
    mocker.patch('server.shutdown_event', new=threading.Event())
    mocker.patch('server.clients', new=set())
    mocker.patch('server.clients_lock', new=threading.Lock())
    
    mock_socket.accept.side_effect = KeyboardInterrupt
    
    server_start(mock_socket, mock_file_searcher, use_ssl=False, test_mode=True)
    
    mock_socket.close.assert_called_once()



@pytest.fixture
def temp_file(tmp_path):
    file_path = tmp_path / "test_file.txt"
    with open(file_path, 'w') as f:
        f.write("test_string1\ntest_string2\ntest_string3\n")
    return str(file_path)

def test_file_searcher_init(temp_file):
    searcher = FileSearcher(temp_file, False)
    assert searcher.file_path == temp_file
    assert searcher.reread_on_query == False
    assert isinstance(searcher.file_content, set)
    assert searcher.mmapped_file is None

def test_file_searcher_init_file_not_found():
    with pytest.raises(FileNotFoundError):
        FileSearcher("nonexistent_file.txt", False)

def test_file_searcher_init_permission_error(temp_file):
    os.chmod(temp_file, 0o000)  # Remove all permissions
    with pytest.raises(PermissionError):
        FileSearcher(temp_file, False)
    os.chmod(temp_file, 0o644)  # Restore permissions

def test_load_file_reread_on_query(temp_file):
    searcher = FileSearcher(temp_file, True)
    assert isinstance(searcher.mmapped_file, mmap.mmap)

def test_load_file_not_reread_on_query(temp_file):
    searcher = FileSearcher(temp_file, False)
    assert searcher.file_content == {"test_string1", "test_string2", "test_string3"}

def test_search_reread_on_query(temp_file):
    searcher = FileSearcher(temp_file, True)
    assert searcher.search("test_string2") == "STRING EXISTS\n"
    assert searcher.search("nonexistent") == "STRING NOT FOUND\n"

def test_search_not_reread_on_query(temp_file):
    searcher = FileSearcher(temp_file, False)
    assert searcher.search("test_string3") == "STRING EXISTS\n"
    assert searcher.search("nonexistent") == "STRING NOT FOUND\n"

def test_search_empty_string(temp_file):
    searcher = FileSearcher(temp_file, False)
    with pytest.raises(ValueError):
        searcher.search("")

def test_file_searcher_del(temp_file):
    searcher = FileSearcher(temp_file, True)
    del searcher  


def test_main_no_file_path(mock_config_file_no_path, caplog):
    """Test that main function handles missing 'linuxpath' correctly."""
    with patch('server.get_config_path', return_value=None):
        with caplog.at_level(logging.ERROR):
            main()

    # Check if the correct error message was logged
    assert "No file path specified in the configuration." in caplog.text


@pytest.fixture(scope="session", autouse=True)
def cleanup(request):
    """Cleanup function to stop the server thread and close the server socket."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 0))
    server_port = server_socket.getsockname()[1]

    mock_file_searcher = MagicMock()
    mock_file_searcher.search.return_value = "Test response"

    def run_server():
        server_start(server_socket, mock_file_searcher, use_ssl=False)

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    time.sleep(0.1)  # Give the server time to start

    yield  # Run the tests

    server_socket.close()
    server_thread.join(timeout=1)

    # Exit the entire Python process after the tests are completed
    pytest.exit("Exiting the test suite.")


if __name__ == "__main__":
    pytest.main([__file__])