"""
Tests for MiniTel-Lite TCP Client
Validates connection handling, protocol communication, and error recovery.
"""

import pytest
import socket
import threading
import time
from unittest.mock import Mock, patch, MagicMock

from minitel.client import MiniTelClient, ConnectionConfig, ConnectionError
from minitel.protocol import Command, Frame
from minitel.session import SessionRecorder


class TestConnectionConfig:
    """Test ConnectionConfig dataclass"""

    def test_default_values(self):
        """Test default configuration values"""
        config = ConnectionConfig(host="test.com", port=1234)
        assert config.host == "test.com"
        assert config.port == 1234
        assert config.timeout == 5.0
        assert config.max_retries == 3
        assert config.retry_delay == 1.0

    def test_custom_values(self):
        """Test custom configuration values"""
        config = ConnectionConfig(
            host="example.com",
            port=9999,
            timeout=10.0,
            max_retries=5,
            retry_delay=2.0
        )
        assert config.host == "example.com"
        assert config.port == 9999
        assert config.timeout == 10.0
        assert config.max_retries == 5
        assert config.retry_delay == 2.0


class TestMiniTelClient:
    """Test MiniTelClient functionality"""

    def test_client_initialization(self):
        """Test client initialization"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        assert client.config == config
        assert client.socket is None
        assert client.session_recorder is None
        assert client.nonce_manager is not None
        assert client.encoder is not None
        assert client.decoder is not None

    def test_client_with_session_recorder(self):
        """Test client initialization with session recorder"""
        config = ConnectionConfig(host="test.com", port=1234)
        recorder = Mock(spec=SessionRecorder)
        client = MiniTelClient(config, recorder)

        assert client.session_recorder == recorder

    @patch('socket.socket')
    def test_successful_connection(self, mock_socket_class):
        """Test successful connection establishment"""
        # Setup mock
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Test connection
        result = client.connect()

        assert result is True
        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket.settimeout.assert_called_with(config.timeout)
        mock_socket.connect.assert_called_with((config.host, config.port))

    @patch('socket.socket')
    def test_connection_failure_with_retries(self, mock_socket_class):
        """Test connection failure with retry logic"""
        # Setup mock to fail all attempts
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.error("Connection failed")
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234, max_retries=2, retry_delay=0.1)
        client = MiniTelClient(config)

        with patch('time.sleep') as mock_sleep:
            result = client.connect()

        assert result is False
        assert mock_socket.connect.call_count == 2
        assert mock_sleep.call_count == 1  # Sleep between retries

    @patch('socket.socket')
    def test_connection_timeout(self, mock_socket_class):
        """Test connection timeout handling"""
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.timeout("Connection timeout")
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234, max_retries=1)
        client = MiniTelClient(config)

        result = client.connect()
        assert result is False

    def test_disconnect_with_socket(self):
        """Test disconnection when socket exists"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Mock socket
        mock_socket = Mock()
        client.socket = mock_socket

        client.disconnect()

        mock_socket.close.assert_called_once()
        assert client.socket is None

    def test_disconnect_without_socket(self):
        """Test disconnection when no socket exists"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Should not raise exception
        client.disconnect()
        assert client.socket is None

    def test_disconnect_with_error(self):
        """Test disconnection when socket.close() raises error"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        mock_socket.close.side_effect = Exception("Close error")
        client.socket = mock_socket

        # Should handle exception gracefully
        client.disconnect()
        assert client.socket is None

    def test_send_frame_without_connection(self):
        """Test sending frame without connection"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with pytest.raises(ConnectionError, match="Not connected to server"):
            client._send_frame(Command.HELLO)

    @patch('socket.socket')
    def test_send_frame_success(self, mock_socket_class):
        """Test successful frame sending"""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)
        client.socket = mock_socket

        result = client._send_frame(Command.HELLO, b"test")

        assert result is True
        mock_socket.send.assert_called_once()

    @patch('socket.socket')
    def test_send_frame_with_session_recording(self, mock_socket_class):
        """Test frame sending with session recording"""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_recorder = Mock(spec=SessionRecorder)

        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config, mock_recorder)
        client.socket = mock_socket

        result = client._send_frame(Command.HELLO, b"test")

        assert result is True
        mock_recorder.record_request.assert_called_once()

    @patch('socket.socket')
    def test_send_frame_socket_error(self, mock_socket_class):
        """Test frame sending with socket error"""
        mock_socket = Mock()
        mock_socket.send.side_effect = socket.error("Send failed")
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)
        client.socket = mock_socket

        result = client._send_frame(Command.HELLO)
        assert result is False

    def test_receive_frame_without_connection(self):
        """Test receiving frame without connection"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with pytest.raises(ConnectionError, match="Not connected to server"):
            client._receive_frame()

    def test_receive_exact_success(self):
        """Test _receive_exact with successful data reception"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        mock_socket.recv.return_value = b"test_data"
        client.socket = mock_socket

        result = client._receive_exact(9)
        assert result == b"test_data"

    def test_receive_exact_partial_data(self):
        """Test _receive_exact with partial data reception"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        # First call returns partial data, second call returns rest
        mock_socket.recv.side_effect = [b"test", b"_data"]
        client.socket = mock_socket

        result = client._receive_exact(9)
        assert result == b"test_data"
        assert mock_socket.recv.call_count == 2

    def test_receive_exact_connection_closed(self):
        """Test _receive_exact when connection is closed"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        mock_socket.recv.return_value = b""  # Connection closed
        client.socket = mock_socket

        result = client._receive_exact(10)
        assert result is None

    def test_receive_exact_timeout(self):
        """Test _receive_exact with timeout"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        mock_socket.recv.side_effect = socket.timeout("Timeout")
        client.socket = mock_socket

        result = client._receive_exact(10)
        assert result is None

    def test_send_hello_command(self):
        """Test send_hello method"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Mock the internal methods
        with patch.object(client, '_send_frame', return_value=True) as mock_send, \
             patch.object(client, '_receive_frame') as mock_receive:

            # Mock successful HELLO_ACK response
            mock_frame = Mock(spec=Frame)
            mock_frame.cmd = Command.HELLO_ACK
            mock_receive.return_value = mock_frame

            result = client.send_hello()

            mock_send.assert_called_with(Command.HELLO)
            assert result == mock_frame

    def test_send_hello_send_failure(self):
        """Test send_hello when frame sending fails"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=False):
            result = client.send_hello()
            assert result is None

    def test_send_hello_invalid_response(self):
        """Test send_hello with invalid response"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=True), \
             patch.object(client, '_receive_frame') as mock_receive:

            # Mock wrong response
            mock_frame = Mock(spec=Frame)
            mock_frame.cmd = Command.DUMP_OK  # Wrong response
            mock_receive.return_value = mock_frame

            result = client.send_hello()
            assert result is None

    def test_send_dump_success(self):
        """Test send_dump with DUMP_OK response"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=True), \
             patch.object(client, '_receive_frame') as mock_receive:

            mock_frame = Mock(spec=Frame)
            mock_frame.cmd = Command.DUMP_OK
            mock_receive.return_value = mock_frame

            result = client.send_dump()
            assert result == mock_frame

    def test_send_dump_failed(self):
        """Test send_dump with DUMP_FAILED response"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=True), \
             patch.object(client, '_receive_frame') as mock_receive:

            mock_frame = Mock(spec=Frame)
            mock_frame.cmd = Command.DUMP_FAILED
            mock_receive.return_value = mock_frame

            result = client.send_dump()
            assert result == mock_frame

    def test_execute_mission_success(self):
        """Test successful mission execution"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Mock all the steps of the mission
        with patch.object(client, 'connect', return_value=True), \
             patch.object(client, 'send_hello') as mock_hello, \
             patch.object(client, 'send_dump') as mock_dump, \
             patch.object(client, 'send_stop') as mock_stop, \
             patch.object(client, 'disconnect') as mock_disconnect:

            # Mock successful responses
            mock_hello.return_value = Mock(spec=Frame)

            # First DUMP fails, second succeeds
            dump_failed = Mock(spec=Frame)
            dump_failed.cmd = Command.DUMP_FAILED

            dump_success = Mock(spec=Frame)
            dump_success.cmd = Command.DUMP_OK
            dump_success.payload = b"SECRET_CODE_12345"

            mock_dump.side_effect = [dump_failed, dump_success]
            mock_stop.return_value = Mock(spec=Frame)

            result = client.execute_mission()

            # Verify mission steps
            assert client.connect.called
            assert mock_hello.called
            assert mock_dump.call_count == 2
            assert mock_stop.called
            assert mock_disconnect.called
            assert result == "SECRET_CODE_12345"

    def test_execute_mission_connection_failure(self):
        """Test mission execution with connection failure"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, 'connect', return_value=False), \
             patch.object(client, 'disconnect') as mock_disconnect:

            result = client.execute_mission()

            assert result is None
            assert mock_disconnect.called

    def test_execute_mission_auth_failure(self):
        """Test mission execution with authentication failure"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, 'connect', return_value=True), \
             patch.object(client, 'send_hello', return_value=None), \
             patch.object(client, 'disconnect') as mock_disconnect:

            result = client.execute_mission()

            assert result is None
            assert mock_disconnect.called

    def test_execute_mission_dump_failure(self):
        """Test mission execution with DUMP command failure"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, 'connect', return_value=True), \
             patch.object(client, 'send_hello') as mock_hello, \
             patch.object(client, 'send_dump', return_value=None), \
             patch.object(client, 'disconnect') as mock_disconnect:

            mock_hello.return_value = Mock(spec=Frame)

            result = client.execute_mission()

            assert result is None
            assert mock_disconnect.called

    def test_execute_mission_exception_handling(self):
        """Test mission execution with unexpected exception"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, 'connect', side_effect=Exception("Unexpected error")), \
             patch.object(client, 'disconnect') as mock_disconnect:

            result = client.execute_mission()

            assert result is None
            assert mock_disconnect.called


class TestClientIntegration:
    """Integration tests for client functionality"""

    def test_client_nonce_sequence(self):
        """Test that client maintains proper nonce sequence"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Get initial nonce
        nonce1 = client.nonce_manager.get_next_client_nonce()
        nonce2 = client.nonce_manager.get_next_client_nonce()
        nonce3 = client.nonce_manager.get_next_client_nonce()

        # Should be even numbers: 0, 2, 4
        assert nonce1 == 0
        assert nonce2 == 2
        assert nonce3 == 4

    def test_client_session_recording_integration(self):
        """Test client integration with session recorder"""
        mock_recorder = Mock(spec=SessionRecorder)
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config, mock_recorder)

        # Mock socket operations
        mock_socket = Mock()
        client.socket = mock_socket

        # Test sending frame with recording
        client._send_frame(Command.HELLO, b"test_payload")

        # Verify recorder was called
        mock_recorder.record_request.assert_called_once_with(
            "HELLO", 0, b"test_payload"
        )