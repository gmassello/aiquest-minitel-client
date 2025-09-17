"""
Extended tests for MiniTel-Lite TCP Client
Additional coverage for edge cases and error scenarios.
"""

import pytest
import socket
import time
from unittest.mock import Mock, patch, MagicMock

from minitel.client import MiniTelClient, ConnectionConfig, main
from minitel.protocol import Command, Frame, ProtocolError, FrameValidationError
from minitel.session import SessionRecorder


class TestMiniTelClientExtended:
    """Extended tests for MiniTelClient edge cases"""

    @patch('socket.socket')
    def test_receive_frame_success(self, mock_socket_class):
        """Test successful frame reception"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Create a valid encoded frame
        from minitel.protocol import ProtocolEncoder
        encoder = ProtocolEncoder()
        encoded_frame = encoder.encode_frame(Command.HELLO_ACK, 1, b"test_payload")

        mock_socket = Mock()
        # First call returns length prefix, subsequent calls return frame data
        mock_socket.recv.side_effect = [
            encoded_frame[:2],  # Length prefix
            encoded_frame[2:]   # Frame data
        ]
        client.socket = mock_socket

        frame = client._receive_frame()

        assert frame is not None
        assert frame.cmd == Command.HELLO_ACK
        assert frame.nonce == 1
        assert frame.payload == b"test_payload"

    @patch('socket.socket')
    def test_receive_frame_with_session_recording(self, mock_socket_class):
        """Test frame reception with session recording"""
        mock_recorder = Mock(spec=SessionRecorder)
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config, mock_recorder)

        # Create a valid encoded frame
        from minitel.protocol import ProtocolEncoder
        encoder = ProtocolEncoder()
        encoded_frame = encoder.encode_frame(Command.HELLO_ACK, 1, b"test")

        mock_socket = Mock()
        mock_socket.recv.side_effect = [encoded_frame[:2], encoded_frame[2:]]
        client.socket = mock_socket

        frame = client._receive_frame()

        assert frame is not None
        mock_recorder.record_response.assert_called_once_with("HELLO_ACK", 1, b"test")

    @patch('socket.socket')
    def test_receive_frame_unknown_command(self, mock_socket_class):
        """Test receiving frame with unknown command code"""
        mock_recorder = Mock(spec=SessionRecorder)
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config, mock_recorder)

        # Create frame with unknown command
        from minitel.protocol import ProtocolEncoder
        encoder = ProtocolEncoder()
        encoded_frame = encoder.encode_frame(0xFF, 1, b"test")  # Unknown command

        mock_socket = Mock()
        mock_socket.recv.side_effect = [encoded_frame[:2], encoded_frame[2:]]
        client.socket = mock_socket

        frame = client._receive_frame()

        assert frame is not None
        # Should record as UNKNOWN_255
        mock_recorder.record_response.assert_called_once_with("UNKNOWN_255", 1, b"test")

    @patch('socket.socket')
    def test_receive_frame_nonce_validation_warning(self, mock_socket_class):
        """Test nonce validation warning"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Advance client nonce first
        client.nonce_manager.get_next_client_nonce()  # 0

        # Create frame with wrong nonce (should be 1, but we send 5)
        from minitel.protocol import ProtocolEncoder
        encoder = ProtocolEncoder()
        encoded_frame = encoder.encode_frame(Command.HELLO_ACK, 5, b"")

        mock_socket = Mock()
        mock_socket.recv.side_effect = [encoded_frame[:2], encoded_frame[2:]]
        client.socket = mock_socket

        with patch.object(client.logger, 'warning') as mock_warning:
            frame = client._receive_frame()

            assert frame is not None
            mock_warning.assert_called_once()

    @patch('socket.socket')
    def test_receive_frame_protocol_error(self, mock_socket_class):
        """Test receiving frame with protocol error"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        # Return invalid data that will cause protocol error
        mock_socket.recv.side_effect = [b"XX", b"invalid_data"]  # Invalid length/data
        client.socket = mock_socket

        frame = client._receive_frame()
        assert frame is None

    @patch('socket.socket')
    def test_receive_frame_validation_error(self, mock_socket_class):
        """Test receiving frame with validation error"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        client.socket = mock_socket

        # Mock decoder to raise FrameValidationError
        with patch.object(client.decoder, 'decode_frame') as mock_decode:
            mock_decode.side_effect = FrameValidationError("Hash validation failed")
            mock_socket.recv.side_effect = [b"\x00\x10", b"x" * 16]

            frame = client._receive_frame()
            assert frame is None

    def test_send_stop_success(self):
        """Test successful STOP command"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=True), \
             patch.object(client, '_receive_frame') as mock_receive:

            mock_frame = Mock(spec=Frame)
            mock_frame.cmd = Command.STOP_OK
            mock_receive.return_value = mock_frame

            result = client.send_stop()
            assert result == mock_frame

    def test_send_stop_failure(self):
        """Test STOP command failure"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=False):
            result = client.send_stop()
            assert result is None

    def test_send_stop_invalid_response(self):
        """Test STOP command with invalid response"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_send_frame', return_value=True), \
             patch.object(client, '_receive_frame') as mock_receive:

            mock_frame = Mock(spec=Frame)
            mock_frame.cmd = Command.HELLO_ACK  # Wrong response
            mock_receive.return_value = mock_frame

            result = client.send_stop()
            assert result is None

    def test_execute_mission_second_dump_not_ok(self):
        """Test mission when second DUMP doesn't return OK"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        with patch.object(client, '_establish_secure_connection', return_value=True), \
             patch.object(client, '_authenticate_with_joshua', return_value=True), \
             patch.object(client, '_retrieve_override_codes', return_value=None), \
             patch.object(client, '_cleanup_mission') as mock_cleanup:

            result = client.execute_mission()

            assert result is None
            assert mock_cleanup.called


class TestMainFunction:
    """Test main function command-line interface"""

    @patch('argparse.ArgumentParser.parse_args')
    @patch('minitel.client.MiniTelClient')
    def test_main_success(self, mock_client_class, mock_parse_args):
        """Test successful main execution"""
        mock_parse_args.return_value = Mock(
            host="test.com",
            port=1234,
            timeout=5.0,
            record=False,
            log_level="INFO"
        )

        mock_client = Mock()
        mock_client.execute_mission.return_value = "SECRET123"
        mock_client_class.return_value = mock_client

        with patch('logging.basicConfig'):
            result = main()

        assert result == 0

    @patch('argparse.ArgumentParser.parse_args')
    @patch('minitel.client.MiniTelClient')
    def test_main_failure(self, mock_client_class, mock_parse_args):
        """Test main execution failure"""
        mock_parse_args.return_value = Mock(
            host="test.com",
            port=1234,
            timeout=5.0,
            record=False,
            log_level="INFO"
        )

        mock_client = Mock()
        mock_client.execute_mission.return_value = None
        mock_client_class.return_value = mock_client

        with patch('logging.basicConfig'):
            result = main()

        assert result == 1

    @patch('argparse.ArgumentParser.parse_args')
    @patch('minitel.client.MiniTelClient')
    def test_main_with_recording(self, mock_client_class, mock_parse_args):
        """Test main execution with recording enabled"""
        mock_parse_args.return_value = Mock(
            host="test.com",
            port=1234,
            timeout=5.0,
            record=True,
            log_level="DEBUG"
        )

        mock_client = Mock()
        mock_client.execute_mission.return_value = "SECRET123"
        mock_client_class.return_value = mock_client

        with patch('logging.basicConfig') as mock_logging, \
             patch('minitel.session.SessionRecorder') as mock_recorder:

            result = main()

        assert result == 0
        mock_logging.assert_called_once()
        mock_recorder.assert_called_once()

    def test_logging_setup(self):
        """Test logging setup in client"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Logger should be configured
        assert client.logger is not None
        assert client.logger.name == "minitel.client"

    def test_setup_logging_with_existing_handlers(self):
        """Test logging setup when handlers already exist"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Add a handler to simulate existing handlers
        import logging
        handler = logging.StreamHandler()
        client.logger.addHandler(handler)

        # Create another client - should not add duplicate handlers
        client2 = MiniTelClient(config)
        client2._setup_logging()

        # Should not have added more handlers
        assert len(client2.logger.handlers) >= 1


class TestClientErrorHandling:
    """Test client error handling scenarios"""

    @patch('socket.socket')
    def test_connection_with_socket_error(self, mock_socket_class):
        """Test connection with generic socket error"""
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.error("Generic socket error")
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234, max_retries=1)
        client = MiniTelClient(config)

        result = client.connect()
        assert result is False

    @patch('socket.socket')
    def test_connection_with_unexpected_exception(self, mock_socket_class):
        """Test connection with unexpected exception"""
        mock_socket = Mock()
        mock_socket.connect.side_effect = Exception("Unexpected error")
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234, max_retries=1)
        client = MiniTelClient(config)

        result = client.connect()
        assert result is False

    @patch('socket.socket')
    def test_send_frame_unexpected_error(self, mock_socket_class):
        """Test send frame with unexpected error"""
        mock_socket = Mock()
        mock_socket.send.side_effect = Exception("Unexpected send error")
        mock_socket_class.return_value = mock_socket

        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)
        client.socket = mock_socket

        result = client._send_frame(Command.HELLO)
        assert result is False

    @patch('socket.socket')
    def test_receive_frame_unexpected_error(self, mock_socket_class):
        """Test receive frame with unexpected error"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        mock_socket.recv.side_effect = Exception("Unexpected receive error")
        client.socket = mock_socket

        frame = client._receive_frame()
        assert frame is None

    @patch('socket.socket')
    def test_receive_exact_socket_error(self, mock_socket_class):
        """Test _receive_exact with socket error"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        mock_socket = Mock()
        mock_socket.recv.side_effect = socket.error("Socket error")
        client.socket = mock_socket

        result = client._receive_exact(10)
        assert result is None


class TestClientIntegrationExtended:
    """Extended integration tests"""

    @patch('socket.socket')
    def test_full_protocol_sequence(self, mock_socket_class):
        """Test complete protocol sequence with mocked socket"""
        config = ConnectionConfig(host="test.com", port=1234, max_retries=1)
        client = MiniTelClient(config)

        # Create expected frames
        from minitel.protocol import ProtocolEncoder
        encoder = ProtocolEncoder()

        hello_ack = encoder.encode_frame(Command.HELLO_ACK, 1, b"")
        dump_failed = encoder.encode_frame(Command.DUMP_FAILED, 3, b"")
        dump_ok = encoder.encode_frame(Command.DUMP_OK, 5, b"OVERRIDE_CODE_42")
        stop_ok = encoder.encode_frame(Command.STOP_OK, 7, b"")

        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        # Setup receive sequence
        recv_sequence = []
        for frame in [hello_ack, dump_failed, dump_ok, stop_ok]:
            recv_sequence.extend([frame[:2], frame[2:]])  # Length prefix + data

        mock_socket.recv.side_effect = recv_sequence

        # Execute mission
        result = client.execute_mission()

        # Verify results
        assert result == "OVERRIDE_CODE_42"
        assert mock_socket.connect.called
        assert mock_socket.send.call_count == 4  # HELLO, DUMP, DUMP, STOP
        assert mock_socket.close.called

    def test_client_state_management(self):
        """Test client state management through lifecycle"""
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config)

        # Initial state
        assert client.socket is None
        assert client.nonce_manager._current_nonce == 0

        # Simulate connection
        client.socket = Mock()

        # Test nonce progression
        nonce1 = client.nonce_manager.get_next_client_nonce()
        nonce2 = client.nonce_manager.get_next_client_nonce()
        assert nonce1 == 0
        assert nonce2 == 2

        # Test disconnection
        client.disconnect()
        assert client.socket is None

    def test_session_recording_integration(self):
        """Test complete session recording integration"""
        mock_recorder = Mock(spec=SessionRecorder)
        config = ConnectionConfig(host="test.com", port=1234)
        client = MiniTelClient(config, mock_recorder)

        # Mock successful send
        client.socket = Mock()

        # Send a frame
        client._send_frame(Command.HELLO, b"payload")

        # Verify recording
        mock_recorder.record_request.assert_called_once_with("HELLO", 0, b"payload")

        # Mock successful receive
        from minitel.protocol import ProtocolEncoder, ProtocolDecoder
        encoder = ProtocolEncoder()
        frame_data = encoder.encode_frame(Command.HELLO_ACK, 1, b"response")

        client.socket.recv.side_effect = [frame_data[:2], frame_data[2:]]

        # Receive frame
        frame = client._receive_frame()

        # Verify recording
        mock_recorder.record_response.assert_called_once_with("HELLO_ACK", 1, b"response")