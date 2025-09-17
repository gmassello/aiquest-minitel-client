"""
Tests for MiniTel-Lite Protocol Implementation
Validates protocol encoding/decoding and nonce management.
"""

import pytest
import struct
import hashlib
import base64

from minitel.protocol import (
    Command, Frame, ProtocolEncoder, ProtocolDecoder,
    NonceManager, ProtocolError, FrameValidationError
)
from minitel.constants import (
    HASH_SIZE, COMMAND_SIZE, NONCE_SIZE, MAX_PAYLOAD_SIZE,
    MAX_NONCE_VALUE, MAX_COMMAND_CODE, MAX_FRAME_SIZE
)


class TestCommand:
    """Test Command enumeration"""

    def test_command_values(self):
        """Test that command values match protocol specification"""
        assert Command.HELLO == 0x01
        assert Command.DUMP == 0x02
        assert Command.STOP_CMD == 0x04
        assert Command.HELLO_ACK == 0x81
        assert Command.DUMP_FAILED == 0x82
        assert Command.DUMP_OK == 0x83
        assert Command.STOP_OK == 0x84


class TestFrame:
    """Test Frame dataclass"""

    def test_valid_frame_creation(self):
        """Test creating a valid frame"""
        frame = Frame(
            cmd=Command.HELLO,
            nonce=12345,
            payload=b"test",
            hash_value=b"x" * HASH_SIZE
        )
        assert frame.cmd == Command.HELLO
        assert frame.nonce == 12345
        assert frame.payload == b"test"
        assert len(frame.hash_value) == HASH_SIZE

    def test_invalid_command(self):
        """Test frame with invalid command"""
        with pytest.raises(FrameValidationError, match="Command code must be an 8-bit unsigned integer"):
            Frame(cmd=MAX_COMMAND_CODE + 1, nonce=0, payload=b"", hash_value=b"x" * HASH_SIZE)

    def test_invalid_nonce(self):
        """Test frame with invalid nonce"""
        with pytest.raises(FrameValidationError, match="Nonce must be a 32-bit unsigned integer"):
            Frame(cmd=Command.HELLO, nonce=MAX_NONCE_VALUE + 1, payload=b"", hash_value=b"x" * HASH_SIZE)

    def test_payload_too_large(self):
        """Test frame with payload too large"""
        with pytest.raises(FrameValidationError, match="Payload size exceeds maximum"):
            Frame(cmd=Command.HELLO, nonce=0, payload=b"x" * (MAX_PAYLOAD_SIZE + 1), hash_value=b"x" * HASH_SIZE)

    def test_invalid_hash_length(self):
        """Test frame with invalid hash length"""
        with pytest.raises(FrameValidationError, match="Invalid hash length"):
            Frame(cmd=Command.HELLO, nonce=0, payload=b"", hash_value=b"x" * (HASH_SIZE - 1))


class TestProtocolEncoder:
    """Test Protocol Encoder"""

    def test_encode_hello_frame(self):
        """Test encoding a HELLO frame"""
        encoder = ProtocolEncoder()
        frame_data = encoder.encode_frame(Command.HELLO, 0, b"")

        # Validate structure: LEN(2) + BASE64_DATA
        assert len(frame_data) >= 2
        length = struct.unpack(">H", frame_data[:2])[0]
        b64_data = frame_data[2:]
        assert len(b64_data) == length

        # Decode and validate binary frame
        binary_frame = base64.b64decode(b64_data)
        assert len(binary_frame) == COMMAND_SIZE + NONCE_SIZE + 0 + HASH_SIZE  # CMD + NONCE + PAYLOAD + HASH

        # Validate components
        cmd = struct.unpack(">B", binary_frame[0:COMMAND_SIZE])[0]
        nonce = struct.unpack(">I", binary_frame[COMMAND_SIZE:COMMAND_SIZE+NONCE_SIZE])[0]
        payload = binary_frame[COMMAND_SIZE+NONCE_SIZE:-HASH_SIZE]
        hash_value = binary_frame[-HASH_SIZE:]

        assert cmd == Command.HELLO
        assert nonce == 0
        assert payload == b""
        assert len(hash_value) == HASH_SIZE

        # Validate hash
        expected_hash = hashlib.sha256(binary_frame[:-HASH_SIZE]).digest()
        assert hash_value == expected_hash

    def test_encode_with_payload(self):
        """Test encoding frame with payload"""
        encoder = ProtocolEncoder()
        test_payload = b"secret_data"
        frame_data = encoder.encode_frame(Command.DUMP, 42, test_payload)

        # Decode and validate
        length = struct.unpack(">H", frame_data[:2])[0]
        binary_frame = base64.b64decode(frame_data[2:])

        cmd = struct.unpack(">B", binary_frame[0:COMMAND_SIZE])[0]
        nonce = struct.unpack(">I", binary_frame[COMMAND_SIZE:COMMAND_SIZE+NONCE_SIZE])[0]
        payload = binary_frame[COMMAND_SIZE+NONCE_SIZE:-HASH_SIZE]
        hash_value = binary_frame[-HASH_SIZE:]

        assert cmd == Command.DUMP
        assert nonce == 42
        assert payload == test_payload

        # Validate hash
        expected_hash = hashlib.sha256(binary_frame[:-HASH_SIZE]).digest()
        assert hash_value == expected_hash

    def test_encode_large_payload(self):
        """Test encoding with maximum payload size"""
        encoder = ProtocolEncoder()
        large_payload = b"x" * 1000
        frame_data = encoder.encode_frame(Command.DUMP, 1, large_payload)

        # Should succeed for reasonable payload size
        assert len(frame_data) > 0

    def test_encode_frame_too_large(self):
        """Test encoding frame that becomes too large after Base64"""
        encoder = ProtocolEncoder()
        # Create payload that will result in Base64 > MAX_FRAME_SIZE bytes
        huge_payload = b"x" * 50000  # Should cause encoded frame to exceed limit

        with pytest.raises(ProtocolError, match="Encoded frame too large"):
            encoder.encode_frame(Command.DUMP, 1, huge_payload)


class TestProtocolDecoder:
    """Test Protocol Decoder"""

    def test_decode_hello_frame(self):
        """Test decoding a HELLO frame"""
        # First encode a frame
        encoder = ProtocolEncoder()
        encoded = encoder.encode_frame(Command.HELLO, 0, b"")

        # Then decode it
        decoder = ProtocolDecoder()
        frame = decoder.decode_frame(encoded)

        assert frame.cmd == Command.HELLO
        assert frame.nonce == 0
        assert frame.payload == b""
        assert len(frame.hash_value) == HASH_SIZE

    def test_decode_with_payload(self):
        """Test decoding frame with payload"""
        encoder = ProtocolEncoder()
        decoder = ProtocolDecoder()
        test_payload = b"test_payload_data"

        encoded = encoder.encode_frame(Command.DUMP_OK, 123, test_payload)
        frame = decoder.decode_frame(encoded)

        assert frame.cmd == Command.DUMP_OK
        assert frame.nonce == 123
        assert frame.payload == test_payload

    def test_decode_insufficient_data(self):
        """Test decoding with insufficient data"""
        decoder = ProtocolDecoder()

        with pytest.raises(ProtocolError, match="Insufficient data for length prefix"):
            decoder.decode_frame(b"x")

    def test_decode_insufficient_frame_data(self):
        """Test decoding with insufficient frame data"""
        decoder = ProtocolDecoder()

        # Create length prefix indicating more data than available
        length_prefix = struct.pack(">H", 100)
        short_data = b"short"

        with pytest.raises(ProtocolError, match="Insufficient data"):
            decoder.decode_frame(length_prefix + short_data)

    def test_decode_invalid_base64(self):
        """Test decoding with invalid Base64 data"""
        decoder = ProtocolDecoder()

        # Create length prefix + invalid Base64
        invalid_b64 = b"invalid base64!!!"
        length_prefix = struct.pack(">H", len(invalid_b64))

        with pytest.raises(ProtocolError, match="Base64 decode failed"):
            decoder.decode_frame(length_prefix + invalid_b64)

    def test_decode_frame_too_small(self):
        """Test decoding frame that's too small"""
        decoder = ProtocolDecoder()

        # Create minimal valid Base64 that decodes to insufficient data
        small_binary = b"x" * 10  # Less than minimum 37 bytes
        b64_data = base64.b64encode(small_binary)
        length_prefix = struct.pack(">H", len(b64_data))

        with pytest.raises(ProtocolError, match="Frame too small"):
            decoder.decode_frame(length_prefix + b64_data)

    def test_decode_hash_validation_failure(self):
        """Test decoding with hash validation failure"""
        decoder = ProtocolDecoder()

        # Create a frame with invalid hash
        cmd = struct.pack(">B", Command.HELLO)
        nonce = struct.pack(">I", 0)
        payload = b""
        invalid_hash = b"x" * HASH_SIZE  # Wrong hash

        binary_frame = cmd + nonce + payload + invalid_hash
        b64_data = base64.b64encode(binary_frame)
        length_prefix = struct.pack(">H", len(b64_data))

        with pytest.raises(FrameValidationError, match="Hash validation failed"):
            decoder.decode_frame(length_prefix + b64_data)

    def test_extract_length(self):
        """Test length extraction"""
        decoder = ProtocolDecoder()

        # Test valid length extraction
        length_data = struct.pack(">H", 42)
        assert decoder.extract_length(length_data) == 2 + 42

        # Test insufficient data
        assert decoder.extract_length(b"x") is None
        assert decoder.extract_length(b"") is None


class TestNonceManager:
    """Test Nonce Manager"""

    def test_initial_nonce(self):
        """Test initial nonce value"""
        manager = NonceManager()
        assert manager.get_next_client_nonce() == 0

    def test_nonce_sequence(self):
        """Test nonce sequence progression"""
        manager = NonceManager()

        # Client nonces should be even: 0, 2, 4, ...
        assert manager.get_next_client_nonce() == 0
        assert manager.get_next_client_nonce() == 2
        assert manager.get_next_client_nonce() == 4

    def test_server_nonce_validation(self):
        """Test server nonce validation"""
        manager = NonceManager()

        # After client sends nonce 0, server should respond with 1
        client_nonce = manager.get_next_client_nonce()  # 0
        assert manager.validate_server_nonce(1) is True
        assert manager.validate_server_nonce(0) is False
        assert manager.validate_server_nonce(2) is False

        # After client sends nonce 2, server should respond with 3
        client_nonce = manager.get_next_client_nonce()  # 2
        assert manager.validate_server_nonce(3) is True
        assert manager.validate_server_nonce(1) is False

    def test_nonce_reset(self):
        """Test nonce sequence reset"""
        manager = NonceManager()

        # Advance sequence
        manager.get_next_client_nonce()  # 0
        manager.get_next_client_nonce()  # 2

        # Reset and verify
        manager.reset()
        assert manager.get_next_client_nonce() == 0


class TestProtocolIntegration:
    """Integration tests for encoder/decoder"""

    def test_encode_decode_roundtrip(self):
        """Test complete encode/decode roundtrip"""
        encoder = ProtocolEncoder()
        decoder = ProtocolDecoder()

        test_cases = [
            (Command.HELLO, 0, b""),
            (Command.DUMP, 42, b"test_payload"),
            (Command.STOP_CMD, 100, b"longer test payload with more data"),
            (Command.HELLO_ACK, 1, b"response_data"),
        ]

        for cmd, nonce, payload in test_cases:
            # Encode
            encoded = encoder.encode_frame(cmd, nonce, payload)

            # Decode
            frame = decoder.decode_frame(encoded)

            # Verify
            assert frame.cmd == cmd
            assert frame.nonce == nonce
            assert frame.payload == payload

    def test_multiple_frame_handling(self):
        """Test handling multiple frames in sequence"""
        encoder = ProtocolEncoder()
        decoder = ProtocolDecoder()
        nonce_manager = NonceManager()

        # Simulate protocol sequence
        frames = [
            (Command.HELLO, nonce_manager.get_next_client_nonce(), b""),
            (Command.DUMP, nonce_manager.get_next_client_nonce(), b""),
            (Command.DUMP, nonce_manager.get_next_client_nonce(), b""),
            (Command.STOP_CMD, nonce_manager.get_next_client_nonce(), b""),
        ]

        for cmd, nonce, payload in frames:
            encoded = encoder.encode_frame(cmd, nonce, payload)
            decoded = decoder.decode_frame(encoded)

            assert decoded.cmd == cmd
            assert decoded.nonce == nonce
            assert decoded.payload == payload