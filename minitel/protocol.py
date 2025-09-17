"""
MiniTel-Lite Protocol v3.0 Implementation
Handles binary frame encoding/decoding for NORAD emergency communications.
"""

import struct
import hashlib
import hmac
import base64
from enum import IntEnum
from typing import Tuple, Optional
from dataclasses import dataclass

from .validation import InputValidator, validate_and_raise, ValidationError
from .constants import (
    HASH_SIZE, COMMAND_SIZE, NONCE_SIZE, MAX_PAYLOAD_SIZE,
    LENGTH_PREFIX_SIZE, MIN_FRAME_SIZE, MAX_NONCE_VALUE,
    HASH_VALIDATION_FAILED_MSG, INVALID_FRAME_MSG
)


class Command(IntEnum):
    """MiniTel-Lite protocol commands"""
    HELLO = 0x01
    DUMP = 0x02
    STOP_CMD = 0x04

    # Server response codes
    HELLO_ACK = 0x81
    DUMP_FAILED = 0x82
    DUMP_OK = 0x83
    STOP_OK = 0x84


@dataclass
class Frame:
    """Represents a MiniTel-Lite protocol frame"""
    cmd: int
    nonce: int
    payload: bytes
    hash_value: bytes

    def __post_init__(self):
        """Validate frame components using validation framework"""
        # Validate command code
        self.cmd = validate_and_raise(
            InputValidator.validate_command_code,
            self.cmd,
            FrameValidationError
        )

        # Validate nonce
        self.nonce = validate_and_raise(
            InputValidator.validate_nonce,
            self.nonce,
            FrameValidationError
        )

        # Validate payload
        self.payload = validate_and_raise(
            InputValidator.validate_payload,
            self.payload,
            FrameValidationError
        )

        # Validate hash length
        if len(self.hash_value) != HASH_SIZE:
            raise FrameValidationError(
                f"Invalid hash length: {len(self.hash_value)} bytes, expected {HASH_SIZE}"
            )


class ProtocolError(Exception):
    """Base exception for protocol-related errors"""
    pass


class FrameValidationError(ProtocolError):
    """Raised when frame validation fails"""
    pass


class ProtocolEncoder:
    """Encodes MiniTel-Lite frames for transmission"""

    @staticmethod
    def encode_frame(cmd: int, nonce: int, payload: bytes = b"") -> bytes:
        """
        Encode a frame according to MiniTel-Lite v3.0 specification

        Frame Format:
        LEN (2 bytes, big-endian) | DATA_B64 (LEN bytes, Base64 encoded)

        Binary Frame (before Base64):
        CMD (1 byte) | NONCE (4 bytes, big-endian) |
        PAYLOAD (0-65535 bytes) | HASH (32 bytes SHA-256)

        Args:
            cmd: Command code (0-255)
            nonce: Nonce value for replay protection
            payload: Optional payload data

        Returns:
            Encoded frame data ready for transmission

        Raises:
            ProtocolError: If encoded frame exceeds size limits
        """
        # Build binary frame components
        cmd_bytes = struct.pack(">B", cmd)
        nonce_bytes = struct.pack(">I", nonce)

        # Calculate hash: SHA-256(CMD + NONCE + PAYLOAD)
        hash_input = cmd_bytes + nonce_bytes + payload
        hash_value = hashlib.sha256(hash_input).digest()

        # Construct complete binary frame
        binary_frame = cmd_bytes + nonce_bytes + payload + hash_value

        # Base64 encode the frame
        b64_data = base64.b64encode(binary_frame)

        # Prepend 2-byte length prefix (big-endian)
        length = len(b64_data)
        if length > 65535:
            raise ProtocolError(f"Encoded frame too large: {length} bytes")

        length_prefix = struct.pack(">H", length)

        return length_prefix + b64_data


class ProtocolDecoder:
    """Decodes MiniTel-Lite frames from network data"""

    @staticmethod
    def decode_frame(data: bytes) -> Frame:
        """
        Decode a frame according to MiniTel-Lite v3.0 specification

        Args:
            data: Raw bytes from network (with length prefix)

        Returns:
            Decoded Frame object

        Raises:
            ProtocolError: If decoding fails
            FrameValidationError: If frame validation fails
        """
        if len(data) < 2:
            raise ProtocolError("Insufficient data for length prefix")

        # Read 2-byte length prefix
        length = struct.unpack(">H", data[:2])[0]

        if len(data) < 2 + length:
            raise ProtocolError(
                f"Insufficient data: expected {2 + length}, got {len(data)}"
            )

        # Extract Base64 data
        b64_data = data[2:2 + length]

        try:
            # Base64 decode to get binary frame
            binary_frame = base64.b64decode(b64_data)
        except Exception as e:
            raise ProtocolError(f"Base64 decode failed: {e}")

        # Minimum frame size validation
        if len(binary_frame) < MIN_FRAME_SIZE:
            raise ProtocolError(f"Frame too small: {len(binary_frame)} bytes, minimum {MIN_FRAME_SIZE}")

        # Extract frame components
        cmd = struct.unpack(">B", binary_frame[0:COMMAND_SIZE])[0]
        nonce = struct.unpack(">I", binary_frame[COMMAND_SIZE:COMMAND_SIZE+NONCE_SIZE])[0]
        payload = binary_frame[COMMAND_SIZE+NONCE_SIZE:-HASH_SIZE]
        received_hash = binary_frame[-HASH_SIZE:]

        # Verify hash: SHA-256(CMD + NONCE + PAYLOAD)
        expected_hash = hashlib.sha256(binary_frame[:-HASH_SIZE]).digest()
        if not hmac.compare_digest(received_hash, expected_hash):
            raise FrameValidationError(HASH_VALIDATION_FAILED_MSG)

        return Frame(
            cmd=cmd, nonce=nonce, payload=payload, hash_value=received_hash
        )

    @staticmethod
    def extract_length(data: bytes) -> Optional[int]:
        """
        Extract the expected frame length from the first 2 bytes

        Returns:
            Expected total frame size (including 2-byte prefix)
            or None if insufficient data
        """
        if len(data) < LENGTH_PREFIX_SIZE:
            return None
        length = struct.unpack(">H", data[:LENGTH_PREFIX_SIZE])[0]
        return LENGTH_PREFIX_SIZE + length  # Include the length prefix


class NonceManager:
    """Manages nonce sequence for client-server communication"""

    def __init__(self):
        self._current_nonce = 0

    def get_next_client_nonce(self) -> int:
        """Get the next nonce value for client messages"""
        nonce = self._current_nonce
        self._current_nonce += 2  # Client uses even nonces, server responds with odd
        return nonce

    def validate_server_nonce(self, received_nonce: int) -> bool:
        """Validate that server nonce follows expected sequence"""
        expected = self._current_nonce - 1  # Server should respond with client_nonce + 1
        return received_nonce == expected

    def get_expected_server_nonce(self) -> int:
        """Get the expected server nonce value for error reporting"""
        return self._current_nonce - 1

    def reset(self):
        """Reset nonce sequence (for new connections)"""
        self._current_nonce = 0
