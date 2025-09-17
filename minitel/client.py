"""
MiniTel-Lite TCP Client
Agent LIGHTMAN's tool to infiltrate JOSHUA and retrieve override codes.
"""

import socket
import time
import logging
from typing import Optional, Tuple, List
from dataclasses import dataclass

from .protocol import (
    Command, Frame, ProtocolEncoder, ProtocolDecoder,
    NonceManager, ProtocolError, FrameValidationError
)
from .session import SessionRecorder, SessionEntry


@dataclass
class ConnectionConfig:
    """TCP connection configuration"""
    host: str
    port: int
    timeout: float = 5.0
    max_retries: int = 3
    retry_delay: float = 1.0


class ConnectionError(Exception):
    """TCP connection related errors"""
    pass


class MiniTelClient:
    """
    MiniTel-Lite TCP client for NORAD emergency protocol

    Handles connection management, protocol communication, and graceful error recovery.
    """

    def __init__(self, config: ConnectionConfig, session_recorder: Optional[SessionRecorder] = None):
        self.config = config
        self.session_recorder = session_recorder
        self.socket: Optional[socket.socket] = None
        self.nonce_manager = NonceManager()
        self.encoder = ProtocolEncoder()
        self.decoder = ProtocolDecoder()

        # Setup logging
        self.logger = logging.getLogger(__name__)
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging for mission operations"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - NORAD-%(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self) -> bool:
        """
        Establish TCP connection to MiniTel-Lite server

        Returns:
            True if connection successful, False otherwise
        """
        for attempt in range(self.config.max_retries):
            try:
                self.logger.info(f"Attempting connection to {self.config.host}:{self.config.port} (attempt {attempt + 1})")

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.config.timeout)

                self.socket.connect((self.config.host, self.config.port))
                self.nonce_manager.reset()

                self.logger.info("Connection established successfully")
                return True

            except socket.timeout:
                self.logger.warning(f"Connection timeout on attempt {attempt + 1}")
            except socket.error as e:
                self.logger.warning(f"Connection failed on attempt {attempt + 1}: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")

            if self.socket:
                self.socket.close()
                self.socket = None

            if attempt < self.config.max_retries - 1:
                self.logger.info(f"Retrying in {self.config.retry_delay} seconds...")
                time.sleep(self.config.retry_delay)

        self.logger.error("Failed to establish connection after all attempts")
        return False

    def disconnect(self):
        """Close TCP connection"""
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("Connection closed")
            except Exception as e:
                self.logger.warning(f"Error closing connection: {e}")
            finally:
                self.socket = None

    def _send_frame(self, cmd: Command, payload: bytes = b"") -> bool:
        """
        Send a frame to the server

        Args:
            cmd: Command to send
            payload: Optional payload data

        Returns:
            True if frame sent successfully, False otherwise
        """
        if not self.socket:
            raise ConnectionError("Not connected to server")

        try:
            nonce = self.nonce_manager.get_next_client_nonce()
            frame_data = self.encoder.encode_frame(cmd, nonce, payload)

            self.logger.debug(f"Sending {cmd.name} command (nonce={nonce})")
            self.socket.send(frame_data)

            # Record session if recorder is available
            if self.session_recorder:
                self.session_recorder.record_request(cmd.name, nonce, payload)

            return True

        except socket.error as e:
            self.logger.error(f"Failed to send frame: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending frame: {e}")
            return False

    def _receive_frame(self) -> Optional[Frame]:
        """
        Receive a frame from the server

        Returns:
            Decoded Frame object or None if receive failed
        """
        if not self.socket:
            raise ConnectionError("Not connected to server")

        try:
            # First, receive the length prefix (2 bytes)
            length_data = self._receive_exact(2)
            if not length_data:
                return None

            # Determine total frame size
            total_size = self.decoder.extract_length(length_data)
            if total_size is None:
                self.logger.error("Failed to extract frame length")
                return None

            # Receive remaining data
            remaining_data = self._receive_exact(total_size - 2)
            if not remaining_data:
                return None

            # Decode complete frame
            complete_data = length_data + remaining_data
            frame = self.decoder.decode_frame(complete_data)

            self.logger.debug(f"Received command {frame.cmd} (nonce={frame.nonce})")

            # Validate nonce sequence
            if not self.nonce_manager.validate_server_nonce(frame.nonce):
                self.logger.warning(f"Nonce sequence violation: received {frame.nonce}")

            # Record session if recorder is available
            if self.session_recorder:
                response_cmd = Command(frame.cmd).name if frame.cmd in Command.__members__.values() else f"UNKNOWN_{frame.cmd}"
                self.session_recorder.record_response(response_cmd, frame.nonce, frame.payload)

            return frame

        except socket.timeout:
            self.logger.warning("Timeout while receiving frame")
            return None
        except socket.error as e:
            self.logger.error(f"Network error while receiving frame: {e}")
            return None
        except (ProtocolError, FrameValidationError) as e:
            self.logger.error(f"Protocol error while receiving frame: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error while receiving frame: {e}")
            return None

    def _receive_exact(self, size: int) -> Optional[bytes]:
        """
        Receive exactly 'size' bytes from socket

        Args:
            size: Number of bytes to receive

        Returns:
            Received bytes or None if failed
        """
        data = b""
        while len(data) < size:
            try:
                chunk = self.socket.recv(size - len(data))
                if not chunk:
                    self.logger.error("Connection closed by server")
                    return None
                data += chunk
            except socket.timeout:
                self.logger.warning("Timeout while receiving data")
                return None
            except socket.error as e:
                self.logger.error(f"Socket error while receiving data: {e}")
                return None

        return data

    def send_hello(self) -> Optional[Frame]:
        """
        Send HELLO command and receive HELLO_ACK

        Returns:
            Server response frame or None if failed
        """
        self.logger.info("Sending HELLO command...")
        if not self._send_frame(Command.HELLO):
            return None

        response = self._receive_frame()
        if response and response.cmd == Command.HELLO_ACK:
            self.logger.info("HELLO_ACK received - authentication successful")
            return response
        else:
            self.logger.error("Failed to receive valid HELLO_ACK")
            return None

    def send_dump(self) -> Optional[Frame]:
        """
        Send DUMP command and receive response

        Returns:
            Server response frame or None if failed
        """
        self.logger.info("Sending DUMP command...")
        if not self._send_frame(Command.DUMP):
            return None

        response = self._receive_frame()
        if response:
            if response.cmd == Command.DUMP_OK:
                self.logger.info("DUMP_OK received - secret data retrieved!")
                return response
            elif response.cmd == Command.DUMP_FAILED:
                self.logger.info("DUMP_FAILED received - need to try again")
                return response
            else:
                self.logger.error(f"Unexpected response to DUMP: {response.cmd}")
                return response
        else:
            self.logger.error("Failed to receive response to DUMP command")
            return None

    def send_stop(self) -> Optional[Frame]:
        """
        Send STOP_CMD command and receive STOP_OK

        Returns:
            Server response frame or None if failed
        """
        self.logger.info("Sending STOP_CMD...")
        if not self._send_frame(Command.STOP_CMD):
            return None

        response = self._receive_frame()
        if response and response.cmd == Command.STOP_OK:
            self.logger.info("STOP_OK received - session terminated")
            return response
        else:
            self.logger.error("Failed to receive valid STOP_OK")
            return None

    def execute_mission(self) -> Optional[str]:
        """
        Execute the complete NORAD infiltration mission

        Mission sequence:
        1. Connect to server
        2. Send HELLO and authenticate
        3. Send DUMP command twice to retrieve override code
        4. Send STOP_CMD to terminate session
        5. Disconnect

        Returns:
            Retrieved override code or None if mission failed
        """
        override_code = None

        try:
            # Phase 1: Establish connection
            self.logger.info("=== MISSION START: JOSHUA INFILTRATION ===")
            if not self.connect():
                self.logger.error("Mission failed: Unable to connect to JOSHUA")
                return None

            # Phase 2: Authenticate with HELLO protocol
            hello_response = self.send_hello()
            if not hello_response:
                self.logger.error("Mission failed: Authentication failed")
                return None

            # Phase 3: First DUMP attempt (expected to fail)
            dump1_response = self.send_dump()
            if not dump1_response:
                self.logger.error("Mission failed: First DUMP command failed")
                return None

            # Phase 4: Second DUMP attempt (should succeed)
            dump2_response = self.send_dump()
            if not dump2_response:
                self.logger.error("Mission failed: Second DUMP command failed")
                return None

            if dump2_response.cmd == Command.DUMP_OK:
                override_code = dump2_response.payload.decode('utf-8', errors='replace')
                self.logger.info(f"SUCCESS: Override code retrieved: {override_code}")
            else:
                self.logger.error("Mission failed: Second DUMP did not return override code")

            # Phase 5: Clean termination
            self.send_stop()

        except Exception as e:
            self.logger.error(f"Mission failed with unexpected error: {e}")

        finally:
            # Always disconnect
            self.disconnect()
            self.logger.info("=== MISSION END ===")

        return override_code


def main():
    """Command-line entry point for MiniTel client"""
    import argparse

    parser = argparse.ArgumentParser(description="NORAD MiniTel-Lite Emergency Client")
    parser.add_argument("--host", default="35.153.159.192", help="Server hostname")
    parser.add_argument("--port", type=int, default=7321, help="Server port")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout")
    parser.add_argument("--record", action="store_true", help="Enable session recording")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       default="INFO", help="Logging level")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=getattr(logging, args.log_level))

    # Setup configuration
    config = ConnectionConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout
    )

    # Setup session recording if requested
    recorder = None
    if args.record:
        from .session import SessionRecorder
        recorder = SessionRecorder()

    # Execute mission
    client = MiniTelClient(config, recorder)
    override_code = client.execute_mission()

    # Save session recording if enabled
    if recorder:
        try:
            session_file = recorder.save_session()
            print(f"Session recorded: {session_file}")
        except Exception as e:
            print(f"Warning: Failed to save session recording: {e}")

    if override_code:
        print(f"\n🚨 MISSION SUCCESS! Override code: {override_code}")
        print("Report this code to NORAD Command immediately!")
        return 0
    else:
        print("\n💀 MISSION FAILED! JOSHUA remains in control.")
        print("The world is doomed.")
        return 1


if __name__ == "__main__":
    exit(main())