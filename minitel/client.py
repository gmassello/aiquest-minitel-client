"""
MiniTel-Lite TCP Client
Agent LIGHTMAN's tool to infiltrate JOSHUA and retrieve override codes.
"""

import socket
import ssl
import time
import logging
from typing import Optional
from dataclasses import dataclass

from .protocol import (
    Command, Frame, ProtocolEncoder, ProtocolDecoder,
    NonceManager, ProtocolError, FrameValidationError
)
from .session import SessionRecorder
from .validation import (
    InputValidator, ValidationError,
    validate_host_or_raise, validate_port_or_raise, validate_payload_or_raise
)


@dataclass
class ConnectionConfig:
    """TCP connection configuration"""
    host: str
    port: int
    timeout: float = 5.0
    max_retries: int = 3
    retry_delay: float = 1.0
    use_ssl: bool = False
    ssl_verify: bool = True

    def __post_init__(self):
        """Validate configuration parameters"""
        # Validate and sanitize host
        self.host = validate_host_or_raise(self.host)

        # Validate and sanitize port
        self.port = validate_port_or_raise(self.port)

        # Validate timeout
        timeout_result = InputValidator.validate_timeout(self.timeout)
        if not timeout_result.is_valid:
            raise ValidationError(f"Invalid timeout: {timeout_result.error_message}")
        self.timeout = timeout_result.sanitized_value

        # Validate retry parameters
        if not isinstance(self.max_retries, int) or self.max_retries < 1:
            raise ValidationError("max_retries must be a positive integer")
        if not isinstance(self.retry_delay, (int, float)) or self.retry_delay < 0:
            raise ValidationError("retry_delay must be a non-negative number")


class ConnectionError(Exception):
    """TCP connection related errors"""
    pass


class MiniTelClient:
    """
    MiniTel-Lite TCP client for NORAD emergency protocol

    Handles connection management, protocol communication,
    and graceful error recovery.
    """

    def __init__(
        self,
        config: ConnectionConfig,
        session_recorder: Optional[SessionRecorder] = None
    ):
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
            sock = None
            try:
                self.logger.info(
                    f"Attempting connection to {self.config.host}:"
                    f"{self.config.port} (attempt {attempt + 1})"
                )

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)

                if self.config.use_ssl:
                    # Wrap socket with SSL/TLS
                    try:
                        context = ssl.create_default_context()
                        if not self.config.ssl_verify:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            self.logger.warning(
                                "SSL certificate verification disabled - "
                                "not recommended for production"
                            )

                        sock.connect((self.config.host, self.config.port))
                        sock = context.wrap_socket(
                            sock, server_hostname=self.config.host
                        )
                        self.logger.info("SSL/TLS connection established")

                        # Log SSL connection details
                        cipher = sock.cipher()
                        if cipher:
                            self.logger.debug(f"SSL cipher: {cipher[0]} {cipher[1]} {cipher[2]}")

                        cert = sock.getpeercert()
                        if cert and self.config.ssl_verify:
                            self.logger.debug(f"Server certificate subject: {cert.get('subject', 'Unknown')}")

                    except ssl.SSLError as e:
                        self.logger.error(f"SSL/TLS handshake failed: {e}")
                        raise ConnectionError(f"SSL connection failed: {e}")
                    except ssl.CertificateError as e:
                        self.logger.error(f"SSL certificate validation failed: {e}")
                        raise ConnectionError(f"SSL certificate error: {e}")
                    except Exception as e:
                        self.logger.error(f"SSL setup failed: {e}")
                        raise ConnectionError(f"SSL configuration error: {e}")
                else:
                    sock.connect((self.config.host, self.config.port))

                # Only assign to self.socket after successful connection
                self.socket = sock
                self.nonce_manager.reset()

                self.logger.info("Connection established successfully")
                return True

            except socket.timeout:
                self.logger.warning(
                    f"Connection timeout on attempt {attempt + 1}"
                )
            except ConnectionError as e:
                self.logger.warning(
                    f"Connection failed on attempt {attempt + 1}: {e}"
                )
            except socket.error as e:
                self.logger.warning(
                    f"Socket error on attempt {attempt + 1}: {e}"
                )
            except ssl.SSLError as e:
                self.logger.warning(
                    f"SSL error on attempt {attempt + 1}: {e}"
                )
            except Exception as e:
                self.logger.error(
                    f"Unexpected error on attempt {attempt + 1}: {e}"
                )

            # Clean up failed socket attempt
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass  # Ignore cleanup errors

            if attempt < self.config.max_retries - 1:
                self.logger.info(
                    f"Retrying in {self.config.retry_delay} seconds..."
                )
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
            # Validate payload
            payload = validate_payload_or_raise(payload)

            nonce = self.nonce_manager.get_next_client_nonce()
            frame_data = self.encoder.encode_frame(cmd, nonce, payload)

            self.logger.debug(f"Sending {cmd.name} command (nonce={nonce})")
            self.socket.send(frame_data)

            # Record session if recorder is available
            if self.session_recorder:
                self.session_recorder.record_request(cmd.name, nonce, payload)

            return True

        except ValidationError as e:
            self.logger.error(f"Payload validation failed: {e}")
            return False
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
                self.logger.error(
                    f"PROTOCOL VIOLATION: Nonce sequence mismatch. Expected {self.nonce_manager.get_expected_server_nonce()}, received {frame.nonce}. Terminating connection for security."
                )
                # Protocol requires immediate disconnection on nonce violation
                self.disconnect()
                return None

            # Record session if recorder is available
            if self.session_recorder:
                if frame.cmd in Command.__members__.values():
                    response_cmd = Command(frame.cmd).name
                else:
                    response_cmd = f"UNKNOWN_{frame.cmd}"
                self.session_recorder.record_response(
                    response_cmd, frame.nonce, frame.payload
                )

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

        Returns:
            Retrieved override code or None if mission failed
        """
        self.logger.info("=== MISSION START: JOSHUA INFILTRATION ===")

        try:
            # Execute mission phases
            if not self._establish_secure_connection():
                return None

            if not self._authenticate_with_joshua():
                return None

            override_code = self._retrieve_override_codes()
            if not override_code:
                return None

            self._terminate_session_gracefully()
            return override_code

        except Exception as e:
            self.logger.error(f"Mission failed with unexpected error: {e}")
            return None
        finally:
            self._cleanup_mission()

    def _establish_secure_connection(self) -> bool:
        """
        Phase 1: Establish connection to JOSHUA system

        Returns:
            True if connection successful, False otherwise
        """
        if not self.connect():
            self.logger.error("Mission failed: Unable to connect to JOSHUA")
            return False
        return True

    def _authenticate_with_joshua(self) -> bool:
        """
        Phase 2: Authenticate with HELLO protocol

        Returns:
            True if authentication successful, False otherwise
        """
        hello_response = self.send_hello()
        if not hello_response:
            self.logger.error("Mission failed: Authentication failed")
            return False
        return True

    def _retrieve_override_codes(self) -> Optional[str]:
        """
        Phase 3 & 4: Execute DUMP commands to retrieve override codes

        According to intelligence, first DUMP fails, second succeeds.

        Returns:
            Override code string if successful, None otherwise
        """
        # First DUMP attempt (expected to fail)
        dump1_response = self.send_dump()
        if not dump1_response:
            self.logger.error("Mission failed: First DUMP command failed")
            return None

        # Second DUMP attempt (should succeed)
        dump2_response = self.send_dump()
        if not dump2_response:
            self.logger.error("Mission failed: Second DUMP command failed")
            return None

        # Validate successful response
        if dump2_response.cmd == Command.DUMP_OK:
            override_code = self._extract_override_code(dump2_response.payload)
            if override_code:
                self.logger.info("SUCCESS: Override code retrieved successfully")
                return override_code
            else:
                self.logger.error("Mission failed: Invalid override code format")
                return None
        else:
            self.logger.error("Mission failed: Second DUMP did not return override code")
            return None

    def _terminate_session_gracefully(self) -> None:
        """
        Phase 5: Clean termination of JOSHUA session
        """
        self.send_stop()

    def _cleanup_mission(self) -> None:
        """
        Final cleanup: Always disconnect and log mission end
        """
        self.disconnect()
        self.logger.info("=== MISSION END ===")

    def _extract_override_code(self, payload: bytes) -> Optional[str]:
        """
        Safely extract and validate override code from payload

        Args:
            payload: Raw payload bytes from DUMP_OK response

        Returns:
            Validated override code string or None if invalid
        """
        if not payload:
            self.logger.error("Empty payload in DUMP_OK response")
            return None

        try:
            # Validate payload format
            payload = validate_payload_or_raise(payload)

            # Decode UTF-8 with strict validation
            override_code = payload.decode('utf-8')

            # Validate override code format and content
            validation_result = InputValidator.validate_override_code(override_code)
            if not validation_result.is_valid:
                self.logger.error(f"Override code validation failed: {validation_result.error_message}")
                return None

            return validation_result.sanitized_value

        except ValidationError as e:
            self.logger.error(f"Payload validation failed: {e}")
            return None
        except UnicodeDecodeError as e:
            self.logger.error(f"Invalid UTF-8 encoding in override code: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error extracting override code: {e}")
            return None


def main():
    """
    Command-line entry point for the MiniTel client.

    Parses command-line arguments, sets up the client,
    and runs the mission.
    """
    import argparse

    parser = argparse.ArgumentParser(description="NORAD MiniTel-Lite Emergency Client")
    parser.add_argument("--host", required=True, help="Server hostname")
    parser.add_argument("--port", type=int, required=True, help="Server port")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout")
    parser.add_argument("--record", action="store_true", help="Enable session recording")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS encryption")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL certificate verification (not recommended)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       default="INFO", help="Logging level")

    args = parser.parse_args()

    # Validate arguments using validation framework
    try:
        # Validate host
        validate_host_or_raise(args.host)

        # Validate port
        validate_port_or_raise(args.port)

        # Validate timeout
        timeout_result = InputValidator.validate_timeout(args.timeout)
        if not timeout_result.is_valid:
            parser.error(f"Invalid timeout: {timeout_result.error_message}")

    except ValidationError as e:
        parser.error(str(e))

    # Configure logging
    logging.basicConfig(level=getattr(logging, args.log_level))
    logger = logging.getLogger(__name__)

    # Setup configuration
    config = ConnectionConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        use_ssl=args.ssl,
        ssl_verify=not args.no_ssl_verify
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
            logger.info(f"Session recorded: {session_file}")
        except Exception as e:
            logger.warning(f"Failed to save session recording: {e}")

    # Final mission status output (user-facing)
    if override_code:
        logger.info("Mission completed successfully - override code retrieved")
        print(f"\n🚨 MISSION SUCCESS! Override code: {override_code}")
        print("Report this code to NORAD Command immediately!")
        return 0
    else:
        logger.error("Mission failed - unable to retrieve override code")
        print("\n💀 MISSION FAILED! JOSHUA remains in control.")
        print("The world is doomed.")
        return 1


if __name__ == "__main__":
    exit(main())
