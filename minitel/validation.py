"""
Input validation framework for MiniTel-Lite client
Provides comprehensive validation for all user inputs and protocol data.
"""

import re
import ipaddress
from typing import Any, Optional, Union
from dataclasses import dataclass


class ValidationError(Exception):
    """Base exception for validation errors"""
    pass


class HostValidationError(ValidationError):
    """Host/IP address validation error"""
    pass


class PortValidationError(ValidationError):
    """Port number validation error"""
    pass


class PayloadValidationError(ValidationError):
    """Payload data validation error"""
    pass


@dataclass
class ValidationResult:
    """Result of a validation operation"""
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_value: Optional[Any] = None


class InputValidator:
    """
    Comprehensive input validation framework

    Provides validation for network parameters, protocol data,
    and user inputs with security-focused sanitization.
    """

    # Regular expression patterns for common validations
    HOSTNAME_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )

    OVERRIDE_CODE_PATTERN = re.compile(r'^[A-Za-z0-9\-_]+$')

    # Security constraints
    MAX_HOSTNAME_LENGTH = 253
    MAX_PAYLOAD_SIZE = 65535
    MAX_OVERRIDE_CODE_LENGTH = 100
    MIN_OVERRIDE_CODE_LENGTH = 3

    @classmethod
    def validate_host(cls, host: str) -> ValidationResult:
        """
        Validate hostname or IP address

        Args:
            host: Hostname or IP address to validate

        Returns:
            ValidationResult with validation status and sanitized value
        """
        if not isinstance(host, str):
            return ValidationResult(
                is_valid=False,
                error_message="Host must be a string"
            )

        # Strip whitespace and convert to lowercase for hostnames
        sanitized_host = host.strip().lower()

        if not sanitized_host:
            return ValidationResult(
                is_valid=False,
                error_message="Host cannot be empty"
            )

        if len(sanitized_host) > cls.MAX_HOSTNAME_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_message=f"Host length exceeds maximum of {cls.MAX_HOSTNAME_LENGTH} characters"
            )

        # Try to parse as IP address first
        try:
            ip = ipaddress.ip_address(sanitized_host)
            # Additional security checks for IP addresses
            if ip.is_loopback and sanitized_host not in ['127.0.0.1', '::1']:
                return ValidationResult(
                    is_valid=False,
                    error_message="Invalid loopback address"
                )
            if ip.is_multicast:
                return ValidationResult(
                    is_valid=False,
                    error_message="Multicast addresses not allowed"
                )

            return ValidationResult(
                is_valid=True,
                sanitized_value=str(ip)
            )
        except ValueError:
            pass

        # Validate as hostname
        if not cls.HOSTNAME_PATTERN.match(sanitized_host):
            return ValidationResult(
                is_valid=False,
                error_message="Invalid hostname format"
            )

        # Additional hostname security checks
        if sanitized_host.startswith('-') or sanitized_host.endswith('-'):
            return ValidationResult(
                is_valid=False,
                error_message="Hostname cannot start or end with hyphen"
            )

        if '..' in sanitized_host:
            return ValidationResult(
                is_valid=False,
                error_message="Hostname cannot contain consecutive dots"
            )

        return ValidationResult(
            is_valid=True,
            sanitized_value=sanitized_host
        )

    @classmethod
    def validate_port(cls, port: Union[int, str]) -> ValidationResult:
        """
        Validate port number

        Args:
            port: Port number to validate (int or string)

        Returns:
            ValidationResult with validation status and sanitized value
        """
        # Convert string to int if needed
        if isinstance(port, str):
            try:
                port = int(port.strip())
            except ValueError:
                return ValidationResult(
                    is_valid=False,
                    error_message="Port must be a valid integer"
                )

        if not isinstance(port, int):
            return ValidationResult(
                is_valid=False,
                error_message="Port must be an integer"
            )

        if not (1 <= port <= 65535):
            return ValidationResult(
                is_valid=False,
                error_message="Port must be between 1 and 65535"
            )

        # Security check: warn about privileged ports
        if port < 1024:
            # Still valid, but log warning in calling code
            pass

        return ValidationResult(
            is_valid=True,
            sanitized_value=port
        )

    @classmethod
    def validate_timeout(cls, timeout: Union[float, str]) -> ValidationResult:
        """
        Validate timeout value

        Args:
            timeout: Timeout value to validate (float or string)

        Returns:
            ValidationResult with validation status and sanitized value
        """
        # Convert string to float if needed
        if isinstance(timeout, str):
            try:
                timeout = float(timeout.strip())
            except ValueError:
                return ValidationResult(
                    is_valid=False,
                    error_message="Timeout must be a valid number"
                )

        if not isinstance(timeout, (int, float)):
            return ValidationResult(
                is_valid=False,
                error_message="Timeout must be a number"
            )

        if timeout <= 0:
            return ValidationResult(
                is_valid=False,
                error_message="Timeout must be greater than 0"
            )

        if timeout > 300:  # 5 minutes max
            return ValidationResult(
                is_valid=False,
                error_message="Timeout cannot exceed 300 seconds"
            )

        return ValidationResult(
            is_valid=True,
            sanitized_value=float(timeout)
        )

    @classmethod
    def validate_payload(cls, payload: bytes) -> ValidationResult:
        """
        Validate protocol payload data

        Args:
            payload: Payload bytes to validate

        Returns:
            ValidationResult with validation status and sanitized value
        """
        if not isinstance(payload, bytes):
            return ValidationResult(
                is_valid=False,
                error_message="Payload must be bytes"
            )

        if len(payload) > cls.MAX_PAYLOAD_SIZE:
            return ValidationResult(
                is_valid=False,
                error_message=f"Payload size exceeds maximum of {cls.MAX_PAYLOAD_SIZE} bytes"
            )

        # Check for null bytes in text payloads (potential injection)
        if b'\x00' in payload:
            return ValidationResult(
                is_valid=False,
                error_message="Payload contains null bytes"
            )

        return ValidationResult(
            is_valid=True,
            sanitized_value=payload
        )

    @classmethod
    def validate_override_code(cls, code: str) -> ValidationResult:
        """
        Validate override code format and content

        Args:
            code: Override code string to validate

        Returns:
            ValidationResult with validation status and sanitized value
        """
        if not isinstance(code, str):
            return ValidationResult(
                is_valid=False,
                error_message="Override code must be a string"
            )

        # Strip whitespace
        sanitized_code = code.strip()

        if not sanitized_code:
            return ValidationResult(
                is_valid=False,
                error_message="Override code cannot be empty"
            )

        if len(sanitized_code) < cls.MIN_OVERRIDE_CODE_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_message=f"Override code must be at least {cls.MIN_OVERRIDE_CODE_LENGTH} characters"
            )

        if len(sanitized_code) > cls.MAX_OVERRIDE_CODE_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_message=f"Override code cannot exceed {cls.MAX_OVERRIDE_CODE_LENGTH} characters"
            )

        # Validate character set
        if not cls.OVERRIDE_CODE_PATTERN.match(sanitized_code):
            return ValidationResult(
                is_valid=False,
                error_message="Override code contains invalid characters (only alphanumeric, hyphens, and underscores allowed)"
            )

        return ValidationResult(
            is_valid=True,
            sanitized_value=sanitized_code
        )

    @classmethod
    def validate_nonce(cls, nonce: Union[int, str]) -> ValidationResult:
        """
        Validate nonce value

        Args:
            nonce: Nonce value to validate

        Returns:
            ValidationResult with validation status and sanitized value
        """
        # Convert string to int if needed
        if isinstance(nonce, str):
            try:
                nonce = int(nonce.strip())
            except ValueError:
                return ValidationResult(
                    is_valid=False,
                    error_message="Nonce must be a valid integer"
                )

        if not isinstance(nonce, int):
            return ValidationResult(
                is_valid=False,
                error_message="Nonce must be an integer"
            )

        # Nonce must be 32-bit unsigned integer
        if not (0 <= nonce <= 0xFFFFFFFF):
            return ValidationResult(
                is_valid=False,
                error_message="Nonce must be a 32-bit unsigned integer (0-4294967295)"
            )

        return ValidationResult(
            is_valid=True,
            sanitized_value=nonce
        )

    @classmethod
    def validate_command_code(cls, cmd: Union[int, str]) -> ValidationResult:
        """
        Validate command code value

        Args:
            cmd: Command code to validate

        Returns:
            ValidationResult with validation status and sanitized value
        """
        # Convert string to int if needed
        if isinstance(cmd, str):
            try:
                cmd = int(cmd.strip())
            except ValueError:
                return ValidationResult(
                    is_valid=False,
                    error_message="Command code must be a valid integer"
                )

        if not isinstance(cmd, int):
            return ValidationResult(
                is_valid=False,
                error_message="Command code must be an integer"
            )

        # Command must be 8-bit unsigned integer
        if not (0 <= cmd <= 255):
            return ValidationResult(
                is_valid=False,
                error_message="Command code must be an 8-bit unsigned integer (0-255)"
            )

        return ValidationResult(
            is_valid=True,
            sanitized_value=cmd
        )


def validate_and_raise(validator_func, value, exception_class=ValidationError):
    """
    Helper function to validate and raise exception if invalid

    Args:
        validator_func: Validation function to call
        value: Value to validate
        exception_class: Exception class to raise on validation failure

    Returns:
        Sanitized value if validation passes

    Raises:
        exception_class: If validation fails
    """
    result = validator_func(value)
    if not result.is_valid:
        raise exception_class(result.error_message)
    return result.sanitized_value


# Convenience functions for common validations
def validate_host_or_raise(host: str) -> str:
    """Validate host and raise HostValidationError if invalid"""
    return validate_and_raise(
        InputValidator.validate_host,
        host,
        HostValidationError
    )


def validate_port_or_raise(port: Union[int, str]) -> int:
    """Validate port and raise PortValidationError if invalid"""
    return validate_and_raise(
        InputValidator.validate_port,
        port,
        PortValidationError
    )


def validate_payload_or_raise(payload: bytes) -> bytes:
    """Validate payload and raise PayloadValidationError if invalid"""
    return validate_and_raise(
        InputValidator.validate_payload,
        payload,
        PayloadValidationError
    )