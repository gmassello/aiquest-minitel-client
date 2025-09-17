"""
Test suite for input validation framework
"""

import pytest
import ipaddress
from minitel.validation import (
    InputValidator, ValidationResult, ValidationError,
    HostValidationError, PortValidationError, PayloadValidationError,
    validate_host_or_raise, validate_port_or_raise, validate_payload_or_raise
)
from minitel.constants import (
    MAX_HOSTNAME_LENGTH, MAX_PAYLOAD_SIZE, MAX_PORT_NUMBER,
    MAX_TIMEOUT_SECONDS, MAX_NONCE_VALUE, MAX_COMMAND_CODE,
    DEFAULT_TIMEOUT
)


class TestInputValidator:
    """Test cases for InputValidator class"""

    def test_validate_host_valid_ip(self):
        """Test validation of valid IP addresses"""
        # IPv4
        result = InputValidator.validate_host("192.168.1.1")
        assert result.is_valid
        assert result.sanitized_value == "192.168.1.1"

        # IPv6
        result = InputValidator.validate_host("::1")
        assert result.is_valid
        assert result.sanitized_value == "::1"

        # Loopback
        result = InputValidator.validate_host("127.0.0.1")
        assert result.is_valid

    def test_validate_host_valid_hostname(self):
        """Test validation of valid hostnames"""
        result = InputValidator.validate_host("example.com")
        assert result.is_valid
        assert result.sanitized_value == "example.com"

        result = InputValidator.validate_host("subdomain.example.com")
        assert result.is_valid

        result = InputValidator.validate_host("host-with-dashes.com")
        assert result.is_valid

    def test_validate_host_invalid_cases(self):
        """Test validation of invalid hosts"""
        # Empty string
        result = InputValidator.validate_host("")
        assert not result.is_valid

        # Invalid hostname format
        result = InputValidator.validate_host("-invalid.com")
        assert not result.is_valid

        result = InputValidator.validate_host("invalid-.com")
        assert not result.is_valid

        # Consecutive dots
        result = InputValidator.validate_host("invalid..com")
        assert not result.is_valid

        # Multicast IP
        result = InputValidator.validate_host("224.0.0.1")
        assert not result.is_valid

        # Too long hostname
        long_hostname = "a" * (MAX_HOSTNAME_LENGTH + 50) + ".com"
        result = InputValidator.validate_host(long_hostname)
        assert not result.is_valid

    def test_validate_port_valid_cases(self):
        """Test validation of valid port numbers"""
        # Valid ports
        result = InputValidator.validate_port(80)
        assert result.is_valid
        assert result.sanitized_value == 80

        result = InputValidator.validate_port("443")
        assert result.is_valid
        assert result.sanitized_value == 443

        result = InputValidator.validate_port(MAX_PORT_NUMBER)
        assert result.is_valid

        result = InputValidator.validate_port(1)
        assert result.is_valid

    def test_validate_port_invalid_cases(self):
        """Test validation of invalid port numbers"""
        # Out of range
        result = InputValidator.validate_port(0)
        assert not result.is_valid

        result = InputValidator.validate_port(65536)
        assert not result.is_valid

        # Invalid format
        result = InputValidator.validate_port("not_a_number")
        assert not result.is_valid

        result = InputValidator.validate_port(3.14)
        assert not result.is_valid

    def test_validate_timeout_valid_cases(self):
        """Test validation of valid timeout values"""
        result = InputValidator.validate_timeout(DEFAULT_TIMEOUT)
        assert result.is_valid
        assert result.sanitized_value == DEFAULT_TIMEOUT

        result = InputValidator.validate_timeout("10.5")
        assert result.is_valid
        assert result.sanitized_value == 10.5

        result = InputValidator.validate_timeout(1)
        assert result.is_valid

    def test_validate_timeout_invalid_cases(self):
        """Test validation of invalid timeout values"""
        # Negative
        result = InputValidator.validate_timeout(-1)
        assert not result.is_valid

        # Zero
        result = InputValidator.validate_timeout(0)
        assert not result.is_valid

        # Too large
        result = InputValidator.validate_timeout(500)
        assert not result.is_valid

        # Invalid format
        result = InputValidator.validate_timeout("not_a_number")
        assert not result.is_valid

    def test_validate_payload_valid_cases(self):
        """Test validation of valid payloads"""
        result = InputValidator.validate_payload(b"test payload")
        assert result.is_valid
        assert result.sanitized_value == b"test payload"

        result = InputValidator.validate_payload(b"")
        assert result.is_valid

        # Large but valid payload
        large_payload = b"x" * 1000
        result = InputValidator.validate_payload(large_payload)
        assert result.is_valid

    def test_validate_payload_invalid_cases(self):
        """Test validation of invalid payloads"""
        # Not bytes
        result = InputValidator.validate_payload("string")
        assert not result.is_valid

        # Too large
        huge_payload = b"x" * 70000
        result = InputValidator.validate_payload(huge_payload)
        assert not result.is_valid

        # Contains null bytes
        null_payload = b"test\x00payload"
        result = InputValidator.validate_payload(null_payload)
        assert not result.is_valid

    def test_validate_override_code_valid_cases(self):
        """Test validation of valid override codes"""
        result = InputValidator.validate_override_code("ABC123")
        assert result.is_valid
        assert result.sanitized_value == "ABC123"

        result = InputValidator.validate_override_code("test-code_123")
        assert result.is_valid
        assert result.sanitized_value == "test-code_123"

        # With whitespace (should be trimmed)
        result = InputValidator.validate_override_code("  ABC123  ")
        assert result.is_valid
        assert result.sanitized_value == "ABC123"

    def test_validate_override_code_invalid_cases(self):
        """Test validation of invalid override codes"""
        # Empty
        result = InputValidator.validate_override_code("")
        assert not result.is_valid

        # Too short
        result = InputValidator.validate_override_code("AB")
        assert not result.is_valid

        # Too long
        long_code = "A" * 150
        result = InputValidator.validate_override_code(long_code)
        assert not result.is_valid

        # Invalid characters
        result = InputValidator.validate_override_code("ABC@123")
        assert not result.is_valid

        result = InputValidator.validate_override_code("ABC 123")
        assert not result.is_valid

    def test_validate_nonce_valid_cases(self):
        """Test validation of valid nonce values"""
        result = InputValidator.validate_nonce(0)
        assert result.is_valid
        assert result.sanitized_value == 0

        result = InputValidator.validate_nonce(0xFFFFFFFF)
        assert result.is_valid

        result = InputValidator.validate_nonce("12345")
        assert result.is_valid
        assert result.sanitized_value == 12345

    def test_validate_nonce_invalid_cases(self):
        """Test validation of invalid nonce values"""
        # Out of range
        result = InputValidator.validate_nonce(-1)
        assert not result.is_valid

        result = InputValidator.validate_nonce(MAX_NONCE_VALUE + 1)  # 2^32
        assert not result.is_valid

        # Invalid format
        result = InputValidator.validate_nonce("not_a_number")
        assert not result.is_valid

        result = InputValidator.validate_nonce(3.14)
        assert not result.is_valid

    def test_validate_command_code_valid_cases(self):
        """Test validation of valid command codes"""
        result = InputValidator.validate_command_code(0x01)
        assert result.is_valid
        assert result.sanitized_value == 0x01

        result = InputValidator.validate_command_code(255)
        assert result.is_valid

        result = InputValidator.validate_command_code("128")
        assert result.is_valid
        assert result.sanitized_value == 128

    def test_validate_command_code_invalid_cases(self):
        """Test validation of invalid command codes"""
        # Out of range
        result = InputValidator.validate_command_code(-1)
        assert not result.is_valid

        result = InputValidator.validate_command_code(256)
        assert not result.is_valid

        # Invalid format
        result = InputValidator.validate_command_code("not_a_number")
        assert not result.is_valid

        result = InputValidator.validate_command_code(3.14)
        assert not result.is_valid


class TestValidationHelpers:
    """Test cases for validation helper functions"""

    def test_validate_host_or_raise_success(self):
        """Test successful host validation"""
        result = validate_host_or_raise("example.com")
        assert result == "example.com"

        result = validate_host_or_raise("192.168.1.1")
        assert result == "192.168.1.1"

    def test_validate_host_or_raise_failure(self):
        """Test host validation failure raises exception"""
        with pytest.raises(HostValidationError):
            validate_host_or_raise("invalid..host")

        with pytest.raises(HostValidationError):
            validate_host_or_raise("")

    def test_validate_port_or_raise_success(self):
        """Test successful port validation"""
        result = validate_port_or_raise(80)
        assert result == 80

        result = validate_port_or_raise("443")
        assert result == 443

    def test_validate_port_or_raise_failure(self):
        """Test port validation failure raises exception"""
        with pytest.raises(PortValidationError):
            validate_port_or_raise(0)

        with pytest.raises(PortValidationError):
            validate_port_or_raise("invalid")

    def test_validate_payload_or_raise_success(self):
        """Test successful payload validation"""
        result = validate_payload_or_raise(b"test")
        assert result == b"test"

    def test_validate_payload_or_raise_failure(self):
        """Test payload validation failure raises exception"""
        with pytest.raises(PayloadValidationError):
            validate_payload_or_raise("not_bytes")

        with pytest.raises(PayloadValidationError):
            validate_payload_or_raise(b"test\x00payload")


class TestValidationResult:
    """Test cases for ValidationResult dataclass"""

    def test_validation_result_success(self):
        """Test ValidationResult for successful validation"""
        result = ValidationResult(
            is_valid=True,
            sanitized_value="cleaned_value"
        )
        assert result.is_valid
        assert result.sanitized_value == "cleaned_value"
        assert result.error_message is None

    def test_validation_result_failure(self):
        """Test ValidationResult for failed validation"""
        result = ValidationResult(
            is_valid=False,
            error_message="Validation failed"
        )
        assert not result.is_valid
        assert result.error_message == "Validation failed"
        assert result.sanitized_value is None


class TestValidationIntegration:
    """Integration tests for validation framework"""

    def test_validation_with_real_world_values(self):
        """Test validation with realistic input values"""
        # Valid production-like configuration
        host_result = InputValidator.validate_host("production.example.com")
        port_result = InputValidator.validate_port(443)
        timeout_result = InputValidator.validate_timeout(30.0)

        assert all([
            host_result.is_valid,
            port_result.is_valid,
            timeout_result.is_valid
        ])

        # Valid development configuration
        host_result = InputValidator.validate_host("localhost")
        port_result = InputValidator.validate_port(8080)

        assert all([
            host_result.is_valid,
            port_result.is_valid
        ])

    def test_validation_edge_cases(self):
        """Test validation with edge case values"""
        # Maximum valid values
        max_port = InputValidator.validate_port(MAX_PORT_NUMBER)
        max_timeout = InputValidator.validate_timeout(MAX_TIMEOUT_SECONDS)
        large_payload = InputValidator.validate_payload(b"x" * MAX_PAYLOAD_SIZE)

        assert all([
            max_port.is_valid,
            max_timeout.is_valid,
            large_payload.is_valid
        ])

        # Minimum valid values
        min_port = InputValidator.validate_port(1)
        min_timeout = InputValidator.validate_timeout(0.1)
        min_code = InputValidator.validate_override_code("ABC")

        assert all([
            min_port.is_valid,
            min_timeout.is_valid,
            min_code.is_valid
        ])

    def test_security_validations(self):
        """Test security-focused validation scenarios"""
        # Injection attempts
        injection_attempts = [
            "host.com; rm -rf /",
            "host.com\nmalicious",
            "host.com\x00evil",
            "../../../etc/passwd"
        ]

        for attempt in injection_attempts:
            result = InputValidator.validate_host(attempt)
            assert not result.is_valid, f"Should reject injection attempt: {attempt}"

        # Payload security
        malicious_payloads = [
            b"payload\x00injection",
            b"x" * 100000,  # Too large
            "not_bytes_object"
        ]

        for payload in malicious_payloads:
            result = InputValidator.validate_payload(payload)
            assert not result.is_valid, f"Should reject malicious payload: {payload}"