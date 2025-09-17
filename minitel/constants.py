"""
MiniTel-Lite Protocol Constants

Centralized definition of all protocol constants, magic numbers,
and repeated values to improve maintainability and reduce errors.
"""

# Protocol Frame Structure Constants
COMMAND_SIZE = 1        # bytes - Command field size
NONCE_SIZE = 4          # bytes - Nonce field size (32-bit big-endian)
HASH_SIZE = 32          # bytes - SHA-256 hash size
LENGTH_PREFIX_SIZE = 2  # bytes - Wire format length prefix size

# Protocol Limits
MAX_PAYLOAD_SIZE = 65535        # bytes - Maximum payload size (16-bit limit)
MAX_FRAME_SIZE = 65535          # bytes - Maximum total frame size
MIN_FRAME_SIZE = COMMAND_SIZE + NONCE_SIZE + HASH_SIZE  # 37 bytes minimum

# Nonce Constants
MAX_NONCE_VALUE = 0xFFFFFFFF    # Maximum 32-bit unsigned integer
MIN_NONCE_VALUE = 0             # Minimum nonce value

# Command Code Limits
MAX_COMMAND_CODE = 255          # Maximum 8-bit unsigned integer
MIN_COMMAND_CODE = 0            # Minimum command code

# Validation Constants
MAX_HOSTNAME_LENGTH = 253       # Maximum valid hostname length (RFC compliant)
MAX_OVERRIDE_CODE_LENGTH = 100  # Maximum override code length
MIN_OVERRIDE_CODE_LENGTH = 3    # Minimum override code length

# Network Constants
MIN_PORT_NUMBER = 1             # Minimum valid port number
MAX_PORT_NUMBER = 65535         # Maximum valid port number
MAX_TIMEOUT_SECONDS = 300       # Maximum connection timeout (5 minutes)

# Hash Algorithm
HASH_ALGORITHM = "sha256"       # Hash algorithm name
HASH_DIGEST_SIZE = HASH_SIZE    # Alias for consistency

# Wire Format Constants
WIRE_ENCODING = "utf-8"         # Default text encoding
BASE64_ENCODING = "ascii"       # Base64 uses ASCII characters

# Protocol Version Information
PROTOCOL_NAME = "MiniTel-Lite"
PROTOCOL_VERSION = "3.0"
PROTOCOL_DESCRIPTION = f"{PROTOCOL_NAME} Protocol v{PROTOCOL_VERSION}"

# Error Messages (commonly used strings)
NONCE_VIOLATION_MSG = "PROTOCOL VIOLATION: Nonce sequence mismatch"
CONNECTION_TIMEOUT_MSG = "Connection timeout"
INVALID_FRAME_MSG = "Invalid frame format"
HASH_VALIDATION_FAILED_MSG = "Hash validation failed"

# Frame Component Positions (for parsing)
COMMAND_OFFSET = 0
NONCE_OFFSET = COMMAND_OFFSET + COMMAND_SIZE
PAYLOAD_OFFSET = NONCE_OFFSET + NONCE_SIZE
# Hash is always at the end: -HASH_SIZE

# Calculated Constants (for validation and convenience)
HEADER_SIZE = COMMAND_SIZE + NONCE_SIZE  # Size of CMD + NONCE
FRAME_OVERHEAD = HEADER_SIZE + HASH_SIZE  # Total overhead per frame
WIRE_OVERHEAD = LENGTH_PREFIX_SIZE        # Wire format overhead

# Security Constants
SSL_VERIFY_DEFAULT = True       # Default SSL verification setting
SSL_TIMEOUT_DEFAULT = 30        # Default SSL handshake timeout

# Session Recording Constants
SESSION_FILE_EXTENSION = ".json"
SESSION_TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"
SESSION_DIRECTORY_DEFAULT = "sessions"

# Logging Constants
LOG_FORMAT_NORAD = '%(asctime)s - NORAD-%(name)s - %(levelname)s - %(message)s'
LOG_LEVEL_DEFAULT = "INFO"

# Client Configuration Defaults
DEFAULT_TIMEOUT = 5.0           # Default connection timeout
DEFAULT_MAX_RETRIES = 3         # Default retry attempts
DEFAULT_RETRY_DELAY = 1.0       # Default delay between retries

# Validation Patterns (commonly used)
HOSTNAME_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
OVERRIDE_CODE_PATTERN = r'^[A-Za-z0-9\-_]+$'

# Mission Context Constants
MISSION_NAME = "JOSHUA INFILTRATION"
AGENT_CODENAME = "LIGHTMAN"
MISSION_SUCCESS_MSG = "🚨 MISSION SUCCESS! Override code:"
MISSION_FAILED_MSG = "💀 MISSION FAILED! JOSHUA remains in control."

# Contest Requirements
MIN_TEST_COVERAGE = 80          # Minimum required test coverage percentage
CONTEST_REPO_TYPES = ["GitHub", "GitLab", "Bitbucket"]