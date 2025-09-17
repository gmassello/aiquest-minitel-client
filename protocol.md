MiniTel-Lite Protocol Specification
Version: 3.0
Date: January 2025
Status: Current
Overview
MiniTel-Lite is a minimalist TCP-based protocol designed for educational purposes and system testing. The protocol has evolved through three major versions, each adding enhanced security, state management, and resource control features.

Protocol Evolution
Version 3.0 (Current)
Purpose: Resource management with automatic connection timeout
Commands: HELLO, DUMP, STOP_CMD (unchanged from v2.0)
Frame Structure: CMD + NONCE + PAYLOAD + HASH (unchanged from v2.0)
Features: 2-second connection timeout, background cleanup, enhanced metrics
Wire Protocol Specification
Frame Format (v2.0+)
Wire Format:

LEN (2 bytes, big-endian) | DATA_B64 (LEN bytes, Base64 encoded)
Binary Frame (after Base64 decoding):

CMD (1 byte) | NONCE (4 bytes, big-endian) | PAYLOAD (0-65535 bytes) | HASH (32 bytes SHA-256)
Encoding / Decoding Rules
Encoding Process
Build binary frame: CMD + NONCE + PAYLOAD + HASH
Calculate hash: SHA-256(CMD + NONCE + PAYLOAD)
Base64 encode the complete frame (no newlines)
Prepend 2-byte length prefix (big-endian)
Decoding Process
Read 2-byte length prefix
Read exactly length bytes of Base64 data
Base64 decode to get binary frame
Extract CMD, NONCE, PAYLOAD, HASH
Verify hash: SHA-256(CMD + NONCE + PAYLOAD)
Reject frame if hash validation fails
Field Descriptions
LEN – unsigned 16-bit, big-endian, length of Base64-encoded data
CMD – command ID (see Commands)
NONCE – 4-byte unsigned integer, big-endian, sequence tracking
PAYLOAD – command-specific data, UTF-8 prior to encoding
HASH – 32-byte SHA-256 digest of CMD + NONCE + PAYLOAD
Commands
Command	Code	Direction	Purpose	Response
HELLO	0x01	Client → Server	Initialize connection	0x81 HELLO_ACK
DUMP	0x02	Client → Server	Request secret (stateful)	0x82 DUMP_FAILED or 0x83 DUMP_OK
STOP_CMD	0x04	Client → Server	Acknowledgment/testing	0x84 STOP_OK
HELLO Command (0x01)
Purpose: Initialize connection and nonce tracking
Payload: Empty (0 bytes)
Response: HELLO_ACK (0x81) with empty payload
State Changes: Initializes connection nonce tracking, resets DUMP counter to 0, sets last_command to HELLO
DUMP Command (0x02)
Purpose: Request a memory dump
Payload: Empty (0 bytes)
Response:DUMP_OK (0x83) or DUMP_FAILED (0x82)
Nonce Sequence
Client messages: Use expected nonce value
Server responses: Increment nonce by 1
Validation: Any nonce mismatch results in immediate disconnection
Example Sequence
Client HELLO (nonce=0) → Server HELLO_ACK (nonce=1)
Client DUMP (nonce=2) → Server DUMP_FAILED (nonce=3)
Client DUMP (nonce=4) → Server DUMP_OK (nonce=5)
Client STOP_CMD (nonce=6) → Server STOP_OK (nonce=7)
Error Handling
Protocol Violations
Invalid nonce: Immediate disconnection
Unknown command: Immediate disconnection
Malformed frame: Immediate disconnection
Hash validation failure: Immediate disconnection
Invalid Base64: Immediate disconnection


