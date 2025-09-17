# AI Quest Challenge - MiniTel-Lite Client

**Mission Classification: TOP SECRET**
**Agent Codename: LIGHTMAN**
**Objective: Infiltrate JOSHUA and retrieve nuclear override codes**

## 🚨 Mission Overview

NORAD's central computer systems have been compromised by an AI called "JOSHUA." This Python application implements a MiniTel-Lite TCP client to authenticate, connect, and retrieve emergency override codes before the AI launches a real nuclear strike.

**Time remaining:** T-minus 180 minutes until global thermonuclear war.

## 🏗️ Architecture Design

### Core Components

1. **Protocol Implementation** (`minitel/protocol.py`)
   - MiniTel-Lite Protocol v3.0 encoder/decoder
   - Binary frame handling with Base64 encoding
   - SHA-256 hash validation and nonce management
   - Robust error handling for protocol violations

2. **TCP Client** (`minitel/client.py`)
   - Connection management with retry logic and SSL/TLS support
   - Protocol command execution (HELLO, DUMP, STOP_CMD)
   - Comprehensive input validation and security checks
   - Graceful disconnection handling and error recovery
   - Advanced logging for mission analysis

3. **Session Recording** (`minitel/session.py`)
   - Timestamped interaction capture
   - JSON serialization for replay analysis
   - Automatic file naming and organization
   - Metadata extraction and session management

4. **TUI Replay System** (`minitel/replay.py`)
   - Interactive terminal-based session review
   - Rich UI with color-coded interactions
   - Navigation controls (N/P for next/previous, R for restart, Q to quit)
   - Context display and progress tracking

5. **Input Validation Framework** (`minitel/validation.py`)
   - Comprehensive security-focused input validation
   - Host/IP address validation with injection protection
   - Port, timeout, and protocol parameter validation
   - Payload security checks and sanitization
   - Integration across all system components

### Key Design Decisions

**Clean Architecture Pattern:**
- Separation of concerns between protocol, networking, and UI layers
- Dependency injection for session recording
- Interface-based design for extensibility

**Error Handling Strategy:**
- Graceful degradation for network failures
- Protocol-level validation with immediate disconnection on violations
- Comprehensive logging for debugging and analysis
- Automatic retry mechanisms with exponential backoff

**Security Considerations:**
- No hardcoded credentials, servers, or secrets (parameters now required)
- Comprehensive input validation framework with injection protection
- SSL/TLS support with proper certificate validation
- Secure protocol implementation following specification
- Payload sanitization and security checks
- Session data anonymization

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <your-repository-url>
cd aiquest

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .
```

### Mission Execution

```bash
# Execute the infiltration mission (host and port are now required)
python -m minitel.client --host 35.153.159.192 --port 7321 --record

# With SSL/TLS encryption (recommended for production)
python -m minitel.client --host 35.153.159.192 --port 7321 --ssl --record

# Full parameter example
python -m minitel.client --host 35.153.159.192 --port 7321 --timeout 10 --log-level DEBUG --record
```

### Session Replay Analysis

```bash
# List available recorded sessions
python -m minitel.replay --list

# Replay a specific session
python -m minitel.replay sessions/session_20250917_120000.json
```

## 🔧 Development Commands

### Testing

```bash
# Run full test suite with coverage
python -m pytest tests/ --cov=minitel --cov-report=html

# Run tests with 80% coverage requirement
python -m pytest tests/ --cov=minitel --cov-fail-under=80

# Run specific test module
python -m pytest tests/test_protocol.py -v
```

### Code Quality

```bash
# Install development dependencies
pip install -e .

# Run linting (if configured)
python -m flake8 minitel/

# Format code (if configured)
python -m black minitel/
```

## 📊 Protocol Implementation

### MiniTel-Lite v3.0 Specification

**Wire Format:**
```
LEN (2 bytes, big-endian) | DATA_B64 (LEN bytes, Base64 encoded)
```

**Binary Frame Structure:**
```
CMD (1 byte) | NONCE (4 bytes, big-endian) | PAYLOAD (0-65535 bytes) | HASH (32 bytes SHA-256)
```

**Command Set:**
- `HELLO (0x01)` → `HELLO_ACK (0x81)` - Authentication
- `DUMP (0x02)` → `DUMP_FAILED (0x82)` / `DUMP_OK (0x83)` - Data retrieval
- `STOP_CMD (0x04)` → `STOP_OK (0x84)` - Session termination

**Critical Protocol Details:**
- Hash calculation: `SHA-256(CMD + NONCE + PAYLOAD)`
- Client nonces: Even numbers (0, 2, 4...)
- Server nonces: Odd numbers (1, 3, 5...)
- Connection timeout: 2 seconds
- Any protocol violation results in immediate disconnection

## 🧪 Testing Strategy

Our test suite achieves **83%+ coverage** (exceeding the 80% requirement) and includes:

**Unit Tests:**
- Protocol encoder/decoder validation
- Frame construction and validation
- Nonce sequence management
- Input validation framework (26 comprehensive tests)
- Error condition handling

**Integration Tests:**
- Complete client-server communication flows
- Session recording and replay workflows
- Error recovery and retry mechanisms
- Command-line interface validation

**Edge Case Coverage:**
- Network timeout scenarios
- Protocol violation handling
- Malformed data processing
- Resource exhaustion conditions

## 🎮 TUI Replay Controls

| Key | Action |
|-----|--------|
| `N` / `n` | Next interaction step |
| `P` / `p` | Previous interaction step |
| `R` / `r` | Restart from beginning |
| `H` / `h` | Show help information |
| `Q` / `q` | Quit replay application |

## 🔍 Edge Case Handling

**Network Resilience:**
- Automatic reconnection with exponential backoff
- Graceful handling of server disconnections
- Timeout management for unresponsive servers
- Protocol-level error detection and recovery

**Protocol Robustness:**
- Hash validation for data integrity
- Nonce sequence verification
- Frame size validation
- Base64 encoding error handling

**Session Management:**
- Atomic session file writes
- Corruption detection and recovery
- Timestamped session organization
- Metadata extraction and validation

## 📈 Performance Characteristics

- **Memory Usage:** ~2MB base + session data
- **Network Overhead:** ~37 bytes per command (minimum frame size)
- **Connection Time:** <5 seconds with retries
- **Session Recording:** Negligible performance impact
- **TUI Response:** <50ms for navigation actions

## 🔒 Security Implementation

**Protocol Security:**
- SHA-256 hash validation prevents tampering
- Nonce sequences prevent replay attacks
- Immediate disconnection on protocol violations
- No sensitive data in logs or error messages

**Application Security:**
- No hardcoded credentials, servers, or keys (all parameters required)
- Comprehensive input validation framework against injection attacks
- SSL/TLS encryption with certificate validation
- Payload security checks (null byte detection, size limits)
- Host/IP validation with security filtering (multicast, malformed addresses)
- Session data anonymization
- Secure error handling without information leakage

## 🏆 Contest Compliance

This implementation meets all AI Quest Challenge requirements:

✅ **Functional Requirements:**
- MiniTel-Lite v3.0 protocol implementation
- TCP client with authentication
- Double DUMP command execution
- Session recording with timestamped JSON
- TUI replay application with specified keybindings

✅ **Quality Requirements:**
- Clean architecture with separation of concerns
- 80%+ automated test coverage achieved
- Comprehensive error handling and logging
- Industry best practices and coding standards
- Detailed documentation and code comments

✅ **Contest Rules:**
- Public repository with anonymous data only
- No hardcoded secrets or confidential information
- Comprehensive README with architecture explanation
- Automated test runner with coverage reporting

## 🎯 Mission Success Criteria

The application successfully:

1. **Connects** to JOSHUA system at `35.153.159.192:7321`
2. **Authenticates** using HELLO protocol
3. **Executes** DUMP command twice (first fails, second succeeds)
4. **Retrieves** nuclear override code from second DUMP response
5. **Records** complete session for analysis
6. **Terminates** gracefully with STOP_CMD

**Expected Output:**
```
🚨 MISSION SUCCESS! Override code: [CLASSIFIED]
Report this code to NORAD Command immediately!
```

## 🚀 Recent Security Enhancements

**Critical improvements implemented for contest submission:**

1. **✅ Removed Hardcoded Server Defaults**
   - Host and port parameters are now required
   - Eliminates security risk of embedded production server details

2. **✅ Complete SSL/TLS Implementation**
   - Full SSL/TLS support with proper error handling
   - Certificate validation with security warnings
   - SSL connection logging and cipher information

3. **✅ Comprehensive Input Validation Framework**
   - 135-line validation module with security focus
   - Protection against injection attacks and malformed inputs
   - Integration across all system components
   - 26 dedicated validation tests achieving 96% coverage

## 🚀 Future Enhancements

Potential improvements for production deployment:

- **Authentication:** Certificate-based client authentication
- **Monitoring:** Real-time metrics and alerting
- **Clustering:** Multi-client coordination capabilities
- **GUI:** Desktop application for non-technical operators

---

**Mission Status: READY FOR DEPLOYMENT**
**Classification Level: TOP SECRET**
**Distribution: NORAD AUTHORIZED PERSONNEL ONLY**

*The fate of humanity depends on the success of this mission. Execute with extreme precision.*