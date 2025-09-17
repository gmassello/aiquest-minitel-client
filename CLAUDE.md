# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the AI Quest Challenge codebase for developing a MiniTel-Lite client application. The mission is to build a TCP client that can:

1. Connect to a MiniTel-Lite server using a custom binary protocol
2. Authenticate using the HELLO protocol
3. Execute the DUMP command twice to retrieve an emergency override code
4. Handle server disconnections gracefully
5. Include session recording capabilities
6. Provide a TUI replay application for recorded sessions

## Protocol Implementation Requirements

### MiniTel-Lite Protocol v3.0
- **Wire Format**: `LEN (2 bytes, big-endian) | DATA_B64 (LEN bytes, Base64 encoded)`
- **Binary Frame**: `CMD (1 byte) | NONCE (4 bytes, big-endian) | PAYLOAD (0-65535 bytes) | HASH (32 bytes SHA-256)`
- **Commands**:
  - HELLO (0x01) → HELLO_ACK (0x81)
  - DUMP (0x02) → DUMP_FAILED (0x82) or DUMP_OK (0x83)
  - STOP_CMD (0x04) → STOP_OK (0x84)

### Critical Protocol Details
- Hash calculation: SHA-256(CMD + NONCE + PAYLOAD)
- Nonce sequence: Client uses expected nonce, server increments by 1
- Server has 2-second connection timeout
- Any protocol violation results in immediate disconnection

## Application Architecture Requirements

### Core Components Needed
1. **TCP Client**: Handle connection, protocol encoding/decoding, nonce management
2. **Session Recorder**: Capture all client-server interactions in timestamped JSON files
3. **TUI Replay App**: Standalone application with keybindings (N/n: next, P/p: previous, Q/q: quit)
4. **Error Handling**: Graceful handling of disconnections and protocol failures

### Quality Standards
- Minimum 80% test coverage with automated tests
- Clean architecture patterns and separation of concerns
- Comprehensive error handling and logging
- Security best practices (no hardcoded secrets)
- Detailed documentation and code comments

## Development Commands

Since this appears to be a fresh project directory with only documentation files, you'll need to:

1. Initialize the project with appropriate tooling (suggest language-specific setup)
2. Create test runner scripts
3. Implement build/lint commands as needed
4. Set up CI/CD if required

## Contest Requirements & Constraints

### Timeline
- Contest runs September 17-18th (24-hour window)
- Winner selection on September 24th
- Exercise released at 9:00 AM local time (Argentina, LA, Spain, India)

### Development Budget
- $10 in GEAI credits per participant
- API keys provided via email to eligible participants
- Use budget wisely for purposeful development, not experimentation

### Submission Requirements
**CRITICAL - Code Repository Must Include:**
- Public repository (GitHub, GitLab, Bitbucket)
- Anonymized/fictional data only
- NO hardcoded secrets or credentials
- NO confidential company information
- NO personal information
- README with architecture explanation and design decisions
- Minimum 80% automated test coverage
- Clean architecture and industry best practices

### Winner Selection Criteria
To win, participants must:
1. Submit correct secret code + public repository link
2. Achieve minimum 80% test coverage
3. Pass NORAD senior engineer code review
4. Be among first 3 participants meeting ALL criteria

**Evaluation focuses on:**
- Architecture quality
- Test coverage
- Security practices
- Maintainability
- Functional correctness (protocol + secret code)
- Documentation quality

### Legal & IP Considerations
- All submitted code transfers intellectual property rights to Globant
- Participants must be eligible Globant employees (Delivery PM Sr L2+ or Tech L3-L6)
- Code will be reviewed by NORAD engineering panel
- Submissions become property of organizer for any future use

## Mission Context

This is a time-sensitive challenge simulation where:
- The AI "JOSHUA" has compromised NORAD systems
- Agent LIGHTMAN must retrieve override codes before nuclear launch
- Success requires both functional correctness AND code quality
- Quality and completeness matter more than speed alone

## Server Connection

**Server Configuration:**
- Host: Provided via command-line parameter (`--host`)
- Port: Provided via command-line parameter (`--port`)

The application requires connection details as command-line parameters to allow for different server endpoints during testing and deployment. This ensures no hardcoded server information in the codebase.

**Security Note:** Server endpoints should never be hardcoded in source code or documentation to maintain security best practices and contest compliance.