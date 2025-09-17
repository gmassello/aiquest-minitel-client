"""
Tests for Session Recording and Management
Validates session capture, storage, and replay functionality.
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, mock_open

from minitel.session import SessionEntry, SessionRecorder, SessionLoader


class TestSessionEntry:
    """Test SessionEntry dataclass"""

    def test_session_entry_creation(self):
        """Test creating a SessionEntry"""
        entry = SessionEntry(
            timestamp=1234567890.123,
            step_number=1,
            interaction_type="request",
            command="HELLO",
            nonce=0,
            payload_data="test_payload",
            payload_size=12
        )

        assert entry.timestamp == 1234567890.123
        assert entry.step_number == 1
        assert entry.interaction_type == "request"
        assert entry.command == "HELLO"
        assert entry.nonce == 0
        assert entry.payload_data == "test_payload"
        assert entry.payload_size == 12

    def test_session_entry_to_dict(self):
        """Test converting SessionEntry to dictionary"""
        entry = SessionEntry(
            timestamp=1234567890.123,
            step_number=1,
            interaction_type="request",
            command="HELLO",
            nonce=0,
            payload_data="test",
            payload_size=4
        )

        data = entry.to_dict()
        expected = {
            "timestamp": 1234567890.123,
            "step_number": 1,
            "interaction_type": "request",
            "command": "HELLO",
            "nonce": 0,
            "payload_data": "test",
            "payload_size": 4
        }

        assert data == expected

    def test_session_entry_from_dict(self):
        """Test creating SessionEntry from dictionary"""
        data = {
            "timestamp": 1234567890.123,
            "step_number": 1,
            "interaction_type": "response",
            "command": "HELLO_ACK",
            "nonce": 1,
            "payload_data": "",
            "payload_size": 0
        }

        entry = SessionEntry.from_dict(data)

        assert entry.timestamp == 1234567890.123
        assert entry.step_number == 1
        assert entry.interaction_type == "response"
        assert entry.command == "HELLO_ACK"
        assert entry.nonce == 1
        assert entry.payload_data == ""
        assert entry.payload_size == 0


class TestSessionRecorder:
    """Test SessionRecorder functionality"""

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_recorder_initialization(self):
        """Test SessionRecorder initialization"""
        with patch('pathlib.Path.mkdir'):
            recorder = SessionRecorder("test_dir")
            assert recorder.output_dir == Path("test_dir")
            assert len(recorder.session_entries) == 0
            assert recorder.step_counter == 0
            assert recorder.session_id is not None

    def test_record_request(self):
        """Test recording a request"""
        recorder = SessionRecorder()
        recorder.record_request("HELLO", 0, b"test_payload")

        assert len(recorder.session_entries) == 1
        entry = recorder.session_entries[0]

        assert entry.step_number == 1
        assert entry.interaction_type == "request"
        assert entry.command == "HELLO"
        assert entry.nonce == 0
        assert entry.payload_data == "test_payload"
        assert entry.payload_size == 12

    def test_record_request_binary_payload(self):
        """Test recording request with binary payload"""
        recorder = SessionRecorder()
        binary_payload = b'\x00\x01\x02\xff'  # Binary data that can't be decoded as UTF-8

        recorder.record_request("DUMP", 2, binary_payload)

        entry = recorder.session_entries[0]
        # Should be base64 encoded
        import base64
        expected_b64 = base64.b64encode(binary_payload).decode('ascii')
        assert entry.payload_data == expected_b64

    def test_record_request_empty_payload(self):
        """Test recording request with empty payload"""
        recorder = SessionRecorder()
        recorder.record_request("HELLO", 0, b"")

        entry = recorder.session_entries[0]
        assert entry.payload_data == ""
        assert entry.payload_size == 0

    def test_record_response(self):
        """Test recording a response"""
        recorder = SessionRecorder()
        recorder.record_response("HELLO_ACK", 1, b"response_data")

        assert len(recorder.session_entries) == 1
        entry = recorder.session_entries[0]

        assert entry.step_number == 1
        assert entry.interaction_type == "response"
        assert entry.command == "HELLO_ACK"
        assert entry.nonce == 1
        assert entry.payload_data == "response_data"
        assert entry.payload_size == 13

    def test_record_sequence(self):
        """Test recording a sequence of interactions"""
        recorder = SessionRecorder()

        # Record sequence: request -> response -> request -> response
        recorder.record_request("HELLO", 0, b"")
        recorder.record_response("HELLO_ACK", 1, b"")
        recorder.record_request("DUMP", 2, b"")
        recorder.record_response("DUMP_OK", 3, b"secret_code")

        assert len(recorder.session_entries) == 4
        assert recorder.step_counter == 4

        # Verify sequence
        entries = recorder.session_entries
        assert entries[0].interaction_type == "request"
        assert entries[0].command == "HELLO"
        assert entries[1].interaction_type == "response"
        assert entries[1].command == "HELLO_ACK"
        assert entries[2].interaction_type == "request"
        assert entries[2].command == "DUMP"
        assert entries[3].interaction_type == "response"
        assert entries[3].command == "DUMP_OK"

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_save_session(self, mock_json_dump, mock_file):
        """Test saving session to file"""
        recorder = SessionRecorder("test_dir")
        recorder.record_request("HELLO", 0, b"test")

        result_path = recorder.save_session()

        # Verify file operations
        mock_file.assert_called_once()
        mock_json_dump.assert_called_once()

        # Verify return value
        assert result_path is not None

    def test_get_session_summary_empty(self):
        """Test session summary with no interactions"""
        recorder = SessionRecorder()
        summary = recorder.get_session_summary()

        assert summary["status"] == "No interactions recorded"

    def test_get_session_summary_with_data(self):
        """Test session summary with recorded interactions"""
        recorder = SessionRecorder()

        # Record some interactions
        recorder.record_request("HELLO", 0, b"test1")
        recorder.record_response("HELLO_ACK", 1, b"test2")
        recorder.record_request("DUMP", 2, b"test3")

        summary = recorder.get_session_summary()

        assert summary["session_id"] == recorder.session_id
        assert summary["total_interactions"] == 3
        assert summary["requests_sent"] == 2
        assert summary["responses_received"] == 1
        assert "HELLO" in summary["command_breakdown"]
        assert "HELLO_ACK" in summary["command_breakdown"]
        assert "DUMP" in summary["command_breakdown"]
        assert summary["average_payload_size"] == (5 + 5 + 5) / 3  # "test1", "test2", "test3"


class TestSessionLoader:
    """Test SessionLoader functionality"""

    def test_load_session_success(self):
        """Test successful session loading"""
        # Create test session data
        session_data = {
            "session_metadata": {
                "session_id": "test_session",
                "start_time": 1234567890,
                "end_time": 1234567900,
                "total_interactions": 2
            },
            "interactions": [
                {
                    "timestamp": 1234567891.0,
                    "step_number": 1,
                    "interaction_type": "request",
                    "command": "HELLO",
                    "nonce": 0,
                    "payload_data": "",
                    "payload_size": 0
                },
                {
                    "timestamp": 1234567892.0,
                    "step_number": 2,
                    "interaction_type": "response",
                    "command": "HELLO_ACK",
                    "nonce": 1,
                    "payload_data": "",
                    "payload_size": 0
                }
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(session_data))):
            entries = SessionLoader.load_session("test_file.json")

        assert len(entries) == 2
        assert entries[0].command == "HELLO"
        assert entries[0].interaction_type == "request"
        assert entries[1].command == "HELLO_ACK"
        assert entries[1].interaction_type == "response"

    def test_load_session_file_not_found(self):
        """Test loading non-existent session file"""
        with pytest.raises(FileNotFoundError, match="Session file not found"):
            SessionLoader.load_session("nonexistent.json")

    def test_load_session_invalid_json(self):
        """Test loading session file with invalid JSON"""
        with patch('builtins.open', mock_open(read_data="invalid json")):
            with pytest.raises(ValueError, match="Invalid JSON in session file"):
                SessionLoader.load_session("invalid.json")

    def test_load_session_missing_interactions(self):
        """Test loading session file missing interactions key"""
        session_data = {"session_metadata": {}}

        with patch('builtins.open', mock_open(read_data=json.dumps(session_data))):
            with pytest.raises(ValueError, match="Invalid session file format"):
                SessionLoader.load_session("invalid.json")

    def test_get_session_metadata(self):
        """Test extracting session metadata"""
        metadata = {
            "session_id": "test_session",
            "start_time": 1234567890,
            "end_time": 1234567900,
            "total_interactions": 5
        }
        session_data = {
            "session_metadata": metadata,
            "interactions": []
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(session_data))):
            result = SessionLoader.get_session_metadata("test.json")

        assert result == metadata

    def test_get_session_metadata_error(self):
        """Test metadata extraction with file error"""
        with patch('builtins.open', side_effect=FileNotFoundError()):
            with pytest.raises(ValueError, match="Error reading session metadata"):
                SessionLoader.get_session_metadata("nonexistent.json")

    @patch('pathlib.Path.glob')
    @patch('pathlib.Path.exists')
    def test_list_available_sessions(self, mock_exists, mock_glob):
        """Test listing available sessions"""
        mock_exists.return_value = True

        # Mock session files
        mock_file1 = Path("session_20250101_120000.json")
        mock_file2 = Path("session_20250101_130000.json")
        mock_glob.return_value = [mock_file1, mock_file2]

        # Mock metadata for each file
        metadata1 = {"session_id": "session1", "start_time": 1234567890}
        metadata2 = {"session_id": "session2", "start_time": 1234567900}

        with patch.object(SessionLoader, 'get_session_metadata') as mock_get_metadata:
            mock_get_metadata.side_effect = [metadata1, metadata2]

            sessions = SessionLoader.list_available_sessions("test_dir")

        assert len(sessions) == 2
        # Should be sorted by start_time (newest first)
        assert sessions[0]["metadata"]["session_id"] == "session2"
        assert sessions[1]["metadata"]["session_id"] == "session1"

    @patch('pathlib.Path.exists')
    def test_list_available_sessions_no_directory(self, mock_exists):
        """Test listing sessions when directory doesn't exist"""
        mock_exists.return_value = False

        sessions = SessionLoader.list_available_sessions("nonexistent_dir")
        assert sessions == []

    @patch('pathlib.Path.glob')
    @patch('pathlib.Path.exists')
    def test_list_available_sessions_corrupted_file(self, mock_exists, mock_glob):
        """Test listing sessions with corrupted files"""
        mock_exists.return_value = True

        # Mock one good and one corrupted file
        mock_file1 = Path("session_good.json")
        mock_file2 = Path("session_corrupted.json")
        mock_glob.return_value = [mock_file1, mock_file2]

        metadata1 = {"session_id": "good_session", "start_time": 1234567890}

        with patch.object(SessionLoader, 'get_session_metadata') as mock_get_metadata:
            # First call succeeds, second raises exception
            mock_get_metadata.side_effect = [metadata1, Exception("Corrupted file")]

            with patch('builtins.print') as mock_print:  # Capture warning print
                sessions = SessionLoader.list_available_sessions("test_dir")

            # Should return only the good session
            assert len(sessions) == 1
            assert sessions[0]["metadata"]["session_id"] == "good_session"

            # Should have printed warning
            mock_print.assert_called_once()


class TestSessionIntegration:
    """Integration tests for session recording and loading"""

    def test_record_and_load_roundtrip(self):
        """Test complete record and load cycle"""
        # Use temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Record session
            recorder = SessionRecorder(temp_dir)
            recorder.record_request("HELLO", 0, b"test_request")
            recorder.record_response("HELLO_ACK", 1, b"test_response")

            # Save session
            session_file = recorder.save_session()

            # Load session
            entries = SessionLoader.load_session(session_file)

            # Verify loaded data matches recorded data
            assert len(entries) == 2

            assert entries[0].command == "HELLO"
            assert entries[0].interaction_type == "request"
            assert entries[0].payload_data == "test_request"

            assert entries[1].command == "HELLO_ACK"
            assert entries[1].interaction_type == "response"
            assert entries[1].payload_data == "test_response"

    def test_session_file_format_validation(self):
        """Test that saved sessions follow expected JSON format"""
        with tempfile.TemporaryDirectory() as temp_dir:
            recorder = SessionRecorder(temp_dir)
            recorder.record_request("TEST_CMD", 42, b"payload_data")

            session_file = recorder.save_session()

            # Load raw JSON and validate structure
            with open(session_file, 'r') as f:
                data = json.load(f)

            # Validate top-level structure
            assert "session_metadata" in data
            assert "interactions" in data

            # Validate metadata
            metadata = data["session_metadata"]
            assert "session_id" in metadata
            assert "start_time" in metadata
            assert "end_time" in metadata
            assert "total_interactions" in metadata
            assert "duration_seconds" in metadata

            # Validate interactions
            interactions = data["interactions"]
            assert len(interactions) == 1

            interaction = interactions[0]
            assert "timestamp" in interaction
            assert "step_number" in interaction
            assert "interaction_type" in interaction
            assert "command" in interaction
            assert "nonce" in interaction
            assert "payload_data" in interaction
            assert "payload_size" in interaction