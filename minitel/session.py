"""
Session Recording and Management
Captures all client-server interactions for mission analysis and replay.
"""

import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class SessionEntry:
    """Represents a single client-server interaction"""
    timestamp: float
    step_number: int
    interaction_type: str  # "request" or "response"
    command: str
    nonce: int
    payload_data: str  # Base64 encoded or string representation
    payload_size: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionEntry":
        """Create from dictionary (JSON deserialization)"""
        return cls(**data)


class SessionRecorder:
    """
    Records MiniTel-Lite session interactions for analysis and replay

    Features:
    - Timestamped interaction logging
    - JSON serialization for storage
    - Automatic file naming with timestamps
    - Replay data structure optimization
    """

    def __init__(self, output_dir: str = "sessions"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.session_entries: List[SessionEntry] = []
        self.session_start_time = time.time()
        self.step_counter = 0

        # Generate unique session ID
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_filename = f"session_{self.session_id}.json"

    def record_request(self, command: str, nonce: int, payload: bytes):
        """
        Record a client request

        Args:
            command: Command name (e.g., "HELLO", "DUMP")
            nonce: Request nonce value
            payload: Request payload data
        """
        self.step_counter += 1

        # Convert payload to string representation
        if payload:
            try:
                payload_str = payload.decode('utf-8')
            except UnicodeDecodeError:
                # For binary data, use base64 representation
                import base64
                payload_str = base64.b64encode(payload).decode('ascii')
        else:
            payload_str = ""

        entry = SessionEntry(
            timestamp=time.time(),
            step_number=self.step_counter,
            interaction_type="request",
            command=command,
            nonce=nonce,
            payload_data=payload_str,
            payload_size=len(payload)
        )

        self.session_entries.append(entry)

    def record_response(self, command: str, nonce: int, payload: bytes):
        """
        Record a server response

        Args:
            command: Response command name (e.g., "HELLO_ACK", "DUMP_OK")
            nonce: Response nonce value
            payload: Response payload data
        """
        self.step_counter += 1

        # Convert payload to string representation
        if payload:
            try:
                payload_str = payload.decode('utf-8')
            except UnicodeDecodeError:
                # For binary data, use base64 representation
                import base64
                payload_str = base64.b64encode(payload).decode('ascii')
        else:
            payload_str = ""

        entry = SessionEntry(
            timestamp=time.time(),
            step_number=self.step_counter,
            interaction_type="response",
            command=command,
            nonce=nonce,
            payload_data=payload_str,
            payload_size=len(payload)
        )

        self.session_entries.append(entry)

    def save_session(self) -> str:
        """
        Save recorded session to JSON file

        Returns:
            Path to saved session file
        """
        session_data = {
            "session_metadata": {
                "session_id": self.session_id,
                "start_time": self.session_start_time,
                "end_time": time.time(),
                "total_interactions": len(self.session_entries),
                "duration_seconds": time.time() - self.session_start_time
            },
            "interactions": [entry.to_dict() for entry in self.session_entries]
        }

        file_path = self.output_dir / self.session_filename

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)

            print(f"Session recorded: {file_path}")
            return str(file_path)

        except Exception as e:
            print(f"Error saving session: {e}")
            raise

    def get_session_summary(self) -> Dict[str, Any]:
        """
        Get summary information about the recorded session

        Returns:
            Dictionary with session statistics
        """
        if not self.session_entries:
            return {"status": "No interactions recorded"}

        requests = [e for e in self.session_entries if e.interaction_type == "request"]
        responses = [e for e in self.session_entries if e.interaction_type == "response"]

        command_counts = {}
        for entry in self.session_entries:
            cmd = entry.command
            command_counts[cmd] = command_counts.get(cmd, 0) + 1

        return {
            "session_id": self.session_id,
            "duration_seconds": time.time() - self.session_start_time,
            "total_interactions": len(self.session_entries),
            "requests_sent": len(requests),
            "responses_received": len(responses),
            "command_breakdown": command_counts,
            "average_payload_size": sum(e.payload_size for e in self.session_entries) / len(self.session_entries) if self.session_entries else 0
        }


class SessionLoader:
    """
    Loads recorded sessions from JSON files for replay and analysis
    """

    @staticmethod
    def load_session(file_path: str) -> List[SessionEntry]:
        """
        Load session entries from JSON file

        Args:
            file_path: Path to session JSON file

        Returns:
            List of SessionEntry objects

        Raises:
            FileNotFoundError: If session file doesn't exist
            ValueError: If session file format is invalid
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                session_data = json.load(f)

            if "interactions" not in session_data:
                raise ValueError("Invalid session file format: missing 'interactions' key")

            entries = []
            for interaction_data in session_data["interactions"]:
                entry = SessionEntry.from_dict(interaction_data)
                entries.append(entry)

            return entries

        except FileNotFoundError:
            raise FileNotFoundError(f"Session file not found: {file_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in session file: {e}")
        except Exception as e:
            raise ValueError(f"Error loading session file: {e}")

    @staticmethod
    def get_session_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from session file without loading all interactions

        Args:
            file_path: Path to session JSON file

        Returns:
            Session metadata dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                session_data = json.load(f)

            return session_data.get("session_metadata", {})

        except Exception as e:
            raise ValueError(f"Error reading session metadata: {e}")

    @staticmethod
    def list_available_sessions(directory: str = "sessions") -> List[Dict[str, Any]]:
        """
        List all available session files with their metadata

        Args:
            directory: Directory containing session files

        Returns:
            List of session information dictionaries
        """
        sessions_dir = Path(directory)
        if not sessions_dir.exists():
            return []

        sessions = []
        for json_file in sessions_dir.glob("session_*.json"):
            try:
                metadata = SessionLoader.get_session_metadata(str(json_file))
                sessions.append({
                    "filename": json_file.name,
                    "filepath": str(json_file),
                    "metadata": metadata
                })
            except Exception as e:
                # Skip corrupted files
                print(f"Warning: Skipping corrupted session file {json_file}: {e}")
                continue

        # Sort by creation time (newest first)
        sessions.sort(key=lambda x: x.get("metadata", {}).get("start_time", 0), reverse=True)

        return sessions