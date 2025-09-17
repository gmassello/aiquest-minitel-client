"""
Tests for TUI Session Replay Application
Validates replay functionality and user interface components.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from minitel.replay import SessionReplayTUI
from minitel.session import SessionEntry


class TestSessionReplayTUI:
    """Test SessionReplayTUI functionality"""

    def create_test_entries(self):
        """Create test session entries"""
        return [
            SessionEntry(
                timestamp=1234567890.123,
                step_number=1,
                interaction_type="request",
                command="HELLO",
                nonce=0,
                payload_data="",
                payload_size=0
            ),
            SessionEntry(
                timestamp=1234567891.456,
                step_number=2,
                interaction_type="response",
                command="HELLO_ACK",
                nonce=1,
                payload_data="",
                payload_size=0
            ),
            SessionEntry(
                timestamp=1234567892.789,
                step_number=3,
                interaction_type="request",
                command="DUMP",
                nonce=2,
                payload_data="secret_request",
                payload_size=14
            )
        ]

    def test_replay_initialization(self):
        """Test SessionReplayTUI initialization"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        assert replay.session_entries == entries
        assert replay.current_step == 0
        assert replay.running is True
        assert replay.console is not None

    def test_replay_initialization_empty_entries(self):
        """Test initialization with empty entries"""
        with pytest.raises(ValueError, match="No session entries to replay"):
            SessionReplayTUI([])

    def test_format_timestamp(self):
        """Test timestamp formatting"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        formatted = replay._format_timestamp(1234567890.123456)
        # Should be in HH:MM:SS.mmm format
        assert len(formatted) == 12  # HH:MM:SS.mmm
        assert formatted.count(':') == 2
        assert '.' in formatted

    def test_format_payload_empty(self):
        """Test payload formatting with empty payload"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        result = replay._format_payload("")
        assert "[dim]<empty>[/dim]" in result

    def test_format_payload_normal(self):
        """Test payload formatting with normal payload"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        result = replay._format_payload("test_payload")
        assert result == "test_payload"

    def test_format_payload_truncated(self):
        """Test payload formatting with truncation"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        long_payload = "x" * 150
        result = replay._format_payload(long_payload, max_length=100)
        assert len(result) <= 120  # 100 + "[dim]...[/dim]" markup
        assert "[dim]...[/dim]" in result

    def test_get_interaction_color(self):
        """Test interaction color mapping"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        assert replay._get_interaction_color("request") == "blue"
        assert replay._get_interaction_color("response") == "green"
        assert replay._get_interaction_color("unknown") == "white"

    def test_next_step(self):
        """Test advancing to next step"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        assert replay.current_step == 0
        replay.next_step()
        assert replay.current_step == 1
        replay.next_step()
        assert replay.current_step == 2

    def test_next_step_at_end(self):
        """Test next step when at end of entries"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        # Move to last entry
        replay.current_step = len(entries) - 1

        # Calling next_step should not advance further
        with patch.object(replay.console, 'bell') as mock_bell:
            replay.next_step()

        assert replay.current_step == len(entries) - 1
        mock_bell.assert_called_once()

    def test_previous_step(self):
        """Test going back to previous step"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        # Move forward then back
        replay.current_step = 2
        replay.previous_step()
        assert replay.current_step == 1
        replay.previous_step()
        assert replay.current_step == 0

    def test_previous_step_at_beginning(self):
        """Test previous step when at beginning"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        assert replay.current_step == 0

        with patch.object(replay.console, 'bell') as mock_bell:
            replay.previous_step()

        assert replay.current_step == 0
        mock_bell.assert_called_once()

    def test_restart(self):
        """Test restart functionality"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        # Move to middle then restart
        replay.current_step = 2
        replay.restart()
        assert replay.current_step == 0

    @patch('builtins.input')
    def test_show_help(self, mock_input):
        """Test show help functionality"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        with patch.object(replay.console, 'clear') as mock_clear, \
             patch.object(replay.console, 'print') as mock_print:

            replay.show_help()

            mock_clear.assert_called_once()
            mock_print.assert_called_once()
            mock_input.assert_called_once()

    def test_handle_input_quit(self):
        """Test handling quit input"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        result = replay.handle_input('q')
        assert result is False

        result = replay.handle_input('quit')
        assert result is False

    def test_handle_input_next(self):
        """Test handling next input"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        initial_step = replay.current_step
        result = replay.handle_input('n')

        assert result is True
        assert replay.current_step == initial_step + 1

        result = replay.handle_input('next')
        assert result is True
        assert replay.current_step == initial_step + 2

    def test_handle_input_previous(self):
        """Test handling previous input"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        # Move forward first
        replay.current_step = 2

        result = replay.handle_input('p')
        assert result is True
        assert replay.current_step == 1

        result = replay.handle_input('previous')
        assert result is True
        assert replay.current_step == 0

    def test_handle_input_restart(self):
        """Test handling restart input"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        replay.current_step = 2
        result = replay.handle_input('r')

        assert result is True
        assert replay.current_step == 0

    def test_handle_input_help(self):
        """Test handling help input"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        with patch.object(replay, 'show_help') as mock_show_help:
            result = replay.handle_input('h')

            assert result is True
            mock_show_help.assert_called_once()

    def test_handle_input_unknown(self):
        """Test handling unknown input"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        result = replay.handle_input('unknown_key')
        assert result is True  # Should continue running

    def test_create_header_panel(self):
        """Test header panel creation"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        panel = replay._create_header_panel()
        assert panel is not None

    def test_create_interaction_panel(self):
        """Test interaction panel creation"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        panel = replay._create_interaction_panel()
        assert panel is not None

    def test_create_interaction_panel_empty(self):
        """Test interaction panel creation with empty entries"""
        # This shouldn't happen in normal flow, but test defensive code
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)
        replay.session_entries = []

        panel = replay._create_interaction_panel()
        assert panel is not None

    def test_create_navigation_panel(self):
        """Test navigation panel creation"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        panel = replay._create_navigation_panel()
        assert panel is not None

    def test_create_context_panel(self):
        """Test context panel creation"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        panel = replay._create_context_panel()
        assert panel is not None

    def test_create_context_panel_empty(self):
        """Test context panel creation with empty entries"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)
        replay.session_entries = []

        panel = replay._create_context_panel()
        assert panel is not None

    def test_create_layout(self):
        """Test layout creation"""
        entries = self.create_test_entries()
        replay = SessionReplayTUI(entries)

        layout = replay._create_layout()
        assert layout is not None


class TestReplayMain:
    """Test replay main function and command-line interface"""

    @patch('minitel.replay.SessionLoader.list_available_sessions')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_list_sessions_empty(self, mock_parse_args, mock_list_sessions):
        """Test main function with --list when no sessions available"""
        mock_parse_args.return_value = Mock(
            list=True,
            sessions_dir="test_dir",
            session_file=None
        )
        mock_list_sessions.return_value = []

        with patch('minitel.replay.Console') as mock_console_class:
            mock_console = Mock()
            mock_console_class.return_value = mock_console

            from minitel.replay import main
            result = main()

            assert result == 1
            mock_console.print.assert_called()

    @patch('minitel.replay.SessionLoader.list_available_sessions')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_list_sessions_with_data(self, mock_parse_args, mock_list_sessions):
        """Test main function with --list when sessions are available"""
        mock_parse_args.return_value = Mock(
            list=True,
            sessions_dir="test_dir",
            session_file=None
        )

        mock_sessions = [
            {
                "filename": "session_1.json",
                "metadata": {
                    "session_id": "test_session_1",
                    "start_time": 1234567890,
                    "duration_seconds": 10.5,
                    "total_interactions": 5
                }
            }
        ]
        mock_list_sessions.return_value = mock_sessions

        with patch('minitel.replay.Console') as mock_console_class:
            mock_console = Mock()
            mock_console_class.return_value = mock_console

            from minitel.replay import main
            result = main()

            assert result == 0
            mock_console.print.assert_called()

    @patch('minitel.replay.SessionLoader.load_session')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_replay_session_success(self, mock_parse_args, mock_load_session):
        """Test main function replaying a session successfully"""
        mock_parse_args.return_value = Mock(
            list=False,
            session_file="test_session.json"
        )

        test_entries = [
            SessionEntry(
                timestamp=1234567890.0,
                step_number=1,
                interaction_type="request",
                command="HELLO",
                nonce=0,
                payload_data="",
                payload_size=0
            )
        ]
        mock_load_session.return_value = test_entries

        with patch('minitel.replay.Console') as mock_console_class, \
             patch('minitel.replay.SessionReplayTUI') as mock_replay_class:

            mock_console = Mock()
            mock_console_class.return_value = mock_console

            mock_replay = Mock()
            mock_replay_class.return_value = mock_replay

            from minitel.replay import main
            result = main()

            assert result == 0
            mock_load_session.assert_called_with("test_session.json")
            mock_replay_class.assert_called_with(test_entries)
            mock_replay.run.assert_called_once()

    @patch('minitel.replay.SessionLoader.load_session')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_replay_file_not_found(self, mock_parse_args, mock_load_session):
        """Test main function with file not found error"""
        mock_parse_args.return_value = Mock(
            list=False,
            session_file="nonexistent.json"
        )

        mock_load_session.side_effect = FileNotFoundError("File not found")

        with patch('minitel.replay.Console') as mock_console_class:
            mock_console = Mock()
            mock_console_class.return_value = mock_console

            from minitel.replay import main
            result = main()

            assert result == 1
            mock_console.print.assert_called()

    @patch('minitel.replay.SessionLoader.load_session')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_replay_empty_session(self, mock_parse_args, mock_load_session):
        """Test main function with empty session"""
        mock_parse_args.return_value = Mock(
            list=False,
            session_file="empty.json"
        )

        mock_load_session.return_value = []

        with patch('minitel.replay.Console') as mock_console_class:
            mock_console = Mock()
            mock_console_class.return_value = mock_console

            from minitel.replay import main
            result = main()

            assert result == 1
            mock_console.print.assert_called()

    @patch('minitel.replay.SessionLoader.load_session')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_replay_value_error(self, mock_parse_args, mock_load_session):
        """Test main function with value error"""
        mock_parse_args.return_value = Mock(
            list=False,
            session_file="invalid.json"
        )

        mock_load_session.side_effect = ValueError("Invalid session format")

        with patch('minitel.replay.Console') as mock_console_class:
            mock_console = Mock()
            mock_console_class.return_value = mock_console

            from minitel.replay import main
            result = main()

            assert result == 1
            mock_console.print.assert_called()

    @patch('minitel.replay.SessionLoader.load_session')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_replay_unexpected_error(self, mock_parse_args, mock_load_session):
        """Test main function with unexpected error"""
        mock_parse_args.return_value = Mock(
            list=False,
            session_file="test.json"
        )

        mock_load_session.side_effect = Exception("Unexpected error")

        with patch('minitel.replay.Console') as mock_console_class:
            mock_console = Mock()
            mock_console_class.return_value = mock_console

            from minitel.replay import main
            result = main()

            assert result == 1
            mock_console.print.assert_called()


class TestReplayIntegration:
    """Integration tests for replay functionality"""

    def test_replay_step_navigation_integration(self):
        """Test complete step navigation workflow"""
        entries = [
            SessionEntry(
                timestamp=1234567890.0 + i,
                step_number=i + 1,
                interaction_type="request" if i % 2 == 0 else "response",
                command=f"CMD_{i}",
                nonce=i,
                payload_data=f"payload_{i}",
                payload_size=len(f"payload_{i}")
            )
            for i in range(5)
        ]

        replay = SessionReplayTUI(entries)

        # Test forward navigation
        for i in range(len(entries) - 1):
            replay.next_step()
            assert replay.current_step == i + 1

        # Test backward navigation
        for i in range(len(entries) - 1, 0, -1):
            replay.previous_step()
            assert replay.current_step == i - 1

        # Test restart
        replay.current_step = 3
        replay.restart()
        assert replay.current_step == 0

    def test_replay_input_handling_integration(self):
        """Test complete input handling workflow"""
        entries = [
            SessionEntry(
                timestamp=1234567890.0,
                step_number=1,
                interaction_type="request",
                command="HELLO",
                nonce=0,
                payload_data="",
                payload_size=0
            ),
            SessionEntry(
                timestamp=1234567891.0,
                step_number=2,
                interaction_type="response",
                command="HELLO_ACK",
                nonce=1,
                payload_data="",
                payload_size=0
            )
        ]

        replay = SessionReplayTUI(entries)

        # Test next input
        result = replay.handle_input('n')
        assert result is True
        assert replay.current_step == 1

        # Test previous input
        result = replay.handle_input('p')
        assert result is True
        assert replay.current_step == 0

        # Test restart input
        replay.current_step = 1
        result = replay.handle_input('r')
        assert result is True
        assert replay.current_step == 0

        # Test quit separately
        result = replay.handle_input('q')
        assert result is False