"""
TUI Session Replay Application
Allows NORAD analysts to review recorded MiniTel-Lite interactions.
"""

import sys
import os
from typing import List, Optional
from datetime import datetime

RICH_AVAILABLE = True
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    from rich.align import Align
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: Rich library not available. Using basic terminal mode.")

    # Basic fallback implementations
    class Console:
        def print(self, text, style=None):
            print(text)
        def clear(self):
            # This is a fallback, real clearing is handled by the Console object
            pass
        def bell(self):
            print('\a', end='')
        def input(self, prompt=""):
            return input(prompt)

    class Panel:
        def __init__(self, content, title="", border_style=""):
            self.content = content
            self.title = title

    class Table:
        def __init__(self, **kwargs):
            self.rows = []
            self.columns = []
        def add_column(self, header, **kwargs):
            self.columns.append(header)
        def add_row(self, *args):
            self.rows.append(args)

    class Layout:
        def __init__(self, **kwargs):
            pass
        def split_column(self, *args):
            return self
        def split_row(self, *args):
            return self
        def update(self, content):
            pass

    class Live:
        def __init__(self, layout, console=None, refresh_per_second=1):
            self.layout = layout
            self.console = console
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def update(self, layout):
            pass

    class Text:
        def __init__(self, text=""):
            self.text = text
        def append(self, text, style=None):
            self.text += text

    class Align:
        @staticmethod
        def center(content):
            return content

    # For now, exit gracefully if Rich not available for TUI
    # In production, implement full terminal fallback
    if __name__ == "__main__":
        print(
            "Error: TUI replay requires Rich library. "
            "Install with: pip install rich"
        )
        sys.exit(1)

from .session import SessionEntry, SessionLoader


class SessionReplayTUI:
    """
    Terminal User Interface for replaying recorded MiniTel-Lite sessions

    Keybindings:
    - N/n: Next step
    - P/p: Previous step
    - Q/q: Quit
    - H/h: Help
    - R/r: Restart from beginning
    """

    def __init__(self, session_entries: List[SessionEntry]):
        self.session_entries = session_entries
        self.current_step = 0
        self.console = Console()
        self.running = True

        if not session_entries:
            raise ValueError("No session entries to replay")

    def _format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display"""
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%H:%M:%S.%f")[:-3]  # Include milliseconds

    def _format_payload(self, payload_data: str, max_length: int = 100) -> str:
        """Format payload data for display"""
        if not payload_data:
            return "[dim]<empty>[/dim]"

        if len(payload_data) > max_length:
            return payload_data[:max_length] + "[dim]...[/dim]"

        return payload_data

    def _get_interaction_color(self, interaction_type: str) -> str:
        """Get color for interaction type"""
        colors = {
            "request": "blue",
            "response": "green"
        }
        return colors.get(interaction_type, "white")

    def _create_header_panel(self) -> Panel:
        """Create header panel with session information"""
        total_steps = len(self.session_entries)
        progress = f"Step {self.current_step + 1} of {total_steps}"

        header_text = Text()
        header_text.append(
            "🚨 NORAD SESSION REPLAY ANALYSIS 🚨", style="bold red"
        )
        header_text.append(f"\n{progress}", style="bold yellow")

        return Panel(
            Align.center(header_text),
            title="Mission Intelligence",
            border_style="red"
        )

    def _create_interaction_panel(self) -> Panel:
        """Create panel showing current interaction"""
        if not self.session_entries:
            return Panel("No interactions to display", title="Interaction")

        entry = self.session_entries[self.current_step]
        color = self._get_interaction_color(entry.interaction_type)

        # Create interaction table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Field", style="cyan", min_width=15)
        table.add_column("Value", style="white", min_width=40)

        table.add_row("Timestamp", self._format_timestamp(entry.timestamp))
        table.add_row(
            "Type", f"[{color}]{entry.interaction_type.upper()}[/{color}]"
        )
        table.add_row(
            "Command", f"[bold {color}]{entry.command}[/bold {color}]"
        )
        table.add_row("Nonce", str(entry.nonce))
        table.add_row("Payload Size", f"{entry.payload_size} bytes")
        table.add_row("Payload", self._format_payload(entry.payload_data))

        title_icon = "📤" if entry.interaction_type == "request" else "📥"
        panel_title = f"{title_icon} {entry.interaction_type.title()} Details"

        return Panel(
            table,
            title=panel_title,
            border_style=color
        )

    def _create_navigation_panel(self) -> Panel:
        """Create navigation help panel"""
        nav_text = Text()
        nav_text.append("Navigation Controls:\n", style="bold underline")
        nav_text.append("N/n", style="bold green")
        nav_text.append(" - Next step\n")
        nav_text.append("P/p", style="bold blue")
        nav_text.append(" - Previous step\n")
        nav_text.append("R/r", style="bold yellow")
        nav_text.append(" - Restart from beginning\n")
        nav_text.append("H/h", style="bold cyan")
        nav_text.append(" - Show help\n")
        nav_text.append("Q/q", style="bold red")
        nav_text.append(" - Quit\n")

        return Panel(
            nav_text,
            title="Controls",
            border_style="dim"
        )

    def _create_context_panel(self) -> Panel:
        """Create panel showing interaction context"""
        if not self.session_entries:
            return Panel("No context available")

        # Show surrounding interactions for context
        context_entries = []
        start_idx = max(0, self.current_step - 2)
        end_idx = min(len(self.session_entries), self.current_step + 3)

        table = Table(
            show_header=True, header_style="bold magenta", show_lines=True
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Time", style="dim", width=12)
        table.add_column("Type", width=8)
        table.add_column("Command", width=12)
        table.add_column("Status", width=8)

        for idx in range(start_idx, end_idx):
            entry = self.session_entries[idx]
            color = self._get_interaction_color(entry.interaction_type)

            # Highlight current step
            if idx == self.current_step:
                step_style = "bold reverse"
                status = "► CURRENT"
            else:
                step_style = "dim" if abs(idx - self.current_step) > 1 else ""
                status = "  ✓" if idx < self.current_step else "  ○"

            table.add_row(
                str(idx + 1),
                self._format_timestamp(entry.timestamp),
                f"[{color}]{entry.interaction_type[:3].upper()}[/{color}]",
                f"[{color}]{entry.command}[/{color}]",
                status,
                style=step_style
            )

        return Panel(
            table,
            title="Session Context",
            border_style="yellow"
        )

    def _create_layout(self) -> Layout:
        """Create the main TUI layout"""
        layout = Layout()

        layout.split_column(
            Layout(self._create_header_panel(), size=4),
            Layout().split_row(
                Layout(self._create_interaction_panel()),
                Layout().split_column(
                    Layout(self._create_context_panel()),
                    Layout(self._create_navigation_panel(), size=10)
                )
            )
        )

        return layout

    def next_step(self):
        """Move to next interaction step"""
        if self.current_step < len(self.session_entries) - 1:
            self.current_step += 1
        else:
            self.console.bell()  # Alert when at end

    def previous_step(self):
        """Move to previous interaction step"""
        if self.current_step > 0:
            self.current_step -= 1
        else:
            self.console.bell()  # Alert when at beginning

    def restart(self):
        """Restart from the beginning"""
        self.current_step = 0

    def show_help(self):
        """Show detailed help information"""
        help_text = """
🚨 NORAD SESSION REPLAY SYSTEM 🚨

This tool allows you to analyze recorded MiniTel-Lite protocol sessions
from Agent LIGHTMAN's infiltration of the JOSHUA system.

NAVIGATION:
  N, n          - Advance to next interaction
  P, p          - Go back to previous interaction
  R, r          - Restart from beginning of session
  H, h          - Show this help screen
  Q, q          - Quit the replay system

INTERFACE ELEMENTS:
  📤 Request    - Commands sent by Agent LIGHTMAN
  📥 Response   - Replies received from JOSHUA
  ► CURRENT     - Currently viewed interaction
  ✓             - Already reviewed interactions
  ○             - Future interactions

ANALYSIS TIPS:
  - Pay attention to nonce sequences for protocol validation
  - Monitor payload sizes for anomalies
  - Look for DUMP_OK responses containing override codes
  - Check timestamps for connection timeout patterns

Press any key to return to session replay...
        """

        self.console.clear()
        self.console.print(Panel(help_text, title="Help", border_style="cyan"))
        self.console.input()  # Wait for user input

    def handle_input(self, key: str) -> bool:
        """
        Handle keyboard input

        Args:
            key: Pressed key

        Returns:
            True to continue, False to quit
        """
        key = key.lower()

        if key in ('q', 'quit'):
            return False
        elif key in ('n', 'next'):
            self.next_step()
        elif key in ('p', 'prev', 'previous'):
            self.previous_step()
        elif key in ('r', 'restart'):
            self.restart()
        elif key in ('h', 'help'):
            self.show_help()

        return True

    def run(self):
        """Run the TUI replay application"""
        self.console.clear()

        try:
            with Live(
                self._create_layout(),
                console=self.console,
                refresh_per_second=10
            ) as live:
                while self.running:
                    # Update the layout
                    live.update(self._create_layout())

                    # Get user input (non-blocking would be better, but this works)
                    try:
                        # Use a simple input method for
                        # cross-platform compatibility
                        key = self.console.input("")
                        if not self.handle_input(key):
                            break
                    except KeyboardInterrupt:
                        break
                    except EOFError:
                        break

        except Exception as e:
            self.console.print(f"[red]Error in TUI: {e}[/red]")
        finally:
            self.console.clear()
            self.console.print(
                "[green]Session replay terminated. Stay vigilant, Agent.[/green]"
            )


def main():
    """
    Command-line entry point for the session replay tool.

    Parses command-line arguments, lists available sessions,
    or loads and replays a specific session.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="NORAD Session Replay Analysis Tool"
    )
    parser.add_argument("session_file", nargs="?", help="Path to session JSON file")
    parser.add_argument("--list", action="store_true",
                       help="List available session files")
    parser.add_argument("--sessions-dir", default="sessions",
                       help="Directory containing session files")

    args = parser.parse_args()

    console = Console()

    # Handle listing available sessions
    if args.list:
        sessions = SessionLoader.list_available_sessions(args.sessions_dir)
        if not sessions:
            console.print("[yellow]No session files found.[/yellow]")
            return 1

        table = Table(title="Available Sessions")
        table.add_column("Filename", style="cyan")
        table.add_column("Session ID", style="green")
        table.add_column("Start Time", style="yellow")
        table.add_column("Duration", style="magenta")
        table.add_column("Interactions", justify="right", style="blue")

        for session in sessions:
            metadata = session.get("metadata", {})
            start_time = metadata.get("start_time", 0)
            duration = metadata.get("duration_seconds", 0)
            interactions = metadata.get("total_interactions", 0)

            start_str = datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S") if start_time else "Unknown"
            duration_str = f"{duration:.1f}s" if duration else "Unknown"

            table.add_row(
                session["filename"],
                metadata.get("session_id", "Unknown"),
                start_str,
                duration_str,
                str(interactions)
            )

        console.print(table)
        return 0

    # Validate session file argument
    if not args.session_file:
        console.print("[red]Error: session_file argument required when not using --list[/red]")
        return 1

    # Load and replay session
    try:
        entries = SessionLoader.load_session(args.session_file)
        if not entries:
            console.print("[red]Error: Session file contains no interactions[/red]")
            return 1

        console.print(f"[green]Loaded session with {len(entries)} interactions[/green]")
        console.print("[yellow]Starting replay... Use 'h' for help, 'q' to quit[/yellow]")

        replay = SessionReplayTUI(entries)
        replay.run()

        return 0

    except FileNotFoundError:
        console.print(f"[red]Error: Session file not found: {args.session_file}[/red]")
        return 1
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return 1


if __name__ == "__main__":
    exit(main())
