#!/usr/bin/env python3
"""Cross-platform launcher for the PortHawk web dashboard.

Works on Windows, macOS, Linux. Just run:
  python start_dashboard.py

Or use the platform shortcuts:
  Windows:      double-click start_dashboard.bat
  macOS/Linux:  ./start_dashboard.sh
"""

import subprocess
import sys
from pathlib import Path


def main() -> None:
    # check streamlit is available before trying to run it
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("Streamlit not installed.")
        print("Fix: pip install porthawk[dashboard]")
        print("     or: pip install streamlit altair pandas")
        _pause_on_windows()
        sys.exit(1)

    # find dashboard.py — works both from the repo root and when installed as package
    dashboard = Path(__file__).parent / "porthawk" / "dashboard.py"
    if not dashboard.exists():
        # installed via pip — find the package location
        try:
            import porthawk

            dashboard = Path(porthawk.__file__).parent / "dashboard.py"
        except ImportError:
            print("porthawk package not found. Is it installed?")
            _pause_on_windows()
            sys.exit(1)

    if not dashboard.exists():
        print(f"dashboard.py not found at {dashboard}")
        _pause_on_windows()
        sys.exit(1)

    print("PortHawk dashboard starting at http://localhost:8501")
    print("Press Ctrl+C to stop.")
    print()

    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(dashboard),
                "--server.headless",
                "false",
                "--browser.gatherUsageStats",
                "false",
                "--theme.base",
                "dark",
            ],
            check=True,
        )
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    except subprocess.CalledProcessError as e:
        print(f"Dashboard exited with error: {e}")
        _pause_on_windows()
        sys.exit(1)


def _pause_on_windows() -> None:
    """Keep the terminal open on Windows so the user can read the error."""
    if sys.platform == "win32":
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()
