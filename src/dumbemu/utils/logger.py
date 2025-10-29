"""Logging utility for debug output."""
from __future__ import annotations
import sys

class Logger:
    """Simple debug logger with verbosity control.
    
    Provides debug, info, warning, and error logging.
    - debug/info: Only shown when verbose=True
    - warning/error: Always shown regardless of verbose setting
    """
    
    _verbose = False
    
    @classmethod
    def set_verbose(cls, verbose: bool) -> None:
        """Enable or disable verbose logging."""
        cls._verbose = verbose
    
    @classmethod
    def debug(cls, msg: str) -> None:
        """Print debug message if verbose mode is enabled."""
        if cls._verbose:
            print(f"[DEBUG] {msg}", file=sys.stderr)
    
    @classmethod
    def info(cls, msg: str) -> None:
        """Print info message if verbose mode is enabled."""
        if cls._verbose:
            print(f"[INFO] {msg}", file=sys.stderr)
    
    @classmethod
    def warn(cls, msg: str) -> None:
        """Print warning message (deprecated, use warning())."""
        cls.warning(msg)
    
    @classmethod
    def warning(cls, msg: str) -> None:
        """Print warning message."""
        print(f"[WARN] {msg}", file=sys.stderr)
    
    @classmethod
    def error(cls, msg: str) -> None:
        """Print error message."""
        print(f"[ERROR] {msg}", file=sys.stderr)

# Global logger instance
log = Logger()
