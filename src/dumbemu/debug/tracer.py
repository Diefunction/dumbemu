"""Execution tracing for debugging and analysis."""
from __future__ import annotations
from collections import deque
from typing import List, Optional, Callable, Any, TYPE_CHECKING
from unicorn import UcError
from ..utils.constants import UC_HOOK_CODE
from ..utils.logger import log

if TYPE_CHECKING:
    from unicorn import Uc
    from ..core.context import Context


class Tracer:
    """Execution tracer for recording and analyzing code flow.
    
    Captures executed addresses and provides analysis of execution patterns,
    loops, and control flow. Supports ring-buffer mode for memory-efficient
    tracing of long executions by keeping only the most recent N addresses.
    """
    
    def __init__(self, ctx: Context, max_history: Optional[int] = None):
        """Initialize tracer.
        
        Args:
            ctx: Emulation context
            max_history: Maximum addresses to store (None for unlimited, use for ring buffer)
        """
        self.ctx = ctx
        self.uc = ctx.uc
        # Use deque for efficient ring buffer implementation
        self._history = deque(maxlen=max_history) if max_history else deque()
        self.max_history = max_history
        self.enabled = False
        self._hook = None
        self._total_insns = 0  # Track total even with ring buffer
        self._stop_addr: Optional[int] = None
        self._stop_handle = None
    
    def start(self) -> None:
        """Start tracing execution."""
        if not self.enabled:
            self._history.clear()
            self._total_insns = 0
            self._hook = self.uc.hook_add(UC_HOOK_CODE, self._trace_hook)
            self.enabled = True
    
    def stop(self) -> List[int]:
        """Stop tracing and return history.
        
        Returns:
            List of executed addresses
        """
        if self.enabled and self._hook:
            try:
                self.uc.hook_del(self._hook)
            except Exception:
                pass
            self._hook = None
            self.enabled = False
        return list(self._history)
    
    def clear(self) -> None:
        """Clear trace history."""
        self._history.clear()
    
    def _trace_hook(self, uc: Any, addr: int, size: int, _) -> None:
        """Internal hook to record executed addresses."""
        self._total_insns += 1
        # deque automatically handles ring buffer behavior when maxlen is set
        self._history.append(addr)
    
    def run(self, start: int, stop: Optional[int] = None, 
            count: Optional[int] = None) -> tuple[List[int], int]:
        """Run emulation with tracing.
        
        Args:
            start: Start address
            stop: Optional stop address
            count: Optional max instructions
            
        Returns:
            Tuple of (addresses_list, instruction_count)
        """
        self.start()
        
        # Set up stop condition via instance method hook
        if stop:
            self._stop_addr = stop
            stop_handle = self.uc.hook_add(UC_HOOK_CODE, self._stop_at_hook)
        else:
            stop_handle = None
        
        try:
            kwargs = {'count': count} if count else {}
            end = stop if stop else self.ctx.fakeret
            self.uc.emu_start(start, end, **kwargs)
        except UcError as e:
            log.debug(f"Tracer.run: Emulation stopped: {e}")
        finally:
            if stop_handle:
                try:
                    self.uc.hook_del(stop_handle)
                except Exception:
                    pass
        
        addrs = self.stop()
        return addrs, len(addrs)

    def _stop_at_hook(self, uc: Any, addr: int, size: int, _) -> None:
        """Stop emulation when a specific address is executed."""
        if self._stop_addr is not None and addr == self._stop_addr:
            uc.emu_stop()
    
    def history(self, max_len: Optional[int] = None) -> List[int]:
        """Get execution history.
        
        Args:
            max_len: Optional maximum number of addresses to return
            
        Returns:
            List of executed addresses
        """
        if max_len:
            # Convert deque slice to list
            return list(self._history)[-max_len:]
        return list(self._history)
    
    def analyze(self) -> dict:
        """Analyze trace data.
        
        Returns:
            Dictionary with analysis results
        """
        if not self._history:
            return {
                'total': self._total_insns,
                'buffered': 0,
                'unique': 0,
                'common': [],
                'entry': None,
                'exit': None,
                'ring_buffer': self.max_history is not None
            }
        
        from collections import Counter
        counts = Counter(self._history)
        
        return {
            'total': self._total_insns,  # Total instructions executed
            'buffered': len(self._history),  # Instructions in buffer
            'unique': len(counts),
            'common': counts.most_common(10),
            'entry': self._history[0],
            'exit': self._history[-1],
            'ring_buffer': self.max_history is not None
        }
