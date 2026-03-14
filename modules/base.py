"""Abstract base class for all fingerprinting modules."""

from __future__ import annotations

import abc
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models import Finding, ScanConfig


class BaseModule(abc.ABC):
    """Every fingerprinting module inherits from this class."""

    name: str = "base"

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._last_request_time: float = 0.0

    def _rate_limit(self) -> None:
        """Block until at least ``config.rate_limit`` seconds have passed
        since the previous outbound request."""
        elapsed = time.monotonic() - self._last_request_time
        remaining = self.config.rate_limit - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_request_time = time.monotonic()

    @abc.abstractmethod
    def run(self) -> list[Finding]:
        """Execute the module and return a list of findings."""
        ...
