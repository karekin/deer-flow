"""Run-level policy for writing long-term agent memory."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def should_write_memory(run_config: Mapping[str, Any] | None) -> bool:
    """Return whether the current run may update long-term memory.

    Internal acceptance and smoke-test conversations are retained as test
    evidence, but must never become user or role memory.
    """
    if not run_config:
        return True
    metadata = run_config.get("metadata")
    if not isinstance(metadata, Mapping):
        return True
    return metadata.get("visibility") != "internal_test"
