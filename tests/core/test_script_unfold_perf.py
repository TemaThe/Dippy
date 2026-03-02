"""Performance benchmark for script unfolding."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from dippy.core.analyzer import Decision
from dippy.core.config import Config
from dippy.core.script_unfold import analyze_script_file

# Construct blocks that cycle through diverse bash constructs.
_BLOCKS: list[str] = [
    # Pipeline
    "ps aux | grep python | awk '{print $2}' | head -5",
    # If/elif/else
    'if [ -f file ]; then echo exists; elif [ -d dir ]; then echo dir; else echo none; fi',
    # For loop
    "for i in 1 2 3; do echo $i; done",
    # While loop
    'while read line; do echo "$line"; done < /dev/null',
    # Case statement
    'case "$1" in start) echo start;; stop) echo stop;; *) echo unknown;; esac',
    # Function definition
    "my_func() { ls; echo done; }",
    # Command substitution
    'echo "count: $(wc -l < /dev/null)"',
    # Nested: for inside if
    "if true; then for x in a b c; do echo $x; done; fi",
    # Nested: pipeline in loop
    "for f in /tmp/*; do cat $f | head -1; done",
    # Simple commands
    "ls -la",
    "echo hello",
    "cat /dev/null",
    "grep -r pattern .",
    "pwd",
]


def _generate_script(num_lines: int) -> str:
    """Generate a bash script with *num_lines* lines of diverse constructs."""
    lines = ["#!/usr/bin/env bash"]
    idx = 0
    while len(lines) < num_lines:
        lines.append(_BLOCKS[idx % len(_BLOCKS)])
        idx += 1
    return "\n".join(lines[: num_lines + 1]) + "\n"


SIZES = [100, 500, 1000, 2000, 5000, 10000]


@pytest.mark.parametrize("lines", SIZES, ids=[f"{n}L" for n in SIZES])
@patch("dippy.core.script_unfold.MAX_SCRIPT_SIZE", 10_000_000)
def test_script_unfold_perf(lines: int, tmp_path: Path) -> None:
    script = _generate_script(lines)
    bench_sh = tmp_path / "bench.sh"
    bench_sh.write_text(script)

    start = time.perf_counter()
    result = analyze_script_file(bench_sh, Config(), tmp_path)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result.action == "allow", f"expected allow, got {result.action}: {result.reason}"
    print(f"{lines} lines: {elapsed_ms:.1f}ms")
