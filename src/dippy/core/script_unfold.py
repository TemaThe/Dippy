"""
Script unfolding for Dippy.

Reads shell script files and analyzes their contents against
Dippy's allow/ask/deny rules. If all commands in a script are safe,
auto-allows. If any are unsafe, reports exactly which commands failed.
"""

from __future__ import annotations

from pathlib import Path

from dippy.core.config import Config
from dippy.vendor.parable import parse, ParseError

SCRIPT_EXTENSIONS = frozenset({".sh", ".bash", ".zsh", ".ksh"})
MAX_SCRIPT_SIZE = 65_536  # 64KB
MAX_UNFOLD_DEPTH = 5  # prevent infinite recursion


def resolve_script_path(script_arg: str, cwd: Path) -> Path:
    """Resolve a script argument to an absolute path.

    Handles ~, relative, and absolute paths.
    """
    if script_arg.startswith("~"):
        return Path(script_arg).expanduser().resolve()
    p = Path(script_arg)
    if p.is_absolute():
        return p.resolve()
    return (cwd / p).resolve()


def read_script(path: Path) -> tuple[str | None, str | None]:
    """Read a script file with safety checks.

    Returns (contents, None) on success or (None, error_reason) on failure.
    Rejects symlinks, missing files, too-large files, and non-UTF-8 files.
    """
    if not path.exists():
        return None, f"script not found: {path.name}"

    if not path.is_file():
        return None, f"not a file: {path.name}"

    if path.is_symlink():
        return None, f"script is a symlink: {path.name}"

    try:
        size = path.stat().st_size
    except OSError as e:
        return None, f"cannot stat script: {e}"

    if size > MAX_SCRIPT_SIZE:
        return None, "script too large to analyze"

    if size == 0:
        return "", None

    try:
        contents = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None, f"script is not valid UTF-8: {path.name}"
    except OSError as e:
        return None, f"cannot read script: {e}"

    return contents, None


def analyze_script_file(
    path: Path,
    config: Config,
    cwd: Path,
    *,
    remote: bool = False,
    depth: int = 0,
) -> "Decision":
    """Analyze a script file by parsing and checking all commands.

    Returns a Decision. On success with all safe commands, returns allow
    with description like "script.sh (analyzed)". On unsafe commands,
    prefixes the reason with "in script.sh: ...".
    """
    from dippy.core.analyzer import Decision, _analyze_node, _combine

    if depth >= MAX_UNFOLD_DEPTH:
        return Decision("ask", "script nesting too deep")

    contents, error = read_script(path)
    if error is not None:
        return Decision("ask", error)

    if not contents or not contents.strip():
        return Decision("allow", f"{path.name} (empty)")

    try:
        nodes = parse(contents)
    except ParseError as e:
        return Decision("ask", f"script parse error in {path.name}: {e.message}")

    if not nodes:
        return Decision("allow", f"{path.name} (empty)")

    decisions = [
        _analyze_node(node, config, cwd, remote=remote, _unfold_depth=depth + 1)
        for node in nodes
    ]
    result = _combine(decisions)

    if result.action == "allow":
        return Decision("allow", f"{path.name} (analyzed)", children=result.children)

    # Prefix with script name for context
    return Decision(
        result.action,
        f"in {path.name}: {result.reason}",
        children=result.children,
    )
