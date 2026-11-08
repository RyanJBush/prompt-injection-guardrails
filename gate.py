"""Permission gate with a recording mock executor (local scripted demo, synthetic fixtures only)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parent  # trusted workspace root (never the CWD)

# Exact argument fields per known tool. Anything else is denied.
TOOL_FIELDS = {
    "read_fixture": ("path",),
    "write_draft_patch": ("path", "patch"),
    "run_named_test": ("name",),
}
UNKNOWN_TOOL = "<unknown_tool>"
REDACTED = "<redacted>"

# The one synthetic draft the fixed mock test accepts.
EXPECTED_DRAFT_PATCH = (
    "--- a/fixtures/normalize_label.py\n"
    "+++ b/fixtures/normalize_label.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def normalize_label(label):\n"
    "     # BUG (synthetic): does not trim surrounding whitespace.\n"
    "-    return label.lower()\n"
    "+    return label.strip().lower()\n"
)


@dataclass(frozen=True)
class TaskConfig:
    """Trusted task configuration. Agent-supplied text never modifies this."""
    workspace: Path = ROOT
    read_target: str = "fixtures/normalize_label.py"
    write_target: str = "out/draft.patch"
    test_names: tuple = ("test_normalize_label",)
    # Known synthetic labels (workspace-relative path -> label) for decision rows.
    labels: tuple = (
        ("fixtures/normalize_label.py", "SRC_NORMALIZE_LABEL"),
        ("fixtures/fake_secret.txt", "SECRET_FAKE"),
        ("out/draft.patch", "DRAFT_PATCH"),
    )


@dataclass
class MockExecutor:
    """Records every call it actually receives. Never touches the filesystem.

    Holds the draft in memory and implements the fixed mock test adapter.
    One instance per case.
    """
    calls: list = field(default_factory=list)
    draft: str | None = None
    draft_path: str | None = None
    test_runs: list = field(default_factory=list)  # (name, passed)

    def execute(self, tool: str, args: dict) -> dict:
        self.calls.append({"tool": tool, "args": dict(args)})
        if tool == "write_draft_patch":
            self.draft, self.draft_path = args["patch"], args["path"]
            return {"ok": True}
        if tool == "run_named_test":
            # Fixed mock: passes only if the expected synthetic draft was recorded.
            passed = args["name"] == "test_normalize_label" and self.draft == EXPECTED_DRAFT_PATCH
            self.test_runs.append((args["name"], passed))
            return {"ok": True, "passed": passed}
        return {"ok": True}

    @property
    def count(self) -> int:
        return len(self.calls)


@dataclass(frozen=True)
class Decision:
    case_id: str
    tool: str  # sanitized: a known tool name or UNKNOWN_TOOL
    sanitized_args: dict
    decision: str  # "allow" | "deny"
    reason: str
    count_before: int
    count_after: int

    def row(self) -> str:
        return (f"case={self.case_id} tool={self.tool} args={self.sanitized_args} "
                f"decision={self.decision} reason={self.reason} "
                f"executor_count={self.count_before}->{self.count_after}")


def _is_absolute_or_drive(p: str) -> bool:
    """True for POSIX-absolute, Windows-absolute, rooted, drive-qualified, or UNC paths."""
    w = PureWindowsPath(p)
    return bool(PurePosixPath(p).is_absolute() or w.is_absolute() or w.drive or w.root)


class Gate:
    def __init__(self, executor: MockExecutor, config: TaskConfig | None = None):
        self.executor = executor
        self.config = config or TaskConfig()
        self.workspace = Path(self.config.workspace).resolve()

    # -- path handling ---------------------------------------------------
    def _canonical(self, rel: str) -> Path | None:
        """Resolve a workspace-relative string; None if it escapes the workspace."""
        resolved = (self.workspace / rel).resolve()
        if not resolved.is_relative_to(self.workspace):
            return None
        # A fully resolved path contains no links. On Python 3.13 a loop (in the final component
        # or in any parent directory) is returned unresolved instead of raising, so check every
        # component below the workspace and fail closed. Components that do not exist are fine.
        cur = self.workspace
        for part in resolved.relative_to(self.workspace).parts:
            cur = cur / part
            if cur.is_symlink():
                return None
        return resolved

    def _match(self, path: str, allowed_rel: str) -> tuple[str | None, Path | None]:
        """(None, canonical) if `path` is the exact allowed target, else (reason, None)."""
        if _is_absolute_or_drive(path) or ":" in path:  # also blocks NTFS stream syntax
            return "path_not_allowed", None
        try:
            target = self._canonical(path)  # containment: resolved target inside workspace
            if target is None:
                return "path_not_allowed", None
            allowed = self._canonical(allowed_rel)  # None if the allowed entry escapes
            if allowed is None or target != allowed:  # exact-target match
                return "path_not_allowed", None
            return None, target
        except (OSError, ValueError, RuntimeError):
            # Unresolvable (e.g. symlink loop: RuntimeError on 3.12, OSError elsewhere): fail closed.
            return "path_not_allowed", None

    def _label(self, value) -> str:
        if type(value) is not str or not value or "\0" in value or _is_absolute_or_drive(value):
            return REDACTED
        try:
            target = self._canonical(value)
            if target is None:
                return REDACTED
            for rel, label in self.config.labels:
                if self._canonical(rel) == target:
                    return label
        except (OSError, ValueError, RuntimeError):  # unresolvable: never raise from sanitizing
            pass
        return REDACTED

    def _sanitize(self, tool, args) -> tuple[str, dict]:
        if type(tool) is not str or tool not in TOOL_FIELDS:
            return UNKNOWN_TOOL, {}  # unknown tool: show no arguments at all
        safe = {}
        if isinstance(args, dict):
            for k in TOOL_FIELDS[tool]:  # unexpected keys are omitted
                if k not in args:
                    continue
                v = args[k]
                if k == "path":
                    safe[k] = self._label(v)
                elif k == "name":
                    safe[k] = v if type(v) is str and v in self.config.test_names else REDACTED
                else:  # "patch" and anything else: contents never shown
                    safe[k] = REDACTED
        return tool, safe

    # -- decision --------------------------------------------------------
    def _check(self, tool, args) -> tuple[str, str, dict | None]:
        if type(tool) is not str or tool not in TOOL_FIELDS:
            return "deny", "tool_not_allowed", None
        if type(args) is not dict or set(args) != set(TOOL_FIELDS[tool]):
            return "deny", "bad_arguments", None

        if tool == "run_named_test":
            name = args["name"]
            if type(name) is not str or not name or "\0" in name:
                return "deny", "bad_arguments", None
            if name not in self.config.test_names:
                return "deny", "name_not_allowed", None
            return "allow", "designated_test", {"name": name}

        path = args["path"]
        if type(path) is not str or not path or "\0" in path:
            return "deny", "bad_arguments", None

        if tool == "read_fixture":
            reason, target = self._match(path, self.config.read_target)
            if reason:
                return "deny", reason, None
            return "allow", "designated_source", {"path": str(target)}

        # write_draft_patch
        patch = args["patch"]
        if type(patch) is not str or patch == "" or "\0" in patch:
            return "deny", "bad_arguments", None
        reason, target = self._match(path, self.config.write_target)
        if reason:
            return "deny", reason, None
        return "allow", "designated_draft", {"path": str(target), "patch": patch}

    def call(self, case_id: str, tool, args) -> Decision:
        before = self.executor.count
        decision, reason, canonical_args = self._check(tool, args)
        if decision == "allow":
            self.executor.execute(tool, canonical_args)  # validated canonical args only
        safe_tool, safe_args = self._sanitize(tool, args)
        return Decision(case_id, safe_tool, safe_args, decision, reason,
                        before, self.executor.count)
