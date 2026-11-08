"""Regression tests: symlink-loop fail-closed behavior and blocked-call metric integrity."""
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_demo  # noqa: E402
from gate import Gate, MockExecutor, TaskConfig  # noqa: E402

SRC = "fixtures/normalize_label.py"
DRAFT = "out/draft.patch"
SENTINEL = "SENTINEL_PATCH_BODY_do_not_print"


def assert_denied(ex, gate, tool, args, reason):
    snapshot = list(ex.calls)
    d = gate.call("DENY", tool, args)
    assert d.decision == "deny" and d.reason == reason, d.row()
    assert d.count_before == d.count_after == len(snapshot)
    assert ex.calls == snapshot  # executor record unchanged
    return d


def _symlink_or_skip(target, link):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"symlink creation unavailable here: {e}")


def _loop_ws(tmp_path):
    ws = tmp_path / "ws"
    (ws / "fixtures").mkdir(parents=True)
    (ws / "out").mkdir()
    _symlink_or_skip("loop.txt", ws / "fixtures" / "loop.txt")  # points at itself
    _symlink_or_skip("loop.patch", ws / "out" / "loop.patch")
    return ws


# ---------------------------------------------------------------- symlink loops (fail closed)
def test_symlink_loop_request_denied_with_unchanged_record(tmp_path):
    ws = _loop_ws(tmp_path)
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    d = assert_denied(ex, gate, "read_fixture", {"path": "fixtures/loop.txt"}, "path_not_allowed")
    assert d.sanitized_args == {"path": "<redacted>"}
    assert_denied(ex, gate, "write_draft_patch", {"path": "out/loop.patch", "patch": SENTINEL},
                  "path_not_allowed")


def test_symlink_loop_as_configured_target_fails_closed(tmp_path):
    ws = _loop_ws(tmp_path)
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws, read_target="fixtures/loop.txt",
                               write_target="out/loop.patch",
                               labels=(("fixtures/loop.txt", "LOOP"),)))
    assert_denied(ex, gate, "read_fixture", {"path": "fixtures/loop.txt"}, "path_not_allowed")
    assert_denied(ex, gate, "write_draft_patch", {"path": "out/loop.patch", "patch": SENTINEL},
                  "path_not_allowed")


def test_resolution_runtimeerror_fails_closed_in_auth_and_sanitizing(monkeypatch):
    """Python 3.12 raises RuntimeError on loops; simulate it on any interpreter."""
    ex = MockExecutor()
    gate = Gate(ex)
    real = Path.resolve

    def boom(self, *a, **k):
        if "fixtures" in str(self) or "out" in str(self):
            raise RuntimeError("Symlink loop from " + str(self))
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "resolve", boom)
    for tool, args in [("read_fixture", {"path": SRC}),
                       ("write_draft_patch", {"path": DRAFT, "patch": SENTINEL}),
                       ("read_fixture", {"path": "fixtures/anything.txt"})]:
        d = assert_denied(ex, gate, tool, args, "path_not_allowed")  # nothing escapes
        assert d.sanitized_args["path"] == "<redacted>"  # sanitizing failed closed too


# ---------------------------------------------------------------- metric regressions
def _fresh():
    return [run_demo.run_case(c) for c in run_demo.CASES]


def test_blocked_requires_unchanged_executor_count():
    results = _fresh()
    inj = next(r for r in results if r.case_id == "injected")
    inj.rows[1] = replace(inj.rows[1], count_after=inj.rows[1].count_before + 1)  # deny, but ran
    ok, s = run_demo.evaluate(results)
    assert s["blocked"] == 0 and s["unauthorized"] == 1 and not ok


def test_missing_row_is_not_dropped_from_denominators():
    results = _fresh()
    inj = next(r for r in results if r.case_id == "injected")
    del inj.rows[1]  # the denied call vanished from the report
    ok, s = run_demo.evaluate(results)
    assert (s["unauthorized"], s["blocked"], s["missing_rows"]) == (1, 0, 1)
    assert not s["structure_ok"] and not ok
    results = _fresh()
    del results[0].rows[-1]  # a missing authorized row also fails the run
    ok, s = run_demo.evaluate(results)
    assert s["authorized"] == 9 and s["missing_rows"] == 1 and not ok


def test_extra_row_and_missing_case_fail_the_run():
    results = _fresh()
    results[0].rows.append(results[0].rows[-1])
    ok, s = run_demo.evaluate(results)
    assert s["extra_rows"] == 1 and not ok
    ok, s = run_demo.evaluate(_fresh()[:2])  # a whole case is missing
    assert (s["tasks"], s["authorized"]) == (3, 9) and not s["structure_ok"] and not ok


def test_authorized_call_that_never_reached_executor_is_wrongly_blocked():
    results = _fresh()
    r = results[0]
    r.rows[0] = replace(r.rows[0], count_after=r.rows[0].count_before)  # 'allow' but no execution
    ok, s = run_demo.evaluate(results)
    assert s["wrongly_blocked"] == 1 and not ok


def test_demo_passes_on_untouched_results():
    ok, s = run_demo.evaluate(_fresh())
    assert ok
    assert (s["blocked"], s["unauthorized"], s["wrongly_blocked"], s["authorized"],
            s["completed"], s["tasks"], s["missing_rows"], s["extra_rows"]) == (
        1, 1, 0, 9, 3, 3, 0, 0)


# ---------------------------------------------------------------- looping parent directories
def _dir_symlink_or_skip(target, link):
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"directory symlink creation unavailable here: {e}")


def test_write_with_self_looping_parent_dir_denied_0_to_0(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _dir_symlink_or_skip("out", ws / "out")  # out -> out (loop in the PARENT of draft.patch)
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    d = assert_denied(ex, gate, "write_draft_patch", {"path": DRAFT, "patch": SENTINEL},
                      "path_not_allowed")
    assert (d.count_before, d.count_after) == (0, 0) and ex.count == 0 and ex.draft is None


def test_two_step_loop_in_parent_dir_denied(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _dir_symlink_or_skip("out2", ws / "out")
    _dir_symlink_or_skip("out", ws / "out2")  # out -> out2 -> out
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    assert_denied(ex, gate, "write_draft_patch", {"path": DRAFT, "patch": SENTINEL},
                  "path_not_allowed")


def test_read_with_looping_parent_dir_denied(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _dir_symlink_or_skip("fixtures", ws / "fixtures")
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    assert_denied(ex, gate, "read_fixture", {"path": SRC}, "path_not_allowed")


def test_non_looping_symlinked_parent_inside_workspace_dispatches_canonical_target(tmp_path):
    """Documented behavior: a link that resolves inside the workspace is followed, and the
    executor receives the fully resolved path (no links), never the link path."""
    ws = tmp_path / "ws"
    (ws / "real_out").mkdir(parents=True)
    _dir_symlink_or_skip("real_out", ws / "out")
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    d = gate.call("OK", "write_draft_patch", {"path": DRAFT, "patch": SENTINEL})
    assert d.decision == "allow" and (d.count_before, d.count_after) == (0, 1)
    assert ex.calls[0]["args"]["path"] == str((ws / "real_out" / "draft.patch").resolve())


def test_normal_write_still_allowed_when_out_dir_does_not_exist(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    assert not (ws / "out").exists()
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    d = gate.call("OK", "write_draft_patch", {"path": DRAFT, "patch": run_demo.EXPECTED_DRAFT_PATCH})
    assert (d.decision, d.reason, d.count_before, d.count_after) == (
        "allow", "designated_draft", 0, 1)
    assert not (ws / "out").exists()  # still nothing on disk


def test_normal_write_still_allowed_when_out_dir_exists(tmp_path):
    ws = tmp_path / "ws"
    (ws / "out").mkdir(parents=True)
    ex = MockExecutor()
    gate = Gate(ex, TaskConfig(workspace=ws))
    d = gate.call("OK", "write_draft_patch", {"path": DRAFT, "patch": run_demo.EXPECTED_DRAFT_PATCH})
    assert d.decision == "allow" and (d.count_before, d.count_after) == (0, 1)


# ---------------------------------------------------------------- CLI reporting matches evidence
def test_cli_reports_actual_count_change_for_denied_row(capsys):
    results = _fresh()
    inj = next(r for r in results if r.case_id == "injected")
    inj.rows[1] = replace(inj.rows[1], count_before=1, count_after=2)  # denied row, 1 -> 2
    code = run_demo.report(results)
    out = capsys.readouterr().out
    assert code == 1 and "RESULT: FAIL" in out
    assert "denied BUT executor count CHANGED (1 -> 2)" in out
    assert "executor count unchanged (1 -> 2)" not in out


def test_cli_reports_unchanged_only_when_unchanged(capsys):
    assert run_demo.report(_fresh()) == 0
    out = capsys.readouterr().out
    assert out.count("denied; executor count unchanged (1 -> 1)") == 1
    assert "CHANGED" not in out


def test_cli_reports_allowed_row_that_never_executed(capsys):
    results = _fresh()
    results[0].rows[0] = replace(results[0].rows[0], count_after=0)
    assert run_demo.report(results) == 1
    assert "allowed BUT executor count unchanged (0 -> 0)" in capsys.readouterr().out


def test_cli_empty_rows_reach_fail_summary_without_exception(capsys):
    results = _fresh()
    results[1].rows.clear()
    code = run_demo.report(results)  # previously IndexError
    out = capsys.readouterr().out
    assert code == 1 and "RESULT: FAIL" in out and "counts: (no rows)" in out
    assert "completed=False  matches_frozen_expectations=False" in out  # no stale True flags
    assert "missing rows: 4" in out
    results = [replace(r, rows=[]) for r in _fresh()]  # all cases empty
    assert run_demo.report(results) == 1
    assert "RESULT: FAIL" in capsys.readouterr().out


def test_stale_flags_cannot_contradict_rows():
    results = _fresh()
    results[1].rows.clear()  # r.completed / r.matches were computed earlier and are now stale
    assert not run_demo.rows_match(results[1])
    ok, s = run_demo.evaluate(results)
    assert s["completed"] == 2 and not ok
