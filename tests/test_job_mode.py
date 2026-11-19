"""Running as a Databricks job: target reached as an SP with its OAuth secret, results in the job's workspace,
the dashboard published once, and concurrent writers retried."""

import base64
from types import SimpleNamespace

import pytest
from databricks.sdk.service import iam
from databricks.sdk.service.sql import StatementState

from admin_to_power_user import clients
from admin_to_power_user import main as cli
from admin_to_power_user import statements, uc_sink
from admin_to_power_user.readonly import ReadOnlyViolation
from test_end_to_end import fake_workspace

SECRET = "fake-oauth-secret-for-tests"
SP = "0f0e0d0c-1111-2222-3333-444455556666"
JOB_ARGS = ["--workspace-host", "https://adb-1.1.azuredatabricks.net", "--home-current",
            "--target-client-id", SP, "--target-secret-scope", "atpu", "--target-secret-key", "sp-secret",
            "--admin", "sp-admin", "--catalog", "c", "--schema", "s"]


def _home():
    return SimpleNamespace(
        config=SimpleNamespace(host="https://adb-2.2.azuredatabricks.net"), get_workspace_id=lambda: 2,
        current_user=SimpleNamespace(me=lambda: iam.User(user_name=SP)),
        secrets=SimpleNamespace(get_secret=lambda scope, key: SimpleNamespace(
            value=base64.b64encode(SECRET.encode()).decode()) if (scope, key) == ("atpu", "sp-secret") else None))


def _job(monkeypatch):
    """Wire the CLI to a fake home (default auth) and a fake target; record who gets used for what."""
    home, target, seen = _home(), fake_workspace(), {}

    def workspace_client(host, profile, sql=True):
        seen.setdefault("workspace_client", []).append((host, profile, sql))
        return home

    def target_client(host, client_id, client_secret):
        seen["target"] = (host, client_id, client_secret)
        return target

    class Runner:
        def __init__(self, w, warehouse_id):
            seen["usage"] = w

        def query(self, sql):
            return []

    monkeypatch.setattr(cli, "workspace_client", workspace_client)
    monkeypatch.setattr(cli, "target_client", target_client)
    monkeypatch.setattr(cli, "WarehouseRunner", Runner)
    monkeypatch.setattr(cli, "resolve_warehouse", lambda w, wid: seen.update(warehouse=w) or "wh-home")
    monkeypatch.setattr(cli, "output_client", lambda w, scope: seen.update(output=w) or ("output-client", scope))
    return home, target, seen


# ---- clients ----------------------------------------------------------------------------------

def test_target_client_is_oauth_m2m_and_get_only(monkeypatch):
    made, sent = {}, []
    api = SimpleNamespace(do=lambda *a, **k: sent.append(a) or {})
    monkeypatch.setattr(clients, "WorkspaceClient", lambda **kw: made.update(kw) or SimpleNamespace(api_client=api))
    w = clients.target_client("https://adb-9.9.azuredatabricks.net", SP, SECRET)
    assert made == {"host": "https://adb-9.9.azuredatabricks.net", "client_id": SP, "client_secret": SECRET,
                    "auth_type": "oauth-m2m"}  # never the job's own runtime credentials
    w.api_client.do("GET", "/api/2.0/clusters/list")
    for method, path, body in [("POST", "/api/2.0/sql/statements", {"statement": "SELECT 1"}),
                               ("POST", "/api/2.1/jobs/run-now", {"job_id": 1})]:
        with pytest.raises(ReadOnlyViolation):
            w.api_client.do(method, path, body=body)
    assert len(sent) == 1


def test_read_secret_decodes_the_value():
    assert clients.read_secret(_home(), "atpu", "sp-secret") == SECRET


# ---- CLI in job mode --------------------------------------------------------------------------

def test_job_mode_reads_secret_from_home_and_writes_only_there(monkeypatch, capsys, output):
    home, target, seen = _job(monkeypatch)
    assert cli.main(JOB_ARGS + ["--no-dashboard"]) == 0

    assert seen["workspace_client"] == [(None, None, True)]  # home = default auth (the job's workspace)
    assert seen["target"] == ("https://adb-1.1.azuredatabricks.net", SP, SECRET)
    assert seen["usage"] is home and seen["warehouse"] is home and seen["output"] is home
    [run] = output["runs"]
    assert run["workspace_id"] == "1" and run["workspace_host"] == target.config.host
    assert "_dashboard" not in output  # --no-dashboard
    out = capsys.readouterr().out
    assert "dashboard: skipped (--no-dashboard)" in out and "[target] https://adb-1.1" in out
    assert SECRET not in out and SECRET not in repr(output)  # the secret is never printed or written


def test_dashboard_only_skips_the_analysis(monkeypatch, capsys, output):
    home, _, seen = _job(monkeypatch)
    monkeypatch.setattr(cli, "collect", lambda *a, **k: pytest.fail("no analysis in --dashboard-only"))
    monkeypatch.setattr(cli, "UcSink", lambda *a, **k: pytest.fail("no table writes in --dashboard-only"))
    assert cli.main(["--home-current", "--catalog", "c", "--schema", "s", "--warehouse-id", "wh1",
                     "--dashboard-only"]) == 0
    assert output["_dashboard"][0] == f"/Users/{SP}" and seen["output"] is home
    assert "dashboard over c.s: https://" in capsys.readouterr().out


@pytest.mark.parametrize("args, message", [
    (["--workspace-host", "https://x", "--home-current", "--target-client-id", SP], "go together"),
    (["--workspace-host", "https://x", "--target-client-id", SP, "--target-secret-scope", "a",
      "--target-secret-key", "b"], "results workspace"),
    (["--home-current", "--target-client-id", SP, "--target-secret-scope", "a", "--target-secret-key", "b"],
     "--workspace-host"),
])
def test_job_flags_are_checked_before_connecting(monkeypatch, args, message):
    monkeypatch.setattr(cli, "workspace_client", lambda *a, **k: pytest.fail("connected before checking flags"))
    with pytest.raises(SystemExit, match=message):
        cli.main(args + ["--catalog", "c", "--schema", "s"])


# ---- concurrent writers -----------------------------------------------------------------------

def _sink(errors):
    """A UcSink whose statements fail with the given messages, then succeed."""
    calls = []

    def execute_statement(statement, warehouse_id, wait_timeout):
        calls.append(statement)
        msg = errors.pop(0) if errors else None
        state = StatementState.FAILED if msg else StatementState.SUCCEEDED
        return SimpleNamespace(statement_id="x", status=SimpleNamespace(
            state=state, error=SimpleNamespace(message=msg) if msg else None))

    sink = uc_sink.UcSink.__new__(uc_sink.UcSink)
    sink.w = SimpleNamespace(statement_execution=SimpleNamespace(execute_statement=execute_statement))
    sink.warehouse_id = "wh"
    return sink, calls


def test_sink_retries_delta_write_conflicts(monkeypatch):
    monkeypatch.setattr(uc_sink.time, "sleep", lambda s: None)
    sink, calls = _sink(["[DELTA_CONCURRENT_APPEND] ConcurrentAppendException: files were added"] * 2)
    sink.execute("INSERT INTO t VALUES (1)")
    assert len(calls) == 3

    sink, calls = _sink(["ConcurrentAppendException"] * 10)
    with pytest.raises(RuntimeError, match="ConcurrentAppendException"):
        sink.execute("INSERT INTO t VALUES (1)")
    assert len(calls) == uc_sink.RETRIES + 1


def test_sink_does_not_retry_other_errors(monkeypatch):
    monkeypatch.setattr(uc_sink.time, "sleep", lambda s: pytest.fail("no retry for a real error"))
    sink, calls = _sink(["[TABLE_OR_VIEW_NOT_FOUND] no such table"])
    with pytest.raises(RuntimeError, match="TABLE_OR_VIEW_NOT_FOUND"):
        sink.execute("INSERT INTO t VALUES (1)")
    assert len(calls) == 1


def test_statement_that_never_finishes_times_out(monkeypatch):
    clock = iter(range(0, 10_000, 600))
    monkeypatch.setattr(statements.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(statements.time, "sleep", lambda s: None)
    running = SimpleNamespace(statement_id="x", status=SimpleNamespace(state=StatementState.RUNNING))
    w = SimpleNamespace(statement_execution=SimpleNamespace(execute_statement=lambda **k: running,
                                                            get_statement=lambda sid: running))
    with pytest.raises(RuntimeError, match="still running"):
        statements.run_statement(w, "wh", "SELECT 1", timeout_seconds=1800)
