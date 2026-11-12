"""Retained admins (SP / group), the supplied power_users permission set, and the read-only guard."""

import json
from types import SimpleNamespace

import pytest
from conftest import TODAY

from admin_to_power_user import main as cli
from admin_to_power_user.collectors.identities import build_identities
from admin_to_power_user.config import Config, RetainedAdmin
from admin_to_power_user.consolidator import proposed_grants, readiness
from admin_to_power_user.main import simulate
from admin_to_power_user.models import Snapshot
from admin_to_power_user.permission_set import bind, parse_permission_set
from admin_to_power_user.readonly import ReadOnlyViolation, check_request, is_read_only_sql, make_read_only
from admin_to_power_user.recommender import recommend_all
from admin_to_power_user.usage import Usage

ALICE = "user:alice@contoso.com"
BOB = "user:bob@contoso.com"


def _rebuild(snapshot, cfg):
    """Re-run identity resolution on the conftest workspace with a different config."""
    from conftest import _cv  # noqa: F401  (fixture helpers)

    s = Snapshot(snapshot.workspace_id, snapshot.workspace_host)
    s.principals, s.memberships = snapshot.principals, snapshot.memberships
    from admin_to_power_user.collectors.identities import resolve_retained
    from admin_to_power_user.model.graph import PrincipalGraph
    from admin_to_power_user.models import ADMINS_GROUP

    graph = PrincipalGraph(s.principals, s.memberships)
    admins = graph.members_of(ADMINS_GROUP)
    s.retained_admins = resolve_retained(s, cfg, graph, admins)
    s.in_scope = {m: "x" for m in admins if m not in s.retained_admins}
    return s


def test_retained_group_keeps_its_members_admin(snapshot):
    cfg = Config(retained_admins=[RetainedAdmin("service_principal", "sp-admin"), RetainedAdmin("group", "platform")])
    s = _rebuild(snapshot, cfg)
    assert BOB not in s.in_scope  # bob is admin via `platform`, which stays admin
    assert ALICE in s.in_scope
    assert any("human(s) stay workspace admin" in w for w in s.warnings)


def test_retained_sp_by_scim_id_and_unknown_warns(snapshot):
    cfg = Config(retained_admins=[RetainedAdmin("service_principal", "s1"), RetainedAdmin("group", "nope")])
    s = _rebuild(snapshot, cfg)
    assert "sp:sp-admin" in s.retained_admins
    assert any("nope" in w and "not found" in w for w in s.warnings)


def test_no_admin_left_is_a_blocker(snapshot):
    cfg = Config(retained_admins=[RetainedAdmin("user", "carol@contoso.com")])  # carol is not an admin
    snapshot.retained_admins = _rebuild(snapshot, cfg).retained_admins
    cfg.power_users_group = "power_users"
    deltas, _ = simulate(snapshot, cfg)
    [d] = [d for d in deltas if d.kind == "NO_ADMIN_LEFT"]
    assert d.severity == "BLOCKER"
    [rec] = [r for r in recommend_all([d])]
    assert rec.bucket == "PROCESS_CHANGE"


def test_bind_by_name_glob_star_and_id():
    names = {("cluster-policies", "p1"): "etl-policy", ("cluster-policies", "p2"): "etl-small",
             ("cluster-policies", "p3"): "Personal Compute", ("warehouses", "w1"): "shared"}
    ps = parse_permission_set({"grants": [
        {"object_type": "cluster-policies", "object_name": "etl-*", "level": "CAN_USE"},
        {"object_type": "warehouses", "object_id": "*", "level": "CAN_USE"},
        {"object_type": "cluster-policies", "object_id": "gone", "level": "CAN_USE"},
        {"object_type": "queries", "object_id": "q9", "level": "CAN_RUN"},
    ]})
    by_name, star, missing, unverified = bind(ps, names)
    assert by_name.ids == {"p1", "p2"} and by_name.matched == 2
    assert star.ids == {"*"} and star.matched == 1
    assert missing.matched == 0  # cluster policies are fully listed, so this is NOT_FOUND
    assert unverified.matched == -1  # queries are not inventoried


def _with_set(snapshot, perms):
    cfg = Config(power_users_group="power_users", permission_set=parse_permission_set(perms))
    cfg.high_usage_threshold, cfg.token_recent_days = 10, 30
    import admin_to_power_user.simulator as sim

    orig = sim.Simulator.__init__

    def init(self, *a, **k):
        k.setdefault("today", TODAY)
        orig(self, *a, **k)

    sim.Simulator.__init__ = init
    try:
        return cfg, *simulate(snapshot, cfg)
    finally:
        sim.Simulator.__init__ = orig


def test_permission_set_covers_breaks_and_reports_coverage(snapshot):
    snapshot.object_names[("cluster-policies", "p1")] = "etl-policy"
    snapshot.object_names[("instance-pools", "pool1")] = "etl-pool"
    snapshot.object_names[("notebooks", "9001")] = "/Users/carol@contoso.com/util"
    cfg, deltas, cov = _with_set(snapshot, {
        "grants": [
            {"object_type": "cluster-policies", "object_name": "etl-*", "level": "CAN_USE"},
            {"object_type": "directories", "path": "/Users/carol@contoso.com", "level": "CAN_READ"},
            {"object_type": "instance-pools", "object_id": "*", "level": "CAN_MANAGE"},
            {"object_type": "warehouses", "object_id": "nope", "level": "CAN_USE"},
        ],
        "entitlements": ["allow-cluster-create"],
        "uc_privileges": ["CREATE_CATALOG"],
    })
    covered = {(d.object_type, d.object_id): d for d in deltas if d.covered_by}
    assert covered[("cluster-policies", "p1")].covered_by == "CAN_USE on cluster-policies name=etl-*"
    assert ("notebooks", "9001") in covered  # folder grant covers the notebook below it
    assert ("instance-pools", "pool1") in covered
    assert ("uc-metastore", "CREATE_CATALOG") in covered
    # still open: secret scope and cluster of alice's job
    open_ = {(d.object_type, d.object_id) for d in deltas if not d.covered_by and d.breaks}
    assert ("secret-scopes", "prod") in open_ and ("clusters", "c1") in open_

    rows = {c.permission_id: c for c in cov}
    assert rows["CAN_USE on cluster-policies name=etl-*"].status == "USED"
    assert rows["CAN_MANAGE on instance-pools *"].scope_creep
    assert rows["entitlement allow-cluster-create"].scope_creep
    assert rows["CAN_USE on warehouses nope"].status == "NOT_FOUND"

    recs = recommend_all(deltas)
    by_id = {d.delta_id: d for d in deltas}
    assert all(r.bucket == "COVERED" for r in recs if by_id[r.delta_id].covered_by)
    grants = proposed_grants(by_id, recs)
    assert ("cluster-policies", "p1") not in {(g.object_type, g.object_id) for g in grants}
    summary = readiness("123", "h", snapshot.in_scope, snapshot.principals, deltas, grants, [], [])
    assert summary.covered_by_permission_set == sum(1 for d in deltas if d.covered_by)
    assert summary.blockers == sum(1 for d in deltas if d.breaks and not d.covered_by and d.severity == "BLOCKER")


def test_token_usage_in_set_unblocks_pats(snapshot):
    _, deltas, cov = _with_set(snapshot, {"token_usage": True})
    assert all(not d.breaks for d in deltas if d.kind == "TOKEN")
    [row] = cov
    assert row.permission_type == "token_usage" and row.fixes_n_deltas >= 1


# ---- read-only guard -------------------------------------------------------------------------

def test_guard_allows_reads_and_select_only():
    check_request("GET", "/api/2.1/jobs/list", None)
    check_request("POST", "/api/2.0/sql/statements", {"statement": "SELECT 1"})
    check_request("POST", "/api/2.0/sql/statements/", {"statement": "WITH a AS (SELECT 1) SELECT * FROM a"})
    for method, path, body in [("POST", "/api/2.1/jobs/reset", {}), ("PATCH", "/api/2.0/preview/scim/v2/Groups/1", {}),
                               ("PUT", "/api/2.0/permissions/clusters/c1", {}), ("DELETE", "/api/2.0/token/x", None),
                               ("POST", "/api/2.0/sql/statements", {"statement": "DROP TABLE x"}),
                               ("POST", "/api/2.0/sql/statements", {"statement": "SELECT 1; DELETE FROM t"}),
                               ("POST", "/api/2.0/sql/statements",
                                {"statement": "WITH a AS (SELECT 1) INSERT INTO t SELECT * FROM a"})]:
        with pytest.raises(ReadOnlyViolation):
            check_request(method, path, body)
    assert is_read_only_sql("SELECT * FROM t WHERE action_name = 'create' -- delete")


def test_guard_reads_strings_and_comments_in_order():
    # `--` and `/*` inside a string are text, not comments (the dashboard's fix summary says "--permissions")
    assert is_read_only_sql("SELECT 'rerun with --permissions, then Set it' AS what_to_do FROM t")
    assert is_read_only_sql("SELECT '/* not a comment', 'Delete me' FROM t")
    assert is_read_only_sql("SELECT `odd--name`, 1 FROM t -- it's fine")
    # ...and a quote or comment marker must not hide a second statement
    for sql in ("SELECT 1 -- '\n; DROP TABLE t", "SELECT '/*', 1; DELETE FROM t --*/",
                "SELECT 1 /* ' */; DROP TABLE t", "SELECT 'a''; DROP TABLE t; --'; DELETE FROM t"):
        assert not is_read_only_sql(sql), sql


def test_dashboard_queries_pass_the_guard():
    from admin_to_power_user.dashboard import build

    for ds in build("`main`.`adm`")["datasets"]:
        assert is_read_only_sql("".join(ds["queryLines"])), ds["name"]


def test_make_read_only_blocks_before_sending():
    sent = []
    api = SimpleNamespace(do=lambda *a, **k: sent.append(a) or {})
    w = make_read_only(SimpleNamespace(api_client=api))
    w.api_client.do("GET", "/api/2.0/clusters/list", query={"a": 1})
    with pytest.raises(ReadOnlyViolation):
        w.api_client.do("POST", "/api/2.0/clusters/delete", body={"cluster_id": "c"})
    assert len(sent) == 1


def test_target_client_without_sql_only_reads():
    check_request("GET", "/api/2.1/jobs/list", None, allow_sql=False)
    with pytest.raises(ReadOnlyViolation, match="target workspace"):
        check_request("POST", "/api/2.0/sql/statements", {"statement": "SELECT 1"}, allow_sql=False)
    sent = []
    api = SimpleNamespace(do=lambda *a, **k: sent.append(a) or {})
    w = make_read_only(SimpleNamespace(api_client=api), allow_sql=False)
    w.api_client.do("GET", "/api/2.0/clusters/list")
    with pytest.raises(ReadOnlyViolation):
        w.api_client.do("POST", "/api/2.0/sql/statements", body={"statement": "SELECT 1"})
    assert len(sent) == 1


def test_every_usage_query_passes_the_guard(snapshot):
    seen = []

    class Recorder:
        def query(self, sql):
            assert is_read_only_sql(sql), sql
            seen.append(sql)
            return []

    from admin_to_power_user.collectors.identities import NameResolver

    Usage(Recorder(), snapshot, NameResolver(snapshot), 90).collect(Config().admin_only_actions)
    assert len(seen) == 6 and not snapshot.warnings


# ---- end to end with the new inputs ----------------------------------------------------------

def test_cli_with_admin_client_id_and_permission_file(tmp_path, monkeypatch, capsys, output):
    from test_end_to_end import fake_workspace

    monkeypatch.setattr(cli, "workspace_client", lambda cfg, host, profile, **k: fake_workspace())
    perms = tmp_path / "perms.yaml"
    perms.write_text("entitlements: [databricks-sql-access]\n"
                     "grants:\n  - {object_type: clusters, object_name: shared, level: CAN_RESTART}\n"
                     "  - {object_type: secret-scopes, object_id: prod, level: READ}\n")
    rc = cli.main(["analyze", "--admin-client-id", "sp-admin", "--permissions", str(perms), "--workspace-id", "1",
                   "--catalog", "c", "--schema", "s"])
    assert rc == 0
    load = lambda t: output[t]  # noqa: E731
    covered = {(d["object_type"], d["object_id"]) for d in load("deltas") if d["covered_by"]}
    assert {("clusters", "c1"), ("entitlement", "databricks-sql-access")} <= covered
    statuses = {c["permission_id"]: c["status"] for c in load("permission_set_coverage")}
    assert statuses["CAN_RESTART on clusters name=shared"] == "USED"
    [run] = load("runs")
    assert run["retained_admins"] == "sp:sp-admin" and run["permission_set_size"] == 3
    out = capsys.readouterr().out
    assert "Nothing else in the workspace was changed." in out and "dashboard: https://" in out


def test_cli_refuses_backticks_in_output_names(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "workspace_client", lambda *a, **k: called.append(a))
    for args in (["--catalog", "main`; DROP", "--schema", "s"], ["--catalog", "c", "--schema", "a`.`b"]):
        with pytest.raises(SystemExit, match="backtick"):
            cli.main(["--admin", "sp-admin", *args])
    assert not called  # refused before connecting to anything


def test_cli_refuses_wrong_workspace_id(tmp_path, monkeypatch):
    from test_end_to_end import fake_workspace

    monkeypatch.setattr(cli, "workspace_client", lambda cfg, host, profile, **k: fake_workspace())
    with pytest.raises(SystemExit, match="--workspace-id"):
        cli.main(["analyze", "--admin-client-id", "sp-admin", "--workspace-id", "999", "--catalog", "c", "--schema", "s"])


def _fake(me="alice@contoso.com", warehouses=()):
    from databricks.sdk.service import iam as _iam
    from test_end_to_end import fake_workspace

    w = fake_workspace()
    w.current_user = SimpleNamespace(me=lambda: _iam.User(user_name=me))
    w.warehouses = SimpleNamespace(list=lambda: iter(warehouses))
    return w


def test_cli_needs_admin_when_run_by_a_human(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "workspace_client", lambda cfg, host, profile, **k: _fake())
    with pytest.raises(SystemExit, match="--admin"):
        cli.main(["analyze", "--catalog", "c", "--schema", "s"])


def test_cli_defaults_admin_to_running_sp_and_needs_no_other_input(tmp_path, monkeypatch, capsys, output):
    sp = "0f0e0d0c-1111-2222-3333-444455556666"
    w = _fake(me=sp)
    w.service_principals = SimpleNamespace(list=lambda **k: iter([
        __import__("databricks.sdk.service.iam", fromlist=["x"]).ServicePrincipal(id="s9", application_id=sp)]))
    monkeypatch.setattr(cli, "workspace_client", lambda cfg, host, profile, **k: w)
    assert cli.main(["analyze", "--catalog", "c", "--schema", "s"]) == 0
    out = capsys.readouterr().out
    assert f"keeping {sp}" in out and "no permission set given" in out
    assert output["_dashboard"][0] == f"/Users/{sp}"
    text = output["artifacts"][0]["content"]
    import yaml

    assert isinstance(yaml.safe_load(text), list)  # loadable straight back with --permissions


def test_admin_flag_accepts_client_id_or_group(snapshot):
    for ref, expected in (("sp-admin", "sp:sp-admin"), ("platform", "group:platform"), ("s1", "sp:sp-admin")):
        s = _rebuild(snapshot, Config(retained_admins=[RetainedAdmin("auto", ref)]))
        assert expected in s.retained_admins, ref


def test_compact_permission_lines():
    from admin_to_power_user.permission_set import parse_line

    ps = parse_permission_set(["workspace-access", 'CAN_USE policies "Personal Compute"', "CAN_USE warehouses *",
                               "CAN_RUN /Shared", "CREATE_CATALOG", "token-usage", "can_read secrets kv"])
    assert ps.entitlements == {"workspace-access"} and ps.uc_privileges == {"CREATE_CATALOG"} and ps.token_usage
    kinds = {(g.object_type, g.level, g.object_id, g.object_name, g.path) for g in ps.grants}
    assert kinds == {("cluster-policies", "CAN_USE", None, "Personal Compute", None),
                     ("warehouses", "CAN_USE", "*", None, None), ("directories", "CAN_RUN", None, None, "/Shared"),
                     ("secret-scopes", "READ", None, "kv", None)}
    for bad in ("workspace-acess", "CAN_DRIVE clusters x", "a b c d"):
        with pytest.raises(ValueError):
            parse_permission_set([bad]) if bad != "workspace-acess" else parse_line(bad)


def test_name_target_matches_ids_and_unlisted_ids():
    ps = parse_permission_set(["CAN_USE cluster-policies ABC123", "CAN_RUN queries q9"])
    pol, q = bind(ps, {("cluster-policies", "ABC123"): "etl"})
    assert pol.ids == {"ABC123"} and pol.matched == 1
    assert q.ids == {"q9"} and q.matched == -1


def test_suggested_file_round_trips(snapshot, tmp_path):
    from admin_to_power_user.config import load_permission_file
    from admin_to_power_user.consolidator import suggested_permissions_yaml

    cfg, deltas, _ = _with_set(snapshot, ["workspace-access", "CAN_USE cluster-policies p1"])
    recs = recommend_all(deltas)
    grants = proposed_grants({d.delta_id: d for d in deltas}, recs)
    f = tmp_path / "s.yaml"
    f.write_text(suggested_permissions_yaml(cfg.permission_set, grants))
    again = load_permission_file(str(f))
    assert "workspace-access" in again.entitlements and "CREATE_CATALOG" in again.uc_privileges
    assert not any(g.object_type == "instance-pools" for g in again.grants)  # CAN_MANAGE pool = scope creep
    assert "# Also needed, but scope creep" in f.read_text()


def test_pick_warehouse_prefers_running_then_serverless():
    from databricks.sdk.service.sql import EndpointInfo, State

    from admin_to_power_user.usage import pick_warehouse

    stopped = EndpointInfo(id="a", name="classic", state=State.STOPPED)
    sless = EndpointInfo(id="b", name="sless", state=State.STOPPED, enable_serverless_compute=True)
    run = EndpointInfo(id="c", name="run", state=State.RUNNING)
    w = lambda *xs: SimpleNamespace(warehouses=SimpleNamespace(list=lambda: iter(xs)))  # noqa: E731
    assert pick_warehouse(w(stopped, sless, run))[0] == "c"
    assert pick_warehouse(w(stopped, sless))[0] == "b"
    assert pick_warehouse(w(stopped)) is None


def test_build_identities_uses_retained_admins(snapshot):
    assert "sp:sp-admin" in snapshot.retained_admins and "sp:sp-admin" not in snapshot.in_scope
    _ = build_identities  # imported for clarity: conftest builds the snapshot through it


def test_assume_moved_flag_removes_that_jobs_breaks(tmp_path, monkeypatch, output):
    monkeypatch.setattr(cli, "workspace_client", lambda cfg, host, profile, **k: _fake())
    assert cli.main(["--admin", "sp-admin", "--assume-moved", "job:101", "--catalog", "c", "--schema", "s"]) == 0
    deltas = output["deltas"]
    assert not [d for d in deltas if d["artifact_id"] == "101"]
    with pytest.raises(SystemExit, match="assume-moved"):
        cli.main(["--admin", "sp-admin", "--assume-moved", "cluster:1", "--catalog", "c", "--schema", "s"])
