"""UcSink + dashboard deploy through the real SDK service classes and the real output guard."""

import json
from types import SimpleNamespace

import pytest
from databricks.sdk.errors import NotFound
from databricks.sdk.service import catalog, dashboards, iam, sql, workspace

from admin_to_power_user.dashboard import build, deploy
from admin_to_power_user.models import Delta, PermissionCoverage
from admin_to_power_user.readonly import ReadOnlyViolation, WriteScope, check_request, is_output_sql, make_output_only
from admin_to_power_user.uc_sink import UcSink, columns_of, sql_literal

SCOPE = lambda: WriteScope("main", "adm", "/Users/me@x.com")  # noqa: E731
META = {"run_id": "r2", "run_ts": "2026-11-09 10:00:00", "workspace_id": "1"}


class FakeApi:
    """Transport stub: records what reaches the wire and answers like the REST API."""

    def __init__(self, existing_tables=None, existing_dashboard=None):
        self.sent = []
        self.tables = existing_tables or {}
        self.dashboard = existing_dashboard
        self._cfg = SimpleNamespace(workspace_id=None)

    def do(self, method, path=None, url=None, query=None, headers=None, body=None, *a, **k):
        self.sent.append((method, path, body))
        if path.startswith("/api/2.1/unity-catalog/schemas/"):
            raise NotFound("no schema")
        if path.startswith("/api/2.1/unity-catalog/tables/"):
            name = path.rsplit("/", 1)[1].split(".")[-1]
            if name in self.tables:
                return {"name": name, "columns": [{"name": c} for c in self.tables[name]]}
            raise NotFound("no table")
        if path == "/api/2.0/sql/statements":
            return {"statement_id": "s", "status": {"state": "SUCCEEDED"}}
        if path == "/api/2.0/workspace/get-status":
            if self.dashboard and query["path"].endswith(".lvdash.json"):
                return {"path": query["path"], "object_type": "DASHBOARD", "resource_id": self.dashboard}
            raise NotFound("nope")
        if path == "/api/2.0/lakeview/dashboards":
            return {"dashboard_id": "new1", **body}
        return {}

    def statements(self):
        return [b["statement"] for m, p, b in self.sent if p == "/api/2.0/sql/statements"]


def _client(api, scope):
    w = SimpleNamespace(api_client=api, config=SimpleNamespace(host="https://adb-1.1.azuredatabricks.net"),
                        statement_execution=sql.StatementExecutionAPI(api), schemas=catalog.SchemasAPI(api),
                        tables=catalog.TablesAPI(api), workspace=workspace.WorkspaceAPI(api),
                        lakeview=dashboards.LakeviewAPI(api), permissions=iam.PermissionsAPI(api))
    return make_output_only(w, scope)


def _delta(**kw):
    base = dict(workspace_id="1", principal="user:o'neil@x.com", kind="RUN_AS_DEPENDENCY", object_type="clusters",
                object_id="c1", object_name="it's; DROP TABLE x", required_level="CAN_RESTART", level_before="CAN_MANAGE",
                level_after=None, via="task 'a'", breaks=True, severity="BLOCKER", usage_count=3, delta_id="d1")
    base.update(kw)
    return Delta(**base)


def test_sink_creates_schema_and_tables_and_inserts_inside_scope():
    api = FakeApi()
    ww = _client(api, SCOPE())
    sink = UcSink(ww, "wh", "main", "adm", META)
    sink.write("deltas", [_delta(), _delta(delta_id="d2")], Delta)
    sink.write("permission_set_coverage", [], PermissionCoverage)  # empty tables are still created
    sink.finish()
    stmts = api.statements()
    assert stmts[0] == "CREATE SCHEMA IF NOT EXISTS `main`.`adm`"
    assert stmts[1].startswith("CREATE TABLE IF NOT EXISTS `main`.`adm`.`deltas` (`run_id` STRING, `run_ts` TIMESTAMP")
    assert stmts[2].startswith("INSERT INTO `main`.`adm`.`deltas`") and stmts[2].count("), (") == 1
    assert "'it\\'s; DROP TABLE x'" in stmts[2] and "TIMESTAMP '2026-11-09 10:00:00'" in stmts[2]
    assert stmts[3].startswith("CREATE TABLE IF NOT EXISTS `main`.`adm`.`permission_set_coverage`")
    assert not any(s.startswith("DELETE") for s in stmts)  # append mode keeps history


def test_overwrite_deletes_only_this_workspaces_older_runs_after_writing():
    api = FakeApi(existing_tables={"deltas": list(columns_of(Delta))[:-1]})  # table lacks the newest column
    sink = UcSink(_client(api, SCOPE()), "wh", "main", "adm", META, mode="overwrite")
    sink.write("deltas", [_delta()], Delta)
    sink.finish()
    stmts = api.statements()
    assert stmts[1].startswith("ALTER TABLE `main`.`adm`.`deltas` ADD COLUMNS (`covered_by` STRING)")
    assert stmts[-1] == "DELETE FROM `main`.`adm`.`deltas` WHERE workspace_id = '1' AND run_id <> 'r2'"
    assert stmts.index(stmts[-1]) > max(i for i, s in enumerate(stmts) if s.startswith("INSERT"))


def test_large_tables_are_split_into_batches(monkeypatch):
    import admin_to_power_user.uc_sink as uc

    monkeypatch.setattr(uc, "MAX_STATEMENT_BYTES", 2000)
    api = FakeApi()
    UcSink(_client(api, SCOPE()), "wh", "main", "adm", META).write("deltas", [_delta()] * 20, Delta)
    inserts = [s for s in api.statements() if s.startswith("INSERT")]
    assert len(inserts) > 1 and sum(s.count("'user:o\\'neil@x.com'") for s in inserts) == 20


def test_output_guard_refuses_anything_outside_the_scope():
    scope = SCOPE()
    bad_sql = [
        "INSERT INTO `main`.`other`.`deltas` (`a`) VALUES ('x')",
        "CREATE TABLE IF NOT EXISTS `prod`.`adm`.`t` (`a` STRING)",
        "DROP TABLE `main`.`adm`.`deltas`",
        "INSERT INTO `main`.`adm`.`deltas` (`a`) SELECT * FROM secrets",
        "DELETE FROM `main`.`adm`.`deltas` WHERE a IN (SELECT 1)",
        "CREATE TABLE IF NOT EXISTS `main`.`adm`.`t` (`a` STRING) AS SELECT 1",
        "CREATE OR REPLACE VIEW `main`.`adm`.`v` AS SELECT 1",
        "GRANT SELECT ON SCHEMA `main`.`adm` TO `users`",
        "INSERT INTO `main`.`adm`.`t` (`a`) VALUES ('x'); DROP TABLE `main`.`adm`.`t`",
        "ALTER TABLE `main`.`adm`.`t` OWNER TO `x`",
    ]
    for s in bad_sql:
        assert not is_output_sql(s, scope), s
        with pytest.raises(ReadOnlyViolation):
            check_request("POST", "/api/2.0/sql/statements", {"statement": s}, scope)
    assert is_output_sql("INSERT INTO `main`.`adm`.`t` (`a`, `b`) VALUES ('x;y', NULL), ('it\\'s', TRUE)", scope)
    for method, path, body in [
        ("PUT", "/api/2.0/permissions/clusters/c1", {}),
        ("POST", "/api/2.0/lakeview/dashboards", {"parent_path": "/Shared"}),
        ("PATCH", "/api/2.0/lakeview/dashboards/someone-elses", {}),
        ("POST", "/api/2.0/lakeview/dashboards/someone-elses/published", {}),
        ("DELETE", "/api/2.0/lakeview/dashboards/new1", None),
        ("POST", "/api/2.0/workspace/mkdirs", {"path": "/Shared/x"}),
        ("POST", "/api/2.0/workspace/delete", {"path": "/Users/me@x.com"}),
        ("PATCH", "/api/2.0/preview/scim/v2/Groups/1", {}),
    ]:
        with pytest.raises(ReadOnlyViolation):
            check_request(method, path, body, scope)


def test_deploy_creates_then_updates_the_same_dashboard():
    scope = SCOPE()
    api = FakeApi()
    did, url = deploy(_client(api, scope), scope, "wh", "Admin readiness")
    assert did == "new1" and url.endswith("/dashboardsv3/new1/published")
    calls = [(m, p) for m, p, _ in api.sent]
    assert ("POST", "/api/2.0/workspace/mkdirs") in calls and ("POST", "/api/2.0/lakeview/dashboards") in calls
    assert ("POST", "/api/2.0/lakeview/dashboards/new1/published") in calls
    created = next(b for m, p, b in api.sent if p == "/api/2.0/lakeview/dashboards")
    assert created["parent_path"] == "/Users/me@x.com" and "`main`.`adm`.runs" in created["serialized_dashboard"]
    assert "__CATALOG__" not in created["serialized_dashboard"]

    # the dashboard is locked: an existing one is always brought back to the packaged definition
    api2 = FakeApi(existing_dashboard="old7")
    scope2 = SCOPE()
    did2, _ = deploy(_client(api2, scope2), scope2, "wh", "Admin readiness")
    calls2 = [(m, p) for m, p, _ in api2.sent]
    assert did2 == "old7" and ("PATCH", "/api/2.0/lakeview/dashboards/old7") in calls2
    assert ("POST", "/api/2.0/lakeview/dashboards") not in calls2
    patched = next(b for m, p, b in api2.sent if m == "PATCH")
    assert json.loads(patched["serialized_dashboard"]) == build("`main`.`adm`")


def test_packaged_dashboard_is_consistent():
    import re

    d = build("`main`.`adm`")
    names = {ds["name"] for ds in d["datasets"]}
    for page in d["pages"]:
        for item in page["layout"]:
            wdg = item["widget"]
            query_names = {q["name"] for q in wdg.get("queries", [])}
            for q in wdg.get("queries", []):
                assert q["query"]["datasetName"] in names
            for f in (wdg.get("spec", {}).get("encodings", {}).get("fields") or []):
                assert f["queryName"] in query_names  # filters point at their own queries
            if wdg.get("spec", {}).get("widgetType") == "table":
                fields = {f["name"] for q in wdg["queries"] for f in q["query"]["fields"]}
                assert {c["fieldName"] for c in wdg["spec"]["encodings"]["columns"]} <= fields
    for ds in d["datasets"]:  # Lakeview joins queryLines with nothing in between
        q = "".join(ds["queryLines"])
        assert "`main`.`adm`" in q
        for glued in ("ORDER BY", "WHERE", "FROM", "JOIN", "GROUP BY"):
            assert not re.search(r"[A-Za-z0-9_`]" + glued, q), (ds["name"], glued)
    assert [p["displayName"] for p in d["pages"]] == ["Readiness"]  # one page, by design
    for page in d["pages"]:  # 12-column grid, no overlapping widgets
        cells = set()
        for item in page["layout"]:
            q = item["position"]
            for x in range(q["x"], q["x"] + q["width"]):
                for y in range(q["y"], q["y"] + q["height"]):
                    assert x < 12 and (x, y) not in cells, (page["displayName"], item["widget"]["name"])
                    cells.add((x, y))


def test_sql_literal():
    assert sql_literal(None, "STRING") == "NULL" and sql_literal(True, "BOOLEAN") == "TRUE"
    assert sql_literal("a\\b'c", "STRING") == "'a\\\\b\\'c'" and sql_literal(7, "BIGINT") == "7"
