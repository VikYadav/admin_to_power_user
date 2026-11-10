"""Usage evidence from system tables (account-wide, filtered to the selected workspace).

Requires SELECT on system.access.audit and system.lakeflow.* for the identity running the tool.
Audit service/action/parameter names below come from the audit log reference; verify them against your
own logs (`SELECT DISTINCT service_name, action_name FROM system.access.audit`).
"""

from __future__ import annotations

import time
from typing import Iterable, Optional, Protocol

from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.models import Dependency, EntitlementNeed, Kind, Snapshot, key_name
from admin_to_power_user.readonly import check_sql

AUTOMATION_UA = ("terraform|databricks-sdk|databricks-cli|cli/|python-requests|curl|azure-data-factory|"
                 "okhttp|apache-httpclient|go-http-client|postman|powershell|airflow|dbt")

# (service_name, actions, request_params key holding the object id, object type, level the action needs)
TOUCH_RULES: list[tuple[str, tuple[str, ...], str, str, str]] = [
    ("clusters", ("start", "restart", "resize"), "cluster_id", "clusters", "CAN_RESTART"),
    ("clusters", ("edit", "delete", "permanentDelete", "changeClusterAcl"), "cluster_id", "clusters", "CAN_MANAGE"),
    ("jobs", ("runNow", "repairRun", "cancelAllRuns"), "job_id", "jobs", "CAN_MANAGE_RUN"),
    ("jobs", ("update", "reset", "delete", "changeJobAcl"), "job_id", "jobs", "CAN_MANAGE"),
    ("instancePools", ("edit", "delete", "changeInstancePoolAcl"), "instance_pool_id", "instance-pools", "CAN_MANAGE"),
    ("secrets", ("getSecret",), "scope", "secret-scopes", "READ"),
    ("secrets", ("putSecret", "deleteSecret"), "scope", "secret-scopes", "WRITE"),
    ("secrets", ("deleteScope", "putAcl", "deleteAcl"), "scope", "secret-scopes", "MANAGE"),
    ("deltaPipelines", ("startUpdate", "stop"), "pipeline_id", "pipelines", "CAN_RUN"),
    ("deltaPipelines", ("edit", "delete", "changePipelineAcls"), "pipeline_id", "pipelines", "CAN_MANAGE"),
    ("databrickssql", ("startEndpoint",), "id", "warehouses", "CAN_USE"),
    ("databrickssql", ("editEndpoint", "deleteEndpoint", "stopEndpoint"), "id", "warehouses", "CAN_MANAGE"),
]

# unityCatalog action -> metastore privilege it requires
UC_ACTIONS = {
    "createCatalog": "CREATE_CATALOG",
    "createExternalLocation": "CREATE_EXTERNAL_LOCATION",
    "createStorageCredential": "CREATE_STORAGE_CREDENTIAL",
    "createConnection": "CREATE_CONNECTION",
    "createShare": "CREATE_SHARE",
    "createRecipient": "CREATE_RECIPIENT",
    "createProvider": "CREATE_PROVIDER",
}


class SqlRunner(Protocol):
    def query(self, sql: str) -> list[dict]: ...


class WarehouseRunner:
    """Reads system tables through the Statement Execution API (SELECT only; see readonly.py)."""

    def __init__(self, w, warehouse_id: str):
        self.w = w
        self.warehouse_id = warehouse_id

    def query(self, sql: str) -> list[dict]:
        from databricks.sdk.service.sql import StatementState

        se = self.w.statement_execution
        resp = se.execute_statement(statement=check_sql(sql), warehouse_id=self.warehouse_id, wait_timeout="50s")
        while resp.status and resp.status.state in (StatementState.PENDING, StatementState.RUNNING):
            time.sleep(2)
            resp = se.get_statement(resp.statement_id)
        if resp.status.state != StatementState.SUCCEEDED:
            raise RuntimeError(f"Statement failed: {resp.status.error}")
        cols = [c.name for c in resp.manifest.schema.columns]
        rows = list((resp.result and resp.result.data_array) or [])
        for n in range(1, resp.manifest.total_chunk_count or 1):
            rows += se.get_statement_result_chunk_n(resp.statement_id, n).data_array or []
        return [dict(zip(cols, r)) for r in rows]


def lit(s: str) -> str:
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def in_list(values: Iterable[str]) -> str:
    vals = sorted(set(values))
    return "(" + ", ".join(lit(v) for v in vals) + ")" if vals else "(NULL)"


def _window(ws_id: str, days: int) -> str:
    return f"workspace_id = {lit(ws_id)} AND event_date >= date_sub(current_date(), {int(days)})"


class Usage:
    def __init__(self, runner: SqlRunner, snapshot: Snapshot, names: NameResolver, days: int):
        self.r = runner
        self.s = snapshot
        self.names = names
        self.days = days
        self.identities = [key_name(k) for k in snapshot.in_scope]

    def collect(self, admin_only_actions: list[str]) -> None:
        steps = (("job runs", self.job_runs), ("pipeline updates", self.pipeline_updates),
                 ("admin-only actions", lambda: self.admin_actions(admin_only_actions)),
                 ("object touches", self.object_touches), ("entitlement usage", self.entitlement_usage),
                 ("UC actions", self.uc_actions))
        for label, fn in steps:
            try:
                fn()
            except Exception as e:
                self.s.warnings.append(f"Usage query '{label}' failed (check system table access): {e}")

    def job_runs(self) -> None:
        rows = self.r.query(f"""
            SELECT CAST(job_id AS STRING) AS job_id, COUNT(DISTINCT run_id) AS runs,
                   MAX(period_start_time) AS last_run
            FROM system.lakeflow.job_run_timeline
            WHERE workspace_id = {lit(self.s.workspace_id)}
              AND period_start_time >= current_timestamp() - INTERVAL {int(self.days)} DAYS
            GROUP BY job_id""")
        self.s.job_runs = {r["job_id"]: {"runs": int(r["runs"]), "last_run": r["last_run"]} for r in rows}

    def pipeline_updates(self) -> None:
        rows = self.r.query(f"""
            SELECT pipeline_id, COUNT(DISTINCT update_id) AS updates, MAX(period_start_time) AS last_update
            FROM system.lakeflow.pipeline_update_timeline
            WHERE workspace_id = {lit(self.s.workspace_id)}
              AND period_start_time >= current_timestamp() - INTERVAL {int(self.days)} DAYS
            GROUP BY pipeline_id""")
        self.s.pipeline_updates = {r["pipeline_id"]: {"updates": int(r["updates"]), "last_update": r["last_update"]}
                                   for r in rows}

    def admin_actions(self, actions: list[str]) -> None:
        exact = [a for a in actions if not a.endswith(":*")]
        services = [a.split(":", 1)[0] for a in actions if a.endswith(":*")]
        if not self.identities or not actions:
            return
        rows = self.r.query(f"""
            SELECT user_identity.email AS principal, service_name, action_name,
                   CASE WHEN lower(coalesce(user_agent, '')) RLIKE '{AUTOMATION_UA}'
                        THEN 'automation' ELSE 'interactive' END AS client_type,
                   COUNT(*) AS n, MAX(event_time) AS last_seen, MAX(user_agent) AS user_agent_sample
            FROM system.access.audit
            WHERE {_window(self.s.workspace_id, self.days)}
              AND user_identity.email IN {in_list(self.identities)}
              AND (concat(service_name, ':', action_name) IN {in_list(exact)}
                   OR service_name IN {in_list(services)})
              AND response.status_code = 200
            GROUP BY 1, 2, 3, 4""")
        for r in rows:
            r["principal_key"] = self.names.key(r["principal"])
            r["n"] = int(r["n"])
        self.s.admin_only_actions = rows

    def object_touches(self) -> None:
        if not self.identities:
            return
        case = " ".join(f"WHEN service_name = {lit(svc)} AND action_name IN {in_list(acts)} "
                        f"THEN request_params[{lit(param)}]" for svc, acts, param, _, _ in TOUCH_RULES)
        services = {svc for svc, *_ in TOUCH_RULES}
        rows = self.r.query(f"""
            SELECT principal, service_name, action_name, object_id, COUNT(*) AS n, MAX(event_time) AS last_seen
            FROM (
              SELECT user_identity.email AS principal, service_name, action_name, event_time,
                     CASE {case} END AS object_id
              FROM system.access.audit
              WHERE {_window(self.s.workspace_id, self.days)}
                AND user_identity.email IN {in_list(self.identities)}
                AND service_name IN {in_list(services)}
                AND response.status_code = 200)
            WHERE object_id IS NOT NULL
            GROUP BY 1, 2, 3, 4""")
        rule_for = {(svc, a): (otype, level) for svc, acts, _, otype, level in TOUCH_RULES for a in acts}
        for r in rows:
            otype, level = rule_for[(r["service_name"], r["action_name"])]
            oid = str(r["object_id"])
            self.s.dependencies.append(Dependency(
                self.names.key(r["principal"]), Kind.DIRECT_USE, otype, oid,
                self.s.object_names.get((otype, oid), oid), level,
                f"audit {r['service_name']}:{r['action_name']}", None, int(r["n"]), r["last_seen"]))

    def entitlement_usage(self) -> None:
        if not self.identities:
            return
        rows = self.r.query(f"""
            SELECT user_identity.email AS principal, service_name, COUNT(*) AS n, MAX(event_time) AS last_seen
            FROM system.access.audit
            WHERE {_window(self.s.workspace_id, self.days)}
              AND user_identity.email IN {in_list(self.identities)}
              AND ((service_name = 'clusters' AND action_name = 'create'
                    AND coalesce(request_params['policy_id'], '') = '')
                   OR (service_name = 'instancePools' AND action_name = 'create'))
              AND response.status_code = 200
            GROUP BY 1, 2""")
        for r in rows:
            ent = "allow-cluster-create" if r["service_name"] == "clusters" else "allow-instance-pool-create"
            what = "created clusters without a policy" if ent == "allow-cluster-create" else "created instance pools"
            self.s.entitlement_needs.append(EntitlementNeed(
                self.names.key(r["principal"]), ent, f"{what} {r['n']}x", None, int(r["n"]), r["last_seen"]))

    def uc_actions(self) -> None:
        if not self.identities:
            return
        rows = self.r.query(f"""
            SELECT user_identity.email AS principal, action_name, COUNT(*) AS n, MAX(event_time) AS last_seen
            FROM system.access.audit
            WHERE {_window(self.s.workspace_id, self.days)}
              AND user_identity.email IN {in_list(self.identities)}
              AND service_name = 'unityCatalog' AND action_name IN {in_list(UC_ACTIONS)}
              AND response.status_code = 200
            GROUP BY 1, 2""")
        self.s.uc_actions = [{"principal_key": self.names.key(r["principal"]), "action_name": r["action_name"],
                              "privilege": UC_ACTIONS[r["action_name"]], "n": int(r["n"]),
                              "last_seen": r["last_seen"]} for r in rows]


def pick_warehouse(w) -> Optional[tuple[str, str]]:
    """(warehouse id, why) for reading system tables: a running warehouse, else a serverless one."""
    try:
        whs = list(w.warehouses.list())
    except Exception:
        return None
    state = lambda x: getattr(getattr(x, "state", None), "value", x.state)  # noqa: E731
    running = [x for x in whs if state(x) == "RUNNING"]
    serverless = [x for x in whs if x.enable_serverless_compute]
    if running:
        return running[0].id, f"'{running[0].name}' (already running)"
    if serverless:
        return serverless[0].id, f"'{serverless[0].name}' (serverless; starts if stopped)"
    return None
