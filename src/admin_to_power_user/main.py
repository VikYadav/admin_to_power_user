"""Command line entrypoint. Analyzes a live workspace, writes the results to a Unity Catalog schema and
publishes a dashboard over them.

    admin-to-power-user --profile my-ws --catalog main --schema admin_to_power_user \
        --admin <SP client id or group> [--permissions power_users.yaml] [--mode overwrite]

The analysis client can only read. A separate output client can only write tables in <catalog>.<schema> and
the tool's own dashboard (see readonly.py).
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
import uuid
from datetime import datetime, timezone

from admin_to_power_user.clients import output_client, workspace_client
from admin_to_power_user.collectors.acls import collect_acls
from admin_to_power_user.collectors.compute import collect_compute_names
from admin_to_power_user.collectors.identities import NameResolver, collect_identities
from admin_to_power_user.collectors.jobs import collect_jobs
from admin_to_power_user.collectors.notebooks import scan_notebooks
from admin_to_power_user.collectors.pipelines import collect_pipelines
from admin_to_power_user.collectors.sql_objects import collect_sql_objects
from admin_to_power_user.collectors.tokens import collect_tokens
from admin_to_power_user.collectors.uc import collect_uc
from admin_to_power_user.config import Config, RetainedAdmin, load_permission_file, parse_moved
from admin_to_power_user.consolidator import (
    move_to_sp,
    process_changes,
    proposed_grants,
    readiness,
    suggested_permissions_yaml,
)
from admin_to_power_user.model.graph import PrincipalGraph
from admin_to_power_user.models import (
    ADMINS_GROUP,
    AclRow,
    Delta,
    MoveToSpItem,
    PermissionCoverage,
    PrincipalRow,
    ProcessChange,
    ProposedGrant,
    ReadinessSummary,
    Recommendation,
    RelevantObject,
    Snapshot,
)
from admin_to_power_user.model.resolver import WhatIf
from admin_to_power_user.permission_set import bind, coverage, to_what_if
from admin_to_power_user.recommender import recommend_all
from admin_to_power_user.dashboard import DEFAULT_NAME, deploy
from admin_to_power_user.readonly import WriteScope
from admin_to_power_user.simulator import Simulator
from admin_to_power_user.uc_sink import TextArtifact, UcSink
from admin_to_power_user.usage import Usage, WarehouseRunner, pick_warehouse


@dataclasses.dataclass
class RunInfo:
    workspace_host: str
    workspace_id: str
    power_users_group: str
    retained_admins: str
    permission_set_size: int
    lookback_days: int
    status: str
    warnings: str


def _optional(snapshot: Snapshot, label: str, fn, *args) -> None:
    """Secondary collectors: record a warning instead of failing the whole run."""
    try:
        fn(*args)
    except Exception as e:
        snapshot.warnings.append(f"{label} skipped: {e}")


def collect(w, cfg: Config, warehouse_id: str) -> Snapshot:
    snapshot = Snapshot(str(w.get_workspace_id()), w.config.host)
    collect_identities(w, snapshot, cfg)
    names = NameResolver(snapshot)
    print(f"[collect] {len(snapshot.in_scope)} admins in scope: {', '.join(sorted(snapshot.in_scope)) or '-'}")
    collect_compute_names(w, snapshot)
    targets = collect_jobs(w, snapshot, cfg, names)
    _optional(snapshot, "pipelines", collect_pipelines, w, snapshot, cfg, names)
    collect_sql_objects(w, snapshot, cfg, names)
    _optional(snapshot, "notebook scan", scan_notebooks, w, snapshot, cfg, targets)
    Usage(WarehouseRunner(w, warehouse_id), snapshot, names, cfg.lookback_days).collect(cfg.admin_only_actions)
    collect_uc(w, snapshot, names)
    _optional(snapshot, "tokens (needs workspace admin)", collect_tokens, w, snapshot, names)
    collect_acls(w, snapshot, cfg, names)
    print(f"[collect] {len(snapshot.dependencies)} dependencies, {len(snapshot.acls)} ACLs, "
          f"{len(snapshot.tokens)} tokens")
    return snapshot


def principal_rows(snapshot: Snapshot, cfg: Config) -> list[PrincipalRow]:
    graph = PrincipalGraph(snapshot.principals, snapshot.memberships)
    admins = graph.members_of(ADMINS_GROUP)
    keys = admins | set(snapshot.in_scope) | graph.members_of(cfg.power_users_key) | set(snapshot.retained_admins)
    rows = []
    for k in sorted(keys):
        p = snapshot.principals.get(k)
        reason = snapshot.in_scope.get(k) or snapshot.retained_admins.get(k) or \
            ("stays admin" if k in admins else "power_users member")
        rows.append(PrincipalRow(snapshot.workspace_id, k, p.kind if p else k.split(":", 1)[0],
                                 p.display_name if p else k, k in snapshot.in_scope, k in admins, reason))
    return rows


UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def apply_overrides(cfg: Config, args: argparse.Namespace) -> Config:
    for ref in args.admin or []:
        cfg.retained_admins.append(RetainedAdmin("auto", ref))
    for client_id in args.admin_client_id or []:
        cfg.retained_admins.append(RetainedAdmin("service_principal", client_id))
    for group in args.admin_group or []:
        cfg.retained_admins.append(RetainedAdmin("group", group))
    if args.permissions:
        cfg.permission_set = load_permission_file(args.permissions)
    if args.power_users_group:
        cfg.power_users_group = args.power_users_group
    if args.workspace_id:
        cfg.workspace_id = str(args.workspace_id)
    if args.workspace_host:
        cfg.workspace_host = args.workspace_host
    if args.lookback_days:
        cfg.lookback_days = args.lookback_days
    if args.assume_moved:
        cfg.what_if = dataclasses.replace(cfg.what_if, moved_to_sp=cfg.what_if.moved_to_sp | parse_moved(args.assume_moved))
    return cfg


def simulate(snapshot: Snapshot, cfg: Config):
    """Run the move twice: power_users as it exists today, and with your permission set added.

    Returns (deltas incl. covered ones, coverage rows). Covered deltas have `covered_by` set.
    """
    ps = cfg.permission_set
    bound = bind(ps, snapshot.object_names)
    moved = cfg.what_if.moved_to_sp
    sim = lambda wi: Simulator(snapshot, cfg.power_users_key, wi, cfg.high_usage_threshold,  # noqa: E731
                               cfg.token_recent_days).run()
    baseline = sim(WhatIf(moved_to_sp=moved))
    final = sim(to_what_if(ps, bound, moved))
    covered, rows = coverage(snapshot.workspace_id, ps, bound, baseline, final, snapshot.object_names)
    return final + covered, rows


def resolve_warehouse(w, warehouse_id: str | None) -> str:
    if warehouse_id:
        return warehouse_id
    picked = pick_warehouse(w)
    if not picked:
        raise SystemExit("No running or serverless SQL warehouse found; pass --warehouse-id.")
    print(f"[warehouse] using {picked[1]}")
    return picked[0]


def analyze(args: argparse.Namespace) -> int:
    cfg = apply_overrides(Config(), args)
    w = workspace_client(cfg, cfg.workspace_host, args.profile)
    me = w.current_user.me().user_name or ""
    if not cfg.all_retained():
        if not UUID.match(me):
            raise SystemExit(f"You are running as {me}. Say who stays admin: --admin <SP client id or group name>.")
        cfg.retained_admins.append(RetainedAdmin("service_principal", me))
        print(f"[admin] keeping {me} (the service principal running this) as workspace admin")
    if not cfg.permission_set.size:
        print("[power_users] no permission set given: simulating an empty power_users group; the dashboard "
              "shows the set that would fix what can be granted")
    ws_id = str(w.get_workspace_id())
    if cfg.workspace_id and cfg.workspace_id != ws_id:
        raise SystemExit(f"Connected to workspace {ws_id} ({w.config.host}) but --workspace-id is "
                         f"{cfg.workspace_id}. Check --workspace-host / --profile.")
    warehouse_id = resolve_warehouse(w, args.warehouse_id)
    folder = args.dashboard_folder or f"/Users/{me}"
    scope = WriteScope(args.catalog, args.schema, folder)
    ww = output_client(w, scope)
    run_id = uuid.uuid4().hex[:12]
    meta = {"run_id": run_id, "run_ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "workspace_id": ws_id}
    sink = UcSink(ww, warehouse_id, args.catalog, args.schema, meta, args.mode)  # fails fast if not writable

    snapshot = collect(w, cfg, warehouse_id)
    deltas, cov = simulate(snapshot, cfg)
    recs = recommend_all(deltas)
    by_id = {d.delta_id: d for d in deltas}
    grants = proposed_grants(by_id, recs)
    moves = move_to_sp(by_id, recs)
    changes = process_changes(by_id, recs)
    summary = readiness(snapshot.workspace_id, snapshot.workspace_host, snapshot.in_scope, snapshot.principals,
                        deltas, grants, moves, changes)
    retained = ", ".join(k for k, why in snapshot.retained_admins.items() if not why.startswith("member of")) or \
        ", ".join(r.label for r in cfg.all_retained())
    summary.permission_set_size = cfg.permission_set.size
    summary.unused_permissions = sum(1 for c in cov if c.status == "UNUSED")
    summary.not_found_permissions = sum(1 for c in cov if c.status == "NOT_FOUND")
    summary.retained_admins = retained

    relevant = {(d.object_type, d.object_id): d.object_name for d in snapshot.dependencies}
    tables = [
        ("runs", [RunInfo(snapshot.workspace_host, snapshot.workspace_id, cfg.power_users_group, retained,
                          cfg.permission_set.size, cfg.lookback_days, summary.status,
                          " | ".join(snapshot.warnings))], RunInfo),
        ("principals", principal_rows(snapshot, cfg), PrincipalRow),
        ("relevant_objects", [RelevantObject(snapshot.workspace_id, t, i, snapshot.object_names.get((t, i), n),
                                             (t, i) not in snapshot.missing_objects,
                                             snapshot.missing_objects.get((t, i), ""))
                              for (t, i), n in sorted(relevant.items())], RelevantObject),
        ("acls", [AclRow(snapshot.workspace_id, t, i, e.principal_key, e.level, e.inherited)
                  for (t, i), entries in snapshot.acls.items() for e in entries], AclRow),
        ("deltas", deltas, Delta),
        ("recommendations", recs, Recommendation),
        ("proposed_power_user_grants", grants, ProposedGrant),
        ("move_to_sp", moves, MoveToSpItem),
        ("process_changes", changes, ProcessChange),
        ("permission_set_coverage", cov, PermissionCoverage),
        ("readiness_summary", [summary], ReadinessSummary),
        ("artifacts", [TextArtifact("suggested_permissions.yaml",
                                    suggested_permissions_yaml(cfg.permission_set, grants))], TextArtifact),
    ]
    print(f"[output] writing {len(tables)} tables to {args.catalog}.{args.schema} ({args.mode})")
    for name, items, row_type in tables:
        sink.write(name, items, row_type)
    sink.finish()
    dashboard_id, url = deploy(ww, scope, warehouse_id, args.dashboard_name)

    print(f"\n=== {snapshot.workspace_host} (workspace {snapshot.workspace_id}) : {summary.status} ===")
    print(f"retained admins: {retained}")
    print(f"admins moving to {cfg.power_users_group}: {summary.admins_in_scope} ({summary.humans_in_scope} humans)")
    print(f"would fail: {summary.blockers} BLOCKER, {summary.high} HIGH | medium {summary.medium}, "
          f"low {summary.low}, info {summary.info}")
    if cfg.permission_set.size:
        print(f"your permission set ({cfg.permission_set.size} entries) fixes {summary.covered_by_permission_set} "
              f"break(s); unused entries: {summary.unused_permissions}, not found: {summary.not_found_permissions}, "
              f"scope creep: {sum(1 for c in cov if c.scope_creep)}")
    print(f"fixes: {summary.proposed_grants} more power_users grants ({summary.scope_creep_grants} scope creep), "
          f"{summary.move_to_sp_items} move-to-SP items, {summary.process_changes} process changes")
    for warning in snapshot.warnings:
        print(f"warning: {warning}")
    print(f"results: {args.catalog}.{args.schema} (run {run_id}, {args.mode})")
    print(f"dashboard: {url}")
    print("Nothing else in the workspace was changed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="admin-to-power-user",
        description="Predict what fails when workspace admins move to a power_users group. The analysis is "
                    "read-only; results go to <catalog>.<schema> and a published dashboard.")
    p.add_argument("--profile", default=None, help="~/.databrickscfg profile of the target workspace")
    p.add_argument("--catalog", required=True, help="catalog for the result tables")
    p.add_argument("--schema", required=True, help="schema for the result tables (created if missing)")
    p.add_argument("--mode", choices=("append", "overwrite"), default="append",
                   help="append keeps every run (default); overwrite replaces this workspace's earlier results")
    p.add_argument("--admin", action="append",
                   help="who stays admin: SP client id or group name/id; repeatable "
                        "(default: the service principal running this)")
    p.add_argument("--permissions", default=None, help="YAML list of power_users permissions (optional)")
    p.add_argument("--assume-moved", action="append", metavar="TYPE:ID",
                   help="treat job:<id> / pipeline:<id> / token:<id> / query:<id> as already moved to an SP")
    p.add_argument("--warehouse-id", default=None, help="SQL warehouse for system tables (default: auto)")
    p.add_argument("--lookback-days", type=int, default=None, help="usage window (default: 90)")
    p.add_argument("--power-users-group", default=None, help="default: power_users")
    p.add_argument("--workspace-host", default=None, help="default: the profile's workspace")
    p.add_argument("--workspace-id", default=None, help="expected workspace id (safety check)")
    p.add_argument("--dashboard-folder", default=None, help="workspace folder for the dashboard (default: your home)")
    p.add_argument("--dashboard-name", default=DEFAULT_NAME)
    p.add_argument("--admin-client-id", action="append", help=argparse.SUPPRESS)
    p.add_argument("--admin-group", action="append", help=argparse.SUPPRESS)
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["analyze"]:  # the old subcommand name still works
        argv = argv[1:]
    return analyze(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
