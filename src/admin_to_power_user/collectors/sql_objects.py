"""SQL queries/alerts and AI/BI dashboards that execute with an in-scope admin's credentials."""

from __future__ import annotations

from databricks.sdk import WorkspaceClient

from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.config import Config
from admin_to_power_user.model.levels import RUN_AS_REQUIRED
from admin_to_power_user.models import Artifact, Dependency, Kind, Snapshot

MAX_DASHBOARDS = 500


def collect_sql_objects(w: WorkspaceClient, snapshot: Snapshot, cfg: Config, names: NameResolver) -> None:
    try:
        for q in w.queries.list():
            owner = names.key(q.owner_user_name) if q.owner_user_name else None
            if owner not in snapshot.in_scope:
                continue
            artifact = Artifact("query", q.id, q.display_name or q.id)
            snapshot.object_names[("queries", q.id)] = q.display_name or q.id
            run_as_owner = getattr(q.run_as_mode, "value", q.run_as_mode) == "OWNER"
            if run_as_owner and q.warehouse_id:
                snapshot.dependencies.append(Dependency(
                    owner, Kind.RUN_AS_DEPENDENCY, "warehouses", q.warehouse_id, q.warehouse_id,
                    RUN_AS_REQUIRED["warehouses"], "query runs with owner's credentials", artifact))
            snapshot.ownership.append(Dependency(
                owner, Kind.OWNERSHIP_RISK, "queries", q.id, q.display_name or q.id, "IS_OWNER",
                "run as owner" if run_as_owner else "owned query", artifact))
    except Exception as e:
        snapshot.warnings.append(f"Could not list SQL queries: {e}")

    try:
        for a in w.alerts.list():
            owner = names.key(a.owner_user_name) if a.owner_user_name else None
            if owner in snapshot.in_scope:
                snapshot.ownership.append(Dependency(
                    owner, Kind.OWNERSHIP_RISK, "alerts", a.id, a.display_name or a.id, "IS_OWNER",
                    "owned alert", Artifact("alert", a.id, a.display_name or a.id)))
    except Exception as e:
        snapshot.warnings.append(f"Could not list SQL alerts: {e}")

    # AI/BI dashboards published with embedded credentials run as the publisher. The API does not expose
    # the publisher, so use dashboards stored in an in-scope admin's home folder as a proxy.
    homes = {f"/Users/{k.split(':', 1)[1]}/": k for k in snapshot.in_scope if k.startswith("user:")}
    try:
        for i, d in enumerate(w.lakeview.list()):
            if i >= MAX_DASHBOARDS:
                snapshot.warnings.append(f"Stopped dashboard scan after {MAX_DASHBOARDS} dashboards.")
                break
            owner = next((k for home, k in homes.items() if (d.path or "").startswith(home)), None)
            if owner is None:
                continue
            artifact = Artifact("dashboard", d.dashboard_id, d.display_name or d.dashboard_id)
            try:
                pub = w.lakeview.get_published(d.dashboard_id)
            except Exception:
                pub = None  # not published
            if pub and pub.embed_credentials and pub.warehouse_id:
                snapshot.dependencies.append(Dependency(
                    owner, Kind.RUN_AS_DEPENDENCY, "warehouses", pub.warehouse_id, pub.warehouse_id,
                    RUN_AS_REQUIRED["warehouses"], "published dashboard with embedded credentials", artifact))
            snapshot.ownership.append(Dependency(
                owner, Kind.OWNERSHIP_RISK, "dashboards", d.dashboard_id, d.display_name or d.dashboard_id,
                "CAN_MANAGE", "dashboard in admin's home folder" + (" (embedded credentials)" if pub and
                                                                    pub.embed_credentials else ""), artifact))
    except Exception as e:
        snapshot.warnings.append(f"Could not list dashboards: {e}")
