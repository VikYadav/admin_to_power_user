"""Display names for compute objects and secret scopes, so results show names instead of ids."""

from __future__ import annotations

from databricks.sdk import WorkspaceClient

from admin_to_power_user.models import Snapshot


def collect_compute_names(w: WorkspaceClient, snapshot: Snapshot) -> None:
    sources = (
        ("clusters", lambda: ((c.cluster_id, c.cluster_name) for c in w.clusters.list())),
        ("cluster-policies", lambda: ((p.policy_id, p.name) for p in w.cluster_policies.list())),
        ("instance-pools", lambda: ((p.instance_pool_id, p.instance_pool_name) for p in w.instance_pools.list())),
        ("warehouses", lambda: ((x.id, x.name) for x in w.warehouses.list())),
        ("secret-scopes", lambda: ((x.name, x.name) for x in w.secrets.list_scopes())),
    )
    for object_type, items in sources:
        try:
            for oid, name in items():
                if oid:
                    snapshot.object_names[(object_type, oid)] = name or oid
        except Exception as e:  # names are cosmetic; never fail the run for them
            snapshot.warnings.append(f"Could not list {object_type}: {e}")
