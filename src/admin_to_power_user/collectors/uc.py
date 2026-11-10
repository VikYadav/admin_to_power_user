"""Unity Catalog: metastore-level grants, and UC objects owned by in-scope admins.

Workspace admins in automatically enabled workspaces can hold metastore privileges implicitly; those
do not appear in grants. The simulator compares UC actions admins performed (audit) against the
explicit grants collected here.
"""

from __future__ import annotations

from databricks.sdk import WorkspaceClient

from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.models import Artifact, Dependency, Kind, Snapshot


def collect_uc(w: WorkspaceClient, snapshot: Snapshot, names: NameResolver) -> None:
    try:
        metastore_id = w.metastores.current().metastore_id
    except Exception as e:
        snapshot.warnings.append(f"No Unity Catalog metastore assigned or not readable: {e}")
        return

    try:
        grants = w.grants.get("metastore", metastore_id)
        for pa in grants.privilege_assignments or []:
            if pa.principal:
                key = names.key(pa.principal)
                snapshot.uc_metastore_grants.setdefault(key, set()).update(
                    getattr(p, "value", str(p)) for p in pa.privileges or [])
    except Exception as e:
        snapshot.warnings.append(f"Could not read metastore grants: {e}")

    owned_sources = (
        ("uc-catalog", lambda: ((c.name, c.owner) for c in w.catalogs.list())),
        ("uc-external-location", lambda: ((x.name, x.owner) for x in w.external_locations.list())),
        ("uc-storage-credential", lambda: ((x.name, x.owner) for x in w.storage_credentials.list())),
    )
    for object_type, items in owned_sources:
        try:
            for name, owner in items():
                key = names.key(owner) if owner else None
                if key in snapshot.in_scope:
                    snapshot.ownership.append(Dependency(
                        key, Kind.OWNERSHIP_RISK, object_type, name, name, "OWNER", "UC object owned by admin",
                        Artifact(object_type, name, name)))
        except Exception as e:
            snapshot.warnings.append(f"Could not list {object_type}: {e}")
