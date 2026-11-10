"""Fetch ACLs only for objects that something in scope depends on (relevance-driven collection)."""

from __future__ import annotations

import dataclasses
from concurrent.futures import ThreadPoolExecutor

from databricks.sdk import WorkspaceClient
from databricks.sdk.errors import NotFound, PermissionDenied, ResourceDoesNotExist
from databricks.sdk.service import iam

from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.collectors.jobs import PATH_PREFIX
from admin_to_power_user.config import Config
from admin_to_power_user.models import AclEntry, Snapshot, group_key, sp_key, user_key

WORKSPACE_TYPES = {"NOTEBOOK": "notebooks", "FILE": "files", "DIRECTORY": "directories", "REPO": "repos",
                   "DASHBOARD": "dashboards"}


def acl_entries(perms: iam.ObjectPermissions) -> list[AclEntry]:
    out = []
    for a in perms.access_control_list or []:
        if a.user_name:
            k = user_key(a.user_name)
        elif a.service_principal_name:
            k = sp_key(a.service_principal_name)
        elif a.group_name:
            k = group_key(a.group_name)
        else:
            continue
        for p in a.all_permissions or []:
            if p.permission_level:
                out.append(AclEntry(k, p.permission_level.value, bool(p.inherited)))
    return out


def resolve_paths(w: WorkspaceClient, snapshot: Snapshot, cfg: Config) -> None:
    """Rewrite `path:` object ids to (real object type, numeric object id)."""
    paths = {d.object_id[len(PATH_PREFIX):] for d in snapshot.dependencies if d.object_id.startswith(PATH_PREFIX)}

    def lookup(path: str):
        try:
            info = w.workspace.get_status(path)
            return path, WORKSPACE_TYPES.get(info.object_type.value if info.object_type else "", "notebooks"), \
                str(info.object_id)
        except (NotFound, ResourceDoesNotExist):
            return path, None, None

    with ThreadPoolExecutor(cfg.max_workers) as pool:
        resolved = {p: (t, i) for p, t, i in pool.map(lookup, paths)}

    deps = []
    for d in snapshot.dependencies:
        if d.object_id.startswith(PATH_PREFIX):
            path = d.object_id[len(PATH_PREFIX):]
            otype, oid = resolved.get(path, (None, None))
            if oid is None:
                snapshot.missing_objects[(d.object_type, d.object_id)] = "path not found"
            else:
                d = dataclasses.replace(d, object_type=otype, object_id=oid, object_name=path)
                snapshot.object_names[(otype, oid)] = path
        deps.append(d)
    snapshot.dependencies = deps


def collect_acls(w: WorkspaceClient, snapshot: Snapshot, cfg: Config, names: NameResolver) -> None:
    resolve_paths(w, snapshot, cfg)
    objects = {(d.object_type, d.object_id) for d in snapshot.dependencies
               if (d.object_type, d.object_id) not in snapshot.missing_objects} - set(snapshot.acls)

    def fetch(obj):
        otype, oid = obj
        try:
            if otype == "secret-scopes":
                return obj, [AclEntry(names.key(a.principal), a.permission.value) for a in w.secrets.list_acls(oid)
                             if a.principal and a.permission], None
            return obj, acl_entries(w.permissions.get(otype, oid)), None
        except (NotFound, ResourceDoesNotExist) as e:
            return obj, None, f"not found: {e}"
        except PermissionDenied as e:
            return obj, None, f"permission denied (is the tool running as a workspace admin?): {e}"
        except Exception as e:
            return obj, None, f"error: {e}"

    with ThreadPoolExecutor(cfg.max_workers) as pool:
        for obj, entries, err in pool.map(fetch, sorted(objects)):
            if entries is not None:
                snapshot.acls[obj] = entries
            elif err and err.startswith("not found"):
                snapshot.missing_objects[obj] = err
            else:
                snapshot.acls[obj] = []
                snapshot.warnings.append(f"ACL for {obj[0]}/{obj[1]}: {err}")
