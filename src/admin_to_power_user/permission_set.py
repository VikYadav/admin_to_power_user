"""The power_users permission set you intend to grant, matched to one workspace's objects.

Simplest form: a YAML list, one permission per line (see config/power_users.yaml):

    - workspace-access                         # entitlement
    - databricks-sql-access
    - CAN_USE cluster-policies "Personal Compute"   # LEVEL  OBJECT_TYPE  name, id, glob or *
    - CAN_USE warehouses *
    - CAN_RUN /Shared                          # LEVEL  /folder  (covers everything below it)
    - CREATE_CATALOG                           # Unity Catalog metastore privilege
    - token-usage                              # CAN_USE on personal access tokens

Structured form (also accepted in the --permissions file):

    power_users:
      group: power_users
      permissions:
        entitlements: [workspace-access, databricks-sql-access]
        grants:
          - {object_type: cluster-policies, object_name: "Personal Compute", level: CAN_USE}
          - {object_type: warehouses, object_id: "*", level: CAN_USE}
          - {object_type: directories, path: /Shared, level: CAN_READ}
        uc_privileges: [CREATE_CATALOG]
        token_usage: true

An object grant names its target by `object_id` (exact id, or "*" for every object of that type),
`object_name` (glob on the object's name, e.g. "etl-*"), or `path` (workspace folder; covers everything
below it, like a folder ACL). Nothing here changes the workspace: the set is only simulated.
"""

from __future__ import annotations

import fnmatch
import shlex
from dataclasses import dataclass, field
from typing import Optional

from admin_to_power_user.model.levels import LEVELS, satisfies
from admin_to_power_user.model.resolver import WhatIf
from admin_to_power_user.models import Delta, Kind, PermissionCoverage, Severity, key_name
from admin_to_power_user.recommender import SCOPE_CREEP_ENTITLEMENTS, SCOPE_CREEP_LEVELS, SCOPE_CREEP_UC

# Object types whose full inventory the collectors list, so a name/id that matches nothing is NOT_FOUND.
INVENTORIED = {"clusters", "cluster-policies", "instance-pools", "warehouses", "jobs", "pipelines", "secret-scopes"}
PATH_TYPES = {"notebooks", "files", "directories", "repos"}
MAX_NAMES = 5


@dataclass(frozen=True)
class GrantSpec:
    object_type: str
    level: str
    object_id: Optional[str] = None  # exact id or "*"
    object_name: Optional[str] = None  # glob on the object's name
    path: Optional[str] = None  # workspace folder prefix

    @property
    def spec(self) -> str:
        if self.path:
            return f"path={self.path}"
        if self.object_name:
            return f"name={self.object_name}"
        return self.object_id or "*"

    @property
    def label(self) -> str:
        return f"{self.level} on {self.object_type} {self.spec}"


@dataclass(frozen=True)
class PermissionSet:
    grants: tuple[GrantSpec, ...] = ()
    entitlements: frozenset[str] = frozenset()
    uc_privileges: frozenset[str] = frozenset()
    token_usage: bool = False

    @property
    def size(self) -> int:
        return len(self.grants) + len(self.entitlements) + len(self.uc_privileges) + int(self.token_usage)


def parse_grant(raw: dict) -> GrantSpec:
    otype, level = raw.get("object_type"), raw.get("level")
    if not otype or not level:
        raise ValueError(f"power_users grant needs object_type and level: {raw}")
    otype = str(otype)
    level = _level(otype, str(level).upper())
    path = raw.get("path")
    if path:
        path = str(path).rstrip("*").rstrip("/") or "/"
    oid = raw.get("object_id")
    name = raw.get("object_name")
    if oid is None and name is None and path is None:
        raise ValueError(f"power_users grant needs object_id, object_name or path: {raw}")
    return GrantSpec(str(otype), str(level), str(oid) if oid is not None else None,
                     str(name) if name is not None else None, path)


ENTITLEMENT_NAMES = {"workspace-access", "databricks-sql-access", "allow-cluster-create", "allow-instance-pool-create"}
TOKEN_WORDS = {"token-usage", "token_usage", "tokens", "pat", "pats"}
TYPE_ALIASES = {"policies": "cluster-policies", "policy": "cluster-policies", "cluster-policy": "cluster-policies",
                "pools": "instance-pools", "pool": "instance-pools", "instance-pool": "instance-pools",
                "cluster": "clusters", "warehouse": "warehouses", "job": "jobs", "pipeline": "pipelines",
                "secrets": "secret-scopes", "scopes": "secret-scopes", "secret-scope": "secret-scopes",
                "notebook": "notebooks", "file": "files", "folder": "directories", "folders": "directories",
                "directory": "directories", "query": "queries", "alert": "alerts", "dashboard": "dashboards",
                "repo": "repos", "experiment": "experiments", "models": "registered-models",
                "endpoints": "serving-endpoints", "serving-endpoint": "serving-endpoints", "app": "apps"}


def parse_line(line: str) -> dict:
    """One compact permission line -> {kind: value} (see module docstring)."""
    parts = shlex.split(str(line).split(" #", 1)[0])
    if len(parts) == 1:
        word = parts[0]
        if word.lower() in ENTITLEMENT_NAMES:
            return {"entitlement": word.lower()}
        if word.lower() in TOKEN_WORDS:
            return {"token_usage": True}
        if word.replace("_", "").isalpha():
            return {"uc_privilege": word.upper()}
    if len(parts) == 2 and parts[1].startswith("/"):
        return {"grant": {"object_type": "directories", "path": parts[1], "level": parts[0].upper()}}
    if len(parts) == 3:
        level, otype, target = parts[0].upper(), TYPE_ALIASES.get(parts[1].lower(), parts[1].lower()), parts[2]
        if target.startswith("/") and otype in PATH_TYPES:
            return {"grant": {"object_type": otype, "path": target, "level": level}}
        key = "object_id" if target == "*" else "object_name"
        return {"grant": {"object_type": otype, key: target, "level": level}}
    raise ValueError(f"Can't read permission line {line!r}. Use e.g. 'workspace-access', "
                     "'CAN_USE warehouses *', 'CAN_RUN /Shared', 'CREATE_CATALOG' or 'token-usage'.")


def _level(object_type: str, level: str) -> str:
    valid = LEVELS.get(object_type)
    if valid is None or level in valid:
        return level
    for alt in (level.removeprefix("CAN_"), "CAN_" + level):
        if alt in valid:
            return alt
    raise ValueError(f"{level} is not a permission level for {object_type}; use one of {', '.join(valid)}")


def parse_permission_set(raw) -> PermissionSet:
    if isinstance(raw, list):  # compact form
        structured: dict = {"grants": [], "entitlements": [], "uc_privileges": [], "token_usage": False}
        for item in raw:
            if isinstance(item, dict):
                structured["grants"].append(item)
                continue
            parsed = parse_line(item)
            if "grant" in parsed:
                structured["grants"].append(parsed["grant"])
            elif "entitlement" in parsed:
                structured["entitlements"].append(parsed["entitlement"])
            elif "uc_privilege" in parsed:
                structured["uc_privileges"].append(parsed["uc_privilege"])
            else:
                structured["token_usage"] = True
        raw = structured
    raw = raw or {}
    return PermissionSet(
        grants=tuple(parse_grant(g) for g in raw.get("grants") or []),
        entitlements=frozenset(raw.get("entitlements") or []),
        uc_privileges=frozenset(raw.get("uc_privileges") or []),
        token_usage=bool(raw.get("token_usage", False)),
    )


@dataclass
class BoundGrant:
    spec: GrantSpec
    ids: set[str] = field(default_factory=set)  # concrete object ids ("*" = all of that type)
    names: list[str] = field(default_factory=list)
    matched: int = -1  # -1 = cannot be verified for this object type


def _under(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def bind(ps: PermissionSet, object_names: dict[tuple[str, str], str]) -> list[BoundGrant]:
    """Resolve each grant to the concrete objects it covers in this workspace."""
    by_type: dict[str, dict[str, str]] = {}
    for (otype, oid), name in object_names.items():
        by_type.setdefault(otype, {})[oid] = name or oid
    out = []
    for g in ps.grants:
        b = BoundGrant(g)
        if g.path is not None:
            hits = {(t, i): n for t in PATH_TYPES for i, n in by_type.get(t, {}).items() if _under(n, g.path)}
            b.ids = {i for _, i in hits}
            b.names = sorted(set(hits.values()))[:MAX_NAMES]
            b.matched = len(hits) if hits else -1  # folders are not inventoried; only report what we saw
        elif g.object_name is not None:
            # A name target also matches ids, so one field works for "Personal Compute", "etl-*" or "0123ABC".
            objs = by_type.get(g.object_type, {})
            hits = {i: n for i, n in objs.items()
                    if fnmatch.fnmatchcase(n, g.object_name) or fnmatch.fnmatchcase(i, g.object_name)}
            b.ids, b.names = set(hits), sorted(hits.values())[:MAX_NAMES]
            if not hits and not any(c in g.object_name for c in "*?["):
                b.ids = {g.object_name}  # not listed (e.g. a query id): apply it as an exact id
            b.matched = len(hits) if (hits or g.object_type in INVENTORIED) else -1
        elif g.object_id == "*":
            objs = by_type.get(g.object_type, {})
            b.ids, b.names = {"*"}, sorted(objs.values())[:MAX_NAMES]
            b.matched = len(objs) if g.object_type in INVENTORIED else -1
        else:
            objs = by_type.get(g.object_type, {})
            b.ids = {g.object_id}
            if g.object_id in objs:
                b.names, b.matched = [objs[g.object_id]], 1
            else:
                b.matched = 0 if g.object_type in INVENTORIED else -1
        out.append(b)
    return out


def to_what_if(ps: PermissionSet, bound: list[BoundGrant], moved_to_sp: frozenset = frozenset()) -> WhatIf:
    grants = tuple((b.spec.object_type, i, b.spec.level) for b in bound if b.spec.path is None for i in b.ids)
    path_grants = tuple((b.spec.path, b.spec.level) for b in bound if b.spec.path is not None)
    return WhatIf(grants=grants, path_grants=path_grants, entitlements=ps.entitlements,
                  uc_privileges=ps.uc_privileges, token_usage=ps.token_usage, moved_to_sp=moved_to_sp)


def _grant_fixes(b: BoundGrant, d: Delta, object_names: dict[tuple[str, str], str]) -> bool:
    if d.kind not in (Kind.RUN_AS_DEPENDENCY.value, Kind.DIRECT_USE.value):
        return False
    if b.spec.path is not None:
        path = object_names.get((d.object_type, d.object_id), d.object_name or "")
        return d.object_type in PATH_TYPES and _under(path, b.spec.path) and \
            satisfies(d.object_type, b.spec.level, d.required_level)
    return d.object_type == b.spec.object_type and ("*" in b.ids or d.object_id in b.ids) and \
        satisfies(d.object_type, b.spec.level, d.required_level)


def _creep(ps_entry_type: str, object_type: str, level: str, spec: str) -> str:
    if ps_entry_type == "object_grant":
        if level in SCOPE_CREEP_LEVELS.get(object_type, set()):
            where = "every " + object_type if spec == "*" else object_type
            return f"{level} on {where} for a whole group rebuilds admin piecemeal"
    elif ps_entry_type == "entitlement" and spec in SCOPE_CREEP_ENTITLEMENTS:
        return "unrestricted cluster creation; prefer CAN_USE on approved cluster policies"
    elif ps_entry_type == "uc_privilege" and level in SCOPE_CREEP_UC:
        return "metastore-level privilege usually reserved for the platform team / admin SP"
    return ""


def coverage(workspace_id: str, ps: PermissionSet, bound: list[BoundGrant], baseline: list[Delta],
             final: list[Delta], object_names: dict[tuple[str, str], str]) -> tuple[list[Delta], list[PermissionCoverage]]:
    """Deltas fixed by the permission set (marked `covered_by`) and one coverage row per set entry.

    `baseline` is the simulation with power_users as it exists today; `final` adds your permission set.
    A delta is covered when it breaks in the baseline and is gone (or no longer breaks) in the final run.
    """
    final_by_id = {d.delta_id: d for d in final}
    fixed = [d for d in baseline if d.breaks and (d.delta_id not in final_by_id or not final_by_id[d.delta_id].breaks)]

    entries: list[tuple[str, str, str, str, BoundGrant | None, callable]] = []
    for b in bound:
        entries.append(("object_grant", b.spec.object_type, b.spec.spec, b.spec.level, b,
                        lambda d, b=b: _grant_fixes(b, d, object_names)))
    for e in sorted(ps.entitlements):
        entries.append(("entitlement", "entitlement", e, "GRANTED", None,
                        lambda d, e=e: d.kind == Kind.ENTITLEMENT.value and d.object_id == e))
    for p in sorted(ps.uc_privileges):
        entries.append(("uc_privilege", "uc-metastore", p, p, None,
                        lambda d, p=p: d.kind == Kind.UC_PRIVILEGE.value and p in (d.object_id, "ALL_PRIVILEGES")))
    if ps.token_usage:
        entries.append(("token_usage", "authorization", "tokens", "CAN_USE", None,
                        lambda d: d.kind == Kind.TOKEN.value))

    labels: dict[str, list[str]] = {}
    rows = []
    for etype, otype, spec, level, b, fixes in entries:
        label = b.spec.label if b else (f"entitlement {spec}" if etype == "entitlement" else
                                        f"{spec} ON METASTORE" if etype == "uc_privilege" else "CAN_USE on token usage")
        hits = [d for d in fixed if fixes(d)]
        for d in hits:
            labels.setdefault(d.delta_id, []).append(label)
        matched = b.matched if b else -1
        status = "USED" if hits else ("NOT_FOUND" if matched == 0 else "UNUSED")
        reason = _creep(etype, otype, level, spec)
        rows.append(PermissionCoverage(
            workspace_id=workspace_id, permission_id=label, permission_type=etype, object_type=otype,
            object_spec=spec, level=level, matched_objects=matched,
            matched_names=", ".join(b.names) if b else "",
            fixes_n_deltas=len(hits),
            fixes_blocker_high=sum(1 for d in hits if d.severity in (Severity.BLOCKER.value, Severity.HIGH.value)),
            admins_helped=", ".join(sorted({key_name(d.principal) for d in hits})),
            scope_creep=bool(reason), scope_creep_reason=reason, status=status))

    covered = []
    for d in fixed:
        if d.delta_id in final_by_id:
            continue  # still reported (e.g. a PAT that is no longer blocked stays a MOVE_TO_SP risk)
        d.covered_by = "; ".join(labels.get(d.delta_id, ["power_users permission set"]))
        covered.append(d)
    return covered, rows
