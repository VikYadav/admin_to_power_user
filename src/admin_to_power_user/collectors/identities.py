"""Users, service principals, groups (with nested membership) and the admins in scope."""

from __future__ import annotations

from databricks.sdk import WorkspaceClient
from databricks.sdk.service import iam

from admin_to_power_user.config import Config
from admin_to_power_user.model.graph import PrincipalGraph
from admin_to_power_user.models import ADMINS_GROUP, Principal, Snapshot, group_key, sp_key, user_key


def _ents(values) -> frozenset[str]:
    return frozenset(v.value for v in values or [] if v.value)


def build_identities(
    users: list[iam.User],
    sps: list[iam.ServicePrincipal],
    groups: list[iam.Group],
    snapshot: Snapshot,
    cfg: Config,
) -> None:
    by_id: dict[str, str] = {}
    for u in users:
        k = user_key(u.user_name)
        by_id[u.id] = k
        snapshot.principals[k] = Principal(k, "user", u.id, u.display_name or u.user_name,
                                           bool(u.active if u.active is not None else True), _ents(u.entitlements))
    for sp in sps:
        k = sp_key(sp.application_id)
        by_id[sp.id] = k
        snapshot.principals[k] = Principal(k, "service_principal", sp.id, sp.display_name or sp.application_id,
                                           bool(sp.active if sp.active is not None else True),
                                           _ents(sp.entitlements))
    for g in groups:
        k = group_key(g.display_name)
        by_id[g.id] = k
        snapshot.principals[k] = Principal(k, "group", g.id, g.display_name, True, _ents(g.entitlements))

    account_level: dict[str, bool] = {
        group_key(g.display_name): bool(g.meta and g.meta.resource_type == "Group") for g in groups
    }
    for g in groups:
        parent = group_key(g.display_name)
        for m in g.members or []:
            child = by_id.get(m.value)
            if child is None and m.ref:
                # member not returned by list (e.g. inactive); infer kind from $ref
                kind = m.ref.split("/", 1)[0]
                child = {"Groups": group_key, "ServicePrincipals": sp_key}.get(kind, user_key)(m.display or m.value)
            if child:
                snapshot.memberships.setdefault(child, set()).add(parent)

    graph = PrincipalGraph(snapshot.principals, snapshot.memberships)
    admins = graph.members_of(ADMINS_GROUP)
    snapshot.retained_admins = resolve_retained(snapshot, cfg, graph, admins)
    excluded = set(snapshot.retained_admins)
    for member in sorted(admins):
        if member in excluded:
            continue
        p = snapshot.principals.get(member)
        reason = "human workspace admin" if p is None or p.kind == "user" else \
            "service principal admin that is not a retained admin"
        snapshot.in_scope[member] = reason

    pu = cfg.power_users_key
    if pu not in snapshot.principals:
        snapshot.warnings.append(f"Group '{cfg.power_users_group}' does not exist in this workspace yet; "
                                 "simulating it as an empty group plus your permission set.")
    elif not account_level.get(pu, False):
        snapshot.warnings.append(f"Group '{cfg.power_users_group}' is workspace-local. It must be an "
                                 "account-level group to receive Unity Catalog grants.")


def resolve_retained(snapshot: Snapshot, cfg: Config, graph: PrincipalGraph, admins: set[str]) -> dict[str, str]:
    """Principal keys that stay workspace admin (retained SPs/users, and every member of retained groups)."""
    out: dict[str, str] = {}
    by_scim = {p.scim_id: k for k, p in snapshot.principals.items()}
    for r in cfg.all_retained():
        if r.kind == "auto":
            key = next((k for k in (sp_key(r.ref), group_key(r.ref), by_scim.get(r.ref), user_key(r.ref))
                        if k in snapshot.principals), None)
        elif r.kind == "service_principal":
            key = sp_key(r.ref) if sp_key(r.ref) in snapshot.principals else by_scim.get(r.ref)
        elif r.kind == "group":
            key = group_key(r.ref) if group_key(r.ref) in snapshot.principals else by_scim.get(r.ref)
        else:
            key = user_key(r.ref)
        if key is None or key not in snapshot.principals:
            snapshot.warnings.append(f"Retained admin {r.label} was not found in this workspace.")
            continue
        if key.startswith("group:"):
            members = graph.members_of(key)
            if ADMINS_GROUP not in graph.groups_of(key):
                snapshot.warnings.append(f"Retained admin group {r.label} is not a member of `admins` today; "
                                         "add it before removing the other admins.")
            humans = sorted(m for m in members if m.startswith("user:"))
            if humans:
                snapshot.warnings.append(f"{len(humans)} human(s) stay workspace admin through retained group "
                                         f"{r.label}: {', '.join(h.split(':', 1)[1] for h in humans[:10])}"
                                         f"{' ...' if len(humans) > 10 else ''}")
            out[key] = f"retained admin group ({r.label})"
            for m in members:
                out.setdefault(m, f"member of retained admin group {r.label}")
        else:
            if key not in admins:
                snapshot.warnings.append(f"Retained admin {r.label} is not a workspace admin today; add it to "
                                         "`admins` before removing the other admins.")
            out[key] = f"retained admin ({r.label})"
    if not out:
        snapshot.warnings.append("No retained admin was given or found: after the move this workspace would have "
                                 "no admin at all.")
    return out


def collect_identities(w: WorkspaceClient, snapshot: Snapshot, cfg: Config) -> None:
    users = list(w.users.list(attributes="id,userName,displayName,active,entitlements"))
    sps = list(w.service_principals.list(attributes="id,applicationId,displayName,active,entitlements"))
    groups = list(w.groups.list(attributes="id,displayName,members,entitlements,meta"))
    build_identities(users, sps, groups, snapshot, cfg)


class NameResolver:
    """Map a bare principal string (secret ACLs, UC grants, audit email) to a principal key."""

    def __init__(self, snapshot: Snapshot):
        self.groups = {p.display_name for p in snapshot.principals.values() if p.kind == "group"}
        self.sps = {k.split(":", 1)[1] for k, p in snapshot.principals.items() if p.kind == "service_principal"}

    def key(self, name: str) -> str:
        if name in self.groups:
            return group_key(name)
        if name in self.sps:
            return sp_key(name)
        return user_key(name)
