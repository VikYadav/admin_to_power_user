"""Roll recommendations up into the summary tables: the three fix buckets, the action plan and readiness."""

from __future__ import annotations

from collections import defaultdict

import json
import shlex

from admin_to_power_user.model.levels import rank
from admin_to_power_user.models import (
    SEVERITY_ORDER,
    ActionItem,
    Bucket,
    Delta,
    Kind,
    MoveToSpItem,
    ProcessChange,
    ProposedGrant,
    ReadinessSummary,
    Recommendation,
    Severity,
    key_name,
)


def _worst(severities) -> str:
    return min(severities, key=lambda s: SEVERITY_ORDER[Severity(s)])


def proposed_grants(deltas: dict[str, Delta], recs: list[Recommendation]) -> list[ProposedGrant]:
    """Grants that fix used access. LOW deltas (held via admins but never used) are not proposed."""
    groups: dict[tuple[str, str], list[tuple[Delta, Recommendation]]] = defaultdict(list)
    for r in recs:
        d = deltas[r.delta_id]
        if r.bucket == Bucket.POWER_USERS_GRANT.value and d.breaks and r.grant_object_type and \
                SEVERITY_ORDER[Severity(d.severity)] <= SEVERITY_ORDER[Severity.MEDIUM]:
            groups[(r.grant_object_type, r.grant_object_id)].append((d, r))
    out = []
    for (otype, oid), items in groups.items():
        level = max((r.grant_level for _, r in items), key=lambda lv: rank(otype, lv))
        out.append(ProposedGrant(
            workspace_id=items[0][0].workspace_id,
            object_type=otype,
            object_id=oid,
            object_name=items[0][1].grant_object_name or oid,
            level=level,
            fixes_n_deltas=len(items),
            admins_affected=", ".join(sorted({key_name(d.principal) for d, _ in items})),
            max_severity=_worst(d.severity for d, _ in items),
            scope_creep=any(r.scope_creep for _, r in items),
        ))
    return sorted(out, key=lambda g: (g.scope_creep, SEVERITY_ORDER[Severity(g.max_severity)], -g.fixes_n_deltas))


def _move_key(d: Delta) -> tuple[str, str]:
    """What gets moved to an SP: the job/pipeline/PAT, the owned object, or the automation calling an admin API."""
    if d.artifact_type:
        return d.artifact_type, d.artifact_id
    if d.kind == Kind.OWNERSHIP_RISK.value:
        return d.object_type, d.object_id
    return "automation", f"{d.object_id} by {key_name(d.principal)}"


def _sp_needs(items: list[tuple[Delta, Recommendation]]) -> list[str]:
    return sorted({f"{r.grant_level} on {r.grant_object_type} '{r.grant_object_name or r.grant_object_id}'"
                   for _, r in items if r.grant_object_type and r.grant_object_type != "authorization"})


def _move_action(items: list[tuple[Delta, Recommendation]]) -> str:
    if len(items) == 1:
        return items[0][1].primary_action
    return f"Re-own / set run_as to an SP and grant the SP: {'; '.join(_sp_needs(items)) or 'nothing extra'}"


def move_to_sp(deltas: dict[str, Delta], recs: list[Recommendation]) -> list[MoveToSpItem]:
    groups: dict[tuple[str, str], list[tuple[Delta, Recommendation]]] = defaultdict(list)
    for r in recs:
        if r.bucket == Bucket.MOVE_TO_SP.value:
            groups[_move_key(deltas[r.delta_id])].append((deltas[r.delta_id], r))
    out = []
    for (atype, aid), items in groups.items():
        d0 = items[0][0]
        needs = _sp_needs(items)
        out.append(MoveToSpItem(
            workspace_id=d0.workspace_id,
            artifact_type=atype,
            artifact_id=aid,
            artifact_name=d0.artifact_name or d0.object_name or aid,
            current_identity=", ".join(sorted({key_name(d.principal) for d, _ in items})),
            max_severity=_worst(d.severity for d, _ in items),
            sp_needs="; ".join(needs),
            action=_move_action(items),
        ))
    return sorted(out, key=lambda m: SEVERITY_ORDER[Severity(m.max_severity)])


def process_changes(deltas: dict[str, Delta], recs: list[Recommendation]) -> list[ProcessChange]:
    groups: dict[str, list[tuple[Delta, Recommendation]]] = defaultdict(list)
    for r in recs:
        if r.bucket == Bucket.PROCESS_CHANGE.value:
            groups[deltas[r.delta_id].object_id].append((deltas[r.delta_id], r))
    out = []
    for sa, items in groups.items():
        out.append(ProcessChange(
            workspace_id=items[0][0].workspace_id,
            service_action=sa,
            route=items[0][1].route or "",
            admins=", ".join(sorted({key_name(d.principal) for d, _ in items})),
            occurrences=sum(d.usage_count for d, _ in items),
            last_seen=max((d.last_used for d, _ in items if d.last_used), default=None),
        ))
    return sorted(out, key=lambda p: -p.occurrences)


def _grant_action(otype: str, oid: str, name: str, level: str) -> str:
    if otype == "entitlement":
        return f"Grant entitlement '{oid}' to power_users"
    if otype == "uc-metastore":
        return f"GRANT {oid.replace('_', ' ')} ON METASTORE TO `power_users`"
    if otype == "authorization":
        return "Grant power_users CAN_USE on token usage, or revoke the PATs nobody uses"
    return f"Grant power_users {level} on {otype} '{name}'"


def action_plan(deltas: dict[str, Delta], recs: list[Recommendation]) -> list[ActionItem]:
    """The to-do list: one step per action, covering every open break (breaks, not covered by your set).

    Breaks that one action fixes are merged: one grant per object (highest level needed), one move per
    job/pipeline/PAT, one move per person whose scripts call admin-only APIs (all the APIs together), and one
    process change per route (e.g. accounts:add and accounts:delete both go to SCIM). Ordered by worst severity,
    then by how many breaks the step fixes; scope-creep grants (to a group of humans) go last within a severity.
    """
    groups: dict[tuple[str, str, str], list[tuple[Delta, Recommendation]]] = defaultdict(list)
    for r in recs:
        d = deltas[r.delta_id]
        if not d.breaks or d.covered_by:
            continue
        if r.bucket == Bucket.POWER_USERS_GRANT.value and r.grant_object_type:
            key = ("grant", r.grant_object_type, r.grant_object_id)
        elif r.bucket == Bucket.MOVE_TO_SP.value and d.kind == Kind.ADMIN_ONLY_ACTION.value:
            key = ("scripts", d.principal, "")  # one person's automation: switching it fixes every API it calls
        elif r.bucket == Bucket.MOVE_TO_SP.value:
            key = ("move", *_move_key(d))
        elif r.bucket == Bucket.PROCESS_CHANGE.value:
            key = ("process", d.kind, r.route or r.primary_action)
        else:  # not expected; keeps every break in the plan
            key = ("single", d.kind, d.delta_id)
        groups[key].append((d, r))

    plan = []
    for (what, a, b), items in groups.items():
        d0, r0 = items[0]
        people = sorted({key_name(d.principal) for d, _ in items})
        creep = what == "grant" and any(r.scope_creep for _, r in items)  # an SP getting the access is fine
        alternative = r0.alternative_action if len(items) == 1 else ""
        if what == "grant":
            level = max((r.grant_level for _, r in items), key=lambda lv: rank(a, lv))
            action = _grant_action(a, b, r0.grant_object_name or b, level)
            who = "Metastore admin" if a == "uc-metastore" else "Admin SP (workspace admin)"
            if creep and len(items) > 1:
                alternative = "Scope creep: grant it to the people who need it individually, or move the work to an SP"
        elif what == "move":
            action = _move_action(items)
            who = f"{', '.join(people)} (current identity), with the admin SP"
        elif what == "scripts":
            apis = ", ".join(sorted({d.object_id for d, _ in items}))
            action = f"Switch the scripts {people[0]} runs as themselves to the admin SP (OAuth M2M). They call: {apis}"
            who = f"{people[0]}, with the admin SP"
            alternative = r0.route if len({r.route for _, r in items}) == 1 else \
                "Or replace them with account-level SCIM / Terraform run by the admin SP"
        elif a == Kind.NO_ADMIN_LEFT.value:
            action, who = r0.primary_action, "Account admin, before cutover"
        elif what == "process":
            apis = ", ".join(sorted({d.object_id for d, _ in items}))
            action, who = f"{r0.primary_action} (replaces {apis})", "Platform / identity team"
        else:
            action, who = r0.primary_action, "Admin SP"
        item = ActionItem(
            workspace_id=d0.workspace_id, step=0, bucket=r0.bucket, action=action, who_acts=who,
            breaks_resolved=len(items),
            blocker_high=sum(1 for d, _ in items if d.severity in (Severity.BLOCKER.value, Severity.HIGH.value)),
            max_severity=_worst(d.severity for d, _ in items), people=", ".join(people), scope_creep=creep,
            alternative=alternative, delta_ids=", ".join(d.delta_id for d, _ in items))
        first = a == Kind.NO_ADMIN_LEFT.value  # nothing else can be done safely until an admin is kept
        plan.append(((not first, SEVERITY_ORDER[Severity(item.max_severity)], creep, -len(items), action), item))
    out = [item for _, item in sorted(plan, key=lambda p: p[0])]
    for i, item in enumerate(out, 1):
        item.step = i
    return out


def readiness(workspace_id: str, workspace_host: str, in_scope: dict[str, str], principals: dict,
              deltas: list[Delta], grants: list[ProposedGrant], moves: list[MoveToSpItem],
              changes: list[ProcessChange]) -> ReadinessSummary:
    covered = [d for d in deltas if d.covered_by]
    deltas = [d for d in deltas if not d.covered_by]
    counts = {s: 0 for s in Severity}
    for d in deltas:
        counts[Severity(d.severity)] += 1
    blockers = sum(1 for d in deltas if d.breaks and d.severity == Severity.BLOCKER.value)
    high = sum(1 for d in deltas if d.breaks and d.severity == Severity.HIGH.value)
    humans = sum(1 for k in in_scope if getattr(principals.get(k), "kind", "") == "user")
    return ReadinessSummary(
        workspace_id=workspace_id,
        workspace_host=workspace_host,
        admins_in_scope=len(in_scope),
        humans_in_scope=humans,
        blockers=blockers,
        high=high,
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        proposed_grants=len(grants),
        scope_creep_grants=sum(1 for g in grants if g.scope_creep),
        move_to_sp_items=len(moves),
        process_changes=len(changes),
        status="READY" if blockers == 0 and high == 0 else "NOT_READY",
        covered_by_permission_set=len(covered),
    )


def _line(text: str, comment: str = "") -> str:
    return f"- {json.dumps(text)}" + (f"   # {comment}" if comment else "")


def _grant_line(g) -> str:
    if g.path is not None:
        return f"{g.level} {g.path}" if g.object_type == "directories" else f"{g.level} {g.object_type} {g.path}"
    target = g.object_name if g.object_name is not None else (g.object_id or "*")
    return f"{g.level} {g.object_type} {shlex.quote(target) if target != '*' else '*'}"


def suggested_permissions_yaml(ps, grants: list[ProposedGrant], include_scope_creep: bool = False) -> str:
    """Your permission set plus the extra grants this run suggests, one permission per line.

    Pass the file straight back with --permissions and rerun. Scope-creep suggestions are listed as comments
    (review them in the dashboard) unless include_scope_creep is set.
    """
    lines = [_line(e) for e in sorted(ps.entitlements)] + [_line(_grant_line(g)) for g in ps.grants] + \
        [_line(p) for p in sorted(ps.uc_privileges)] + ([_line("token-usage")] if ps.token_usage else [])
    added, creep = [], []
    have_ents, have_uc = set(ps.entitlements), set(ps.uc_privileges)
    for g in grants:
        if g.object_type == "entitlement":
            text = g.object_id if g.object_id not in have_ents else None
        elif g.object_type == "uc-metastore":
            text = g.object_id if g.object_id not in have_uc else None
        elif g.object_type == "authorization":
            text = None if ps.token_usage else "token-usage"
        else:
            text = f"{g.level} {g.object_type} {g.object_id}"
        if text is None:
            continue
        why = f"{g.object_name}; fixes {g.fixes_n_deltas} for {g.admins_affected}" if g.object_name != g.object_id \
            else f"fixes {g.fixes_n_deltas} for {g.admins_affected}"
        (creep if g.scope_creep and not include_scope_creep else added).append(_line(text, why))
    out = ["# power_users permission set: yours" + (" + suggested additions" if added else "") + ".",
           "# Rerun with: admin-to-power-user analyze ... --permissions <this file>"]
    out += lines
    if added:
        out += ["", f"# Suggested by this run ({len(added)}):"] + added
    if creep:
        out += ["", "# Also needed, but scope creep (rebuilds admin piecemeal). Prefer moving the work to an SP:"]
        out += ["# " + c for c in creep]
    if not lines and not added:
        out.append("[]")
    return "\n".join(out) + "\n"
