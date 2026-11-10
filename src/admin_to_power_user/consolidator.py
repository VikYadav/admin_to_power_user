"""Roll recommendations up into the summary tables: the three fix buckets and readiness."""

from __future__ import annotations

from collections import defaultdict

import json
import shlex

from admin_to_power_user.model.levels import rank
from admin_to_power_user.models import (
    SEVERITY_ORDER,
    Bucket,
    Delta,
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


def move_to_sp(deltas: dict[str, Delta], recs: list[Recommendation]) -> list[MoveToSpItem]:
    groups: dict[tuple[str, str], list[tuple[Delta, Recommendation]]] = defaultdict(list)
    for r in recs:
        if r.bucket != Bucket.MOVE_TO_SP.value:
            continue
        d = deltas[r.delta_id]
        if d.artifact_type:
            k = (d.artifact_type, d.artifact_id)
        elif d.kind == "OWNERSHIP_RISK":
            k = (d.object_type, d.object_id)
        else:  # admin-only action called by automation
            k = ("automation", f"{d.object_id} by {key_name(d.principal)}")
        groups[k].append((d, r))
    out = []
    for (atype, aid), items in groups.items():
        d0 = items[0][0]
        needs = sorted({f"{r.grant_level} on {r.grant_object_type} '{r.grant_object_name or r.grant_object_id}'"
                        for _, r in items if r.grant_object_type and r.grant_object_type != "authorization"})
        out.append(MoveToSpItem(
            workspace_id=d0.workspace_id,
            artifact_type=atype,
            artifact_id=aid,
            artifact_name=d0.artifact_name or d0.object_name or aid,
            current_identity=", ".join(sorted({key_name(d.principal) for d, _ in items})),
            max_severity=_worst(d.severity for d, _ in items),
            sp_needs="; ".join(needs),
            action=items[0][1].primary_action if len(items) == 1 else
            f"Re-own / set run_as to an SP and grant the SP: {'; '.join(needs) or 'nothing extra'}",
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
