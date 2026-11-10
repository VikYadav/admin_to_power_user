"""State A vs State B diff: everything an in-scope admin loses, with a severity."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Optional

from admin_to_power_user.model.graph import PrincipalGraph
from admin_to_power_user.model.levels import ENTITLEMENTS, satisfies
from admin_to_power_user.model.resolver import Resolver, WhatIf, after_scenario, before_scenario
from admin_to_power_user.models import ADMINS_GROUP, Artifact, Delta, Kind, Severity, Snapshot

INTERACTIVE_ENTITLEMENTS = {"workspace-access", "databricks-sql-access"}


def _delta_id(*parts: object) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _days_ago(ts: Optional[str], today: date) -> Optional[int]:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).date()
    except ValueError:
        return None
    return (today - d).days


class Simulator:
    def __init__(
        self,
        snapshot: Snapshot,
        power_users_group: str,
        what_if: Optional[WhatIf] = None,
        high_usage_threshold: int = 10,
        token_recent_days: int = 30,
        today: Optional[date] = None,
    ):
        self.s = snapshot
        self.what_if = what_if or WhatIf()
        self.graph = PrincipalGraph(snapshot.principals, snapshot.memberships)
        self.resolver = Resolver(self.graph, snapshot.acls, power_users_group, snapshot.object_names)
        self.before = before_scenario()
        self.after = after_scenario(power_users_group, self.what_if)
        self.high_usage_threshold = high_usage_threshold
        self.token_recent_days = token_recent_days
        self.today = today or datetime.now(timezone.utc).date()

    def run(self) -> list[Delta]:
        deltas: dict[str, Delta] = {}
        for d in (
            self._dependency_deltas()
            + self._entitlement_deltas()
            + self._token_deltas()
            + self._admin_action_deltas()
            + self._uc_deltas()
            + self._ownership_deltas()
            + self._admin_left_deltas()
        ):
            if d.delta_id in deltas:
                deltas[d.delta_id].usage_count += d.usage_count
            else:
                deltas[d.delta_id] = d
        return sorted(deltas.values(), key=lambda d: (list(Severity).index(Severity(d.severity)), d.principal))

    # ---- helpers -------------------------------------------------------------------------

    def _moved(self, artifact) -> bool:
        return artifact is not None and (artifact.type, artifact.id) in self.what_if.moved_to_sp

    def _artifact_activity(self, artifact) -> tuple[int, Optional[str], bool]:
        """(runs in lookback, last run, is scheduled) for a job/pipeline artifact."""
        if artifact is None:
            return 0, None, False
        if artifact.type == "job":
            r = self.s.job_runs.get(artifact.id, {})
            return int(r.get("runs", 0)), r.get("last_run"), artifact.id in self.s.scheduled_jobs
        if artifact.type == "pipeline":
            r = self.s.pipeline_updates.get(artifact.id, {})
            return int(r.get("updates", 0)), r.get("last_update"), False
        return 0, None, False

    def _base(self, principal: str, kind: Kind, object_type: str, object_id: str, object_name: str,
              required: str, before: Optional[str], after: Optional[str], via: str, breaks: bool,
              severity: Severity, artifact=None, usage_count: int = 0, last_used: Optional[str] = None,
              evidence: Optional[dict] = None) -> Delta:
        return Delta(
            workspace_id=self.s.workspace_id,
            principal=principal,
            kind=kind.value,
            object_type=object_type,
            object_id=object_id,
            object_name=object_name,
            required_level=required,
            level_before=before,
            level_after=after,
            via=via,
            breaks=breaks,
            severity=severity.value,
            usage_count=usage_count,
            last_used=last_used,
            artifact_type=artifact.type if artifact else None,
            artifact_id=artifact.id if artifact else None,
            artifact_name=artifact.name if artifact else None,
            evidence=json.dumps(evidence or {}, default=str),
            delta_id=_delta_id(self.s.workspace_id, principal, kind.value, object_type, object_id,
                               required, artifact.type if artifact else "", artifact.id if artifact else ""),
        )

    # ---- delta producers -----------------------------------------------------------------

    def _dependency_deltas(self) -> list[Delta]:
        out = []
        for dep in self.s.dependencies:
            if dep.principal_key not in self.s.in_scope or self._moved(dep.artifact):
                continue
            obj = (dep.object_type, dep.object_id)
            if obj in self.s.missing_objects:
                continue  # object no longer exists; not caused by the transition
            after = self.resolver.level(dep.principal_key, dep.object_type, dep.object_id, self.after)
            if satisfies(dep.object_type, after, dep.required_level):
                continue
            before = self.resolver.level(dep.principal_key, dep.object_type, dep.object_id, self.before)
            name = self.s.object_names.get(obj, dep.object_name)
            if dep.kind == Kind.RUN_AS_DEPENDENCY:
                runs, last_run, scheduled = self._artifact_activity(dep.artifact)
                severity = Severity.BLOCKER if runs > 0 else (Severity.MEDIUM if scheduled else Severity.LOW)
                usage, last = runs, last_run
            else:
                usage, last = dep.usage_count, dep.last_used
                severity = Severity.HIGH if usage >= self.high_usage_threshold else Severity.MEDIUM
            out.append(self._base(dep.principal_key, dep.kind, dep.object_type, dep.object_id, name,
                                  dep.required_level, before, after, dep.via, True, severity,
                                  dep.artifact, usage, last))
        return out

    def _entitlement_deltas(self) -> list[Delta]:
        out = []
        needs: dict[tuple[str, str], list] = {}
        for n in self.s.entitlement_needs:
            needs.setdefault((n.principal_key, n.entitlement), []).append(n)
        for key in self.s.in_scope:
            p = self.s.principals.get(key)
            after = self.resolver.entitlements(key, self.after)
            for ent in ENTITLEMENTS:
                if ent in after:
                    continue
                is_human = p is not None and p.kind == "user"
                ent_needs = [n for n in needs.get((key, ent), []) if not self._moved(n.artifact)]
                if ent in INTERACTIVE_ENTITLEMENTS:
                    severity = Severity.HIGH if is_human else Severity.LOW
                    out.append(self._base(key, Kind.ENTITLEMENT, "entitlement", ent, ent, "GRANTED",
                                          "GRANTED", None, "workspace entitlement held via admins", True,
                                          severity))
                    continue
                if not ent_needs:
                    out.append(self._base(key, Kind.ENTITLEMENT, "entitlement", ent, ent, "GRANTED",
                                          "GRANTED", None, "held via admins; no recent use found", True,
                                          Severity.LOW))
                for n in ent_needs:
                    if n.artifact is not None:
                        runs, last, scheduled = self._artifact_activity(n.artifact)
                        severity = Severity.BLOCKER if runs > 0 else (Severity.MEDIUM if scheduled else Severity.LOW)
                        usage = runs
                    else:
                        usage, last = n.usage_count, n.last_used
                        severity = Severity.HIGH if usage > 0 else Severity.LOW
                    out.append(self._base(key, Kind.ENTITLEMENT, "entitlement", ent, ent, "GRANTED", "GRANTED",
                                          None, n.via, True, severity, n.artifact, usage, last))
        return out

    def _token_deltas(self) -> list[Delta]:
        out = []
        for t in self.s.tokens:
            owner = t["owner_key"]
            if owner not in self.s.in_scope or ("token", t["token_id"]) in self.what_if.moved_to_sp:
                continue
            after = self.resolver.level(owner, "authorization", "tokens", self.after)
            blocked = self.s.token_acl_configured and not self.what_if.token_usage and \
                not satisfies("authorization", after, "CAN_USE")
            age = _days_ago(t.get("last_used"), self.today)
            recent = age is not None and age <= self.token_recent_days
            if blocked:
                severity, breaks = (Severity.BLOCKER if recent else Severity.LOW), True
                via = "token usage permission is not granted to power_users"
            else:
                severity, breaks = (Severity.MEDIUM if recent else Severity.INFO), False
                via = "human-owned PAT; breaks if its caller uses admin-only APIs"
            evidence = {"comment": t.get("comment"), "expiry": t.get("expiry"),
                        "token_acl_configured": self.s.token_acl_configured}
            artifact = Artifact("token", t["token_id"], t.get("comment") or t["token_id"])
            out.append(self._base(owner, Kind.TOKEN, "authorization", "tokens", "token usage", "CAN_USE",
                                  "CAN_MANAGE", after, via, breaks, severity, artifact,
                                  1 if recent else 0, t.get("last_used"), evidence))
        return out

    def _admin_action_deltas(self) -> list[Delta]:
        out = []
        for a in self.s.admin_only_actions:
            key = a["principal_key"]
            if key not in self.s.in_scope:
                continue
            automation = a.get("client_type") == "automation"
            sa = f"{a['service_name']}:{a['action_name']}"
            out.append(self._base(key, Kind.ADMIN_ONLY_ACTION, "admin-action", sa, sa, "WORKSPACE_ADMIN",
                                  "WORKSPACE_ADMIN", None,
                                  f"performed {a['n']}x via {a.get('client_type', 'unknown')} "
                                  f"({a.get('user_agent_sample') or 'n/a'})",
                                  True, Severity.BLOCKER if automation else Severity.HIGH, None,
                                  int(a["n"]), a.get("last_seen"),
                                  {"client_type": a.get("client_type"), "user_agent": a.get("user_agent_sample")}))
        return out

    def _uc_deltas(self) -> list[Delta]:
        out = []
        for a in self.s.uc_actions:
            key = a["principal_key"]
            if key not in self.s.in_scope:
                continue
            if self.resolver.has_uc_privilege(key, a["privilege"], self.s.uc_metastore_grants, self.after):
                continue
            out.append(self._base(key, Kind.UC_PRIVILEGE, "uc-metastore", a["privilege"], a["privilege"],
                                  a["privilege"], "IMPLICIT (workspace admin)", None,
                                  f"unityCatalog:{a['action_name']} {a['n']}x", True, Severity.HIGH, None,
                                  int(a["n"]), a.get("last_seen")))
        return out

    def _admin_left_deltas(self) -> list[Delta]:
        """BLOCKER when none of the retained admins is in `admins` today: the move would leave no admin."""
        if not self.s.in_scope:
            return []
        for key in self.s.retained_admins:
            if key.startswith("group:"):
                if ADMINS_GROUP in self.graph.groups_of(key):
                    return []
            elif key in self.graph.members_of(ADMINS_GROUP):
                return []
        names = ", ".join(sorted(self.s.retained_admins)) or "none given"
        return [self._base(ADMINS_GROUP, Kind.NO_ADMIN_LEFT, "workspace", "admins-group", "workspace admins",
                           "WORKSPACE_ADMIN", "WORKSPACE_ADMIN", None,
                           f"retained admins ({names}) are not members of admins today", True, Severity.BLOCKER)]

    def _ownership_deltas(self) -> list[Delta]:
        out = []
        for dep in self.s.ownership:
            if dep.principal_key not in self.s.in_scope or self._moved(dep.artifact):
                continue
            out.append(self._base(dep.principal_key, Kind.OWNERSHIP_RISK, dep.object_type, dep.object_id,
                                  dep.object_name, dep.required_level, dep.required_level, dep.required_level,
                                  dep.via, False, Severity.INFO, dep.artifact))
        return out

