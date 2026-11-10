"""Effective-permission resolver for the two simulated states.

State A (today):  explicit ACLs via the principal and its groups, plus implicit admin access.
State B (after):  explicit ACLs via groups minus `admins`, plus `power_users`, plus what-if grants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from admin_to_power_user.model.graph import PrincipalGraph
from admin_to_power_user.model.levels import ADMIN_LEVEL, max_level
from admin_to_power_user.models import ADMINS_GROUP, AclEntry

PATH_TYPES = {"notebooks", "files", "directories", "repos"}


def _under(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")


@dataclass(frozen=True)
class WhatIf:
    """Hypothetical grants to power_users (your permission set) and work treated as moved to an SP."""

    grants: tuple[tuple[str, str, str], ...] = ()  # (object_type, object_id or "*", level)
    path_grants: tuple[tuple[str, str], ...] = ()  # (workspace folder, level): covers everything below it
    entitlements: frozenset[str] = frozenset()
    uc_privileges: frozenset[str] = frozenset()
    token_usage: bool = False
    moved_to_sp: frozenset[tuple[str, str]] = frozenset()  # (artifact_type, artifact_id)


@dataclass(frozen=True)
class Scenario:
    name: str
    implicit_admin: bool
    exclude_groups: frozenset[str] = frozenset()
    extra_groups: frozenset[str] = frozenset()
    what_if: WhatIf = field(default_factory=WhatIf)


def before_scenario() -> Scenario:
    return Scenario(name="before", implicit_admin=True)


def after_scenario(power_users_group: str, what_if: Optional[WhatIf] = None) -> Scenario:
    return Scenario(
        name="after",
        implicit_admin=False,
        exclude_groups=frozenset({ADMINS_GROUP}),
        extra_groups=frozenset({power_users_group}),
        what_if=what_if or WhatIf(),
    )


class Resolver:
    def __init__(
        self,
        graph: PrincipalGraph,
        acls: dict[tuple[str, str], list[AclEntry]],
        power_users_group: str,
        object_names: Optional[dict[tuple[str, str], str]] = None,
    ):
        self.graph = graph
        self.acls = acls
        self.power_users_group = power_users_group
        self.object_names = object_names or {}

    def groups(self, key: str, scenario: Scenario) -> set[str]:
        return self.graph.groups_of(key, exclude=scenario.exclude_groups, extra=scenario.extra_groups)

    def level(self, key: str, object_type: str, object_id: str, scenario: Scenario) -> Optional[str]:
        if scenario.implicit_admin:
            return ADMIN_LEVEL.get(object_type)
        holders = {key} | self.groups(key, scenario)
        levels = [e.level for e in self.acls.get((object_type, object_id), []) if e.principal_key in holders]
        if self.power_users_group in holders:
            for g_type, g_id, g_level in scenario.what_if.grants:
                if g_type == object_type and g_id in (object_id, "*"):
                    levels.append(g_level)
            if object_type in PATH_TYPES and scenario.what_if.path_grants:
                path = self.object_names.get((object_type, object_id), "")
                levels += [lv for prefix, lv in scenario.what_if.path_grants if path and _under(path, prefix)]
        return max_level(object_type, levels)

    def entitlements(self, key: str, scenario: Scenario) -> set[str]:
        groups = self.groups(key, scenario)
        ents = self.graph.entitlements(key, groups)
        if self.power_users_group in groups:
            ents |= scenario.what_if.entitlements
        return ents

    def has_uc_privilege(
        self,
        key: str,
        privilege: str,
        metastore_grants: dict[str, set[str]],
        scenario: Scenario,
    ) -> bool:
        holders = {key} | self.groups(key, scenario)
        for h in holders:
            privs = metastore_grants.get(h, set())
            if privilege in privs or "ALL_PRIVILEGES" in privs:
                return True
        wanted = scenario.what_if.uc_privileges
        return self.power_users_group in holders and (privilege in wanted or "ALL_PRIVILEGES" in wanted)
