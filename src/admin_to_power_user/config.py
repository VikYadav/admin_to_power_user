"""Run settings. Everything has a default; the command-line flags set what users need.

The only file the tool reads is the power_users permission set (--permissions, see config/power_users.yaml).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import yaml

from admin_to_power_user.model.resolver import WhatIf
from admin_to_power_user.permission_set import PermissionSet, parse_permission_set

DEFAULT_ADMIN_ONLY_ACTIONS = [
    "accounts:add",
    "accounts:delete",
    "accounts:createGroup",
    "accounts:removeGroup",
    "accounts:addPrincipalToGroup",
    "accounts:removePrincipalFromGroup",
    "accounts:setAdmin",
    "accounts:removeAdmin",
    "accounts:changeDbTokenAcl",
    "accounts:changeDatabricksSqlAcl",
    "accounts:changeDatabricksWorkspaceAcl",
    "accounts:createIpAccessList",
    "accounts:updateIpAccessList",
    "accounts:deleteIpAccessList",
    "workspace:workspaceConfEdit",
    "globalInitScripts:*",
    "clusterPolicies:create",
    "clusterPolicies:edit",
    "clusterPolicies:delete",
]


@dataclass(frozen=True)
class RetainedAdmin:
    """A principal that stays workspace admin. kind: auto | service_principal | group | user.

    `ref` is an SP application (client) id, a group display name, a SCIM id, or a user's email.
    `auto` tries them in that order, so `--admin <whatever you have>` just works.
    """

    kind: str
    ref: str

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.ref}"


@dataclass
class Config:
    power_users_group: str = "power_users"
    retained_admins: list[RetainedAdmin] = field(default_factory=list)
    permission_set: PermissionSet = field(default_factory=PermissionSet)
    workspace_host: Optional[str] = None
    workspace_id: Optional[str] = None  # if set, the run aborts unless the target has this id
    lookback_days: int = 90
    high_usage_threshold: int = 10
    token_recent_days: int = 30
    admin_only_actions: list[str] = field(default_factory=lambda: list(DEFAULT_ADMIN_ONLY_ACTIONS))
    max_notebooks: int = 200
    max_workers: int = 8
    what_if: WhatIf = field(default_factory=WhatIf)

    @property
    def power_users_key(self) -> str:
        return f"group:{self.power_users_group}"

    def all_retained(self) -> list[RetainedAdmin]:
        return list(self.retained_admins)


MOVED_TYPES = {"job", "pipeline", "token", "query"}


def parse_moved(items: list[str]) -> frozenset[tuple[str, str]]:
    """["job:123", "token:abc"] -> {("job", "123"), ("token", "abc")}"""
    out = set()
    for item in items:
        kind, _, oid = item.partition(":")
        if kind not in MOVED_TYPES or not oid:
            raise SystemExit(f"--assume-moved expects job:<id>, pipeline:<id>, token:<id> or query:<id>, got {item!r}")
        out.add((kind, oid))
    return frozenset(out)


def load_permission_file(path: str) -> PermissionSet:
    """A standalone YAML holding just the permission set (the `power_users.permissions` block)."""
    with open(path) as f:
        raw = yaml.safe_load(f) or []
    if isinstance(raw, dict):
        raw = (raw.get("power_users") or {}).get("permissions", raw.get("permissions", raw))
    return parse_permission_set(raw)
