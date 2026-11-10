"""Permission levels per object type, lowest to highest.

Object type names match the Permissions API `request_object_type` where one exists
(`/api/2.0/permissions/{type}/{id}`). `secret-scopes` uses the Secrets ACL API.
"""

from __future__ import annotations

from typing import Optional

LEVELS: dict[str, list[str]] = {
    "jobs": ["CAN_VIEW", "CAN_MANAGE_RUN", "CAN_MANAGE", "IS_OWNER"],
    "clusters": ["CAN_ATTACH_TO", "CAN_RESTART", "CAN_MANAGE"],
    "cluster-policies": ["CAN_USE"],
    "instance-pools": ["CAN_ATTACH_TO", "CAN_MANAGE"],
    "pipelines": ["CAN_VIEW", "CAN_RUN", "CAN_MANAGE", "IS_OWNER"],
    "warehouses": ["CAN_VIEW", "CAN_MONITOR", "CAN_USE", "CAN_MANAGE", "IS_OWNER"],
    "notebooks": ["CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"],
    "directories": ["CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"],
    "files": ["CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"],
    "repos": ["CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"],
    "experiments": ["CAN_READ", "CAN_EDIT", "CAN_MANAGE"],
    "registered-models": [
        "CAN_READ",
        "CAN_EDIT",
        "CAN_MANAGE_STAGING_VERSIONS",
        "CAN_MANAGE_PRODUCTION_VERSIONS",
        "CAN_MANAGE",
    ],
    "serving-endpoints": ["CAN_VIEW", "CAN_QUERY", "CAN_MANAGE"],
    "dashboards": ["CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"],
    "queries": ["CAN_VIEW", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE", "IS_OWNER"],
    "alerts": ["CAN_VIEW", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE", "IS_OWNER"],
    "apps": ["CAN_USE", "CAN_MANAGE"],
    "authorization": ["CAN_USE", "CAN_MANAGE"],  # object id "tokens" = token usage permission
    "secret-scopes": ["READ", "WRITE", "MANAGE"],
}

# Workspace admins implicitly hold the top level on every object type.
ADMIN_LEVEL: dict[str, str] = {t: levels[-1] for t, levels in LEVELS.items()}
# Admins can manage but not "own" other people's jobs/pipelines/warehouses/queries.
for _t in ("jobs", "pipelines", "warehouses", "queries", "alerts"):
    ADMIN_LEVEL[_t] = "CAN_MANAGE"

# Minimum level the run_as identity of a job/pipeline needs on each dependency.
RUN_AS_REQUIRED: dict[str, str] = {
    "clusters": "CAN_RESTART",  # job on an existing all-purpose cluster may need to start it
    "cluster-policies": "CAN_USE",
    "instance-pools": "CAN_ATTACH_TO",
    "notebooks": "CAN_READ",
    "files": "CAN_READ",
    "directories": "CAN_READ",
    "warehouses": "CAN_USE",
    "pipelines": "CAN_RUN",
    "jobs": "CAN_MANAGE_RUN",
    "secret-scopes": "READ",
    "queries": "CAN_RUN",
    "alerts": "CAN_RUN",
    "dashboards": "CAN_RUN",
}

ENTITLEMENTS = (
    "workspace-access",
    "databricks-sql-access",
    "allow-cluster-create",
    "allow-instance-pool-create",
)


def rank(object_type: str, level: Optional[str]) -> int:
    """-1 for no access; unknown levels rank as 0 so they never satisfy a higher requirement."""
    if level is None:
        return -1
    levels = LEVELS.get(object_type)
    if not levels or level not in levels:
        return 0
    return levels.index(level)


def max_level(object_type: str, levels: list[Optional[str]]) -> Optional[str]:
    best: Optional[str] = None
    for level in levels:
        if rank(object_type, level) > rank(object_type, best):
            best = level
    return best


def satisfies(object_type: str, have: Optional[str], need: str) -> bool:
    return rank(object_type, have) >= rank(object_type, need)
