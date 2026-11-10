"""Shared data types.

Principals are identified by a canonical key string so that ACLs from different APIs
(Permissions API, secret ACLs, UC grants, audit logs) can be joined:

    user:<user_name>          e.g. user:alice@contoso.com
    sp:<application_id>       e.g. sp:5f0c...-...
    group:<display_name>      e.g. group:power_users
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

USERS_GROUP = "group:users"
ADMINS_GROUP = "group:admins"


def user_key(user_name: str) -> str:
    return f"user:{user_name}"


def sp_key(application_id: str) -> str:
    return f"sp:{application_id}"


def group_key(display_name: str) -> str:
    return f"group:{display_name}"


def key_name(key: str) -> str:
    """Strip the kind prefix: 'user:alice@x' -> 'alice@x'."""
    return key.split(":", 1)[1]


class Kind(str, Enum):
    RUN_AS_DEPENDENCY = "RUN_AS_DEPENDENCY"  # a job/pipeline running as the admin needs this object
    DIRECT_USE = "DIRECT_USE"  # the admin touched this object (audit) and will lose the access
    ENTITLEMENT = "ENTITLEMENT"  # workspace entitlement only held through `admins`
    ADMIN_ONLY_ACTION = "ADMIN_ONLY_ACTION"  # admin performed a non-delegable action (audit)
    TOKEN = "TOKEN"  # personal access token owned by the admin
    UC_PRIVILEGE = "UC_PRIVILEGE"  # metastore-level privilege used but only held implicitly
    OWNERSHIP_RISK = "OWNERSHIP_RISK"  # human-owned production object (does not break)
    NO_ADMIN_LEFT = "NO_ADMIN_LEFT"  # no retained admin is a workspace admin today


class Severity(str, Enum):
    BLOCKER = "BLOCKER"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


class Bucket(str, Enum):
    COVERED = "COVERED"  # already fixed by the power_users permission set you supplied
    POWER_USERS_GRANT = "POWER_USERS_GRANT"
    MOVE_TO_SP = "MOVE_TO_SP"
    PROCESS_CHANGE = "PROCESS_CHANGE"


@dataclass(frozen=True)
class Principal:
    key: str
    kind: str  # user | service_principal | group
    scim_id: str
    display_name: str
    active: bool = True
    entitlements: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AclEntry:
    principal_key: str
    level: str
    inherited: bool = False


@dataclass(frozen=True)
class Artifact:
    """The thing that creates a dependency (a job, pipeline, query...), used for MOVE_TO_SP."""

    type: str  # job | pipeline | query | token | automation
    id: str
    name: str


@dataclass(frozen=True)
class Dependency:
    """`principal_key` needs at least `required_level` on (object_type, object_id)."""

    principal_key: str
    kind: Kind
    object_type: str
    object_id: str
    object_name: str
    required_level: str
    via: str
    artifact: Optional[Artifact] = None
    usage_count: int = 0
    last_used: Optional[str] = None


@dataclass(frozen=True)
class EntitlementNeed:
    principal_key: str
    entitlement: str
    via: str
    artifact: Optional[Artifact] = None
    usage_count: int = 0
    last_used: Optional[str] = None


@dataclass
class Delta:
    workspace_id: str
    principal: str
    kind: str
    object_type: str
    object_id: str
    object_name: str
    required_level: str
    level_before: Optional[str]
    level_after: Optional[str]
    via: str
    breaks: bool
    severity: str
    usage_count: int = 0
    last_used: Optional[str] = None
    artifact_type: Optional[str] = None
    artifact_id: Optional[str] = None
    artifact_name: Optional[str] = None
    evidence: str = ""  # free text / JSON
    delta_id: str = ""
    # Set when this would break with an empty power_users group but your permission set fixes it.
    # Covered deltas are reported for transparency and never count towards readiness.
    covered_by: Optional[str] = None


@dataclass
class Recommendation:
    delta_id: str
    workspace_id: str
    principal: str
    bucket: str
    primary_action: str
    alternative_action: str
    rationale: str
    scope_creep: bool
    # Grant this recommendation implies (for POWER_USERS_GRANT, or the grant the SP needs for MOVE_TO_SP)
    grant_object_type: Optional[str] = None
    grant_object_id: Optional[str] = None
    grant_object_name: Optional[str] = None
    grant_level: Optional[str] = None
    route: Optional[str] = None  # PROCESS_CHANGE routing target


@dataclass
class ProposedGrant:
    workspace_id: str
    object_type: str
    object_id: str
    object_name: str
    level: str
    fixes_n_deltas: int
    admins_affected: str
    max_severity: str
    scope_creep: bool


@dataclass
class MoveToSpItem:
    workspace_id: str
    artifact_type: str
    artifact_id: str
    artifact_name: str
    current_identity: str
    max_severity: str
    sp_needs: str  # "; "-joined list of grants the SP needs
    action: str


@dataclass
class ProcessChange:
    workspace_id: str
    service_action: str
    route: str
    admins: str
    occurrences: int
    last_seen: Optional[str]


@dataclass
class PermissionCoverage:
    """One entry of the power_users permission set you supplied, evaluated against one workspace."""

    workspace_id: str
    permission_id: str  # stable label, e.g. "cluster-policies name='Personal*' CAN_USE"
    permission_type: str  # object_grant | entitlement | uc_privilege | token_usage
    object_type: str
    object_spec: str  # object id, "*", or name pattern as written in the config
    level: str
    matched_objects: int  # objects in this workspace the entry resolves to (-1 = not applicable)
    matched_names: str  # first few matched names
    fixes_n_deltas: int  # breaks this entry fixes (would break without the permission set)
    fixes_blocker_high: int
    admins_helped: str
    scope_creep: bool
    scope_creep_reason: str
    status: str  # USED | UNUSED | NOT_FOUND


@dataclass
class ReadinessSummary:
    workspace_id: str
    workspace_host: str
    admins_in_scope: int
    humans_in_scope: int
    blockers: int
    high: int
    medium: int
    low: int
    info: int
    proposed_grants: int
    scope_creep_grants: int
    move_to_sp_items: int
    process_changes: int
    status: str  # READY | NOT_READY
    covered_by_permission_set: int = 0  # breaks your permission set already fixes
    permission_set_size: int = 0
    unused_permissions: int = 0
    not_found_permissions: int = 0
    retained_admins: str = ""


@dataclass
class PrincipalRow:
    workspace_id: str
    principal: str
    kind: str
    display_name: str
    in_scope: bool
    is_admin: bool
    reason: str


@dataclass
class AclRow:
    workspace_id: str
    object_type: str
    object_id: str
    principal: str
    level: str
    inherited: bool


@dataclass
class RelevantObject:
    workspace_id: str
    object_type: str
    object_id: str
    object_name: str
    found: bool
    error: str = ""


@dataclass
class Snapshot:
    """Everything collected for one workspace, input to the simulator."""

    workspace_id: str
    workspace_host: str
    principals: dict[str, Principal] = field(default_factory=dict)
    memberships: dict[str, set[str]] = field(default_factory=dict)  # member key -> direct parent groups
    in_scope: dict[str, str] = field(default_factory=dict)  # principal key -> reason
    acls: dict[tuple[str, str], list[AclEntry]] = field(default_factory=dict)
    object_names: dict[tuple[str, str], str] = field(default_factory=dict)
    missing_objects: dict[tuple[str, str], str] = field(default_factory=dict)
    dependencies: list[Dependency] = field(default_factory=list)
    entitlement_needs: list[EntitlementNeed] = field(default_factory=list)
    tokens: list[dict] = field(default_factory=list)
    token_acl_configured: bool = True
    admin_only_actions: list[dict] = field(default_factory=list)
    uc_actions: list[dict] = field(default_factory=list)
    uc_metastore_grants: dict[str, set[str]] = field(default_factory=dict)  # principal key -> privileges
    retained_admins: dict[str, str] = field(default_factory=dict)  # principal key -> why it stays admin
    ownership: list[Dependency] = field(default_factory=list)
    job_runs: dict[str, dict] = field(default_factory=dict)  # job_id -> {runs, last_run}
    pipeline_updates: dict[str, dict] = field(default_factory=dict)
    scheduled_jobs: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
