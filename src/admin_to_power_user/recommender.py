"""Map each delta to an advisory remediation in one of three buckets.

POWER_USERS_GRANT  grant something to the power_users group (deduplicated by the consolidator)
MOVE_TO_SP         the dependency belongs to automation; re-own / re-run_as it to a service principal
PROCESS_CHANGE     the action cannot be delegated; route it to the admin SP, a group manager, or PIM JIT
"""

from __future__ import annotations

from admin_to_power_user.models import Bucket, Delta, Kind, Recommendation, key_name

# Grants to a whole group of humans that we consider "scope creep" (rebuilding admin piecemeal).
SCOPE_CREEP_LEVELS = {
    "jobs": {"CAN_MANAGE", "IS_OWNER"},
    "pipelines": {"CAN_MANAGE", "IS_OWNER"},
    "clusters": {"CAN_MANAGE"},
    "instance-pools": {"CAN_MANAGE"},
    "warehouses": {"CAN_MANAGE", "IS_OWNER"},
    "secret-scopes": {"READ", "WRITE", "MANAGE"},  # a whole group reading prod secrets is a red flag
    "directories": {"CAN_MANAGE"},
    "authorization": {"CAN_MANAGE"},
}
SCOPE_CREEP_ENTITLEMENTS = {"allow-cluster-create"}  # unrestricted clusters; prefer policy CAN_USE
SCOPE_CREEP_UC = {"CREATE_STORAGE_CREDENTIAL", "CREATE_EXTERNAL_LOCATION", "CREATE_CONNECTION",
                  "CREATE_SHARE", "CREATE_RECIPIENT", "CREATE_PROVIDER", "MANAGE_ALLOWLIST"}

# Non-delegable admin actions -> where the work should go after cutover.
# Keys are "service:action" or "service:*". Verify names against your own audit logs.
PROCESS_ROUTES = {
    "accounts:add": "Provision users via Entra ID SCIM / automatic identity management at account level",
    "accounts:delete": "Provision users via Entra ID SCIM / automatic identity management at account level",
    "accounts:createGroup": "Create account-level groups (Entra ID sync); assign group managers",
    "accounts:removeGroup": "Account-level groups (Entra ID sync); assign group managers",
    "accounts:addPrincipalToGroup": "Account-level group manager role, or Entra ID group membership",
    "accounts:removePrincipalFromGroup": "Account-level group manager role, or Entra ID group membership",
    "accounts:setAdmin": "Should not happen after cutover; use Entra PIM JIT elevation for break-glass",
    "accounts:removeAdmin": "Should not happen after cutover; use Entra PIM JIT elevation for break-glass",
    "accounts:changeDbTokenAcl": "Admin SP via Terraform PR (token permissions)",
    "accounts:changeDatabricksSqlAcl": "Admin SP via Terraform PR (entitlements)",
    "accounts:changeDatabricksWorkspaceAcl": "Admin SP via Terraform PR (entitlements)",
    "accounts:createIpAccessList": "Admin SP via Terraform PR (IP access lists)",
    "accounts:updateIpAccessList": "Admin SP via Terraform PR (IP access lists)",
    "accounts:deleteIpAccessList": "Admin SP via Terraform PR (IP access lists)",
    "workspace:workspaceConfEdit": "Admin SP via Terraform PR (workspace settings)",
    "globalInitScripts:*": "Admin SP via Terraform PR (global init scripts)",
    "clusterPolicies:*": "Admin SP via Terraform PR (cluster policies); grant power_users CAN_USE on policies",
    "settings:*": "Admin SP via Terraform PR (workspace settings)",
}
DEFAULT_ROUTE = "Admin SP via Terraform/Asset Bundle PR, or Entra PIM JIT elevation for rare tasks"


def route_for(service_action: str) -> str:
    if service_action in PROCESS_ROUTES:
        return PROCESS_ROUTES[service_action]
    return PROCESS_ROUTES.get(service_action.split(":", 1)[0] + ":*", DEFAULT_ROUTE)


def _obj(d: Delta) -> str:
    return f"{d.object_type} '{d.object_name or d.object_id}'"


def recommend(d: Delta) -> Recommendation:
    who = key_name(d.principal)
    rec = Recommendation(delta_id=d.delta_id, workspace_id=d.workspace_id, principal=d.principal,
                         bucket="", primary_action="", alternative_action="", rationale="", scope_creep=False)
    kind = Kind(d.kind)

    if d.covered_by:
        rec.bucket = Bucket.COVERED.value
        rec.primary_action = f"None: covered by your power_users permission set ({d.covered_by})"
        rec.alternative_action = (f"Still consider moving {d.artifact_type} '{d.artifact_name}' to a service principal"
                                  if d.artifact_type in ("job", "pipeline") else "")
        rec.rationale = f"Would fail for {who} with an empty power_users group; your permission set covers it"
        return rec

    if kind == Kind.NO_ADMIN_LEFT:
        rec.bucket = Bucket.PROCESS_CHANGE.value
        rec.route = "Add the admin SP (or admin group) to the workspace `admins` group first"
        rec.primary_action = rec.route + ", then remove the human admins"
        rec.alternative_action = "Check retained_admins: the client id / group name may be wrong"
        rec.rationale = "Removing every in-scope admin would leave the workspace without any admin"
        return rec

    if kind == Kind.RUN_AS_DEPENDENCY:
        creep = d.required_level in SCOPE_CREEP_LEVELS.get(d.object_type, set())
        rec.bucket = Bucket.MOVE_TO_SP.value
        rec.primary_action = (f"Set run_as of {d.artifact_type} '{d.artifact_name}' to a service principal "
                              f"and grant that SP {d.required_level} on {_obj(d)}")
        rec.alternative_action = f"Grant {who} {d.required_level} on {_obj(d)} directly (not via power_users)"
        rec.rationale = (f"{d.artifact_type} runs as {who}, who only has access through admins "
                         f"(after: {d.level_after or 'none'}). Production should not depend on a human.")
        rec.scope_creep = creep
        rec.grant_object_type, rec.grant_object_id = d.object_type, d.object_id
        rec.grant_object_name, rec.grant_level = d.object_name, d.required_level

    elif kind == Kind.DIRECT_USE:
        creep = d.required_level in SCOPE_CREEP_LEVELS.get(d.object_type, set())
        rec.bucket = Bucket.POWER_USERS_GRANT.value
        rec.primary_action = f"Grant power_users {d.required_level} on {_obj(d)}"
        rec.alternative_action = (f"Grant {who} {d.required_level} on {_obj(d)} individually, or ask the "
                                  f"object owner to share it")
        if creep:
            rec.alternative_action = (f"Grant {who} (not the group) {d.required_level} on {_obj(d)}; if this is "
                                      f"automation, move it to an SP")
        rec.rationale = f"{who} used this {d.usage_count}x in the lookback window via implicit admin access"
        rec.scope_creep = creep
        rec.grant_object_type, rec.grant_object_id = d.object_type, d.object_id
        rec.grant_object_name, rec.grant_level = d.object_name, d.required_level

    elif kind == Kind.ENTITLEMENT:
        ent = d.object_id
        creep = ent in SCOPE_CREEP_ENTITLEMENTS
        if d.artifact_type in ("job", "pipeline"):
            rec.bucket = Bucket.MOVE_TO_SP.value
            rec.primary_action = (f"Set run_as of {d.artifact_type} '{d.artifact_name}' to an SP with "
                                  f"'{ent}', or attach a cluster policy to its job clusters")
            rec.alternative_action = f"Grant entitlement '{ent}' to power_users"
        else:
            rec.bucket = Bucket.POWER_USERS_GRANT.value
            rec.primary_action = f"Grant entitlement '{ent}' to power_users"
            rec.alternative_action = ("Grant CAN_USE on approved cluster policies to power_users instead of "
                                      "unrestricted cluster creation") if creep else "Grant to the user directly"
        rec.rationale = f"{who} only has '{ent}' through the admins group"
        rec.scope_creep = creep and rec.bucket == Bucket.POWER_USERS_GRANT.value
        rec.grant_object_type, rec.grant_object_id = "entitlement", ent
        rec.grant_object_name, rec.grant_level = ent, "GRANTED"

    elif kind == Kind.TOKEN:
        if d.breaks:
            rec.bucket = Bucket.MOVE_TO_SP.value if d.usage_count else Bucket.POWER_USERS_GRANT.value
            rec.primary_action = ("Replace the PAT with an SP using OAuth M2M (or a managed identity) in the "
                                  "calling system" if d.usage_count else
                                  "Grant power_users CAN_USE on token usage, or revoke the unused PAT")
            rec.alternative_action = "Grant power_users CAN_USE on token usage (Settings > Advanced > PAT)"
            rec.grant_object_type, rec.grant_object_id = "authorization", "tokens"
            rec.grant_object_name, rec.grant_level = "token usage", "CAN_USE"
        else:
            rec.bucket = Bucket.MOVE_TO_SP.value
            rec.primary_action = "Move the caller of this PAT to an SP (OAuth M2M / managed identity)"
            rec.alternative_action = "Keep the PAT; confirm its caller does not call admin-only APIs"
        rec.rationale = f"PAT '{d.artifact_name}' owned by {who}, last used {d.last_used or 'never'}"

    elif kind == Kind.ADMIN_ONLY_ACTION:
        sa = d.object_id
        rec.route = route_for(sa)
        automation = '"client_type": "automation"' in d.evidence
        if automation:
            rec.bucket = Bucket.MOVE_TO_SP.value
            rec.primary_action = f"Run the automation that calls {sa} as the admin SP (OAuth M2M)"
            rec.alternative_action = rec.route
        else:
            rec.bucket = Bucket.PROCESS_CHANGE.value
            rec.primary_action = rec.route
            rec.alternative_action = "Entra PIM just-in-time elevation into admins for rare, audited tasks"
        rec.rationale = f"{sa} is admin-only and cannot be delegated to a group; {who} did it {d.usage_count}x"
        rec.scope_creep = False

    elif kind == Kind.UC_PRIVILEGE:
        priv = d.object_id
        creep = priv in SCOPE_CREEP_UC
        rec.bucket = Bucket.POWER_USERS_GRANT.value
        rec.primary_action = f"GRANT {priv.replace('_', ' ')} ON METASTORE TO `power_users`"
        rec.alternative_action = ("Have the admin SP create these via Terraform PR" if creep else
                                  "Grant to the individual user")
        rec.rationale = f"{who} used {priv} implicitly as a workspace admin"
        rec.scope_creep = creep
        rec.grant_object_type, rec.grant_object_id = "uc-metastore", priv
        rec.grant_object_name, rec.grant_level = priv, priv

    else:  # OWNERSHIP_RISK
        rec.bucket = Bucket.MOVE_TO_SP.value
        rec.primary_action = f"Transfer ownership of {_obj(d)} to a service principal or group"
        rec.alternative_action = "Keep as is; this does not break, but is an offboarding risk"
        rec.rationale = f"Owned by {who}; ownership survives the transition but ties production to a person"

    return rec


def recommend_all(deltas: list[Delta]) -> list[Recommendation]:
    return [recommend(d) for d in deltas]
