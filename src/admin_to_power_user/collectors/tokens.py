"""Personal access tokens owned by in-scope admins, and the token-usage permission."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from databricks.sdk import WorkspaceClient

from admin_to_power_user.collectors.acls import acl_entries
from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.models import ADMINS_GROUP, Snapshot


def _iso_day(epoch_ms: Optional[int]) -> Optional[str]:
    if not epoch_ms or epoch_ms < 0:
        return None
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).date().isoformat()


def collect_tokens(w: WorkspaceClient, snapshot: Snapshot, names: NameResolver) -> None:
    by_scim = {p.scim_id: k for k, p in snapshot.principals.items()}
    for t in w.token_management.list():
        owner = by_scim.get(str(t.owner_id)) if t.owner_id is not None else None
        if owner is None and t.created_by_username:
            owner = names.key(t.created_by_username)
        if owner not in snapshot.in_scope:
            continue
        snapshot.tokens.append({
            "token_id": t.token_id,
            "owner_key": owner,
            "comment": t.comment,
            "created": _iso_day(t.creation_time),
            "expiry": _iso_day(t.expiry_time) or "never",
            "last_used": _iso_day(t.last_used_day),
        })

    perms = w.permissions.get("authorization", "tokens")
    entries = acl_entries(perms)
    snapshot.acls[("authorization", "tokens")] = entries
    # If only `admins` appears, token permissions were probably never configured; we cannot tell whether
    # all users can use tokens, so don't report blocked tokens as breaks.
    snapshot.token_acl_configured = any(e.principal_key != ADMINS_GROUP for e in entries)
    if not snapshot.token_acl_configured:
        snapshot.warnings.append("Token usage permissions look unconfigured (only admins listed). Verify in "
                                 "Settings > Advanced > Personal Access Tokens whether non-admins can use PATs.")
