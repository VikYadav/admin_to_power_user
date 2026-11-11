"""WorkspaceClients for the target workspace and the results workspace.

Auth: `--profile` (a ~/.databrickscfg profile), otherwise the SDK's default auth (env vars / DEFAULT profile).
`--workspace-host` overrides the profile's host. `--home-profile` / `--home-host` pick the results workspace
(the warehouse, output tables and dashboard); without them it is the target itself.
"""

from __future__ import annotations

from typing import Optional

from databricks.sdk import WorkspaceClient

from admin_to_power_user.config import Config
from admin_to_power_user.readonly import WriteScope, make_output_only, make_read_only


def workspace_client(cfg: Config, host: Optional[str], profile: Optional[str] = None,
                     sql: bool = True) -> WorkspaceClient:
    """Every non-GET call on the returned client is refused, except SELECTs when sql=True (see readonly.py)."""
    kwargs = {k: v for k, v in (("host", host), ("profile", profile)) if v}
    return make_read_only(WorkspaceClient(**kwargs), allow_sql=sql)


def output_client(w: WorkspaceClient, scope: WriteScope) -> WorkspaceClient:
    """A second client, same workspace and identity, that may only write the output tables and dashboard."""
    return make_output_only(WorkspaceClient(config=w.config), scope)
