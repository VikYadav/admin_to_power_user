"""WorkspaceClients for the target workspace and the results workspace.

Auth: `--profile` (a ~/.databrickscfg profile), otherwise the SDK's default auth (env vars / DEFAULT profile).
`--workspace-host` overrides the profile's host. `--home-profile` / `--home-host` pick the results workspace
(the warehouse, output tables and dashboard); without them it is the target itself. `--home-current` uses the
default auth for the results workspace (inside a job: the job's own workspace and run-as identity).

In a job, the target is reached with a service principal's Databricks OAuth secret (`target_client`), because the
job's own credentials only work in the workspace it runs in.
"""

from __future__ import annotations

import base64
from typing import Optional

from databricks.sdk import WorkspaceClient

from admin_to_power_user.readonly import WriteScope, make_output_only, make_read_only


def workspace_client(host: Optional[str], profile: Optional[str] = None, sql: bool = True) -> WorkspaceClient:
    """Every non-GET call on the returned client is refused, except SELECTs when sql=True (see readonly.py)."""
    kwargs = {k: v for k, v in (("host", host), ("profile", profile)) if v}
    return make_read_only(WorkspaceClient(**kwargs), allow_sql=sql)


def target_client(host: str, client_id: str, client_secret: str) -> WorkspaceClient:
    """GET-only client for a target, authenticated as an SP with OAuth M2M (never the job's own credentials)."""
    return make_read_only(WorkspaceClient(host=host, client_id=client_id, client_secret=client_secret,
                                          auth_type="oauth-m2m"), allow_sql=False)


def read_secret(home: WorkspaceClient, scope: str, key: str) -> str:
    """The SP's OAuth secret from a secret scope in the results workspace (a GET; kept in memory only)."""
    value = home.secrets.get_secret(scope=scope, key=key).value or ""
    return base64.b64decode(value).decode("utf-8").strip()


def output_client(w: WorkspaceClient, scope: WriteScope) -> WorkspaceClient:
    """A second client, same workspace and identity, that may only write the output tables and dashboard."""
    return make_output_only(WorkspaceClient(config=w.config), scope)
