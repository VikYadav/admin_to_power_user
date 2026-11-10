"""The AI/BI dashboard over the output tables: one page, "What breaks and how to fix it".

The definition is `dashboard.lvdash.json` next to this file, with the output schema written as
`__CATALOG__`.`__SCHEMA__`. It is locked: every run creates the dashboard, or updates it to exactly this
definition, and publishes it. Edits made in the UI are overwritten on the next run, so change the file instead.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Optional

from databricks.sdk.errors import NotFound, ResourceDoesNotExist

from admin_to_power_user.readonly import WriteScope

DEFAULT_NAME = "Admin to power_users readiness"
PLACEHOLDER = "`__CATALOG__`.`__SCHEMA__`"


def template() -> str:
    return files("admin_to_power_user").joinpath("dashboard.lvdash.json").read_text(encoding="utf-8")


def build(prefix: str) -> dict:
    """The dashboard definition with the output schema filled in (prefix = `catalog`.`schema`)."""
    return json.loads(template().replace(PLACEHOLDER, prefix))


def deploy(ww, scope: WriteScope, warehouse_id: str, name: str = DEFAULT_NAME) -> tuple[str, str]:
    """Create the dashboard, or update it to the packaged definition, then publish. Returns (id, URL)."""
    from databricks.sdk.service.dashboards import Dashboard

    folder = scope.dashboard_folder.rstrip("/")
    existing: Optional[str] = None
    try:
        existing = ww.workspace.get_status(f"{folder}/{name}.lvdash.json").resource_id
    except (NotFound, ResourceDoesNotExist):
        try:
            ww.workspace.get_status(folder)
        except (NotFound, ResourceDoesNotExist):
            ww.workspace.mkdirs(folder)
    serialized = json.dumps(build(scope.prefix))
    if existing:
        scope.dashboard_ids.add(existing)
        ww.lakeview.update(existing, Dashboard(display_name=name, serialized_dashboard=serialized,
                                               warehouse_id=warehouse_id))
        dashboard_id = existing
    else:
        created = ww.lakeview.create(Dashboard(display_name=name, parent_path=folder,
                                               serialized_dashboard=serialized, warehouse_id=warehouse_id))
        dashboard_id = created.dashboard_id
        scope.dashboard_ids.add(dashboard_id)
    # Viewers query with their own credentials: they need CAN_VIEW on the dashboard and SELECT on the schema.
    ww.lakeview.publish(dashboard_id, embed_credentials=False, warehouse_id=warehouse_id)
    host = ww.config.host.rstrip("/")
    return dashboard_id, f"{host}/dashboardsv3/{dashboard_id}/published"
