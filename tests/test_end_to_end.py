"""Run the full `analyze` command against a fake WorkspaceClient built from real SDK dataclasses."""

import base64
import json
import os
from types import SimpleNamespace

from databricks.sdk.errors import NotFound
from databricks.sdk.service import catalog, compute, dashboards, iam, jobs, settings, sql, workspace

from admin_to_power_user import main as cli


def _list(items):
    return lambda *a, **k: iter(items)


def _perm(user=None, group=None, sp=None, level="CAN_MANAGE", inherited=False):
    return iam.AccessControlResponse(user_name=user, group_name=group, service_principal_name=sp, all_permissions=[
        iam.Permission(permission_level=iam.PermissionLevel(level), inherited=inherited)])


def fake_workspace():
    cv = iam.ComplexValue
    users = [iam.User(id="u1", user_name="alice@contoso.com", active=True),
             iam.User(id="u2", user_name="carol@contoso.com", active=True)]
    sps = [iam.ServicePrincipal(id="s1", application_id="sp-admin", active=True)]
    groups = [
        iam.Group(id="g1", display_name="admins", members=[cv(value="u1"), cv(value="s1")],
                  meta=iam.ResourceMeta(resource_type="WorkspaceGroup")),
        iam.Group(id="g2", display_name="users", members=[cv(value="u1"), cv(value="u2")],
                  entitlements=[cv(value="workspace-access")], meta=iam.ResourceMeta(resource_type="WorkspaceGroup")),
        iam.Group(id="g3", display_name="power_users", meta=iam.ResourceMeta(resource_type="Group")),
    ]
    job = jobs.Job.from_dict({"job_id": 101, "creator_user_name": "alice@contoso.com",
                              "run_as_user_name": "alice@contoso.com", "settings": {
                                  "name": "nightly", "tasks": [{
                                      "task_key": "a", "existing_cluster_id": "c1",
                                      "notebook_task": {"notebook_path": "/Shared/etl", "source": "WORKSPACE"}}]}})
    acls = {
        ("clusters", "c1"): [_perm(group="admins")],
        ("notebooks", "77"): [_perm(group="users", level="CAN_READ")],
        ("authorization", "tokens"): [_perm(group="admins"), _perm(group="power_users", level="CAN_USE")],
    }
    nb_src = base64.b64encode(b'x = dbutils.secrets.get(scope="prod", key="k")').decode()

    def get_status(path):
        if path == "/Shared/etl":
            return workspace.ObjectInfo(object_type=workspace.ObjectType.NOTEBOOK, object_id=77, path=path)
        raise NotFound("nope")

    return SimpleNamespace(
        config=SimpleNamespace(host="https://adb-1.1.azuredatabricks.net"),
        current_user=SimpleNamespace(me=lambda: iam.User(user_name="alice@contoso.com")),
        get_workspace_id=lambda: 1,
        users=SimpleNamespace(list=_list(users)),
        service_principals=SimpleNamespace(list=_list(sps)),
        groups=SimpleNamespace(list=_list(groups)),
        clusters=SimpleNamespace(list=_list([compute.ClusterDetails(cluster_id="c1", cluster_name="shared")])),
        cluster_policies=SimpleNamespace(list=_list([])),
        instance_pools=SimpleNamespace(list=_list([])),
        warehouses=SimpleNamespace(list=_list([])),
        jobs=SimpleNamespace(list=_list([jobs.BaseJob(job_id=101, creator_user_name="alice@contoso.com",
                                                       settings=job.settings)]),
                             get=lambda job_id: job),
        pipelines=SimpleNamespace(list_pipelines=_list([])),
        queries=SimpleNamespace(list=_list([sql.ListQueryObjectsResponseQuery(
            id="q1", display_name="kpis", owner_user_name="alice@contoso.com", warehouse_id="wh1",
            run_as_mode=sql.RunAsMode.OWNER)])),
        alerts=SimpleNamespace(list=_list([])),
        lakeview=SimpleNamespace(list=_list([dashboards.Dashboard(dashboard_id="d1", display_name="exec",
                                                                  path="/Users/alice@contoso.com/exec.lvdash.json")]),
                                 get_published=lambda _id: dashboards.PublishedDashboard(embed_credentials=True,
                                                                                         warehouse_id="wh1")),
        workspace=SimpleNamespace(export=lambda path, format=None: workspace.ExportResponse(content=nb_src),
                                  get_status=get_status),
        metastores=SimpleNamespace(current=lambda: catalog.MetastoreAssignment(metastore_id="m1", workspace_id=1)),
        grants=SimpleNamespace(get=lambda *a, **k: catalog.GetPermissionsResponse(privilege_assignments=[])),
        catalogs=SimpleNamespace(list=_list([catalog.CatalogInfo(name="sales", owner="alice@contoso.com")])),
        external_locations=SimpleNamespace(list=_list([])),
        storage_credentials=SimpleNamespace(list=_list([])),
        token_management=SimpleNamespace(list=_list([settings.TokenInfo(
            token_id="t1", owner_id=None, created_by_username="alice@contoso.com", comment="adf")])),
        permissions=SimpleNamespace(get=lambda t, i: iam.ObjectPermissions(access_control_list=acls.get((t, i), []))),
        secrets=SimpleNamespace(list_scopes=_list([workspace.SecretScope(name="prod")]),
                                list_acls=lambda scope: iter([workspace.AclItem(
            principal="admins", permission=workspace.AclPermission.MANAGE)])),
    )


def test_analyze_end_to_end(tmp_path, monkeypatch, capsys, output):
    monkeypatch.setattr(cli, "workspace_client", lambda cfg, host, profile: fake_workspace())
    assert cli.main(["--admin", "sp-admin", "--catalog", "c", "--schema", "s"]) == 0

    load = lambda t: output[t]  # noqa: E731
    deltas = load("deltas")
    found = {(d["kind"], d["object_type"], d["object_id"]) for d in deltas}
    assert ("RUN_AS_DEPENDENCY", "clusters", "c1") in found
    assert ("RUN_AS_DEPENDENCY", "secret-scopes", "prod") in found  # found by the notebook scan
    assert ("RUN_AS_DEPENDENCY", "warehouses", "wh1") in found  # run-as-owner query / embedded dashboard
    assert ("ENTITLEMENT", "entitlement", "databricks-sql-access") in found
    assert ("OWNERSHIP_RISK", "uc-catalog", "sales") in found
    assert not any(d["object_id"] == "77" for d in deltas)  # notebook readable via `users`
    token = next(d for d in deltas if d["kind"] == "TOKEN")
    assert token["breaks"] is False  # power_users already has token CAN_USE
    [summary] = load("readiness_summary")
    assert summary["status"] == "NOT_READY" and summary["admins_in_scope"] == 1
    assert {p["principal"] for p in load("principals") if p["in_scope"]} == {"user:alice@contoso.com"}
    assert output["artifacts"][0]["name"] == "suggested_permissions.yaml"
    assert output["_target"] == ("c", "s", "wh-auto") and output["_finished"] == "append"
    assert output["_dashboard"][0] == "/Users/alice@contoso.com"  # default: home of the running identity
    assert "NOT_READY" in capsys.readouterr().out
