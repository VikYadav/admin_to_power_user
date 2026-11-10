"""A small synthetic workspace mirroring the verification scenario in the plan.

alice  - human admin (direct member of admins); job 101 runs as her
bob    - human admin via nested group `platform`; `platform` is also in `data-eng`
sp-admin - designated admin SP (out of scope)
sp-etl - another SP in admins (in scope)
"""

from datetime import date

import pytest
from databricks.sdk.service import iam

from admin_to_power_user.collectors.identities import build_identities
from admin_to_power_user.config import Config, RetainedAdmin
from admin_to_power_user.models import (
    AclEntry,
    Artifact,
    Dependency,
    EntitlementNeed,
    Kind,
    Snapshot,
)

TODAY = date(2026, 11, 6)


def _cv(value, ref=None, display=None):
    return iam.ComplexValue(value=value, ref=ref, display=display)


@pytest.fixture
def cfg() -> Config:
    c = Config()
    c.power_users_group = "power_users"
    c.retained_admins = [RetainedAdmin("service_principal", "sp-admin")]
    return c


@pytest.fixture
def snapshot(cfg) -> Snapshot:
    s = Snapshot("123", "https://adb-123.0.azuredatabricks.net")
    users = [
        iam.User(id="u1", user_name="alice@contoso.com", display_name="Alice", active=True),
        iam.User(id="u2", user_name="bob@contoso.com", display_name="Bob", active=True),
        iam.User(id="u3", user_name="carol@contoso.com", display_name="Carol", active=True),
    ]
    sps = [
        iam.ServicePrincipal(id="s1", application_id="sp-admin", display_name="admin sp", active=True),
        iam.ServicePrincipal(id="s2", application_id="sp-etl", display_name="etl sp", active=True),
    ]
    groups = [
        iam.Group(id="g1", display_name="admins",
                  members=[_cv("u1", "Users/u1"), _cv("g3", "Groups/g3"), _cv("s1", "ServicePrincipals/s1"),
                           _cv("s2", "ServicePrincipals/s2")],
                  entitlements=[_cv("workspace-access"), _cv("databricks-sql-access"),
                                _cv("allow-cluster-create"), _cv("allow-instance-pool-create")],
                  meta=iam.ResourceMeta(resource_type="WorkspaceGroup")),
        iam.Group(id="g2", display_name="users", members=[_cv("u1"), _cv("u2"), _cv("u3")],
                  entitlements=[_cv("workspace-access"), _cv("databricks-sql-access")],
                  meta=iam.ResourceMeta(resource_type="WorkspaceGroup")),
        iam.Group(id="g3", display_name="platform", members=[_cv("u2", "Users/u2")],
                  meta=iam.ResourceMeta(resource_type="Group")),
        iam.Group(id="g4", display_name="data-eng", members=[_cv("g3", "Groups/g3")],
                  meta=iam.ResourceMeta(resource_type="Group")),
        iam.Group(id="g5", display_name="power_users", members=[],
                  meta=iam.ResourceMeta(resource_type="Group")),
    ]
    build_identities(users, sps, groups, s, cfg)

    job = Artifact("job", "101", "nightly_load")
    alice = "user:alice@contoso.com"
    s.dependencies = [
        Dependency(alice, Kind.RUN_AS_DEPENDENCY, "secret-scopes", "prod", "prod", "READ", "spark_conf", job),
        Dependency(alice, Kind.RUN_AS_DEPENDENCY, "clusters", "c1", "shared-etl", "CAN_RESTART", "task 'a'", job),
        Dependency(alice, Kind.RUN_AS_DEPENDENCY, "notebooks", "9001", "/Users/carol@contoso.com/util",
                   "CAN_READ", "%run", job),
        Dependency(alice, Kind.RUN_AS_DEPENDENCY, "cluster-policies", "p1", "etl-policy", "CAN_USE", "task 'a'", job),
        # bob restarted c1 interactively; data-eng (via platform) already grants CAN_RESTART -> no delta
        Dependency("user:bob@contoso.com", Kind.DIRECT_USE, "clusters", "c1", "shared-etl", "CAN_RESTART",
                   "audit clusters:restart", None, 12, "2026-11-01"),
        # bob edited pool1 -> needs CAN_MANAGE he only has as admin
        Dependency("user:bob@contoso.com", Kind.DIRECT_USE, "instance-pools", "pool1", "etl-pool", "CAN_MANAGE",
                   "audit instancePools:edit", None, 3, "2026-10-20"),
    ]
    s.entitlement_needs = [
        EntitlementNeed("user:bob@contoso.com", "allow-cluster-create", "created clusters without a policy 4x",
                        None, 4, "2026-10-30"),
    ]
    s.acls = {
        ("secret-scopes", "prod"): [AclEntry("group:admins", "MANAGE")],
        ("clusters", "c1"): [AclEntry("group:admins", "CAN_MANAGE", True), AclEntry("group:data-eng", "CAN_RESTART")],
        ("notebooks", "9001"): [AclEntry("user:carol@contoso.com", "CAN_MANAGE"),
                                AclEntry("group:admins", "CAN_MANAGE", True)],
        ("cluster-policies", "p1"): [AclEntry("group:admins", "CAN_USE")],
        ("instance-pools", "pool1"): [AclEntry("group:admins", "CAN_MANAGE")],
        ("authorization", "tokens"): [AclEntry("group:admins", "CAN_MANAGE"), AclEntry("group:automation", "CAN_USE")],
    }
    s.tokens = [
        {"token_id": "t1", "owner_key": alice, "comment": "adf-linked-service", "expiry": "never",
         "last_used": "2026-11-05"},
        {"token_id": "t2", "owner_key": "user:bob@contoso.com", "comment": "old laptop", "expiry": "never",
         "last_used": "2025-01-01"},
    ]
    s.admin_only_actions = [
        {"principal_key": "user:bob@contoso.com", "service_name": "accounts", "action_name": "addPrincipalToGroup",
         "client_type": "interactive", "n": 7, "last_seen": "2026-11-02", "user_agent_sample": "Mozilla/5.0"},
        {"principal_key": alice, "service_name": "workspace", "action_name": "workspaceConfEdit",
         "client_type": "automation", "n": 2, "last_seen": "2026-10-15", "user_agent_sample": "terraform/1.9"},
    ]
    s.uc_actions = [
        {"principal_key": alice, "action_name": "createCatalog", "privilege": "CREATE_CATALOG", "n": 3,
         "last_seen": "2026-10-01"},
    ]
    s.job_runs = {"101": {"runs": 30, "last_run": "2026-11-05"}}
    return s


class CapturingSink:
    """Stands in for UcSink in CLI tests: keeps the rows instead of writing them."""

    def __init__(self, store, meta, mode):
        self.store, self.meta, self.mode = store, meta, mode

    def write(self, table, items, row_type):
        import dataclasses

        self.store[table] = [{**self.meta, **dataclasses.asdict(i)} for i in items]

    def finish(self):
        self.store["_finished"] = self.mode


@pytest.fixture(autouse=True)
def output(monkeypatch):
    """CLI runs never touch a real workspace in tests: capture tables and the dashboard deploy."""
    from admin_to_power_user import main as cli

    store: dict = {}
    monkeypatch.setattr(cli, "output_client", lambda w, scope: ("output-client", scope))
    monkeypatch.setattr(cli, "resolve_warehouse", lambda w, wid: wid or "wh-auto")
    monkeypatch.setattr(cli, "UcSink", lambda ww, wh, cat, sch, meta, mode: (
        store.update(_target=(cat, sch, wh)) or CapturingSink(store, meta, mode)))
    monkeypatch.setattr(cli, "deploy", lambda ww, scope, wh, name: (
        store.update(_dashboard=(scope.dashboard_folder, name)) or ("d1", "https://x/dashboardsv3/d1/published")))
    return store
