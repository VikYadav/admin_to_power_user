from conftest import TODAY

from admin_to_power_user.consolidator import move_to_sp, process_changes, proposed_grants, readiness
from admin_to_power_user.model.graph import PrincipalGraph
from admin_to_power_user.model.resolver import WhatIf
from admin_to_power_user.recommender import recommend_all
from admin_to_power_user.simulator import Simulator

ALICE = "user:alice@contoso.com"
BOB = "user:bob@contoso.com"


def _run(snapshot, what_if=None):
    deltas = Simulator(snapshot, "group:power_users", what_if, today=TODAY).run()
    recs = recommend_all(deltas)
    return deltas, recs, {d.delta_id: d for d in deltas}


def _find(deltas, principal, kind, object_id):
    return [d for d in deltas if d.principal == principal and d.kind == kind and d.object_id == object_id]


def test_scope_includes_humans_and_other_sps_but_not_admin_sp(snapshot):
    assert set(snapshot.in_scope) == {ALICE, BOB, "sp:sp-etl"}
    assert "sp:sp-admin" not in snapshot.in_scope


def test_nested_group_membership_survives_admin_removal(snapshot):
    g = PrincipalGraph(snapshot.principals, snapshot.memberships)
    after = g.groups_of(BOB, exclude={"group:admins"}, extra={"group:power_users"})
    assert {"group:platform", "group:data-eng", "group:power_users", "group:users"} <= after
    assert "group:admins" not in after


def test_run_as_dependencies_are_blockers(snapshot):
    deltas, _, _ = _run(snapshot)
    for obj in ("prod", "c1", "9001", "p1"):
        [d] = _find(deltas, ALICE, "RUN_AS_DEPENDENCY", obj)
        assert d.severity == "BLOCKER" and d.breaks and d.artifact_id == "101"


def test_access_held_via_other_group_is_not_a_delta(snapshot):
    deltas, _, _ = _run(snapshot)
    assert not _find(deltas, BOB, "DIRECT_USE", "c1")  # data-eng grants CAN_RESTART
    [pool] = _find(deltas, BOB, "DIRECT_USE", "pool1")
    assert pool.severity == "MEDIUM"


def test_entitlements(snapshot):
    deltas, _, _ = _run(snapshot)
    # workspace-access comes from `users`, so no delta
    assert not _find(deltas, ALICE, "ENTITLEMENT", "workspace-access")
    [cc] = _find(deltas, BOB, "ENTITLEMENT", "allow-cluster-create")
    assert cc.severity == "HIGH"


def test_tokens_admin_actions_and_uc(snapshot):
    deltas, _, _ = _run(snapshot)
    [t1] = [d for d in deltas if d.artifact_id == "t1"]
    [t2] = [d for d in deltas if d.artifact_id == "t2"]
    assert t1.severity == "BLOCKER" and t1.breaks
    assert t2.severity == "LOW"
    [conf] = _find(deltas, ALICE, "ADMIN_ONLY_ACTION", "workspace:workspaceConfEdit")
    assert conf.severity == "BLOCKER"  # done by automation (terraform)
    [grp] = _find(deltas, BOB, "ADMIN_ONLY_ACTION", "accounts:addPrincipalToGroup")
    assert grp.severity == "HIGH"
    [uc] = _find(deltas, ALICE, "UC_PRIVILEGE", "CREATE_CATALOG")
    assert uc.severity == "HIGH"


def test_buckets_and_readiness(snapshot):
    deltas, recs, by_id = _run(snapshot)
    grants = proposed_grants(by_id, recs)
    moves = move_to_sp(by_id, recs)
    changes = process_changes(by_id, recs)
    summary = readiness("123", "h", snapshot.in_scope, snapshot.principals, deltas, grants, moves, changes)

    grant_keys = {(g.object_type, g.object_id): g for g in grants}
    assert grant_keys[("instance-pools", "pool1")].scope_creep  # CAN_MANAGE to a group of humans
    assert grant_keys[("uc-metastore", "CREATE_CATALOG")].level == "CREATE_CATALOG"
    assert grant_keys[("entitlement", "allow-cluster-create")].scope_creep

    job = next(m for m in moves if m.artifact_type == "job" and m.artifact_id == "101")
    assert "READ on secret-scopes 'prod'" in job.sp_needs and "CAN_RESTART on clusters 'shared-etl'" in job.sp_needs
    assert any(m.artifact_type == "automation" for m in moves)  # terraform workspaceConfEdit
    assert [c.service_action for c in changes] == ["accounts:addPrincipalToGroup"]
    assert summary.status == "NOT_READY" and summary.blockers >= 5 and summary.humans_in_scope == 2


def test_what_if_closes_deltas(snapshot):
    what_if = WhatIf(
        grants=(("cluster-policies", "p1", "CAN_USE"), ("instance-pools", "pool1", "CAN_MANAGE")),
        entitlements=frozenset({"allow-cluster-create"}),
        uc_privileges=frozenset({"CREATE_CATALOG"}),
        token_usage=True,
        moved_to_sp=frozenset({("job", "101")}),
    )
    after, _, _ = _run(snapshot, what_if)
    assert not [d for d in after if d.artifact_id == "101"]
    assert not _find(after, BOB, "DIRECT_USE", "pool1")
    assert not _find(after, ALICE, "UC_PRIVILEGE", "CREATE_CATALOG")
    assert all(not d.breaks for d in after if d.kind == "TOKEN")
    remaining = {d.kind for d in after if d.breaks and d.severity in ("BLOCKER", "HIGH")}
    assert remaining == {"ADMIN_ONLY_ACTION"}  # only process/automation changes left


def test_missing_objects_are_ignored(snapshot):
    snapshot.missing_objects[("clusters", "c1")] = "not found"
    deltas, _, _ = _run(snapshot)
    assert not _find(deltas, ALICE, "RUN_AS_DEPENDENCY", "c1")
