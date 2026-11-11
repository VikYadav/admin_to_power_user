from conftest import TODAY

from admin_to_power_user.consolidator import action_plan, move_to_sp, process_changes, proposed_grants, readiness
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


def test_action_plan_covers_every_open_break_once(snapshot):
    deltas, recs, by_id = _run(snapshot)
    plan = action_plan(by_id, recs)

    open_breaks = sorted(d.delta_id for d in deltas if d.breaks and not d.covered_by)
    in_plan = sorted(i for a in plan for i in a.delta_ids.split(", "))
    assert in_plan == open_breaks  # do every step and every break is fixed; no break is listed twice
    assert len(plan) < len(open_breaks)  # breaks that one action fixes are merged
    assert [a.step for a in plan] == list(range(1, len(plan) + 1))
    assert sum(a.breaks_resolved for a in plan) == len(open_breaks)

    job = next(a for a in plan if a.bucket == "MOVE_TO_SP" and "READ on secret-scopes 'prod'" in a.action)
    assert job.breaks_resolved >= 4 and job.max_severity == "BLOCKER" and "alice@contoso.com" in job.who_acts
    assert not job.scope_creep  # the job's own SP reading the secret is the fix, not scope creep
    grant = next(a for a in plan if a.action == "GRANT CREATE CATALOG ON METASTORE TO `power_users`")
    assert grant.who_acts == "Metastore admin"
    process = next(a for a in plan if a.bucket == "PROCESS_CHANGE")
    assert process.who_acts == "Platform / identity team" and process.people == "bob@contoso.com"
    assert process.action.endswith("(replaces accounts:addPrincipalToGroup)")
    scripts = next(a for a in plan if a.action.startswith("Switch the scripts"))
    assert scripts.people == "alice@contoso.com" and "workspace:workspaceConfEdit" in scripts.action
    order = [(a.max_severity != "BLOCKER", a.max_severity not in ("BLOCKER", "HIGH")) for a in plan]
    assert order == sorted(order)  # worst first


def test_action_plan_skips_covered_and_puts_no_admin_left_first(snapshot):
    deltas, recs, by_id = _run(snapshot)
    first = next(d for d in deltas if d.breaks)
    first.covered_by = "your set"
    assert first.delta_id not in {i for a in action_plan(by_id, recs) for i in a.delta_ids.split(", ")}

    snapshot.retained_admins = {"sp:nobody": "given"}  # retained admin not in admins -> NO_ADMIN_LEFT
    deltas, recs, by_id = _run(snapshot)
    plan = action_plan(by_id, recs)
    assert plan[0].who_acts == "Account admin, before cutover" and plan[0].bucket == "PROCESS_CHANGE"


def test_action_plan_groups_scripts_per_person_and_processes_per_route(snapshot):
    """Real-world shape: several admins script admin APIs; add and delete share one route (SCIM)."""
    alice, bob = "user:alice@contoso.com", "user:bob@contoso.com"
    row = lambda who, action, client: {"principal_key": who, "service_name": "accounts", "action_name": action,  # noqa: E731
                                       "client_type": client, "n": 2, "last_seen": "2026-11-01",
                                       "user_agent_sample": "terraform/1.9" if client == "automation" else "Mozilla"}
    snapshot.admin_only_actions = [row(alice, "add", "automation"), row(alice, "delete", "automation"),
                                   row(bob, "add", "automation"),
                                   row("sp:sp-etl", "add", "interactive"), row(bob, "delete", "interactive")]
    deltas, recs, by_id = _run(snapshot)
    plan = action_plan(by_id, recs)
    scripts = {a.people: a for a in plan if a.action.startswith("Switch the scripts")}
    assert set(scripts) == {"alice@contoso.com", "bob@contoso.com"}
    assert scripts["alice@contoso.com"].breaks_resolved == 2 and "accounts:add, accounts:delete" in \
        scripts["alice@contoso.com"].action
    [scim] = [a for a in plan if a.bucket == "PROCESS_CHANGE" and "SCIM" in a.action]
    assert scim.breaks_resolved == 2 and scim.action.endswith("(replaces accounts:add, accounts:delete)")
    assert scim.people == "bob@contoso.com, sp-etl"


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
