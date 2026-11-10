from databricks.sdk.service import jobs, pipelines

from admin_to_power_user.collectors.jobs import PATH_PREFIX, is_scheduled, job_dependencies
from admin_to_power_user.collectors.notebooks import references
from admin_to_power_user.collectors.pipelines import pipeline_dependencies
from admin_to_power_user.models import Snapshot
from admin_to_power_user.usage import Usage, in_list, lit

from admin_to_power_user.collectors.identities import NameResolver

P = "user:alice@contoso.com"

JOB = jobs.Job.from_dict({
    "job_id": 101,
    "creator_user_name": "alice@contoso.com",
    "settings": {
        "name": "nightly_load",
        "schedule": {"quartz_cron_expression": "0 0 2 * * ?", "timezone_id": "UTC", "pause_status": "UNPAUSED"},
        "job_clusters": [{"job_cluster_key": "jc", "new_cluster": {
            "spark_version": "15.4.x-scala2.12", "num_workers": 2, "instance_pool_id": "pool1",
            "spark_conf": {"fs.azure.account.key": "{{secrets/prod/storage-key}}"}}}],
        "tasks": [
            {"task_key": "a", "existing_cluster_id": "c1",
             "notebook_task": {"notebook_path": "/Users/carol@contoso.com/etl", "source": "WORKSPACE"}},
            {"task_key": "b", "job_cluster_key": "jc", "new_cluster": {"spark_version": "x", "policy_id": "p1"},
             "spark_python_task": {"python_file": "/Workspace/Shared/run.py"}},
            {"task_key": "c", "sql_task": {"warehouse_id": "wh1", "query": {"query_id": "q1"}}},
            {"task_key": "d", "pipeline_task": {"pipeline_id": "pl1"}},
            {"task_key": "e", "for_each_task": {"inputs": "[1]", "task": {
                "task_key": "e_inner", "run_job_task": {"job_id": 202}}}},
            {"task_key": "f", "notebook_task": {"notebook_path": "etl/git_nb", "source": "GIT"}},
        ],
    },
})


def test_job_dependencies():
    deps, needs, notebooks = job_dependencies(JOB, P)
    got = {(d.object_type, d.object_id, d.required_level) for d in deps}
    assert ("clusters", "c1", "CAN_RESTART") in got
    assert ("instance-pools", "pool1", "CAN_ATTACH_TO") in got
    assert ("secret-scopes", "prod", "READ") in got
    assert ("cluster-policies", "p1", "CAN_USE") in got
    assert ("notebooks", PATH_PREFIX + "/Users/carol@contoso.com/etl", "CAN_READ") in got
    assert ("files", PATH_PREFIX + "/Workspace/Shared/run.py", "CAN_READ") in got
    assert ("warehouses", "wh1", "CAN_USE") in got and ("queries", "q1", "CAN_RUN") in got
    assert ("pipelines", "pl1", "CAN_RUN") in got
    assert ("jobs", "202", "CAN_MANAGE_RUN") in got  # nested in for_each
    assert not any("git_nb" in d.object_id for d in deps)  # Git-sourced notebooks are not workspace objects
    assert [n.entitlement for n in needs] == ["allow-cluster-create"]  # job cluster `jc` has no policy
    assert notebooks == ["/Users/carol@contoso.com/etl"]
    assert all(d.artifact.id == "101" for d in deps)
    assert is_scheduled(JOB)


def test_pipeline_dependencies():
    spec = pipelines.PipelineSpec.from_dict({
        "name": "bronze", "serverless": False,
        "clusters": [{"label": "default", "policy_id": "p2"}],
        "configuration": {"key": "{{secrets/kv-prod/sas}}"},
        "libraries": [{"notebook": {"path": "/Repos/x/dlt"}}, {"file": {"path": "relative.py"}}],
    })
    deps, needs = pipeline_dependencies("pl1", spec, P)
    got = {(d.object_type, d.object_id) for d in deps}
    assert got == {("cluster-policies", "p2"), ("secret-scopes", "kv-prod"), ("notebooks", PATH_PREFIX + "/Repos/x/dlt")}
    assert not needs


def test_notebook_references():
    src = '''# Databricks notebook source
# MAGIC %run ../common/setup
key = dbutils.secrets.get(scope="kv-prod", key="sas")
other = dbutils.secrets.get("legacy", "pwd")
dbutils.notebook.run("/Shared/child", 60)
'''
    scopes, paths = references(src, "/Users/alice@contoso.com/etl/main")
    assert scopes == {"kv-prod", "legacy"}
    assert paths == {"/Users/alice@contoso.com/common/setup", "/Shared/child"}


class FakeRunner:
    def __init__(self, rows_by_marker):
        self.rows_by_marker = rows_by_marker
        self.queries = []

    def query(self, sql):
        self.queries.append(sql)
        for marker, rows in self.rows_by_marker.items():
            if marker in sql:
                return rows
        return []


def test_usage_maps_audit_rows(snapshot):
    names = NameResolver(snapshot)
    runner = FakeRunner({
        "CASE WHEN service_name": [
            {"principal": "bob@contoso.com", "service_name": "secrets", "action_name": "getSecret",
             "object_id": "prod", "n": "40", "last_seen": "2026-11-04"}],
        "job_run_timeline": [{"job_id": "101", "runs": "30", "last_run": "2026-11-05"}],
        "'unityCatalog'": [{"principal": "sp-etl", "action_name": "createCatalog", "n": 1, "last_seen": "x"}],
    })
    s = Snapshot("123", "h", principals=snapshot.principals, memberships=snapshot.memberships,
                 in_scope=snapshot.in_scope)
    Usage(runner, s, names, 90).collect(["accounts:add", "globalInitScripts:*"])
    [dep] = s.dependencies
    assert (dep.principal_key, dep.object_type, dep.object_id, dep.required_level, dep.usage_count) == \
        ("user:bob@contoso.com", "secret-scopes", "prod", "READ", 40)
    assert s.job_runs["101"]["runs"] == 30
    assert s.uc_actions[0]["principal_key"] == "sp:sp-etl"
    admin_sql = next(q for q in runner.queries if "concat(service_name, ':', action_name) IN" in q)
    assert "'accounts:add'" in admin_sql and "service_name IN ('globalInitScripts')" in admin_sql
    assert all("workspace_id = '123'" in q for q in runner.queries)
    assert not s.warnings


def test_sql_literals_are_escaped():
    assert lit("o'brien") == "'o\\'brien'"
    assert in_list([]) == "(NULL)"
