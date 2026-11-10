"""Jobs whose run_as (or creator) is an in-scope admin, and everything they depend on."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

from databricks.sdk import WorkspaceClient
from databricks.sdk.service import jobs

from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.config import Config
from admin_to_power_user.model.levels import RUN_AS_REQUIRED
from admin_to_power_user.models import Artifact, Dependency, EntitlementNeed, Kind, Snapshot

SECRET_REF = re.compile(r"\{\{\s*secrets/([^/}\s]+)/([^}\s]+)\s*\}\}")
PATH_PREFIX = "path:"  # object ids that are workspace paths, resolved to (type, id) by the ACL collector


def secret_scopes_in(values: Iterable[Optional[str]]) -> set[str]:
    scopes = set()
    for v in values:
        if v:
            scopes.update(m.group(1) for m in SECRET_REF.finditer(str(v)))
    return scopes


def _dep(principal: str, object_type: str, object_id: str, name: str, via: str, artifact: Artifact) -> Dependency:
    return Dependency(principal, Kind.RUN_AS_DEPENDENCY, object_type, object_id, name,
                      RUN_AS_REQUIRED[object_type], via, artifact)


def cluster_spec_dependencies(spec, principal: str, via: str, artifact: Artifact,
                              ) -> tuple[list[Dependency], list[EntitlementNeed]]:
    """Dependencies of a new job/pipeline cluster spec (jobs.ClusterSpec or pipelines.PipelineCluster)."""
    deps: list[Dependency] = []
    needs: list[EntitlementNeed] = []
    if getattr(spec, "policy_id", None):
        deps.append(_dep(principal, "cluster-policies", spec.policy_id, spec.policy_id, via, artifact))
    else:
        needs.append(EntitlementNeed(principal, "allow-cluster-create", f"{via}: cluster without a policy", artifact))
    for pool in {getattr(spec, "instance_pool_id", None), getattr(spec, "driver_instance_pool_id", None)} - {None}:
        deps.append(_dep(principal, "instance-pools", pool, pool, via, artifact))
    conf_values = list((spec.spark_conf or {}).values()) + list((spec.spark_env_vars or {}).values())
    for scope in secret_scopes_in(conf_values):
        deps.append(_dep(principal, "secret-scopes", scope, scope, f"{via}: spark_conf/env secret ref", artifact))
    for init in getattr(spec, "init_scripts", None) or []:
        ws = getattr(init, "workspace", None)
        if ws and ws.destination:
            deps.append(_dep(principal, "files", PATH_PREFIX + ws.destination, ws.destination,
                             f"{via}: init script", artifact))
    return deps, needs


def _iter_tasks(tasks: Iterable[jobs.Task]) -> Iterable[jobs.Task]:
    for t in tasks or []:
        yield t
        if t.for_each_task and t.for_each_task.task:
            yield from _iter_tasks([t.for_each_task.task])


def _is_workspace_source(source, has_git: bool) -> bool:
    if source is None:
        return not has_git
    return getattr(source, "value", source) == "WORKSPACE"


def job_dependencies(job: jobs.Job, principal: str) -> tuple[list[Dependency], list[EntitlementNeed], list[str]]:
    """Returns (dependencies, entitlement needs, workspace notebook paths) for one job."""
    s = job.settings or jobs.JobSettings()
    artifact = Artifact("job", str(job.job_id), s.name or str(job.job_id))
    has_git = s.git_source is not None
    deps: list[Dependency] = []
    needs: list[EntitlementNeed] = []
    notebooks: list[str] = []

    for jc in s.job_clusters or []:
        if jc.new_cluster:
            d, n = cluster_spec_dependencies(jc.new_cluster, principal, f"job cluster '{jc.job_cluster_key}'", artifact)
            deps += d
            needs += n

    for t in _iter_tasks(s.tasks):
        via = f"task '{t.task_key}'"
        if t.existing_cluster_id:
            deps.append(_dep(principal, "clusters", t.existing_cluster_id, t.existing_cluster_id, via, artifact))
        if t.new_cluster:
            d, n = cluster_spec_dependencies(t.new_cluster, principal, via, artifact)
            deps += d
            needs += n
        nb = t.notebook_task
        if nb:
            if nb.notebook_path and _is_workspace_source(nb.source, has_git):
                deps.append(_dep(principal, "notebooks", PATH_PREFIX + nb.notebook_path, nb.notebook_path, via, artifact))
                notebooks.append(nb.notebook_path)
            if nb.warehouse_id:
                deps.append(_dep(principal, "warehouses", nb.warehouse_id, nb.warehouse_id, via, artifact))
        py = t.spark_python_task
        if py and py.python_file and py.python_file.startswith("/") and _is_workspace_source(py.source, has_git):
            deps.append(_dep(principal, "files", PATH_PREFIX + py.python_file, py.python_file, via, artifact))
        sql = t.sql_task
        if sql:
            if sql.warehouse_id:
                deps.append(_dep(principal, "warehouses", sql.warehouse_id, sql.warehouse_id, via, artifact))
            if sql.query and sql.query.query_id:
                deps.append(_dep(principal, "queries", sql.query.query_id, sql.query.query_id, via, artifact))
            if sql.alert and sql.alert.alert_id:
                deps.append(_dep(principal, "alerts", sql.alert.alert_id, sql.alert.alert_id, via, artifact))
            if sql.file and sql.file.path and sql.file.path.startswith("/") and \
                    _is_workspace_source(sql.file.source, has_git):
                deps.append(_dep(principal, "files", PATH_PREFIX + sql.file.path, sql.file.path, via, artifact))
        if t.pipeline_task and t.pipeline_task.pipeline_id:
            pid = t.pipeline_task.pipeline_id
            deps.append(_dep(principal, "pipelines", pid, pid, via, artifact))
        if t.run_job_task and t.run_job_task.job_id:
            jid = str(t.run_job_task.job_id)
            deps.append(_dep(principal, "jobs", jid, jid, via, artifact))
        if t.dashboard_task and t.dashboard_task.warehouse_id:
            deps.append(_dep(principal, "warehouses", t.dashboard_task.warehouse_id,
                             t.dashboard_task.warehouse_id, via, artifact))
    return deps, needs, notebooks


def is_scheduled(job: jobs.Job) -> bool:
    s = job.settings
    if not s:
        return False
    for trig in (s.schedule, s.trigger, s.continuous):
        if trig is not None and getattr(getattr(trig, "pause_status", None), "value", None) != "PAUSED":
            return True
    return False


def run_as_of(job: jobs.Job, names: NameResolver) -> Optional[str]:
    s = job.settings
    if s and s.run_as:
        if s.run_as.service_principal_name:
            return names.key(s.run_as.service_principal_name)
        if s.run_as.user_name:
            return names.key(s.run_as.user_name)
    if job.run_as_user_name:
        return names.key(job.run_as_user_name)
    return None


def collect_jobs(w: WorkspaceClient, snapshot: Snapshot, cfg: Config, names: NameResolver) -> list[tuple[str, str, Artifact]]:
    """Adds job dependencies to the snapshot. Returns (principal, notebook path, artifact) for notebook scanning."""
    listed = list(w.jobs.list(expand_tasks=True))

    failed: list[str] = []

    def full(j: jobs.BaseJob) -> jobs.Job:
        listed_job = jobs.Job(job_id=j.job_id, creator_user_name=j.creator_user_name, settings=j.settings)
        if j.settings and j.settings.run_as and not j.has_more:
            return listed_job
        try:
            return w.jobs.get(j.job_id)
        except Exception as e:  # one unreadable job must not abort the run; use what the list returned
            failed.append(f"{j.job_id} ({type(e).__name__})")
            return listed_job

    with ThreadPoolExecutor(cfg.max_workers) as pool:
        all_jobs = list(pool.map(full, listed))
    if failed:
        snapshot.warnings.append(f"Could not read full settings of {len(failed)} job(s); analyzed them from the job "
                                 f"list only: {', '.join(failed[:10])}{' ...' if len(failed) > 10 else ''}")

    to_scan: list[tuple[str, str, Artifact]] = []
    for job in all_jobs:
        run_as = run_as_of(job, names)
        creator = names.key(job.creator_user_name) if job.creator_user_name else None
        name = (job.settings.name if job.settings else None) or str(job.job_id)
        artifact = Artifact("job", str(job.job_id), name)
        snapshot.object_names[("jobs", str(job.job_id))] = name
        if is_scheduled(job):
            snapshot.scheduled_jobs.add(str(job.job_id))
        if creator in snapshot.in_scope and run_as not in snapshot.in_scope:
            snapshot.ownership.append(Dependency(creator, Kind.OWNERSHIP_RISK, "jobs", str(job.job_id), name,
                                                 "IS_OWNER", "created by an in-scope admin", artifact))
        if run_as in snapshot.in_scope:
            deps, needs, notebooks = job_dependencies(job, run_as)
            snapshot.dependencies += deps
            snapshot.entitlement_needs += needs
            to_scan += [(run_as, p, artifact) for p in notebooks]
    return to_scan
