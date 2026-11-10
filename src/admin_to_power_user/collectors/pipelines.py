"""Lakeflow Declarative Pipelines running as an in-scope admin, and their dependencies."""

from __future__ import annotations

from databricks.sdk import WorkspaceClient
from databricks.sdk.service import pipelines

from admin_to_power_user.collectors.identities import NameResolver
from admin_to_power_user.collectors.jobs import PATH_PREFIX, cluster_spec_dependencies, secret_scopes_in
from admin_to_power_user.config import Config
from admin_to_power_user.model.levels import RUN_AS_REQUIRED
from admin_to_power_user.models import Artifact, Dependency, EntitlementNeed, Kind, Snapshot


def pipeline_dependencies(pipeline_id: str, spec: pipelines.PipelineSpec, principal: str,
                          ) -> tuple[list[Dependency], list[EntitlementNeed]]:
    artifact = Artifact("pipeline", pipeline_id, spec.name or pipeline_id)
    deps: list[Dependency] = []
    needs: list[EntitlementNeed] = []
    if not spec.serverless:
        for c in spec.clusters or []:
            d, n = cluster_spec_dependencies(c, principal, f"pipeline cluster '{c.label or 'default'}'", artifact)
            deps += d
            needs += n
    for scope in secret_scopes_in((spec.configuration or {}).values()):
        deps.append(Dependency(principal, Kind.RUN_AS_DEPENDENCY, "secret-scopes", scope, scope,
                               RUN_AS_REQUIRED["secret-scopes"], "pipeline configuration secret ref", artifact))
    for lib in spec.libraries or []:
        for obj_type, ref in (("notebooks", lib.notebook), ("files", lib.file)):
            if ref and ref.path and ref.path.startswith("/"):
                deps.append(Dependency(principal, Kind.RUN_AS_DEPENDENCY, obj_type, PATH_PREFIX + ref.path,
                                       ref.path, RUN_AS_REQUIRED[obj_type], "pipeline library", artifact))
    return deps, needs


def collect_pipelines(w: WorkspaceClient, snapshot: Snapshot, cfg: Config, names: NameResolver) -> None:
    for p in w.pipelines.list_pipelines():
        snapshot.object_names[("pipelines", p.pipeline_id)] = p.name or p.pipeline_id
        run_as = names.key(p.run_as_user_name) if p.run_as_user_name else None
        creator = names.key(p.creator_user_name) if p.creator_user_name else None
        artifact = Artifact("pipeline", p.pipeline_id, p.name or p.pipeline_id)
        if creator in snapshot.in_scope and run_as not in snapshot.in_scope:
            snapshot.ownership.append(Dependency(creator, Kind.OWNERSHIP_RISK, "pipelines", p.pipeline_id,
                                                 p.name or p.pipeline_id, "IS_OWNER",
                                                 "created by an in-scope admin", artifact))
        if run_as not in snapshot.in_scope:
            continue
        spec = w.pipelines.get(p.pipeline_id).spec
        if spec:
            deps, needs = pipeline_dependencies(p.pipeline_id, spec, run_as)
            snapshot.dependencies += deps
            snapshot.entitlement_needs += needs
