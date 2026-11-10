"""Best-effort static scan of notebooks run by in-scope admins' jobs.

Finds secret scopes and other notebooks referenced in code. Audit logs (`secrets:getSecret`) are the
more reliable signal; this catches dependencies of jobs that have not run in the lookback window.
"""

from __future__ import annotations

import base64
import posixpath
import re
from concurrent.futures import ThreadPoolExecutor

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.workspace import ExportFormat

from admin_to_power_user.collectors.jobs import PATH_PREFIX
from admin_to_power_user.config import Config
from admin_to_power_user.model.levels import RUN_AS_REQUIRED
from admin_to_power_user.models import Artifact, Dependency, Kind, Snapshot

SECRET_GET = re.compile(r"""dbutils\.secrets\.get(?:Bytes)?\(\s*(?:scope\s*=\s*)?["']([^"']+)["']""")
MAGIC_RUN = re.compile(r"""^\s*(?:#\s*MAGIC\s*)?%run\s+["']?([^\s"']+)""", re.MULTILINE)
NOTEBOOK_RUN = re.compile(r"""dbutils\.notebook\.run\(\s*["']([^"']+)["']""")


def references(source: str, notebook_path: str) -> tuple[set[str], set[str]]:
    """(secret scopes, absolute notebook paths) referenced by a notebook's source."""
    scopes = set(SECRET_GET.findall(source))
    base = posixpath.dirname(notebook_path)
    paths = set()
    for p in MAGIC_RUN.findall(source) + NOTEBOOK_RUN.findall(source):
        paths.add(posixpath.normpath(p if p.startswith("/") else posixpath.join(base, p)))
    return scopes, paths


def scan_notebooks(w: WorkspaceClient, snapshot: Snapshot, cfg: Config,
                   targets: list[tuple[str, str, Artifact]]) -> None:
    unique = list(dict.fromkeys(targets))
    if len(unique) > cfg.max_notebooks:
        snapshot.warnings.append(f"Notebook scan capped at {cfg.max_notebooks} of {len(unique)} notebooks.")
        unique = unique[: cfg.max_notebooks]

    def export(path: str):
        try:
            content = w.workspace.export(path, format=ExportFormat.SOURCE).content or ""
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return None

    paths = sorted({p for _, p, _ in unique})
    with ThreadPoolExecutor(cfg.max_workers) as pool:
        sources = dict(zip(paths, pool.map(export, paths)))

    for principal, path, artifact in unique:
        src = sources.get(path)
        if not src:
            continue
        scopes, notebooks = references(src, path)
        via = f"code in {path}"
        for scope in scopes:
            snapshot.dependencies.append(Dependency(principal, Kind.RUN_AS_DEPENDENCY, "secret-scopes", scope, scope,
                                                    RUN_AS_REQUIRED["secret-scopes"], via, artifact))
        for nb in notebooks:
            snapshot.dependencies.append(Dependency(principal, Kind.RUN_AS_DEPENDENCY, "notebooks",
                                                    PATH_PREFIX + nb, nb, RUN_AS_REQUIRED["notebooks"], via,
                                                    artifact))
