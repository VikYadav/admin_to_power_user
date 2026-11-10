"""API guards for every call the tool makes.

Two clients are used, each wrapped before any request is sent:

* `make_read_only(w)`: the analysis client. Only GET/HEAD, plus single SELECT/WITH statements through the
  SQL Statement Execution API (system tables). Everything else is refused.
* `make_output_only(w, scope)`: the output client. On top of reads it may only
  - create the output schema, create/alter tables in it, insert rows (VALUES only) and delete old rows,
    all inside `catalog`.`schema`;
  - create the tool's dashboard in `scope.dashboard_folder` (and that folder), and update / publish
    dashboards whose id was registered in `scope.dashboard_ids`.

Nothing else in the workspace can be changed: no permissions, groups, jobs, clusters, tokens or settings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

READ_METHODS = {"GET", "HEAD"}
SQL_STATEMENT_PATH = "/api/2.0/sql/statements"
LAKEVIEW_PATH = "/api/2.0/lakeview/dashboards"
MKDIRS_PATH = "/api/2.0/workspace/mkdirs"
WRITE_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COPY|OPTIMIZE|VACUUM|REFRESH|"
    r"CACHE|UNCACHE|SET|RESET|USE|CALL|MSCK|REPAIR|ANALYZE|LOAD|REPLACE|RESTORE|COMMENT|DENY)\b",
    re.IGNORECASE,
)


class ReadOnlyViolation(RuntimeError):
    pass


@dataclass
class WriteScope:
    catalog: str
    schema: str
    dashboard_folder: str
    dashboard_ids: set[str] = field(default_factory=set)

    @property
    def prefix(self) -> str:
        return f"`{self.catalog}`.`{self.schema}`"


def _strip_literals(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"'(?:\\.|''|[^'\\])*'", "''", sql)  # string literals (audit action names like 'create')
    return sql.strip()


def _strip(sql: str) -> str:
    return re.sub(r"`[^`]*`", "``", _strip_literals(sql))


def _single(body: str) -> bool:
    return ";" not in body.rstrip().rstrip(";")


def is_read_only_sql(sql: str) -> bool:
    body = _strip(sql).rstrip(";").strip()
    if not _single(body):
        return False
    first = body.split(None, 1)[0].upper() if body else ""
    return first in ("SELECT", "WITH") and not WRITE_KEYWORDS.search(body)


def check_sql(sql: str) -> str:
    if not is_read_only_sql(sql):
        raise ReadOnlyViolation(f"Refusing non-read-only SQL: {sql.strip()[:200]}")
    return sql


_IDENT = r"`[A-Za-z0-9_]+`"
_LITERAL_WORDS = re.compile(r"\b(NULL|TRUE|FALSE|TIMESTAMP)\b", re.I)


def _values_only(text: str) -> bool:
    """VALUES (...), (...) made of literals only (strings were already blanked to '')."""
    return re.fullmatch(r"[\s(),0-9.+\-']*", _LITERAL_WORDS.sub(" ", text)) is not None


def is_output_sql(sql: str, scope: WriteScope) -> bool:
    """A write the output client may run: only inside scope.catalog.scope.schema, one statement."""
    body = _strip_literals(sql).rstrip(";").strip()
    if not _single(body):
        return False
    p = re.escape(scope.prefix)
    if re.fullmatch(rf"CREATE SCHEMA IF NOT EXISTS {p}", body, re.I):
        return True
    m = re.match(rf"(CREATE TABLE IF NOT EXISTS|ALTER TABLE) {p}\.{_IDENT}\s+(ADD COLUMNS\s*)?\((.*)\)$", body,
                 re.I | re.S)
    if m:  # column definitions only: `name` TYPE, ...
        if m.group(1).upper() == "ALTER TABLE" and not m.group(2):
            return False
        return all(re.fullmatch(rf"\s*{_IDENT}\s+(STRING|BIGINT|BOOLEAN|DOUBLE|TIMESTAMP)\s*", c, re.I)
                   for c in m.group(3).split(","))
    m = re.match(rf"INSERT INTO {p}\.{_IDENT}\s*\(([^)]*)\)\s*VALUES\s*(.*)$", body, re.I | re.S)
    if m:
        return all(re.fullmatch(rf"\s*{_IDENT}\s*", c) for c in m.group(1).split(",")) and \
            _values_only(m.group(2))
    m = re.match(rf"DELETE FROM {p}\.{_IDENT}\s+WHERE\s+(.*)$", body, re.I | re.S)
    if m:
        return not WRITE_KEYWORDS.search(m.group(1)) and "SELECT" not in m.group(1).upper()
    return False


def _norm_folder(path: str) -> str:
    path = (path or "").rstrip("/")
    return path[len("/Workspace"):] if path.startswith("/Workspace/") else path


def check_request(method: str, path: Optional[str], body: Optional[dict], scope: Optional[WriteScope] = None) -> None:
    m = (method or "").upper()
    path = (path or "").rstrip("/")
    if m in READ_METHODS:
        return
    if m == "POST" and path == SQL_STATEMENT_PATH:
        sql = (body or {}).get("statement") or ""
        if is_read_only_sql(sql) or (scope is not None and is_output_sql(sql, scope)):
            return
        raise ReadOnlyViolation(f"Refusing SQL outside the allowed scope: {sql.strip()[:200]}")
    if scope is not None:
        folder = _norm_folder(scope.dashboard_folder)
        if m == "POST" and path == MKDIRS_PATH and _norm_folder((body or {}).get("path", "")) == folder:
            return
        if m == "POST" and path == LAKEVIEW_PATH and _norm_folder((body or {}).get("parent_path", "")) == folder:
            return
        dm = re.fullmatch(re.escape(LAKEVIEW_PATH) + r"/([^/]+)(/published)?", path)
        if dm and dm.group(1) in scope.dashboard_ids and \
                ((m == "PATCH" and not dm.group(2)) or (m == "POST" and dm.group(2))):
            return
    what = "outside the output schema and dashboard" if scope is not None else "the analysis is read-only"
    raise ReadOnlyViolation(f"Refusing {m} {path}: {what}")


def _wrap(w, scope: Optional[WriteScope]):
    api = w.api_client
    if getattr(api, "_admin_to_power_user_guard", False):
        return w
    original = api.do

    def do(method, path=None, url=None, query=None, headers=None, body=None, *args, **kwargs):
        check_request(method, path or url, body, scope)
        return original(method, path, url, query, headers, body, *args, **kwargs)

    api.do = do
    api._admin_to_power_user_guard = True
    return w


def make_read_only(w):
    """Patch the client in place so it can only read. Returns the same client."""
    return _wrap(w, None)


def make_output_only(w, scope: WriteScope):
    """Patch a *separate* client so it can only write the output tables and the dashboard."""
    return _wrap(w, scope)
