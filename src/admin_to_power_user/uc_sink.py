"""Write result tables to `<catalog>.<schema>` through a SQL warehouse (Statement Execution API).

Every row carries `run_id`, `run_ts` and `workspace_id`.
mode=append     keeps every run; the dashboard shows the latest run per workspace.
mode=overwrite  replaces this workspace's earlier rows; other workspaces' rows in the same tables are kept.
Old rows are deleted only after every table has been written, so a failed run never loses earlier results.
"""

from __future__ import annotations

import dataclasses
import time
import typing
from typing import Any

from databricks.sdk.errors import NotFound, ResourceDoesNotExist

META_COLUMNS = {"run_id": "STRING", "run_ts": "TIMESTAMP", "workspace_id": "STRING"}
SQL_TYPES = {str: "STRING", int: "BIGINT", bool: "BOOLEAN", float: "DOUBLE"}
MAX_STATEMENT_BYTES = 1_000_000


def sql_literal(value: Any, sql_type: str) -> str:
    if value is None:
        return "NULL"
    if sql_type == "BOOLEAN":
        return "TRUE" if value else "FALSE"
    if sql_type in ("BIGINT", "DOUBLE"):
        return str(int(value) if sql_type == "BIGINT" else float(value))
    text = "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"
    return f"TIMESTAMP {text}" if sql_type == "TIMESTAMP" else text


def columns_of(row_type: type) -> dict[str, str]:
    cols = dict(META_COLUMNS)
    for name, hint in typing.get_type_hints(row_type).items():
        if name in cols:
            continue
        args = [a for a in typing.get_args(hint) if a is not type(None)]
        cols[name] = SQL_TYPES.get(args[0] if args else hint, "STRING")
    return cols


class UcSink:
    def __init__(self, w, warehouse_id: str, catalog: str, schema: str, meta: dict, mode: str = "append"):
        if mode not in ("append", "overwrite"):
            raise ValueError("mode must be append or overwrite")
        self.w = w
        self.warehouse_id = warehouse_id
        self.full = f"{catalog}.{schema}"
        self.prefix = f"`{catalog}`.`{schema}`"
        self.meta = meta
        self.mode = mode
        self.written: list[str] = []
        self._ensure_schema()

    # ---- SQL ----------------------------------------------------------------------------------

    def execute(self, sql: str) -> None:
        from databricks.sdk.service.sql import StatementState

        se = self.w.statement_execution
        resp = se.execute_statement(statement=sql, warehouse_id=self.warehouse_id, wait_timeout="50s")
        while resp.status and resp.status.state in (StatementState.PENDING, StatementState.RUNNING):
            time.sleep(2)
            resp = se.get_statement(resp.statement_id)
        if not resp.status or resp.status.state != StatementState.SUCCEEDED:
            err = resp.status.error if resp.status else None
            raise RuntimeError(f"Statement failed: {getattr(err, 'message', err)}\n{sql[:300]}")

    def _ensure_schema(self) -> None:
        try:
            self.w.schemas.get(self.full)
        except (NotFound, ResourceDoesNotExist):
            self.execute(f"CREATE SCHEMA IF NOT EXISTS {self.prefix}")

    def _ensure_table(self, table: str, cols: dict[str, str]) -> None:
        name = f"{self.prefix}.`{table}`"
        try:
            info = self.w.tables.get(f"{self.full}.{table}")
        except (NotFound, ResourceDoesNotExist):
            defs = ", ".join(f"`{c}` {t}" for c, t in cols.items())
            self.execute(f"CREATE TABLE IF NOT EXISTS {name} ({defs})")
            return
        have = {c.name for c in info.columns or []}
        missing = [(c, t) for c, t in cols.items() if c not in have]
        if missing:  # results gained a column since the table was created
            self.execute(f"ALTER TABLE {name} ADD COLUMNS ({', '.join(f'`{c}` {t}' for c, t in missing)})")

    # ---- public -------------------------------------------------------------------------------

    def write(self, table: str, items: list[Any], row_type: type) -> None:
        cols = columns_of(row_type)
        self._ensure_table(table, cols)
        self.written.append(table)
        names = ", ".join(f"`{c}`" for c in cols)
        head = f"INSERT INTO {self.prefix}.`{table}` ({names}) VALUES "
        batch: list[str] = []
        size = len(head)
        for item in items:
            row = {**self.meta, **(dataclasses.asdict(item) if dataclasses.is_dataclass(item) else dict(item))}
            values = "(" + ", ".join(sql_literal(row.get(c), t) for c, t in cols.items()) + ")"
            if batch and size + len(values) > MAX_STATEMENT_BYTES:
                self.execute(head + ", ".join(batch))
                batch, size = [], len(head)
            batch.append(values)
            size += len(values) + 2
        if batch:
            self.execute(head + ", ".join(batch))

    def finish(self) -> None:
        """overwrite: drop this workspace's rows from earlier runs, now that the new run is fully written."""
        if self.mode != "overwrite":
            return
        ws, run = sql_literal(self.meta["workspace_id"], "STRING"), sql_literal(self.meta["run_id"], "STRING")
        for table in self.written:
            self.execute(f"DELETE FROM {self.prefix}.`{table}` WHERE workspace_id = {ws} AND run_id <> {run}")


@dataclasses.dataclass
class TextArtifact:
    name: str
    content: str


