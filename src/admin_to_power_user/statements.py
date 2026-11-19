"""Run one SQL statement on a warehouse through the Statement Execution API and wait for the result."""

from __future__ import annotations

import time

TIMEOUT_SECONDS = 30 * 60  # a stopped serverless warehouse starts in seconds; this only stops a hung run


def lit(value: object) -> str:
    """A SQL string literal."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def run_statement(w, warehouse_id: str, sql: str, timeout_seconds: int = TIMEOUT_SECONDS):
    """Execute `sql` and wait until it finishes. Returns the final response; raises RuntimeError on failure."""
    from databricks.sdk.service.sql import StatementState

    se = w.statement_execution
    deadline = time.monotonic() + timeout_seconds
    resp = se.execute_statement(statement=sql, warehouse_id=warehouse_id, wait_timeout="50s")
    while resp.status and resp.status.state in (StatementState.PENDING, StatementState.RUNNING):
        if time.monotonic() > deadline:
            raise RuntimeError(f"Statement {resp.statement_id} still running after {timeout_seconds}s\n{sql[:300]}")
        time.sleep(2)
        resp = se.get_statement(resp.statement_id)
    if not resp.status or resp.status.state != StatementState.SUCCEEDED:
        err = resp.status.error if resp.status else None
        raise RuntimeError(f"Statement failed: {getattr(err, 'message', None) or err}\n{sql[:300]}")
    return resp
