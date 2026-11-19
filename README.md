# admin_to_power_user

Find out what breaks before you take workspace admin away from people in Databricks, and what to do about it.

> **Not an official Databricks product.** Provided as is under the [Apache License 2.0](LICENSE), without warranty
> or support. It runs with workspace-admin credentials: read the code and [SECURITY.md](SECURITY.md) first, and try
> it on a non-production workspace.

## Why

Workspace admin bypasses every ACL and every workspace setting. A safer model is **no human is workspace admin**.
Only an admin service principal (or an admin group) keeps the role, and everyone else moves to a `power_users` group
with a permission set you choose.

The risk is in what admins reach without explicit grants. A job that runs as an admin, a PAT used by a script, or a
cluster created without a policy can fail after the move. This tool finds those cases for you.

## What it does

For each target workspace, it:

- **predicts what breaks** and ranks each break by real usage from the system tables (`BLOCKER` → `LOW`);
- **checks your permission set**: what it covers, and which entries are unused or match nothing;
- **builds an action plan**: grants for `power_users`, jobs/pipelines/PATs to move to a service principal, and
  admin-only tasks that need a process change;
- **reports readiness**: `READY` means no open `BLOCKER` or `HIGH` break;
- **saves results** to a Unity Catalog schema and publishes an AI/BI dashboard over them.

It is **read-only**. Every request is checked before it is sent, and anything other than reads and the tool's own
output (schema, tables, dashboard) is refused. It never makes the move itself.

## Requirements

- Python 3.10+ and [uv](https://docs.astral.sh/uv/); the Databricks CLI
- `system.access.audit` and `system.lakeflow.*` enabled
- An identity with **workspace admin** on the target (ideally the admin SP), plus `SELECT` on those system tables,
  `USE CATALOG` + `CREATE SCHEMA` on the output catalog, and `CAN_USE` on a SQL warehouse

## Quick start

```bash
uv venv --python 3.12 && uv pip install -e .
databricks auth login --profile my-ws

admin-to-power-user --profile my-ws --catalog main --schema admin_to_power_user --admin <admin SP client id>
# -> prints the dashboard URL
```

`--admin` is who stays admin (an SP client ID or a group name; repeatable). Run `admin-to-power-user --help` for
all options, or see [docs/reference.md](docs/reference.md#cli-options).

## Usage

1. **Baseline:** run without `--permissions` to see everything that would break. The run also saves a suggested
   permission set in the `artifacts` table.
2. **Choose a permission set:** start from [`config/power_users.yaml`](config/power_users.yaml) or the
   suggested set. It has one permission per line:
   ```yaml
   - workspace-access                       # entitlement
   - CAN_USE cluster-policies "Personal*"   # LEVEL OBJECT_TYPE name/id/glob, or *
   - CAN_RUN /Shared                        # folder and everything below it
   - CREATE_CATALOG                         # Unity Catalog metastore privilege
   ```
3. **Rerun with `--permissions config/power_users.yaml`** to see what your set covers and what still breaks.
4. **Work through the action plan** in the dashboard, in order. To preview a job you plan to move to an SP, use
   `--assume-moved job:<id>`.
5. **Repeat until `READY`**, then make the move yourself: grant the set to `power_users`, add the people to it, and
   remove them from `admins`.

## Multiple workspaces

**From your machine:** add `--home-profile w1` to run the SQL and write the results in a separate results
workspace. The target only gets GET calls, and several targets can share one schema and dashboard.

```bash
admin-to-power-user --profile w2 --home-profile w1 --catalog main --schema admin_to_power_user --admin <admin SP>
```

**As a scheduled job:** deploy the bundle to the results workspace. It runs as the admin SP over a list of
targets, with a weekly schedule that is deployed paused.

```bash
export BUNDLE_VAR_workspaces='["https://adb-111.1.azuredatabricks.net", "https://adb-222.2.azuredatabricks.net"]'
export BUNDLE_VAR_admin_sp_application_id=<SP application id>
export BUNDLE_VAR_catalog=<catalog>
export BUNDLE_VAR_warehouse_id=<warehouse id>

databricks bundle deploy -p w1
databricks bundle run admin_to_power_user -p w1
```

The job needs a one-time setup first: the SP's OAuth secret goes in a secret scope only the SP can read. For that
setup and the optional variables (`schema`, `secret_scope`, `secret_key`, `mode`, `concurrency`), see
[docs/reference.md](docs/reference.md#run-as-a-databricks-job).

## Output

Tables in `<catalog>.<schema>`: the main ones are `readiness_summary`, `deltas` (what breaks), `recommendations`,
`action_plan` and `permission_set_coverage`. There is one dashboard, "What breaks and how to fix it". The output
contains admins' emails and ACLs, so limit who can read it. See [docs/reference.md](docs/reference.md#outputs).

## Documentation

- [docs/reference.md](docs/reference.md): CLI options, how it works, output tables, job setup, assumptions to verify
- [SECURITY.md](SECURITY.md): credentials, what the read-only guard covers, how to report a problem

## Development

```bash
uv pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

## License

[Apache License 2.0](LICENSE). Not an official Databricks product; no warranty or support.
