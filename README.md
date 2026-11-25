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

## Multiple workspaces from your machine

Add `--home-profile w1` to run the SQL and write the results in a separate results workspace. The target only gets
GET calls, and several targets can share one schema and dashboard.

```bash
admin-to-power-user --profile w2 --home-profile w1 --catalog main --schema admin_to_power_user --admin <admin SP>
```

To do this for many workspaces on a schedule, without running anything locally, use the job below.

## Run as a scheduled job

The tool is deployed once, as a Databricks job, into a **results workspace**. It runs as your **admin service
principal (SP)**, assesses every workspace in a list, writes all results to one schema and publishes one
dashboard there. Nothing is created in the assessed workspaces: they only get read (GET) calls.

Placeholders used below: `<results URL>` is the results workspace, `<SP id>` is the SP's application (client) ID,
`<catalog>` and `<warehouse id>` are in the results workspace.

### 1. Choose the results workspace

Pick one workspace to host the job, the results and the dashboard. It must be in the **same account and region**
as the workspaces you assess (the audit log is regional) and have **serverless jobs** enabled, with access to PyPI
to install the tool's dependencies. You need a catalog there for the results (access to it should be restricted)
and a SQL warehouse; a 2X-Small serverless warehouse is enough.

### 2. Create the service principal (account admin)

Use the SP that will **stay workspace admin after the migration**: the job keeps the SP it runs as.

1. Account console → **User management → Service principals → Add service principal** (skip if you have one).
2. Account console → **Workspaces** → each workspace you assess → **Permissions** → add the SP as **Admin**.
3. Same for the results workspace, as **User** (or Admin if you also assess it).
4. Open the SP → **Credentials & secrets** → **Generate secret**. Copy the secret; it's shown once.
5. Open the SP → **Permissions** → give yourself the **Service principal: User** role, so you can deploy a job
   that runs as it.

### 3. Store the secret in the results workspace

The job reads the SP's secret from a secret scope to reach the other workspaces. Only the SP and you (the scope's
manager) should be able to read it.

```bash
databricks auth login --host <results URL> --profile w1
databricks secrets create-scope admin_to_power_user -p w1
databricks secrets put-secret admin_to_power_user sp-oauth-secret -p w1     # paste the secret when prompted
databricks secrets put-acl admin_to_power_user <SP id> READ -p w1
databricks secrets list-acls admin_to_power_user -p w1                       # expect only you (MANAGE) and the SP (READ)
```

OAuth secrets expire. Before yours does, generate a new one and run `put-secret` again.

### 4. Grant the SP access in the results workspace

In the SQL editor, as the catalog owner or a metastore admin:

```sql
GRANT USE CATALOG, CREATE SCHEMA ON CATALOG <catalog> TO `<SP id>`;
GRANT USE CATALOG ON CATALOG system TO `<SP id>`;
GRANT USE SCHEMA, SELECT ON SCHEMA system.access TO `<SP id>`;
GRANT USE SCHEMA, SELECT ON SCHEMA system.lakeflow TO `<SP id>`;
```

Then let it use the warehouse:

```bash
databricks warehouses update-permissions <warehouse id> -p w1 \
  --json '{"access_control_list": [{"service_principal_name": "<SP id>", "permission_level": "CAN_USE"}]}'
```

### 5. Get the code and fill in the variables

You need the [Databricks CLI](https://docs.databricks.com/dev-tools/cli/install.html) and
[uv](https://docs.astral.sh/uv/) (the deploy builds the tool's wheel with it).

```bash
git clone <this repository> && cd admin_to_power_user
mkdir -p .databricks/bundle/default
cp config/job-variables.example.json .databricks/bundle/default/variable-overrides.json
```

Edit `.databricks/bundle/default/variable-overrides.json`. The CLI reads it on every deploy, and git ignores it,
so your workspace URLs and IDs stay out of the repository:

```json
{
  "workspaces": "[\"1111111111111111\", \"2222222222222222\"]",
  "admin_sp_application_id": "<SP id>",
  "catalog": "<catalog>",
  "warehouse_id": "<warehouse id>"
}
```

`workspaces` is a JSON list, written as a string, of **workspace IDs** (the number after `?o=` in the workspace's
URL, also shown in the account console) or workspace URLs; you can mix both. The job looks up each ID's URL in
`system.access.workspaces_latest`, which the SP can read after step 4. Start with one non-production workspace.
Optional variables (add them to the same file only to change the default):

| Variable | Default | Change it to |
|---|---|---|
| `schema` | `admin_to_power_user` | use another schema name |
| `secret_scope`, `secret_key` | `admin_to_power_user`, `sp-oauth-secret` | match the names you used in step 3 |
| `mode` | `overwrite` | `append` to keep every run, e.g. to track progress over weeks |
| `concurrency` | `1` | `2`–`4` to assess many workspaces faster |
| `schedule_status` | `PAUSED` | `UNPAUSED` to run every Monday at 06:00 UTC |

Also review the permission set you plan to give `power_users`, in `config/power_users.yaml`. The job uses it.

### 6. Deploy and run

```bash
databricks bundle validate -p w1                  # checks the configuration
databricks bundle deploy -p w1                    # builds the wheel and creates the job
databricks bundle run admin_to_power_user -p w1   # one run over every workspace in the list
```

The command prints a link to the run. There is one `assess` iteration per workspace: a workspace that fails
doesn't stop the others, and the dashboard is published at the end either way. If your network only reaches PyPI
through a mirror, set `UV_DEFAULT_INDEX=<mirror URL>` before deploying.

### 7. Open and share the dashboard

The dashboard, **Admin to power_users readiness**, is in `/Users/<SP id>/admin_to_power_user` in the results
workspace. Each viewer needs `CAN_VIEW` on it (a workspace admin can share it, since the folder belongs to the SP),
`USE CATALOG`/`USE SCHEMA` and `SELECT` on `<catalog>.admin_to_power_user`, and `CAN_USE` on the warehouse. Keep this
list short: the results include admins' emails, PAT IDs and ACLs.

### Changing it later

Edit `variable-overrides.json` (add or remove workspaces, turn on the schedule) or `config/power_users.yaml`, then
run `databricks bundle deploy -p w1` again. Don't edit the job in the UI: the next deploy overwrites it.

To deploy from CI instead of your machine (recommended once it's set up, see [SECURITY.md](SECURITY.md)), set the
same values as `BUNDLE_VAR_<name>` pipeline variables, for example `BUNDLE_VAR_catalog`, and run
`databricks bundle deploy`.

## Output

Tables in `<catalog>.<schema>`: the main ones are `readiness_summary`, `deltas` (what breaks), `recommendations`,
`action_plan` and `permission_set_coverage`. There is one dashboard, "What breaks and how to fix it". The output
contains admins' emails and ACLs, so limit who can read it. See [docs/reference.md](docs/reference.md#outputs).

## Documentation

- [docs/reference.md](docs/reference.md): CLI options, how it works, output tables, what the job runs, assumptions to verify
- [SECURITY.md](SECURITY.md): credentials, what the read-only guard covers, how to report a problem

## Development

```bash
uv pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

## License

[Apache License 2.0](LICENSE). Not an official Databricks product; no warranty or support.
