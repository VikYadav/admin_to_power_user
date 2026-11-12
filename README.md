# admin_to_power_user

Goal: no human is workspace admin. The admin service principal (and/or an admin group) stays admin; every
other member of `admins` moves to an account-level `power_users` group that gets **the permission set you
choose**. For one target workspace, this tool predicts what would fail after the move, shows what your
permission set already fixes, recommends a fix for everything else, saves the results to a Unity Catalog
schema you choose, and publishes an AI/BI dashboard over them.

**It changes nothing except its own output.** Two API clients are used (`readonly.py`):
- The **analysis client** only reads: GET calls, plus single SELECT statements on the system tables.
- The **output client** may only create the schema and tables in `<catalog>.<schema>`, insert rows, delete
  this workspace's older rows (overwrite mode), and create/update/publish the tool's own dashboard in one folder.

Any other request (permissions, groups, jobs, clusters, tokens, settings, other schemas) is refused before it is
sent. Nothing is written to your machine. Running SQL starts the chosen warehouse if it is stopped.

To leave the target completely untouched, run from a separate **results workspace** with `--home-profile`
(see [Running from another workspace](#running-from-another-workspace)). The target then gets only GET calls.

## Quick start

```bash
uv venv --python 3.12 && uv pip install -e .
databricks auth login --profile my-ws            # an identity with workspace admin on the target

admin-to-power-user --profile my-ws --catalog main --schema admin_to_power_user --admin <admin SP client id>
# -> prints the dashboard URL
```

Rerun with your planned permission set to see what it fixes and what still fails:

```bash
admin-to-power-user --profile my-ws --catalog main --schema admin_to_power_user --admin <admin SP client id> \
    --permissions config/power_users.yaml
```

| Input | How | Default |
|---|---|---|
| Workspace | `--profile` (or `--workspace-host`) | the default profile's workspace |
| Results workspace (warehouse, tables, dashboard) | `--home-profile` (or `--home-host`) | the target workspace |
| Where results go | `--catalog`, `--schema` (required; the schema is created if missing) | |
| Append or overwrite | `--mode append` / `--mode overwrite` | append |
| Who stays admin | `--admin <SP client id or group name>`, repeatable | the SP running the tool |
| power_users permissions | `--permissions file.yaml` | none: the run writes a suggested set (`artifacts` table) |
| SQL warehouse (in the results workspace) | `--warehouse-id` | a running warehouse, else a serverless one |
| Dashboard location (in the results workspace) | `--dashboard-folder`, `--dashboard-name` | your home folder, "Admin to power_users readiness" |
| Work already moved to an SP | `--assume-moved job:<id>` (also `pipeline:`, `token:`, `query:`), repeatable | none |
| Usage window | `--lookback-days` | 90 |

The permission file is a list with one permission per line (see `config/power_users.yaml`):

```yaml
- workspace-access                       # entitlement
- CAN_USE cluster-policies "Personal*"   # LEVEL OBJECT_TYPE name/id/glob, or * for all
- CAN_USE warehouses *
- CAN_RUN /Shared                        # folder and everything below it
- CREATE_CATALOG                         # Unity Catalog metastore privilege
- token-usage                            # PATs
```

Members of a group passed to `--admin` stay admin too; the run warns you about any humans among them. If none of the
admins you keep is in `admins` today, the run reports a BLOCKER, because the move would leave the workspace with
no admin.

## How it works

1. **Collect** (as the admin SP): users, SPs, nested groups, entitlements; jobs/pipelines/queries/dashboards
   that run as an admin and everything they depend on (clusters, policies, pools, notebooks, files,
   warehouses, secret scopes, including `{{secrets/...}}` refs and `dbutils.secrets.get` in notebook code);
   admins' PATs; UC metastore grants and admin-owned UC objects; ACLs for only those objects.
2. **Usage** from system tables: job runs, `secrets:getSecret` and other object touches, admin-only actions
   (with a terraform/SDK vs browser split), cluster creation without a policy, UC `create*` actions.
3. **Simulate**: each admin's access *today* (implicit admin) vs *after* (groups minus `admins`, plus
   `power_users` with your permission set). The run happens twice: once with `power_users` as it is today
   and once with your set added. Anything that fails only without your set is reported as **covered by your
   permission set** (`covered_by`). Each entry in the set is reported as USED, UNUSED (fixes nothing here) or
   NOT_FOUND (matches no object), and flagged when it is scope creep. Every remaining shortfall becomes a
   **delta** with a severity:
   - `BLOCKER`: a job/pipeline that ran in the lookback window, a PAT that's in use and would be blocked, or an admin-only action run by automation
   - `HIGH`: heavily used access, a used entitlement or UC privilege, or an admin-only action done by hand
   - `MEDIUM` / `LOW`: lighter or no recent use · `INFO`: ownership risk (does not break)
4. **Recommend**: each delta goes into one of three buckets:
   - `POWER_USERS_GRANT`: a grant for the group. Grants that rebuild admin bit by bit are flagged `scope_creep`.
   - `MOVE_TO_SP`: automation tied to a person. Re-own it or set its `run_as` to an SP, and grant the SP what it needs.
   - `PROCESS_CHANGE`: tasks that can't be delegated. Route them to SP + Terraform PR, account group managers, or Entra PIM JIT.
5. **Consolidate**: readiness (`READY` = no open BLOCKER/HIGH), extra `power_users` grants beyond your set,
   the move-to-SP list, process changes, and your permission set's coverage. The suggested permission set (your
   set plus the non-scope-creep additions) is saved in the `artifacts` table, ready to pass back with
   `--permissions`.
6. **Action plan**: every open break (it breaks and your set doesn't cover it) is put into exactly one action:
   one grant per object (at the highest level anyone needs), one move per job, pipeline, PAT or script, and one
   process change per admin-only task. Actions are numbered worst-first, so doing them in order fixes every open
   break without reading the breaks one by one.

## Outputs

**Tables** in `<catalog>.<schema>`. Every row carries `run_id`, `run_ts` and `workspace_id`:

| Table | Holds |
|---|---|
| `runs`, `readiness_summary` | One row per run: workspace, who stays admin, readiness counts, warnings |
| `deltas`, `recommendations` | What breaks, and the fix for each item |
| `action_plan` | The to-do list: one row per action, with who does it, how many breaks it fixes, and the `delta_ids` it fixes |
| `proposed_power_user_grants`, `move_to_sp`, `process_changes` | The fixes rolled up by type |
| `permission_set_coverage` | Each entry of your permission set: USED, UNUSED or NOT_FOUND |
| `artifacts` | The suggested permission set (`suggested_permissions.yaml`), ready to pass back with `--permissions` |
| `principals`, `relevant_objects`, `acls` | The evidence the analysis used |

- `--mode append` (default) adds each run. The dashboard always shows the latest run per workspace.
- `--mode overwrite` replaces this workspace's earlier rows and keeps other workspaces' rows. Old rows are deleted
  only after the new run is fully written.

**Dashboard**: one page, "What breaks and how to fix it". From the top:
- filters for workspace, status, what breaks, person and fix type;
- four counters: breaks with high impact, breaks with lower impact, covered by your permission set, and keeps
  working but review;
- two charts and the detail table (one row per break);
- **Fix summary**: one row per fix type with what to do, who does it, how many actions and how many breaks it fixes;
- **Action plan**: the numbered actions behind the summary. Doing all of them fixes every open break;
- the run's details and warnings (About this run).

The workspace and fix type filters apply to every table. Status, what breaks and person filter only the detail table.

The dashboard is locked to `src/admin_to_power_user/dashboard.lvdash.json`. Every run creates it, or updates it to
exactly that definition, at `<folder>/<name>.lvdash.json`, and publishes it. Edits made in the UI are overwritten on
the next run, so change the file instead (the output schema is written as `` `__CATALOG__`.`__SCHEMA__` ``).
It is published without embedded credentials, so viewers need CAN_VIEW on the dashboard and SELECT on the schema.
Granting those is left to you: the tool never changes permissions.

## Running from another workspace

Run everything from one workspace (w1) against others (w2, w3) without creating anything in w2 or w3:

```bash
admin-to-power-user --profile w2 --home-profile w1 --catalog main --schema admin_to_power_user --admin <admin SP>
admin-to-power-user --profile w3 --home-profile w1 --catalog main --schema admin_to_power_user --admin <admin SP>
```

| | Target (w2, w3) | Results workspace (w1) |
|---|---|---|
| REST reads (identities, jobs, ACLs, UC grants, tokens...) | GET only | |
| System-table queries (filtered to the target's `workspace_id`) | | SELECT on w1's warehouse |
| Output schema, tables, dashboard | | created / written here |

- The target client refuses every SQL statement, not just writes, so a warehouse in the target is never used
  (nor started). The target still records the GET calls in its own audit log.
- Every row carries the target's `workspace_id`, so w2 and w3 can share one schema and one dashboard (use its
  workspace filter). `--mode overwrite` replaces only that workspace's rows.
- **Same account, and probably the same region:** `system.access.audit` holds workspace-level events only for
  workspaces in the querying workspace's region. If w1 sees no audit events for the target, the run warns you,
  because the usage evidence is then missing and severities are understated. Check with
  `SELECT DISTINCT workspace_id FROM system.access.audit WHERE event_date >= current_date() - 7` on w1.
- **Identity:** workspace admin on each target. On w1: `SELECT` on the system tables, write access to the
  output schema, and `CAN_USE` on the warehouse. An account-level SP with OAuth M2M and a profile per
  workspace works well. The two profiles may use different identities. The default retained admin is the
  identity on the *target* profile, and the default dashboard folder is the home folder of the identity on the
  *home* profile.

## Tests

```bash
.venv/bin/python -m pytest -q
```

## Assumptions to verify in your environment

- **Audit names**: the service, action and parameter names in `usage.py` (`TOUCH_RULES`, `UC_ACTIONS`) and
  in `DEFAULT_ADMIN_ONLY_ACTIONS` (`config.py`) follow the audit log reference. Check them with
  `SELECT DISTINCT service_name, action_name FROM system.access.audit`.
- **Required levels**: the levels a run_as identity needs are in `model/levels.py` (`RUN_AS_REQUIRED`, e.g.
  existing cluster = `CAN_RESTART`). Tune them if your jobs only attach to running clusters.
- **Token usage permission**: if the token permission lists only `admins`, the tool can't tell whether
  non-admins can use PATs. Token deltas are then reported as risks, not breaks, with a warning.
- **Implicit UC privileges** (workspaces enabled for UC automatically) don't show up in grants. The tool infers them from
  successful UC `create*` actions in the audit log.
- **Publisher of AI/BI dashboards**: the API doesn't expose who published a dashboard, so dashboards in an admin's home folder stand in for it.
- **Notebook scanning** is a best-effort regex. `secrets:getSecret` in the audit log is the reliable signal.
- **Name/path matching** relies on what the tool can list. Clusters, policies, pools, warehouses, jobs,
  pipelines and secret scopes are listed in full, so a name that matches nothing is reported as NOT_FOUND. Folder
  (`path`) grants are checked against the notebooks and files that something in scope actually uses.
- **One target workspace per run.** Run the tool once for each workspace. Results from several targets can go to
  one results workspace (`--home-profile`).
- **Identity**: run it as an identity with workspace admin on the target (ideally the admin SP), with `SELECT` on
  `system.access.audit` and `system.lakeflow.*` for the usage data, `USE CATALOG` + `CREATE SCHEMA` (or
  `USE SCHEMA` + `CREATE TABLE` + `MODIFY`) on the output, and `CAN_USE` on the warehouse. With
  `--home-profile`, everything except workspace admin is needed in the results workspace, not in the target.
- **Not covered yet**: legacy Hive metastore table ACLs, serving endpoints, apps, MLflow experiments/models
  (add a collector that emits `Dependency` rows; the simulator and recommender are generic).
