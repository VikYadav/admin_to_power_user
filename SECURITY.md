# Security

admin_to_power_user runs with workspace-admin credentials. Read this, and the code, before you use it.

- **Credentials.** The tool never stores credentials: authentication is the Databricks SDK's (`--profile`,
  environment variables, OAuth). Prefer an OAuth service principal over a personal access token. The one exception
  is the job mode: with `--target-secret-scope`/`--target-secret-key`, the tool reads **its own** SP's OAuth secret
  from the results workspace to reach the targets. It is kept in memory only and never printed or written.
- **No other secret or token values are read.** The tool only needs secret *scope names* (from `{{secrets/...}}`
  references and `dbutils.secrets.get` calls). Notebook source is read into memory to find them and is not
  stored. The token API returns token metadata, never token values.
- **The output is sensitive.** `<catalog>.<schema>` holds admins' emails, PAT IDs and comments, ACLs, user agents and
  the objects they use. Limit `SELECT` on the schema, and `CAN_VIEW` on the dashboard, to the people running the
  migration. The dashboard is published without embedded credentials, so viewers only see what they can query.
- **What the read-only guard is, and isn't.** `readonly.py` checks every request the SDK sends and refuses
  anything outside the allowed reads and the output schema/dashboard. That protects you from mistakes in the
  tool. It isn't a sandbox: it only holds for unmodified code, so review changes before you run them.
- **The job runs as the admin SP.** Whoever can change the deployed bundle files, or redeploy the bundle, can run
  code as that SP. Deploy from a protected location (e.g. CI on a protected branch), keep the bundle folder
  writable only by the deployer (the bundle gives the SP read access only), and let only the SP read the secret
  scope.
- **SQL.** Values written to the result tables are escaped as SQL literals and every write is re-checked against
  the allowed statement forms. `--catalog` and `--schema` must not contain backticks.
- **Reporting a problem.** Please open an issue without workspace URLs, IDs or names, or contact the maintainer
  directly for anything sensitive.
