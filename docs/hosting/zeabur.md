# Hosting on Zeabur

Zeabur provides a one-click template that provisions both the PostgreSQL
database and the Prappser Spaces service.

## What the template provisions

The template is defined in [`zeabur-template.yaml`](../../zeabur-template.yaml)
and creates two services:

- **`postgresql`**: a `postgres:16-alpine` container with a persistent volume
  at `/var/lib/postgresql/data`. Its host, port, user, and password are
  generated and exposed to the other service as variables.
- **`prappser-spaces`**: built from this repo's `main` branch (GitHub source,
  repo id `925100212`), listening on port `4545`, with a persistent volume at
  `/app/storage`.

Deploying the template asks for two inputs:

- **`MASTER_PASSWORD`**: plain text admin password, hashed by the server on startup
- **`SERVER_DOMAIN`**: the domain the service is deployed to (a generated
  `*.zeabur.app` subdomain, or a custom domain you attach)

Every other environment variable on the `prappser-spaces` service is wired
automatically from the `postgresql` service and from `SERVER_DOMAIN`:
`DATABASE_URL`, `MASTER_PASSWORD`, `PORT`, `EXTERNAL_URL`, `ALLOWED_ORIGINS`,
`LOG_LEVEL`, `STORAGE_TYPE`, `STORAGE_PATH`, `STORAGE_MAX_FILE_SIZE_MB`, and
`STORAGE_CHUNK_SIZE_MB`.

## HOSTING_PROVIDER=zeabur

The template sets `HOSTING_PROVIDER=zeabur`. This changes how the server
resolves `EXTERNAL_URL` (see `resolveExternalURL` in
[`internal/config.go`](../../internal/config.go)): if `EXTERNAL_URL` is set to
a bare subdomain name with no dots (for example `myserver`, not a full
domain), the server suffixes it to `https://myserver.zeabur.app`. If
`EXTERNAL_URL` already contains a dot (a full custom domain), it is used
as-is with `https://` added if no scheme is present.

## Updates

Zeabur rebuilds the `prappser-spaces` service automatically whenever `main`
is pushed, since the service source is `GIT` (GitHub, branch `main`). There is
no separate release step to trigger a Zeabur redeploy.

## Maintaining the template

The template itself (the YAML that defines what gets provisioned) is
versioned separately from the app code, as Zeabur template code `5MCVV7`.
After editing `zeabur-template.yaml`, push the change to Zeabur with:

```bash
./scripts/deploy-zeabur-template.sh
```

This requires the `zeabur` CLI (`npm i -g zeabur`, or it falls back to `npx
zeabur`) and runs `zeabur template update -f zeabur-template.yaml -c 5MCVV7`.
This only updates the template definition seen by future deploys; it does not
redeploy any already-running instance.
