# Self-host deploy stack

Docker Compose stack for running Prappser Spaces on your own server, with Caddy
for TLS and watchtower for automatic updates. A Cloudflare Tunnel override
(`docker-compose.cloudflare-tunnel.yml`) is also available if you'd rather not
open any inbound ports.

See [docs/hosting/selfhost.md](../docs/hosting/selfhost.md) for the full setup
and operations runbook.

## Backups

`backup.sh` writes one age-encrypted bundle per run, `space-<UTC timestamp>.tar.age`,
holding a gzipped `pg_dump` and a tarball of the app storage volume (including
`.space/identity.key`). Needs `age` and `rclone` on the host.

Variables: `AGE_RECIPIENT` and `RCLONE_DEST` (`remote:path`) are required;
`KEEP_DAYS` (56), `DUMP_CMD` and `STORAGE_CMD` (`docker compose exec` commands
for this stack) are optional.

The copy is crash-consistent: the database and files are taken a few seconds apart.

### One-time setup

1. Run `age-keygen` on a trusted machine, not the server. Keep the private key
   in a password manager, along with the space's live public key (see the check
   below) and one identity export (selfhost.md §9, step 1). Only the public
   key goes on the server.
2. Create a bucket at an S3-compatible provider that is not the one hosting
   the space (not Hetzner or Railway). Enable versioning or object lock, since
   the host's credentials can delete backups. Configure rclone through
   env vars, for example `RCLONE_CONFIG_OFFSITE_TYPE=s3`,
   `RCLONE_CONFIG_OFFSITE_PROVIDER=...`, `RCLONE_CONFIG_OFFSITE_ACCESS_KEY_ID`,
   `RCLONE_CONFIG_OFFSITE_SECRET_ACCESS_KEY`, `RCLONE_CONFIG_OFFSITE_ENDPOINT`,
   then `RCLONE_DEST=offsite:bucket/space`.
3. Put these and `AGE_RECIPIENT` in an env file, `chmod 0600`, with each line
   as `export NAME=value`.
4. Run it once by hand, then add a weekly cron entry:

```
0 3 * * 0 . /etc/prappser-backup.env && /path/to/deploy/backup.sh && curl -fsS <healthcheck-url>
```

Cron runs with a minimal `PATH` and needs docker access, so run it as a user in
the `docker` group and set `PATH` in the env file if `age` or `rclone` live
elsewhere. Failures are silent otherwise, so use `MAILTO` or the healthcheck ping.

### Restore

Run from this directory on the target host, fresh or existing. The restore
must finish before the app first starts, or it creates a new identity.

1. Export the same `RCLONE_CONFIG_*` vars on the restore machine, then fetch and
   decrypt the newest bundle with the age private key:
   ```bash
   rclone copy offsite:bucket/space/<newest space-*.tar.age> .
   age -d -i key.txt space-*.tar.age | tar xf -
   ```
   This yields `db.sql.gz` and `storage.tar.gz`.
2. Check the identity before touching anything. Unpack the storage archive to a
   scratch dir and compute the public key:
   ```bash
   mkdir scratch && tar xzf storage.tar.gz -C scratch
   openssl pkey -in scratch/.space/identity.key -pubout -outform DER | tail -c 32 | base64
   ```
   Compare with the recorded live public key. Stop on a mismatch.
3. Stop the app and start only the database, then wait until it is ready:
   ```bash
   docker compose stop prappser-spaces watchtower
   docker compose up -d postgres
   until docker compose exec -T postgres pg_isready -U prappser; do sleep 1; done
   ```
4. Drop and recreate the database so it is empty, then load the dump (a plain
   dump, so no `--clean`):
   ```bash
   docker compose exec -T postgres psql -U prappser -d postgres -c 'DROP DATABASE IF EXISTS prappser WITH (FORCE)' -c 'CREATE DATABASE prappser'
   gunzip -c db.sql.gz | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U prappser prappser
   ```
5. Clear and restore the volume:
   ```bash
   docker compose run --rm --no-deps -T prappser-spaces sh -c 'find /app/storage -mindepth 1 -delete'
   docker compose run --rm --no-deps -T prappser-spaces sh -c 'tar xzf - -C /app/storage' < storage.tar.gz
   ```
6. `docker compose up -d`, then confirm the `publicKey` field on the
   `[KEYS] space key loaded from file` boot log line equals the key from step 2
   (`GET /status` `identityPublicKey` shows the same value with a login), check
   `/health`, and log in.

Restoring into Railway is not scripted: use Railway's native volume backups.
