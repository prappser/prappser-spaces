# Self-hosting Prappser Spaces

Runbook for running Prappser Spaces on your own server using the Docker
Compose stack in [`deploy/`](../../deploy/). The stack runs four containers:
Caddy (TLS termination), PostgreSQL, the `prappser-spaces` app, and
watchtower (auto-updates).

## 1. Install Docker

Install Docker Engine and the Compose plugin on the host. Verify with:

```bash
docker --version
docker compose version
```

## 2. Get a GHCR pull token

The app image is published to `ghcr.io/prappser/prappser-spaces` and may be
private. Create a fine-grained GitHub personal access token scoped to
`read:packages`, then log in on the host:

```bash
docker login ghcr.io -u <your-github-username>
# paste the token as the password
```

This writes `~/.docker/config.json`, which watchtower mounts read-only so it
can pull new images on your behalf. The compose default for
`DOCKER_CONFIG_PATH` is `$HOME/.docker/config.json` (Compose only does plain
string substitution, so it cannot expand a literal `~`). If you keep the
config somewhere else, or `$HOME` is not set in the environment `docker
compose` runs from, point `DOCKER_CONFIG_PATH` at the absolute path in
`.env`.

## 3. Point DNS at the host

Create an A record for your `DOMAIN` pointing at the host's IP address, and
make sure ports 80 and 443 are open. Caddy uses port 80 for the Let's Encrypt
HTTP-01 challenge and port 443 for HTTPS traffic; both must be reachable from
the internet for certificate issuance to succeed.

## 4. Configure the stack

Copy the `deploy/` directory to the host, then create your `.env`:

```bash
cd deploy
cp .env.example .env
```

Fill in `DOMAIN`, `POSTGRES_PASSWORD`, and `MASTER_PASSWORD` at minimum.
`ALLOWED_ORIGINS`, `LOG_LEVEL`, `WATCHTOWER_POLL_INTERVAL`, and
`DOCKER_CONFIG_PATH` all have sane defaults in the compose file if left
blank.

## 5. Start the stack

```bash
docker compose up -d
```

Confirm the app is healthy:

```bash
curl https://<your-domain>/health
```

This should return `{"status":"ok","version":"..."}`. The server runs
database migrations automatically on startup, so no separate migration step
is needed on first boot or after an update.

## 6. How updates work

A push to `main` triggers the `docker-publish.yml` GitHub Actions workflow,
which builds and pushes `ghcr.io/prappser/prappser-spaces:latest`. watchtower
polls GHCR every `WATCHTOWER_POLL_INTERVAL` seconds
(default 300) and, because only the `prappser-spaces` container carries the
`com.centurylinklabs.watchtower.enable=true` label, recreates just that
container when a new `latest` image is available. Caddy and Postgres are
never touched by watchtower. On restart, the app runs any new migrations
before serving traffic. `DOCKER_API_VERSION` is pinned to `1.44` on the
watchtower service because its bundled docker client otherwise defaults to
an API version below the minimum Docker Engine 29 requires, which crash-loops
watchtower on hosts running Engine 29+.

## Cloudflare variants

If your domain's DNS is on Cloudflare, there are three ways to combine it
with this stack.

### DNS only (grey cloud)

Works with the stack unchanged. Point an A record at your host and leave the
Cloudflare proxy off (grey cloud icon). Caddy still talks directly to Let's
Encrypt for the HTTP-01 challenge and terminates TLS itself, exactly as
described in step 3.

### Proxied (orange cloud)

Cloudflare terminates TLS at its edge and proxies to your origin. With the
Cloudflare SSL mode set to Full (strict), the origin also needs a certificate
Cloudflare trusts.

**Option a: Cloudflare Origin CA certificate.** Issue a free Origin CA
certificate (up to 15 years, trusted only by Cloudflare, which is fine since
only Cloudflare's edge should be reaching your origin) from the Cloudflare
dashboard, mount it into the caddy container, and reference it statically in
the Caddyfile instead of using Caddy's automatic HTTPS:

```
{$DOMAIN} {
    tls /certs/origin.pem /certs/origin.key
    reverse_proxy prappser-spaces:4545
}
```

**Option b: DNS-01 challenge.** Caddy can still get a publicly trusted
certificate through orange cloud via the DNS-01 challenge, but the stock
`caddy:2-alpine` image doesn't include the DNS provider plugin needed for
it. That requires a custom Caddy build with the `caddy-dns/cloudflare`
module (via `xcaddy` or a custom Dockerfile) and a Cloudflare API token with
DNS edit permission. Not covered in detail here; the plain HTTP-01 challenge
used by this stack does not work reliably through orange cloud, since
Cloudflare's "Always Use HTTPS" redirect interferes with the plaintext
HTTP-01 request.

**Caveats for proxied mode:**

- WebSocket connections (`/ws`) work through the Cloudflare proxy.
- The app sees Cloudflare's edge IPs as the client IP, not the real client
  IP, unless you configure IP restoration separately.
- Free-plan Cloudflare has an idle timeout of roughly 100 seconds on proxied
  connections, which can drop long-lived WebSocket connections. The app's
  client reconnects automatically, but expect more reconnect churn than with
  DNS-only or a tunnel.

### Cloudflare Tunnel (cloudflared)

Runs the server with no open inbound ports at all, works behind NAT or
CGNAT, and replaces Caddy entirely since Cloudflare terminates TLS and
tunnels the connection to `cloudflared` inside your network.

1. In the Cloudflare Zero Trust dashboard, create a remote-managed tunnel and
   copy its token.
2. Add a public hostname on the tunnel for your `DOMAIN`, pointing to
   `http://prappser-spaces:4545` (the service name and port from
   `docker-compose.yml`).
3. Add the token to `.env`:

   ```
   CLOUDFLARE_TUNNEL_TOKEN=your-tunnel-token
   ```
4. Start the stack with the tunnel override, which disables `caddy` and adds
   a `cloudflared` container:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.cloudflare-tunnel.yml up -d
   ```

See [`docker-compose.cloudflare-tunnel.yml`](../../deploy/docker-compose.cloudflare-tunnel.yml)
for the override definition.

## 7. Rollback

Only `latest` is published, so a rollback means building the older commit
yourself. Clone the repo on the host, check out the commit you want, and build
it under a local tag:

```bash
git clone https://github.com/prappser/prappser-spaces
cd prappser-spaces
git checkout <sha>
docker build -t prappser-spaces:rollback .
```

Then pin that tag in `deploy/docker-compose.yml`:

```yaml
prappser-spaces:
  image: prappser-spaces:rollback
```

Stop watchtower first so it cannot pull `latest` back over the rollback, then
apply:

```bash
docker compose stop watchtower
docker compose up -d prappser-spaces
```

When you are ready to return to the current build, restore
`image: ghcr.io/prappser/prappser-spaces:latest`, then `docker compose up -d prappser-spaces`
and `docker compose start watchtower`.

## 8. Backups

Dump the database:

```bash
docker compose exec postgres pg_dump -U prappser prappser > backup.sql
```

Example daily cron entry (2am, keeps the dump in the deploy directory):

```
0 2 * * * cd /path/to/deploy && docker compose exec -T postgres pg_dump -U prappser prappser > backup-$(date +\%Y\%m\%d).sql
```

Uploaded files live in the `app_storage` named volume; back it up separately
if you need file-level recovery, for example with `docker run --rm -v
app_storage:/data -v $(pwd):/backup alpine tar czf /backup/storage.tar.gz -C
/data .`

## 9. Moving to new hosting

A `pg_dump` restore (§8) carries everything, including `space_keys` -
encrypted under the OLD host's `MASTER_PASSWORD`. If the new host boots with
a different `MASTER_PASSWORD`, it can't decrypt that row. Export/import
decouples the two: you export the space's identity keypair, wrapped under a
passphrase you choose, and the new host unwraps and re-encrypts it under
whatever `MASTER_PASSWORD` it's given.

If you're keeping the same `MASTER_PASSWORD` on the new host, none of this
is needed - skip straight to a normal restore. This exists so you *can*
change it.

1. On the OLD, still-running host: in the app, go to Settings → My Space →
   Export identity key, choose a passphrase, and store the resulting blob
   in a password manager. **This must happen before the move** - there is
   no way to export from a host that's already offline.
2. Take the `pg_dump` (§8) and back up the `app_storage` volume as usual.
3. On the NEW host's `.env`, set the new `MASTER_PASSWORD` plus:
   ```
   SPACE_IDENTITY_IMPORT=PRAPSPACE1....
   SPACE_IDENTITY_IMPORT_PASSPHRASE=...
   ```
4. Restore the dump into an empty database, then start the stack. Watch the
   logs for `[KEYS] identity imported, re-encrypted under current
   MASTER_PASSWORD`. A public-key mismatch between the restored dump and the
   import blob aborts startup instead of silently swapping identities - if
   you see that error, double check you're pointed at the right database
   and the right export blob.
5. Verify `GET /status` on the new host reports the same `identityPublicKey`
   it reported on the old one before the move.
6. Flip DNS. The `SPACE_IDENTITY_IMPORT*` vars can be removed at your
   leisure afterwards - once the row decrypts under `MASTER_PASSWORD`,
   `Initialize` short-circuits before ever looking at them, so leaving them
   set is a no-op, not a repeat import.

**Cutover warning:** existing members are unaffected by the move itself -
their sessions and enrolled devices keep working, since the identity key
(and therefore every JWT it signs) is unchanged. The one thing that *does*
depend on timing is a brand-new device logging in for the first time during
the cutover window - that has to wait until DNS actually points at the new
host, since a new device has no existing session to fall back on.
