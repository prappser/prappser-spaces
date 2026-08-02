# Self-host deploy stack

Docker Compose stack for running Prappser Spaces on your own server, with Caddy
for TLS and watchtower for automatic updates. A Cloudflare Tunnel override
(`docker-compose.cloudflare-tunnel.yml`) is also available if you'd rather not
open any inbound ports.

See [docs/hosting/selfhost.md](../docs/hosting/selfhost.md) for the full setup
and operations runbook.
