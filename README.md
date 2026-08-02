# Perch

Monitoring for one Linux machine and its Docker containers.
One small Go binary, no accounts, no cloud, no agents to install.

Run it on the host you want to watch and it serves a live dashboard of the machine and everything running on it.
It only reports on the box it runs on, so to watch several machines, run one instance on each.

## What you get

- CPU, memory, swap, load, uptime, disk usage per mount.
- NVIDIA GPU utilization, VRAM, temperature, power draw.
- Containers from the Docker API: state, health, live CPU/memory, ports.
- Per-container log tails.
- Incoming HTTP requests, read from nginx proxy manager's access logs.
- Health checks against your own URLs, with latency and uptime.
- A "curl from the browser" for hitting services from inside the network.
- Alerts to a Discord, Slack, or Telegram webhook when a check fails, a container turns unhealthy, or a disk fills up.
- OpenAI and Anthropic API spend, if you supply org admin keys.
- Optional login with a shared key or GitHub OAuth.

## Quick start

```sh
export PERCH_KEY=$(openssl rand -hex 24)
docker compose up -d
```

That starts Perch plus a read-only Docker socket proxy.
The dashboard listens on `127.0.0.1:3535`, so it is reachable from the host but not from the internet.
To see it from your laptop:

```sh
ssh -L 3535:localhost:3535 you@your-server
```

For permanent access, put it behind a reverse proxy over HTTPS.
Don't publish `3535:3535` on a public server; published Docker ports bypass ufw/firewalld.

Health checks are added from the dashboard and persist in the `/data` volume.

## From source

```sh
go run .
```

Then open <http://localhost:3535>.
Auth is off unless `ACCESS_KEY` is set.
On WSL2 you need Docker Desktop's WSL integration enabled for the Containers tile to work.

## Configuration

A `.env` file in the working directory is loaded on startup; the real environment wins over it.

| Env var | Default | Purpose |
|---|---|---|
| `ACCESS_KEY` | *(empty = auth off)* | login key; compose wires `PERCH_KEY` into it |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | *(empty = off)* | GitHub OAuth App credentials |
| `GITHUB_ALLOWED_USERS` | *(empty)* | usernames allowed to sign in, comma-separated |
| `GITHUB_ALLOWED_EMAILS` | *(empty)* | verified emails allowed to sign in |
| `RATE_LIMIT` / `RATE_WINDOW_SECONDS` | `50` / `10` | unauthenticated requests per IP per window |
| `BAN_HOURS` | `10` | how long an over-limit IP stays banned |
| `BAN_FILE` | `/data/banned_ips.txt` | ban persistence |
| `PORT` | `3535` | listen port |
| `CHECKS_YAML` | *(empty)* | health checks declared up front, instead of adding them in the UI |
| `NPM_LOG_DIR` | `/npm-logs` | nginx proxy manager access logs |
| `ALERT_WEBHOOK_URL` | *(empty = alerts off)* | Discord, Slack, or Telegram webhook; also settable in the UI |
| `ALERT_DISK_PCT` | `90` | percent-full at which a disk alerts |
| `OPENAI_ADMIN_KEY` / `ANTHROPIC_ADMIN_KEY` | *(empty = tab off)* | org admin keys for the spend tab, read server-side only |
| `DOCKER_HOST` | *(unix socket)* | `tcp://socket-proxy:2375` for proxied access |
| `HOST_PROC` / `HOST_SYS` / `HOST_ROOT` | `/host/...` | host proc/sys/rootfs mounts |
| `NVIDIA_SMI_PATH` | *(auto-detect)* | explicit `nvidia-smi` location |

For GitHub login, create an OAuth App with callback URL `https://<your-domain>/api/auth/github/callback`, then set the client ID, secret, and an allowlist.
Only usernames and verified emails are matched, never display names.

## Security

The Docker socket is never mounted into Perch.
A [socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) forwards read-only `GET /containers/*` calls and rejects everything else, so a hijacked Perch cannot start, stop, or remove containers.
The container drops all capabilities and runs with a read-only root filesystem and read-only host mounts.

Perch only reads. There is no start, stop, restart, or redeploy; every Docker call it makes is a `GET`.

The API-calls feature sends its requests from the Perch container, so a logged-in user can reach anything the container can reach on your internal network, including a cloud provider's metadata endpoint.

## License

[MIT](LICENSE).
