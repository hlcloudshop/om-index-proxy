# OM Index Direct

Google Drive proxy that turns Drive file IDs into direct download / streaming URLs. Access tokens come from the omindex.org broker — you only need a broker API key, no Google OAuth setup.

Two deploy targets, same behavior:

| | Cost | Cold start | Setup time |
|---|---|---|---|
| Cloudflare Worker (free tier) | Free up to 100k req/day | ~0ms | ~2 min |
| Docker on a VPS | Your VPS cost | n/a | ~5 min |

## Routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/dl?id=<fileId>` | Download (attachment) |
| `GET` | `/stream?id=<fileId>` | Inline playback, Range-aware |
| `HEAD` | `/dl?id=<fileId>` | Metadata-only probe |
| `HEAD` | `/stream?id=<fileId>` | Same, for media players |
| `GET` | `/info?id=<fileId>` | JSON metadata |
| `OPTIONS` | `*` | CORS preflight |
| `GET` | `/` | Health check (`OK`) |

## Option 1 — Cloudflare Worker

1. **Get a broker API key** from omindex.org.
2. **Create a worker** in the Cloudflare dashboard (Workers & Pages → Create → Worker).
3. **Open `worker.js`** in this repo and edit the two constants near the top:
   ```js
   const INDEX_API_KEY = 'om_xxxxxxxxxxxxxxxxxxxxxxxxxxxx';
   const ENABLE_CORS   = true;
   ```
4. **Paste the entire file** into the dashboard editor, **Save and deploy**.

That's it — no `wrangler`, no build step, no other env vars to configure. The worker auto-detects its public origin from incoming requests.

Test it:
```
curl -I https://<your-worker>.workers.dev/dl?id=<fileId>
```

## Option 2 — Docker on a VPS

Everything lives under [vps_docker/](vps_docker/).

1. **Get a broker API key** from omindex.org.
2. **Edit `vps_docker/.env`**:
   ```env
   INDEX_API_KEY=om_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
   WORKER_ORIGIN=
   ```
   Leave `WORKER_ORIGIN` empty to auto-detect from `Host` / `X-Forwarded-Host` headers. Set it explicitly only if the broker whitelists a specific canonical origin and your reverse proxy doesn't forward the right host.
3. **Build and run**:
   ```sh
   cd vps_docker
   docker compose up -d
   ```
4. **Verify**: `curl http://<vps-ip>:8080/` → `OK`.

Container listens on `:8080`. Front it with nginx / Caddy / Traefik for TLS and a public hostname.

### Behind a reverse proxy

The server reads `X-Forwarded-Proto` and `X-Forwarded-Host` to reconstruct the public origin sent to the broker. Make sure your proxy forwards them. Example nginx:

```nginx
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host  $host;
}
```

If the broker rejects the auto-detected origin, set `WORKER_ORIGIN` explicitly in `.env`.

## Caching behavior

Both deploys keep two in-memory caches:

- **Broker access token** — reused until ~30 seconds before expiry (typical ~55 min).
- **File metadata** — 1-hour TTL, max 1000 entries (LRU-bounded).

On Cloudflare these are per-isolate (many warm isolates → many caches). On Docker they're per-container.

## Source layout

| File | Role |
|---|---|
| [worker.js](worker.js) | Single-file Cloudflare Worker (paste-and-deploy) |
| [vps_docker/server.js](vps_docker/server.js) | Same handler, Node 20+ http adapter |
| [vps_docker/Dockerfile](vps_docker/Dockerfile) | `node:20-alpine`, zero npm deps |
| [vps_docker/docker-compose.yml](vps_docker/docker-compose.yml) | Compose with `.env`, healthcheck, restart policy |
| [vps_docker/.env](vps_docker/.env) | Runtime config template |
