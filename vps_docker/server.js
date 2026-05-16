import http from 'node:http';
import { Readable } from 'node:stream';

const INDEX_API_KEY = process.env.INDEX_API_KEY || '';
const ENABLE_CORS = process.env.ENABLE_CORS !== 'false';
const WORKER_ORIGIN_OVERRIDE = process.env.WORKER_ORIGIN || '';
const PORT = Number(process.env.PORT || 8080);

if (!INDEX_API_KEY) {
  console.error('FATAL: INDEX_API_KEY env var is required');
  process.exit(1);
}

const DRIVE_API = 'https://www.googleapis.com/drive/v3/files';
const FIELDS = 'id,name,mimeType,size,modifiedTime';
const DROP = ['alt-svc','server','x-guploader-uploadid','x-goog-hash','x-goog-storage-class','x-goog-generation','x-goog-metageneration','x-goog-stored-content-encoding','x-goog-stored-content-length','expires'];
const INFO_TTL = 36e5, INFO_MAX = 1e3;
const POOL_TTL = 3e5; // refresh token pool after 5 min even if tokens still valid

let tokenPool = { tokens: [], badIds: new Set(), fetchedAt: 0 }, fetchInFlight = null;
const infoCache = new Map();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const drain = r => { try { r?.body?.cancel(); } catch {} };
const httpDate = ms => new Date(ms).toUTCString();

let logBuffer = [];
function log(level, event, message, details) {
  if (logBuffer.length >= 50) return;
  const entry = { level, event, message: String(message ?? '').slice(0, 500) };
  if (details && typeof details === 'object') entry.details = details;
  logBuffer.push(entry);
}
async function flushLogs(origin) {
  if (!logBuffer.length || !origin) return;
  const logs = logBuffer.splice(0, 50);
  try {
    await fetch('https://omindex.org/api/logs/ingest', {
      method: 'POST',
      headers: { Authorization: `Bearer ${INDEX_API_KEY}`, Origin: origin, 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs }),
    });
  } catch {}
}

async function fetchTokenPool(origin) {
  if (fetchInFlight) return fetchInFlight;
  fetchInFlight = (async () => {
    const r = await fetch('https://omindex.org/api/drive-tokens', { headers: { Authorization: `Bearer ${INDEX_API_KEY}`, Origin: origin } });
    if (!r.ok) {
      const text = await r.text();
      log('error', 'proxy.tokens.fetch_failed', `drive-tokens ${r.status}`, { status: r.status, body: text.slice(0, 200) });
      throw new Error(`drive-tokens ${r.status}: ${text}`);
    }
    const body = await r.json();
    const list = Array.isArray(body?.tokens) ? body.tokens : [];
    if (!list.length) { log('error', 'proxy.tokens.empty', 'drive-tokens returned empty pool'); throw new Error('drive-tokens: empty pool'); }
    const now = Date.now();
    tokenPool = {
      tokens: list.map(t => ({ id: t.id, accessToken: t.accessToken, expiresAt: now + Math.max(60, t.expiresInSeconds || 60) * 1e3 })),
      badIds: new Set(),
      fetchedAt: now,
    };
  })().finally(() => { fetchInFlight = null; });
  return fetchInFlight;
}

function pickToken() {
  const now = Date.now();
  const usable = tokenPool.tokens.filter(t => !tokenPool.badIds.has(t.id) && t.expiresAt - 3e4 > now);
  if (!usable.length) return null;
  return usable[Math.floor(Math.random() * usable.length)];
}

async function getToken(origin) {
  const stale = Date.now() - tokenPool.fetchedAt > POOL_TTL;
  let t = stale ? null : pickToken();
  if (!t) {
    try { await fetchTokenPool(origin); } catch (e) { if (!tokenPool.tokens.length) throw e; }
    t = pickToken();
  }
  if (!t) throw new Error('No usable drive tokens');
  return t;
}

const markBadToken = id => { if (id) tokenPool.badIds.add(id); };

async function driveInit(origin, extra) {
  const t = await getToken(origin);
  return { tokenId: t.id, init: { method: 'GET', headers: { Authorization: `Bearer ${t.accessToken}`, Accept: '*/*', ...(extra || {}) } } };
}

async function getFileInfo(id, origin) {
  const now = Date.now(), hit = infoCache.get(id);
  if (hit && now < hit.expiresAt) {
    infoCache.delete(id);
    infoCache.set(id, hit);
    return hit.data;
  }
  if (hit) infoCache.delete(id);
  const u = `${DRIVE_API}/${id}?fields=${encodeURIComponent(FIELDS)}&supportsAllDrives=true`;
  let { init: i, tokenId } = await driveInit(origin);
  let r;
  for (let k = 0; k < 3; k++) {
    r = await fetch(u, i);
    if (r.ok) break;
    if (r.status === 401 && k < 2) {
      drain(r);
      markBadToken(tokenId);
      const prev = tokenId;
      ({ init: i, tokenId } = await driveInit(origin));
      log('warn', 'drive.info.401', '401 on metadata, rotating token', { fileId: id, tokenId: prev, retriedWith: tokenId });
      continue;
    }
    if (r.status === 403 || r.status === 404) break;
    drain(r);
    await sleep(400);
  }
  if (!r.ok) { log('warn', 'drive.info.fail', `${r.status} on metadata`, { fileId: id, status: r.status, tokenId }); drain(r); return null; }
  const data = await r.json();
  if (data?.name) {
    if (infoCache.size >= INFO_MAX) infoCache.delete(infoCache.keys().next().value);
    infoCache.set(id, { data, expiresAt: now + INFO_TTL });
  }
  return data;
}

const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const errorPage = (m, s = 400) => new Response(`<!doctype html><meta charset=utf-8><title>Error</title><style>body{margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:system-ui,sans-serif;background:#0a0a0a;color:#eee}.b{max-width:480px;padding:32px;text-align:center}h1{font-size:18px;margin:0 0 12px;color:#ff6b6b}p{margin:0;font-size:14px;line-height:1.5;color:#aaa}</style><div class=b><h1>Error</h1><p>${escapeHtml(m)}</div>`, { status: s, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
const jsonResponse = (d, s = 200, x = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', ...x } });

async function handleFile(req, id, stream, origin) {
  if (!id) return errorPage('Missing file id.', 400);
  const f = await getFileInfo(id, origin);
  if (!f?.name) return errorPage('File not found. Try other download method!', 404);
  const enc = encodeURIComponent(f.name);
  const lastModified = f.modifiedTime ? httpDate(Date.parse(f.modifiedTime)) : null;
  const range = req.headers.get('Range') || '';

  if (req.method === 'HEAD') {
    const h = new Headers();
    if (f.size) h.set('Content-Length', String(f.size));
    h.set('Content-Type', f.mimeType || 'application/octet-stream');
    h.set('Accept-Ranges', 'bytes');
    h.set('Cache-Control', 'public, max-age=86400');
    h.set('Content-Disposition', stream ? 'inline' : `attachment; filename*=UTF-8''${enc}`);
    if (lastModified) h.set('Last-Modified', lastModified);
    if (ENABLE_CORS) { h.set('Access-Control-Allow-Origin', '*'); h.set('Access-Control-Expose-Headers', 'Content-Length, Accept-Ranges, Content-Disposition, Content-Type, Last-Modified'); }
    return new Response(null, { status: 200, headers: h });
  }

  let { init: i, tokenId } = await driveInit(origin);
  if (range) i.headers.Range = range;
  let r;
  for (let k = 0; k < 3; k++) {
    r = await fetch(`${DRIVE_API}/${id}?alt=media&supportsAllDrives=true`, i);
    if (r.ok || r.status === 206) break;
    if (r.status === 401 && k < 2) {
      drain(r);
      markBadToken(tokenId);
      const prev = tokenId;
      ({ init: i, tokenId } = await driveInit(origin));
      if (range) i.headers.Range = range;
      log('warn', 'drive.dl.401', '401 on alt=media, rotating token', { fileId: id, tokenId: prev, retriedWith: tokenId });
      continue;
    }
    if (r.status === 403 || r.status === 404 || r.status === 416) break;
    drain(r);
    await sleep(800 * (k + 1));
  }
  if (r.status === 404) { log('warn', 'drive.dl.404', '404 on alt=media', { fileId: id, tokenId }); drain(r); return errorPage('File not found. Try other download method!', 404); }
  if (r.status === 403) { log('warn', 'drive.quota', '403 on alt=media', { fileId: id, tokenId }); drain(r); return errorPage('Limit Exceeded. Try another link or visit this link after 24 hours.', 403); }
  if (r.status === 416) { drain(r); return new Response('Range not satisfiable', { status: 416 }); }
  if (!r.ok && r.status !== 206) { log('error', 'drive.dl.fail', `${r.status} on alt=media`, { fileId: id, status: r.status, tokenId }); drain(r); return errorPage('Unknown error.', 502); }

  const h = new Headers(r.headers);
  h.set('Accept-Ranges', 'bytes');
  if (!h.has('Content-Type') && f.mimeType) h.set('Content-Type', f.mimeType);
  if (lastModified) h.set('Last-Modified', lastModified);
  if (stream) {
    h.set('Content-Disposition', 'inline');
    h.set('Cache-Control', 'public, max-age=3600');
  } else {
    h.set('Content-Disposition', `attachment; filename="${f.name.replace(/"/g, '')}"; filename*=UTF-8''${enc}`);
    h.set('Cache-Control', 'public, max-age=86400');
  }
  if (ENABLE_CORS) {
    h.set('Access-Control-Allow-Origin', '*');
    h.set('Access-Control-Expose-Headers', stream ? 'Content-Length, Content-Range, Accept-Ranges, Content-Type, Last-Modified' : 'Content-Length, Content-Range, Accept-Ranges, Content-Disposition, Last-Modified');
  }
  for (const k of DROP) h.delete(k);
  return new Response(r.body, { status: r.status, statusText: r.statusText, headers: h });
}

async function handle(req) {
  let origin = '';
  try {
    const u = new URL(req.url);
    origin = WORKER_ORIGIN_OVERRIDE || u.origin;
    const id = u.searchParams.get('id');
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS', 'Access-Control-Allow-Headers': 'Range, Content-Type, If-Modified-Since', 'Access-Control-Max-Age': '86400' } });
    if (u.pathname === '/') return new Response('OK');
    if (u.pathname === '/info') {
      if (!id) return jsonResponse({ error: 'Missing file id.' }, 400);
      const f = await getFileInfo(id, origin);
      return f?.name ? jsonResponse(f, 200, { 'Cache-Control': 'public, max-age=3600' }) : jsonResponse({ error: 'File not found.' }, 404);
    }
    const s = u.pathname === '/stream';
    if (s || u.pathname === '/dl') return handleFile(req, id, s, origin);
    return new Response('Not found', { status: 404 });
  } catch (e) { console.error(e); log('error', 'proxy.exception', e?.message || String(e)); return errorPage('Unknown error.', 500); }
  finally { if (origin && logBuffer.length) flushLogs(origin).catch(() => {}); }
}

function toHeaders(nodeHeaders) {
  const h = new Headers();
  for (const [k, v] of Object.entries(nodeHeaders)) {
    if (v == null) continue;
    if (Array.isArray(v)) v.forEach(val => h.append(k, val));
    else h.set(k, v);
  }
  return h;
}

const server = http.createServer(async (nodeReq, nodeRes) => {
  try {
    const proto = (nodeReq.headers['x-forwarded-proto'] || '').split(',')[0].trim() || 'http';
    const host = nodeReq.headers['x-forwarded-host'] || nodeReq.headers.host || `localhost:${PORT}`;
    const url = `${proto}://${host}${nodeReq.url}`;
    const req = { method: nodeReq.method, url, headers: toHeaders(nodeReq.headers) };
    const response = await handle(req);

    nodeRes.statusCode = response.status;
    for (const [k, v] of response.headers) nodeRes.setHeader(k, v);

    if (nodeReq.method === 'HEAD' || !response.body) {
      nodeRes.end();
      return;
    }
    const body = Readable.fromWeb(response.body);
    body.on('error', err => { console.error('stream error:', err); nodeRes.destroy(); });
    nodeReq.on('close', () => body.destroy());
    body.pipe(nodeRes);
  } catch (e) {
    console.error('server error:', e);
    if (!nodeRes.headersSent) { nodeRes.statusCode = 500; nodeRes.end('Internal error'); }
    else nodeRes.destroy();
  }
});

server.listen(PORT, () => console.log(`drive-proxy listening on :${PORT}`));

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => { console.log(`${sig} received, closing`); server.close(() => process.exit(0)); });
}
