'use strict';
// RAILWATCH_SECRET=... DISCORD_WEBHOOK_URL=... node node/server.js   (POST /railwatch on :8787)
// Node 18+, no dependencies.
const http = require('node:http');
const { verifySignature, SIGNATURE_HEADER } = require('./verify');

const MAX_BODY = 1_000_000;

function discordMessage(env, limit = 10) {
  const lines = [`**${env.watch_name || 'RailWatch'}**: ${env.event_count || 0} change(s)`];
  for (const ev of (env.events || []).slice(0, limit)) {
    const title = ev.title || ev.identity || 'change';
    const head = ev.url ? `[${title}](<${ev.url}>)` : title;
    lines.push(`- \`${ev.change_type || 'change'}\` ${head}: ${ev.summary || ''}`);
  }
  return { content: lines.join('\n').slice(0, 1990), allowed_mentions: { parse: [] } };
}

function createServer({
  secret = process.env.RAILWATCH_SECRET || '',
  discordUrl = process.env.DISCORD_WEBHOOK_URL || '',
  path = process.env.RELAY_PATH || '/railwatch',
  send = (url, payload) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) }),
} = {}) {
  const seen = new Set();
  return http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== path) { res.writeHead(404).end('not found'); return; }
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) tooBig = true; else chunks.push(c);
    });
    req.on('end', async () => {
      if (tooBig) { res.writeHead(413).end('too large'); return; }
      const raw = Buffer.concat(chunks);
      if (!verifySignature(secret, raw, req.headers[SIGNATURE_HEADER])) { res.writeHead(401).end('invalid signature'); return; }
      let env;
      try { env = JSON.parse(raw.toString('utf8')); } catch (e) { res.writeHead(400).end('bad json'); return; }
      // Key on the signed body's delivery_id: the x-railwatch-delivery-id header is not signed.
      const id = env.delivery_id;
      if (id && seen.has(id)) { res.writeHead(200).end('duplicate ignored'); return; }
      if (id) seen.add(id);
      try {
        if (discordUrl) {
          const r = await send(discordUrl, discordMessage(env));
          if (r && r.ok === false) throw new Error(`discord ${r.status}`);
        }
        res.writeHead(200).end('ok');
      } catch (e) {
        if (id) seen.delete(id);
        res.writeHead(502).end('relay failed');
      }
    });
  });
}

module.exports = { createServer, discordMessage };

if (require.main === module) {
  if (!process.env.RAILWATCH_SECRET) {
    console.error('Set RAILWATCH_SECRET to the channel_secret you gave RailWatch.');
    process.exit(1);
  }
  const port = Number(process.env.PORT || 8787);
  createServer().listen(port, () => console.log(`listening on :${port}${process.env.RELAY_PATH || '/railwatch'}`));
}
