'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { verifySignature } = require('../node/verify');
const { createServer, discordMessage } = require('../node/server');

const ROOT = path.join(__dirname, '..');
const BODY = fs.readFileSync(path.join(ROOT, 'fixtures', 'delivery.body.json'));
const META = JSON.parse(fs.readFileSync(path.join(ROOT, 'fixtures', 'delivery.meta.json'), 'utf8'));
const SECRET = META.secret;
const SIG = META.headers['X-RailWatch-Signature'];

test('fixture from the production signer verifies on raw bytes', () => {
  assert.equal(verifySignature(SECRET, BODY, SIG), true);
});

test('JSON.stringify of the parsed body does not verify', () => {
  const reser = Buffer.from(JSON.stringify(JSON.parse(BODY.toString('utf8'))));
  assert.notDeepEqual(reser, BODY);
  assert.equal(verifySignature(SECRET, reser, SIG), false);
});

test('rejects wrong secret, tampered body, missing header, non-buffer', () => {
  assert.equal(verifySignature('other', BODY, SIG), false);
  assert.equal(verifySignature(SECRET, Buffer.from(BODY.toString().replace('1799.0', '1.0')), SIG), false);
  assert.equal(verifySignature(SECRET, BODY, undefined), false);
  assert.equal(verifySignature(SECRET, BODY.toString(), SIG), false);
  assert.equal(verifySignature(SECRET, BODY, 'sha256=short'), false);
});

test('relay: valid -> Discord, duplicate ignored, bad signature 401', async () => {
  const sent = [];
  const server = createServer({ secret: SECRET, discordUrl: 'https://discord.invalid/x', send: async (u, p) => { sent.push(p); return { ok: true }; } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/railwatch`;
  const post = (sig, id) => fetch(url, { method: 'POST', body: BODY, headers: { 'content-type': 'application/json', 'x-railwatch-signature': sig, 'x-railwatch-delivery-id': id } });
  try {
    assert.equal((await post(SIG, 'dlv_n1')).status, 200);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].allowed_mentions.parse.length, 0);
    const dup = await post(SIG, 'dlv_n1');
    assert.equal(await dup.text(), 'duplicate ignored');
    // replay with a changed (unsigned) header id is still a duplicate
    const dup2 = await post(SIG, 'dlv_other_header');
    assert.equal(await dup2.text(), 'duplicate ignored');
    assert.equal((await post('sha256=' + '0'.repeat(64), 'dlv_n2')).status, 401);
    assert.equal(sent.length, 1);
  } finally {
    server.close();
  }
});

test('n8n Code node logic (run outside n8n with mocked $input and helpers)', async () => {
  const wf = JSON.parse(fs.readFileSync(path.join(ROOT, 'n8n', 'railwatch-verify-to-discord.json'), 'utf8'));
  const code = wf.nodes.find((n) => n.type === 'n8n-nodes-base.code').parameters.jsCode
    .replace("'replace-with-your-channel-secret'", JSON.stringify(SECRET));
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const run = (sig) => {
    const $input = { first: () => ({ json: { headers: { 'x-railwatch-signature': sig, 'x-railwatch-delivery-id': 'dlv_demo456' } } }) };
    const ctx = { helpers: { getBinaryDataBuffer: async () => BODY } };
    return new AsyncFunction('$input', 'require', code).call(ctx, $input, require);
  };
  const ok = await run(SIG);
  assert.equal(ok[0].json.valid, true);
  assert.equal(ok[0].json.deliveryId, 'dlv_demo456');
  assert.match(ok[0].json.discord.content, /price_drop/);
  const bad = await run('sha256=' + '0'.repeat(64));
  assert.equal(bad[0].json.valid, false);
  // workflow wiring: true branch -> Discord, false branch -> 401
  assert.equal(wf.connections['Valid?'].main[0][0].node, 'Post to Discord');
  assert.equal(wf.connections['Valid?'].main[1][0].node, 'Respond 401');
  assert.equal(wf.nodes[0].parameters.options.rawBody, true);
  // no real secret or webhook URL ships in the template
  assert.match(wf.nodes.find((n) => n.name === 'Post to Discord').parameters.url, /REPLACE/);
  assert.equal(crypto.timingSafeEqual(Buffer.from('a'), Buffer.from('a')), true);
});
