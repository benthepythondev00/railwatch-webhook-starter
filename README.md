# RailWatch webhook starter

Verify RailWatch signed webhooks and route the change alerts where you want them: a Discord channel, an n8n workflow, or your own code. Python and Node receivers, no dependencies, tested against a delivery signed by RailWatch's own signer.

[RailWatch](https://alerts.listingrail.com/?utm_source=github&utm_medium=repo&utm_campaign=webhook-starter) is a hosted change monitor. It watches Best Buy open-box and price changes, Zumper rent drops and new listings, and Greenhouse job boards plus tech-stack changes, then alerts by email, Slack, Discord, Telegram or a signed JSON webhook. It is made by Listingrail. This repo is the receiving end of that last channel.

If you came here looking for a Best Buy Discord monitor or a website change monitor you run yourself: this is not a scraper. RailWatch does the fetching. You only receive verified JSON.

## What a delivery looks like

RailWatch sends `POST` to your URL with:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-RailWatch-Signature` | `sha256=` + hex HMAC-SHA256 of the raw body, keyed with your `channel_secret` |
| `X-RailWatch-Delivery-Id` | the delivery id, for example `dlv_...` (also in the body as `delivery_id`) |

The body (shortened; the full sample is [fixtures/delivery.body.json](fixtures/delivery.body.json)):

```json
{
  "delivery_id": "dlv_demo456",
  "watch_id": "wat_demo123",
  "watch_name": "Austin 2BR under $1,800",
  "vertical": "real-estate-rent-drops",
  "event_count": 2,
  "events": [
    {
      "id": "evt_1",
      "identity": "zumper:12345",
      "change_type": "price_drop",
      "title": "Café Lofts, 2BR — East Austin",
      "summary": "Rent dropped from $1,950 to $1,799 (-7.7%)",
      "url": "https://www.zumper.com/apartment-buildings/p12345",
      "previous_price": 1950.0,
      "current_price": 1799.0,
      "delta_amount": -151.0,
      "delta_pct": -7.74,
      "added": [],
      "removed": [],
      "detected_at": "2026-11-26T10:00:00Z"
    }
  ],
  "attribution": "Monitored with RailWatch · https://alerts.listingrail.com"
}
```

`change_type` is one of `new_listing`, `open_box_arrival`, `price_drop`, `price_increase`, `restock`, `new_job`, `tech_added`, `tech_removed`, `details_changed`. `attribution` is left out on plans without branding.

## Verify the raw body, not parsed JSON

The signature covers the exact bytes RailWatch sent. RailWatch writes compact, key-sorted JSON with non-ASCII escaped (`é`) and floats as `1799.0`. If you parse the body and serialize it again (`JSON.stringify(req.body)` in Express, `json.dumps(request.json)` in Flask), the bytes change and a valid delivery fails. The tests in this repo check exactly that case.

There is no timestamp in the signature, so it proves who sent the body, not when. To stop a captured request from being replayed, keep the `delivery_id` values from verified bodies and ignore repeats. Use the body field, not the header: the header is not covered by the signature.

## Quick start

### 1. Create a webhook watch with your own secret

Webhook delivery needs the Pro plan ($49/month) or Agency ($149/month); see [pricing](https://alerts.listingrail.com). If you only want alerts in Discord, Slack or Telegram, the Starter plan ($19/month) sends them natively and you do not need this repo.

The signing secret is set through the API (`channel_secret`); the dashboard form does not have a field for it yet. Your `session_token` is the `token=` value in your dashboard link (`https://alerts.listingrail.com/app?token=...`).

```bash
SECRET=$(openssl rand -hex 32)   # keep this, the receiver needs it

curl -s https://alerts.listingrail.com/v1/watches \
  -H 'Content-Type: application/json' \
  -d '{
    "session_token": "tok_your_token",
    "vertical_slug": "best-buy-open-box-drops",
    "query": "https://www.bestbuy.com/site/searchpage.jsp?st=macbook+pro+m4+open+box",
    "name": "MacBook Pro M4 open-box",
    "channel": "webhook",
    "channel_target": "https://your-host.example.com/railwatch",
    "channel_secret": "'"$SECRET"'",
    "interval_minutes": 15
  }'
```

Vertical slugs: `real-estate-rent-drops` (Zumper search URL), `best-buy-open-box-drops` (Best Buy search or SKU URL), `tech-hiring-stack-alerts` (Greenhouse board URL or a domain). The live list is at [`/v1/verticals`](https://alerts.listingrail.com/v1/verticals).

### 2. Run a receiver

Python 3.9+, standard library only:

```bash
cd python
RAILWATCH_SECRET="$SECRET" DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..." python discord_relay.py
# listening on :8787/railwatch
```

Node 18+, no dependencies:

```bash
RAILWATCH_SECRET="$SECRET" DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..." node node/server.js
```

Both answer `401` on a bad signature, `200 duplicate ignored` on a repeated (replayed) delivery_id, and `502` if Discord refuses the post. The Discord message lists up to 10 events with links and turns off `@` mentions, so a listing title cannot ping your server. Leave `DISCORD_WEBHOOK_URL` empty to verify only and add your own handling.

Put the receiver behind HTTPS (a reverse proxy, Cloudflare Tunnel, or your platform's ingress) before you use it as `channel_target`.

### 3. Or use the functions in your own app

```python
from railwatch_verify import parse_verified, InvalidSignature

envelope = parse_verified(secret, request_body_bytes, headers.get("X-RailWatch-Signature"))
```

```js
const { verifySignature } = require('./node/verify');
// Express: app.post('/railwatch', express.raw({ type: 'application/json' }), handler)
if (!verifySignature(secret, req.body /* Buffer */, req.get('x-railwatch-signature'))) return res.sendStatus(401);
```

## n8n workflow

[n8n/railwatch-verify-to-discord.json](n8n/railwatch-verify-to-discord.json) is an importable workflow: Webhook (Raw Body on) → Code node that checks the HMAC → IF → HTTP Request to Discord → Respond 200, or Respond 401 on a bad signature.

After import: paste your secret into the first line of the Code node, set the Discord URL in "Post to Discord", activate the workflow, and use its production webhook URL as `channel_target`.

- n8n Cloud makes the `crypto` module available in the Code node ([n8n docs](https://docs.n8n.io/build/code-in-n8n/using-the-code-node.md)).
- Self-hosted n8n needs built-in modules allowed: `NODE_FUNCTION_ALLOW_BUILTIN=crypto` (set it on the Task Runners if you use them; [n8n docs](https://docs.n8n.io/hosting/configuration/configuration-examples/modules-in-code-node/)).
- The Code node reads the raw body from the binary property `data`. n8n's docs do not name that property for the Raw Body option, so if your first test run shows it under another name, change `'data'` in the Code node to match.

Status: the Code node logic is tested in this repo's test suite with mocked n8n inputs. The workflow has not yet been imported into a running n8n instance by us; if a node version differs in yours, open an issue with your n8n version.

## Tests

```bash
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/node.test.js
```

The fixture in `fixtures/` was produced by RailWatch's production signing function with the test secret `whsec_test_railwatch_starter_0001`. The tests check: the fixture verifies in Python, Node and the n8n Code node; a re-serialized body fails; a wrong secret, a tampered price, a missing or short header fail; replayed deliveries are ignored even with a changed header id; the relay end to end.

## FAQ

**Is this a Best Buy restock bot?** No. It runs no browser and fetches nothing from Best Buy. RailWatch's hosted monitor does the checking; this repo receives the alerts.

**Do I need it for Discord alerts?** Not if the built-in Discord channel (Starter, $19/month) looks the way you want. Use this when you want your own message format, filtering, several destinations, or to store events first.

**How is the signature made?** `"sha256=" + hex(HMAC_SHA256(channel_secret, raw_body))`, compared in constant time.

**Which plan sends webhooks?** Pro ($49/month, 15-minute checks) and Agency ($149/month, 5-minute checks). Free is one email watch every 6 hours.

## License

MIT. RailWatch is a service of Listingrail; this starter is free to copy into your own projects.
