'use strict';
// Verify RailWatch signed webhooks (X-RailWatch-Signature: sha256=<hex>).
// Pass the raw body Buffer you received, never JSON.stringify(req.body).
const crypto = require('node:crypto');

const SIGNATURE_HEADER = 'x-railwatch-signature';
const DELIVERY_ID_HEADER = 'x-railwatch-delivery-id';

function computeSignature(secret, rawBody) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function verifySignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader || !Buffer.isBuffer(rawBody)) return false;
  const expected = Buffer.from(computeSignature(secret, rawBody));
  const given = Buffer.from(String(signatureHeader).trim());
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

module.exports = { SIGNATURE_HEADER, DELIVERY_ID_HEADER, computeSignature, verifySignature };
