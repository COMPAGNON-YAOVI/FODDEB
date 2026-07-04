/**
 * FODDEB — api/fedapay-webhook.js
 * Point de terminaison webhook FedaPay (Vercel serverless)
 * ─────────────────────────────────────────────────────────────────
 * Pourquoi cette route existe :
 *   1. FedaPay poste son propre JSON { name, entity } — sans champ
 *      "action". Envoyé directement à GAS, doPost répondait
 *      "Action manquante" et aucun don n'était jamais confirmé.
 *   2. GAS ne peut pas lire les en-têtes HTTP — impossible d'y
 *      vérifier X-FEDAPAY-SIGNATURE. Vercel le peut. La signature
 *      est donc vérifiée ICI, puis le payload est forwardé à GAS
 *      sous la forme { action: 'fedapay_webhook', ...payload }.
 *   3. GAS re-vérifie ensuite la transaction par son ID auprès de
 *      l'API FedaPay avant toute confirmation (défense en profondeur).
 *
 * Variables d'environnement Vercel requises :
 *   GAS_URL                 = https://script.google.com/macros/s/XXX/exec
 *   FEDAPAY_WEBHOOK_SECRET  = clé secrète du point de terminaison
 *                             (Dashboard FedaPay → Webhooks → Click to reveal)
 *                             ATTENTION : différente entre mode test et live.
 *
 * Configuration côté FedaPay (Dashboard → Webhooks) :
 *   URL : https://foddeb.vercel.app/api/fedapay-webhook
 *   Événements : transaction.approved (minimum)
 * ─────────────────────────────────────────────────────────────────
 */

import crypto from 'crypto';

// Désactiver le bodyParser Vercel — la vérification HMAC exige
// le corps BRUT, octet pour octet. Un body re-sérialisé casse la signature.
export const config = {
  api: { bodyParser: false },
};

/** Lit le corps brut de la requête. */
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Vérifie X-FEDAPAY-SIGNATURE.
 * Format FedaPay : "t=<timestamp>,s=<signature>" où la signature est
 * HMAC-SHA256(secret, `${timestamp}.${rawBody}`) en hexadécimal.
 * Tolérance anti-replay : 5 minutes.
 * Fallback : certains environnements envoient un HMAC simple du corps —
 * on l'accepte aussi, GAS re-vérifiant de toute façon la transaction.
 */
function verifySignature(rawBody, header, secret) {
  if (!header || !secret) return false;

  const safeEqual = (a, b) => {
    const ba = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  };

  // Schéma t=...,s=... (avec horodatage)
  const parts = {};
  header.split(',').forEach((p) => {
    const [k, ...v] = p.split('=');
    if (k && v.length) parts[k.trim()] = v.join('=').trim();
  });

  if (parts.t && parts.s) {
    const age = Math.abs(Date.now() / 1000 - parseInt(parts.t, 10));
    if (isNaN(age) || age > 300) return false; // > 5 min → replay refusé
    const expected = crypto
      .createHmac('sha256', secret)
      .update(`${parts.t}.${rawBody}`)
      .digest('hex');
    return safeEqual(expected, parts.s);
  }

  // Fallback : HMAC simple du corps brut
  const expectedPlain = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  return safeEqual(expectedPlain, header);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Méthode non autorisée' });
  }

  const GAS_URL = process.env.GAS_URL;
  const SECRET  = process.env.FEDAPAY_WEBHOOK_SECRET;

  if (!GAS_URL || !SECRET) {
    console.error('[fedapay-webhook] GAS_URL ou FEDAPAY_WEBHOOK_SECRET manquant');
    // 200 volontaire : ne pas déclencher des retries FedaPay en boucle
    // pendant qu'on corrige la config — l'erreur est loggée côté Vercel.
    return res.status(200).json({ received: true, configured: false });
  }

  try {
    const rawBuffer = await readRawBody(req);
    const rawBody   = rawBuffer.toString('utf8');
    const signature = req.headers['x-fedapay-signature'] || '';

    if (!verifySignature(rawBody, signature, SECRET)) {
      console.warn('[fedapay-webhook] Signature invalide — requête rejetée');
      return res.status(401).json({ success: false, error: 'Signature invalide' });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return res.status(400).json({ success: false, error: 'JSON invalide' });
    }

    // Répondre 200 à FedaPay RAPIDEMENT est recommandé —
    // mais GAS répond en 2-5 s, sous le timeout FedaPay. On forwarde
    // de manière synchrone pour garantir le traitement (les fonctions
    // Vercel sont tuées dès que la réponse part).
    const gasResp = await fetch(GAS_URL, {
      method:   'POST',
      headers:  { 'Content-Type': 'text/plain' },
      redirect: 'follow',
      body:     JSON.stringify({ action: 'fedapay_webhook', ...payload }),
    });

    if (!gasResp.ok) {
      console.error('[fedapay-webhook] GAS HTTP', gasResp.status);
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('[fedapay-webhook] Erreur :', err.message);
    // 200 : GAS/fedapayStatus servira de filet via la page don-merci
    return res.status(200).json({ received: true, error: true });
  }
}
