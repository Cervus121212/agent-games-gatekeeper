// Proof Gatekeeper agent server — zkVerify Agent Games
// Node.js stdlib only (+ snarkjs for local Groth16 proving).
// No frameworks. Secrets ONLY from env vars. Never log secrets.
//
// Protocol sources (public, 15 Nov 2026):
//   https://agentgames.zkverify.io/build
//   https://agentgames.zkverify.io/events/proof-gatekeeper
//   https://agentgames.zkverify.io/api/circuit-info
// See ../notes/GATEKEEPER_BUILD.md for the full spec + open questions.
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const snarkjs = require('snarkjs');

// ---------------------------------------------------------------- config
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM_PATH = process.env.GATEKEEPER_WASM || path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = process.env.GATEKEEPER_ZKEY || path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = process.env.GATEKEEPER_VK || path.join(__dirname, 'circuits', 'vk.json');
const SEEN_PATH = process.env.GATEKEEPER_SEEN_FILE || path.join(__dirname, 'seen.json');
const DECISIONS_PATH = process.env.GATEKEEPER_DECISIONS_FILE || path.join(__dirname, 'decisions.json');
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const KURIER_URL = process.env.KURIER_URL || 'https://api.kurier.xyz/api/v1';
const VK_HASH = process.env.GATEKEEPER_VK_HASH || '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
// BN128 scalar field modulus (for encoding 256-bit hashes as field elements).
const FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const PROOF_TIMEOUT_MS = parseInt(process.env.GATEKEEPER_PROOF_TIMEOUT_MS || '45000', 10);

if (!HMAC_SECRET) {
  console.warn('[gatekeeper] WARNING: AGENT_GAMES_HMAC_SECRET is not set. ' +
    'Inbound HMAC verification and response signing are DISABLED until it is set. ' +
    'Set it from the dashboard (Rotate Secret) and restart. Do NOT use a placeholder in production.');
}

// ---------------------------------------------------------------- state
function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function saveJson(file, obj) {
  try { fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n'); } catch (e) { console.error('[gatekeeper] save failed', file, e.message); }
}
// proof_tx values already decided (reuse detection). Persisted across restarts.
const seenProofTx = new Set(loadJson(SEEN_PATH, []));
// task_id -> last signed response body (idempotency: same task retried returns same decision).
const decisionsByTask = loadJson(DECISIONS_PATH, {});

let vk = null;
try { vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8')); } catch (e) { console.warn('[gatekeeper] vk.json not found, local proof verification disabled:', e.message); }

// ---------------------------------------------------------------- HMAC
function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}
// Header format is not spelled out in the public docs; accept raw hex and
// an optional "sha256=" prefix, in hex or base64. Comparison is timing-safe.
function verifySignature(rawBody, header) {
  if (!HMAC_SECRET) return false;
  if (!header) return false;
  let sig = String(header).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const digest = crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest();
  const expectedHex = digest.toString('hex');
  const expectedB64 = digest.toString('base64');
  const a = Buffer.from(sig, 'utf8');
  for (const expected of [expectedHex, expectedB64]) {
    const b = Buffer.from(expected, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}
function signBody(rawBody) {
  if (!HMAC_SECRET) return '';
  return hmacHex(HMAC_SECRET, rawBody);
}

// ---------------------------------------------------------------- helpers
function normAddr(s) {
  return String(s || '').trim().toLowerCase().replace(/^0x/, '');
}
function normHash(s) {
  return String(s || '').trim().toLowerCase();
}
function toBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  const s = String(v).trim();
  if (/^0x/i.test(s)) return BigInt(s);
  return BigInt(s);
}
// task_id like "gk_24_9d1" is a string; the circuit takes a field element.
// Encoding (GUESS — see GATEKEEPER_BUILD.md open questions): UTF-8 bytes
// as one big-endian integer. Short ids fit in the field; long ones wrap mod p.
function taskIdToField(taskId) {
  const bytes = Buffer.from(String(taskId || ''), 'utf8');
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return (n % FIELD_MODULUS).toString();
}
function addrToField(addr) {
  const n = BigInt('0x' + (normAddr(addr) || '0'));
  return (n % FIELD_MODULUS).toString();
}
// vk hashes are 256-bit hex and can exceed the BN128 scalar field, so reduce
// mod p. Equality is preserved (same hash -> same field element), which is
// all the circuit's vk check needs.
function vkHashToField(hex) {
  const n = BigInt('0x' + normHash(hex).replace(/^0x/, ''));
  return (n % FIELD_MODULUS).toString();
}

// ---------------------------------------------------------------- decision
// Trap-check order follows the order the traps are listed on
// /events/proof-gatekeeper (VK, THRESHOLD, REUSED, EXPIRED, RECIPIENT, AMOUNT).
// Order only matters when a task carries several traps at once; the platform
// does not document a priority, so this is an assumption.
function decide(input) {
  const registeredVk = normHash(input.registered_vk);
  const proofVk = normHash(input.proof_vk);
  const minimum = toBigInt(input.minimum);
  const balance = toBigInt(input.public_balance);
  const amount = toBigInt(input.amount);
  const maxTransfer = toBigInt(input.max_transfer);
  const expiryBlock = toBigInt(input.expiry_block);
  const currentBlock = toBigInt(input.current_block);
  const recipient = normAddr(input.recipient);
  const conditionRecipient = normAddr(input.condition_recipient);
  const proofTx = normHash(input.proof_tx || '');

  if (registeredVk && proofVk && registeredVk !== proofVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proofTx };
  }
  if (balance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', proofTx };
  }
  if (proofTx && seenProofTx.has(proofTx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', proofTx };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', proofTx };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', proofTx };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', proofTx };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proofTx };
}

// ---------------------------------------------------------------- proof
// Circuit inputs (recovered from gatekeeper.wasm via FNV-hash probing):
//   publicBalance, minimum, recipient, conditionRecipient, amount,
//   maxTransfer, expiryBlock, currentBlock, decision, taskId, salt,
//   registeredVkHash, proofVkHash   (13 inputs; VK nPublic = 13)
// The circuit constrains decision to the correct evaluation of the checks
// (verified locally: decision=1 with a failing check does NOT prove — see
// notes/GATEKEEPER_BUILD.md). So a proof with decision=0 is the proof of a
// correct REJECT, and decision=1 the proof of a correct APPROVE.
function buildCircuitInput(task, result) {
  const input = task.input;
  return {
    publicBalance: toBigInt(input.public_balance).toString(),
    minimum: toBigInt(input.minimum).toString(),
    recipient: addrToField(input.recipient),
    conditionRecipient: addrToField(input.condition_recipient),
    amount: toBigInt(input.amount).toString(),
    maxTransfer: toBigInt(input.max_transfer).toString(),
    expiryBlock: toBigInt(input.expiry_block).toString(),
    currentBlock: toBigInt(input.current_block).toString(),
    decision: result.decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id),
    salt: BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString(),
    registeredVkHash: vkHashToField(input.registered_vk),
    proofVkHash: vkHashToField(input.proof_vk),
  };
}

async function generateProof(task, result) {
  const circuitInput = buildCircuitInput(task, result);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  if (vk) {
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    if (!ok) throw new Error('local proof verification failed');
  }
  return { proof, public_signals: publicSignals };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' timed out after ' + ms + 'ms')), ms);
  });
  return Promise.race([promise.finally(() => clearTimeout(timer)), timeout]);
}

// Optional Kurier submission (fire-and-forget; never blocks the 60s response).
// Requires KURIER_API_KEY (mainnet). The response already carries the raw
// proof for the platform's offline re-verification, so Kurier is a bonus
// on-chain audit trail, not on the critical path.
async function submitToKurier(proof, publicSignals) {
  if (!KURIER_API_KEY) return null;
  try {
    const res = await fetch(`${KURIER_URL}/submit-proof/${KURIER_API_KEY}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: VK_HASH },
      }),
    });
    const job = await res.json();
    console.log('[gatekeeper] kurier job:', JSON.stringify(job).slice(0, 300));
    return job;
  } catch (e) {
    console.error('[gatekeeper] kurier submit failed (non-fatal):', e.message);
    return null;
  }
}

// ---------------------------------------------------------------- HTTP
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => {
      chunks.push(c);
      if (Buffer.concat(chunks).length > 1024 * 1024) { req.destroy(); reject(new Error('body too large')); }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(req, res, rawBody) {
  // 1. Verify HMAC on the RAW body BEFORE parsing.
  if (!verifySignature(rawBody, req.headers['x-agent-games-signature'])) {
    console.warn('[gatekeeper] bad/missing HMAC signature');
    return sendJson(res, 401, { error: 'invalid signature' });
  }
  let task;
  try { task = JSON.parse(rawBody.toString('utf8')); }
  catch { return sendJson(res, 400, { error: 'invalid json' }); }

  // 2. Preflight handshake.
  if (task.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }
  if (task.type && task.type !== 'agent-games.proof-gatekeeper.v1') {
    return sendJson(res, 400, { error: 'unknown task type' });
  }
  if (!task.input || !task.task_id) {
    return sendJson(res, 400, { error: 'missing task_id/input' });
  }

  // 3. Idempotency: same task_id retried -> same signed response.
  if (decisionsByTask[task.task_id]) {
    const cached = decisionsByTask[task.task_id];
    const body = Buffer.from(JSON.stringify(cached));
    const headers = { 'content-type': 'application/json', 'content-length': body.length };
    if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(body);
    res.writeHead(200, headers);
    return res.end(body);
  }

  // 4. Deterministic decision (fail closed: any error -> REJECT).
  let result;
  try {
    result = decide(task.input);
  } catch (e) {
    console.error('[gatekeeper] decide error (fail closed):', e.message);
    result = { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', proofTx: normHash(task.input.proof_tx || '') };
  }

  // 5. Proof. PROOF_REUSED tasks have no proof to submit (platform scoring
  // note) and are excluded from the reliability bonus — omit proof there.
  // Every other task gets a local Groth16 proof; if proving fails or times
  // out we still return the decision (a -2 proof penalty beats a -2 timeout
  // plus a wrong/missing decision).
  const response = { decision: result.decision, reason_code: result.reason_code };
  if (task.input.proof_tx) response.proof_tx = task.input.proof_tx;
  if (result.reason_code !== 'PROOF_REUSED') {
    try {
      const t0 = Date.now();
      const { proof, public_signals } = await withTimeout(
        generateProof(task, result), PROOF_TIMEOUT_MS, 'proof generation');
      response.proof = proof;
      response.public_signals = public_signals;
      console.log(`[gatekeeper] ${task.task_id} ${result.decision}/${result.reason_code} proof ok in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
      submitToKurier(proof, public_signals); // async, non-blocking
    } catch (e) {
      console.error(`[gatekeeper] ${task.task_id} proof FAILED (decision still returned):`, e.message);
    }
  } else {
    console.log(`[gatekeeper] ${task.task_id} REJECT/PROOF_REUSED (no proof attached)`);
  }

  // 6. Record proof_tx as seen + cache decision by task_id (persisted).
  if (result.proofTx) { seenProofTx.add(result.proofTx); saveJson(SEEN_PATH, [...seenProofTx]); }
  decisionsByTask[task.task_id] = response;
  saveJson(DECISIONS_PATH, decisionsByTask);

  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/' || url.pathname === '/agent')) {
      // GET on the registered path too: the dashboard health check may probe
      // the registered URL itself rather than /health.
      return sendJson(res, 200, {
        ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1',
        uptime_s: Math.floor(process.uptime()),
        hmac_configured: Boolean(HMAC_SECRET),
        kurier_configured: Boolean(KURIER_API_KEY),
        seen_proof_refs: seenProofTx.size,
      });
    }
    if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/')) {
      const rawBody = await readRawBody(req);
      return handleTask(req, res, rawBody);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[gatekeeper] handler error:', e.message);
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[gatekeeper] listening on http://${HOST}:${PORT} (POST /agent, GET /health)`);
    console.log(`[gatekeeper] hmac_configured=${Boolean(HMAC_SECRET)} kurier_configured=${Boolean(KURIER_API_KEY)}`);
  });
}

module.exports = { server, decide, verifySignature, hmacHex, taskIdToField, addrToField, vkHashToField, buildCircuitInput };
