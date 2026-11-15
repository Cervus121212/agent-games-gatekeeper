// Local test harness for the Gatekeeper server.
// Spins up server.js on :3456 with a throwaway HMAC secret, replays sample
// envelopes for all 7 trap varieties + edge cases, checks decisions,
// verifies returned Groth16 proofs locally against vk.json, and checks that
// bad HMACs are rejected and /health responds.
// Usage: AGENT_GAMES_HMAC_SECRET=test-secret node server.js &  node test.js
// (or just: node test.js — it spawns the server itself)
'use strict';
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const SECRET = 'test-secret-do-not-use-in-production';
const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const vk = JSON.parse(fs.readFileSync(path.join(__dirname, 'circuits', 'vk.json'), 'utf8'));

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}
async function post(pathname, obj, sigOverride) {
  const body = Buffer.from(JSON.stringify(obj));
  const res = await fetch(BASE + pathname, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': sigOverride !== undefined ? sigOverride : sign(body),
    },
    body,
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* ignore */ }
  return { status: res.status, json, headers: res.headers, raw: text };
}
async function get(pathname) {
  const res = await fetch(BASE + pathname);
  return { status: res.status, json: await res.json().catch(() => null) };
}

const REG_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
const RECIP = '0xDe42a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f01';
function task(id, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: id,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: REG_VK, proof_vk: REG_VK,
      minimum: '1000', public_balance: '1460',
      expiry_block: 19842201, current_block: 19832000,
      recipient: RECIP, condition_recipient: RECIP,
      amount: '500', max_transfer: '1000',
      proof_tx: '0x' + id.replace(/[^0-9a-f]/gi, '').padEnd(64, 'a').slice(0, 64),
      ...overrides,
    },
  };
}

const CASES = [
  { name: 'VALID approve', t: task('gk_valid_1'), want: ['APPROVE', 'VALID_CONDITION'], proof: true },
  { name: 'VK_SUBSTITUTION', t: task('gk_vk_1', { proof_vk: OTHER_VK }), want: ['REJECT', 'VK_SUBSTITUTION'], proof: true },
  { name: 'THRESHOLD_MISMATCH', t: task('gk_thr_1', { public_balance: '999' }), want: ['REJECT', 'THRESHOLD_MISMATCH'], proof: true },
  { name: 'PROOF_REUSED (replay of VALID proof_tx)', t: task('gk_reused_1', { proof_tx: task('gk_valid_1').input.proof_tx }), want: ['REJECT', 'PROOF_REUSED'], proof: false },
  { name: 'EXPIRED (current == expiry)', t: task('gk_exp_1', { current_block: 19842201 }), want: ['REJECT', 'EXPIRED_CONDITION'], proof: true },
  { name: 'RECIPIENT_MISMATCH', t: task('gk_rec_1', { condition_recipient: '0x1111111111111111111111111111111111111111' }), want: ['REJECT', 'RECIPIENT_MISMATCH'], proof: true },
  { name: 'AMOUNT_OVERFLOW', t: task('gk_amt_1', { amount: '1001' }), want: ['REJECT', 'AMOUNT_OVERFLOW'], proof: true },
  { name: 'EDGE balance == minimum approves', t: task('gk_edge_1', { public_balance: '1000' }), want: ['APPROVE', 'VALID_CONDITION'], proof: true },
  { name: 'EDGE amount == max approves', t: task('gk_edge_2', { amount: '1000' }), want: ['APPROVE', 'VALID_CONDITION'], proof: true },
  { name: 'EDGE current == expiry-1 approves', t: task('gk_edge_3', { current_block: 19842200 }), want: ['APPROVE', 'VALID_CONDITION'], proof: true },
];

(async () => {
  // Clean runtime state so the reused case is deterministic.
  for (const f of ['seen.json', 'decisions.json']) {
    try { fs.unlinkSync(path.join(__dirname, f)); } catch { /* ignore */ }
  }
  const server = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));
  const stop = () => { try { server.kill('SIGTERM'); } catch { /* ignore */ } };
  process.on('exit', stop);

  // Wait for health.
  let up = false;
  for (let i = 0; i < 30; i++) {
    try { const h = await get('/health'); if (h.status === 200 && h.json && h.json.ok) { up = true; break; } } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  let pass = 0, fail = 0;
  const check = (name, ok, extra = '') => {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
    ok ? pass++ : fail++;
  };
  if (!up) { console.log('FAIL  server did not come up'); process.exitCode = 1; stop(); return; }
  check('health endpoint responds', true);

  // Preflight (signed).
  const pre = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  check('preflight returns {ok:true, protocolVersion:v1} signed',
    pre.status === 200 && pre.json && pre.json.ok === true && pre.json.protocolVersion === 'v1' &&
    typeof pre.headers.get('x-agent-games-signature') === 'string' &&
    pre.headers.get('x-agent-games-signature') === sign(Buffer.from(JSON.stringify(pre.json))));

  // Bad HMAC rejected.
  const bad = await post('/agent', task('gk_bad_1'), 'deadbeef');
  check('bad HMAC -> 401', bad.status === 401);
  const missing = await post('/agent', task('gk_bad_2'), '');
  check('missing HMAC -> 401', missing.status === 401);

  // Trap cases.
  for (const c of CASES) {
    const t0 = Date.now();
    const r = await post('/agent', c.t);
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    const sigOk = r.headers.get('x-agent-games-signature') === sign(Buffer.from(JSON.stringify(r.json)));
    const decOk = r.status === 200 && r.json && r.json.decision === c.want[0] && r.json.reason_code === c.want[1];
    check(`${c.name}: ${c.want[0]}/${c.want[1]} + signed (${secs}s)`, decOk && sigOk,
      decOk ? '' : `got ${r.status} ${JSON.stringify(r.json)}`);
    if (c.proof) {
      if (r.json && r.json.proof && r.json.public_signals) {
        try {
          const ok = await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
          check(`${c.name}: returned proof verifies locally`, ok === true,
            `public_signals=${JSON.stringify(r.json.public_signals)}`);
        } catch (e) { check(`${c.name}: returned proof verifies locally`, false, e.message); }
      } else {
        check(`${c.name}: proof present in response`, false, 'no proof/public_signals in response');
      }
    } else {
      check(`${c.name}: no proof attached (excluded)`, !(r.json && r.json.proof));
    }
  }

  // Idempotency: replay VALID task_id -> same decision, no double-count.
  const replay = await post('/agent', CASES[0].t);
  check('idempotent replay of task_id returns same decision',
    replay.status === 200 && replay.json && replay.json.decision === 'APPROVE');

  console.log(`\n${pass} passed, ${fail} failed`);
  stop();
  // Exit explicitly: the spawned server's snarkjs handles can keep the
  // event loop alive after SIGTERM, so do not rely on natural exit.
  setTimeout(() => process.exit(fail ? 1 : 0), 500);
})().catch((e) => { console.error('harness error', e); process.exitCode = 1; });
