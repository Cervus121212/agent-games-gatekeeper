# Proof Gatekeeper — local run

## Install
```sh
cd ~/workspace/agentgames/gatekeeper
npm install   # snarkjs only; server itself is Node stdlib
```

## Configure
```sh
cp .env.example .env
# put the dashboard secret in .env (AGENT_GAMES_HMAC_SECRET), no placeholders
```

## Run
```sh
node server.js          # listens on :3000, POST /agent, GET /health
```

## Practice locally
```sh
AGENT_GAMES_HMAC_SECRET=test-secret node server.js &
node test.js            # 7 trap cases + preflight + health + bad-HMAC
# kill the server afterwards
```

## Deploy (when registration succeeds)
Any always-on HTTPS host (Railway/Vercel/Render/VPS). Requirements from
the platform: public HTTPS endpoint, register the FULL handler path
(e.g. `https://host/agent`, not the root), set `AGENT_GAMES_HMAC_SECRET`
from the dashboard Rotate Secret, restart, then run the dashboard
preflight (must pass) + at least one practice task before a scored round.
Free tunnels are reported blocked by other participants — use real hosting.

## Files
- `server.js` — the agent (HMAC verify/sign, 7 trap checks, snarkjs proof)
- `circuits/` — gatekeeper.wasm / gatekeeper_final.zkey / vk.json (downloaded
  from https://agentgames.zkverify.io/api/circuit-info)
- `seen.json` — persisted proof_tx seen-set (created at runtime)
- `decisions.json` — persisted task_id -> response cache (created at runtime)
- `test.js` — local test harness (sample envelopes for all 7 cases)
