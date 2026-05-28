const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const express = require("express");
const Database = require("better-sqlite3");

const ROOT = __dirname;
const PANEL_FILE = path.join(ROOT, "G2Leafy.html");
const DATA_DIR = path.join(ROOT, "data");
const XRAY_DIR = path.join(DATA_DIR, "xray");
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "panel.db");
const XRAY_CONFIG_PATH = process.env.XRAY_CONFIG_PATH || path.join(XRAY_DIR, "config.json");
const XRAY_STATE_PATH = process.env.XRAY_STATE_PATH || path.join(XRAY_DIR, "runtime-state.json");
const PORT = Number(process.env.PANEL_PORT || 8080);
const XRAY_ENABLED = String(process.env.XRAY_ENABLED || "0") === "1";
const XRAY_COMMAND = process.env.XRAY_COMMAND || `xray run -c ${XRAY_CONFIG_PATH}`;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(XRAY_DIR, { recursive: true });

const app = express();
app.use(express.json({ limit: "4mb" }));

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

let xrayChild = null;
let xrayLock = false;
let xrayCooldownUntil = 0;
let opLocks = new Map();
let latestTelemetry = {
  totalRxGb: 0,
  totalTxGb: 0,
  connections: 0,
  cpuPct: 0,
  ramMb: 0,
  timestamp: new Date().toISOString()
};
const sseClients = new Set();
const auditRing = [];

function nowIso() {
  return new Date().toISOString();
}

function hashJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function recordAudit(level, action, details = "") {
  const at = nowIso();
  const row = { at, level, action, details };
  auditRing.push(row);
  if (auditRing.length > 1000) {
    auditRing.shift();
  }
  db.prepare(
    "INSERT INTO audit_logs(created_at, level, action, details) VALUES(?,?,?,?)"
  ).run(at, level, action, details);
  broadcastEvent("audit", row);
}

function broadcastEvent(type, payload) {
  const frame = `event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(frame);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS state_snapshots (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      payload TEXT NOT NULL,
      state_hash TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS inbounds (
      id TEXT PRIMARY KEY,
      tag TEXT NOT NULL UNIQUE,
      port INTEGER NOT NULL UNIQUE,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS outbounds (
      id TEXT PRIMARY KEY,
      tag TEXT NOT NULL UNIQUE,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS subscriptions (
      client_id TEXT PRIMARY KEY,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS routing_rules (
      id TEXT PRIMARY KEY,
      match_rule TEXT NOT NULL,
      outbound TEXT NOT NULL,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_policy (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS quota_counters (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      total_rx_gb REAL NOT NULL DEFAULT 0,
      total_tx_gb REAL NOT NULL DEFAULT 0,
      hours_used REAL NOT NULL DEFAULT 0,
      extra_hours REAL NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS op_locks (
      op_key TEXT PRIMARY KEY,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      level TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_clients_name ON clients(name);
    CREATE INDEX IF NOT EXISTS idx_inbounds_port ON inbounds(port);
    CREATE INDEX IF NOT EXISTS idx_outbounds_tag ON outbounds(tag);
  `);
}

function defaultState() {
  return {
    version: 2,
    updatedAt: nowIso(),
    inbounds: [{ id: "1", tag: "xray-vless-xhttp", proto: "vless", port: 443, net: "xhttp", sec: "tls", flow: "", sniff: true }],
    outbounds: [
      { id: "1", tag: "direct-out", proto: "freedom", target: "Direct Connection" },
      { id: "2", tag: "block-out", proto: "blackhole", target: "Drop Traffic" }
    ],
    clients: [],
    ipProfiles: [{ id: "1", name: "Codespace Dynamic", ip: "None", sni: "auto-locked.github.dev", lock: true, port: 443 }],
    routingRules: [{ id: "1", match: "geoip:private", outbound: "direct-out" }],
    subEntries: [],
    subProfiles: [],
    subClientSubscriptions: {},
    securityPolicyState: { ipLimit: 2, fail2ban: false, banMinutes: 60, savedAt: null },
    integrationSettings: {},
    quotaState: { hoursUsed: 0, extraHours: 0, totalRxGb: 0, totalTxGb: 0 },
    logs: []
  };
}

function withIds(arr) {
  return (arr || []).map((item, idx) => ({
    ...item,
    id: String(item?.id ?? `${Date.now()}_${idx}`)
  }));
}

function normalizeState(raw) {
  const base = defaultState();
  const merged = { ...base, ...(raw || {}) };
  merged.inbounds = withIds(merged.inbounds);
  merged.outbounds = withIds(merged.outbounds);
  merged.clients = withIds(merged.clients);
  merged.ipProfiles = withIds(merged.ipProfiles);
  merged.routingRules = withIds(merged.routingRules);
  merged.subEntries = withIds(merged.subEntries);
  merged.subProfiles = withIds(merged.subProfiles);
  if (!merged.subClientSubscriptions || typeof merged.subClientSubscriptions !== "object") {
    merged.subClientSubscriptions = {};
  }
  if (!merged.securityPolicyState || typeof merged.securityPolicyState !== "object") {
    merged.securityPolicyState = base.securityPolicyState;
  }
  if (!merged.quotaState || typeof merged.quotaState !== "object") {
    merged.quotaState = base.quotaState;
  }
  merged.updatedAt = nowIso();
  return merged;
}

function enforceUniqueness(state) {
  const checkUnique = (arr, key, label) => {
    const seen = new Set();
    for (const item of arr) {
      const value = String(item?.[key] ?? "").trim().toLowerCase();
      if (!value) continue;
      if (seen.has(value)) {
        throw new Error(`Duplicate ${label}: ${item[key]}`);
      }
      seen.add(value);
    }
  };

  checkUnique(state.inbounds, "tag", "inbound tag");
  checkUnique(state.inbounds, "port", "inbound port");
  checkUnique(state.outbounds, "tag", "outbound tag");
  checkUnique(state.clients, "id", "client id");
  checkUnique(state.clients, "name", "client name");
}

function validateState(state) {
  if (!Array.isArray(state.inbounds) || state.inbounds.length === 0) {
    throw new Error("At least one inbound is required");
  }
  if (!Array.isArray(state.outbounds) || state.outbounds.length === 0) {
    throw new Error("At least one outbound is required");
  }
  for (const inb of state.inbounds) {
    if (!inb.tag || Number(inb.port) <= 0) {
      throw new Error("Invalid inbound record");
    }
  }
  for (const out of state.outbounds) {
    if (!out.tag || !out.proto) {
      throw new Error("Invalid outbound record");
    }
  }
  enforceUniqueness(state);
}

function getState() {
  const row = db.prepare("SELECT payload FROM state_snapshots WHERE id = 1").get();
  if (!row) {
    const initial = defaultState();
    persistState(initial, "bootstrap", true);
    return initial;
  }
  return normalizeState(JSON.parse(row.payload));
}

function writeDomainTables(state) {
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM inbounds").run();
    db.prepare("DELETE FROM outbounds").run();
    db.prepare("DELETE FROM clients").run();
    db.prepare("DELETE FROM subscriptions").run();
    db.prepare("DELETE FROM routing_rules").run();

    const inbStmt = db.prepare("INSERT INTO inbounds(id, tag, port, payload, updated_at) VALUES(?,?,?,?,?)");
    for (const inb of state.inbounds) {
      inbStmt.run(String(inb.id), String(inb.tag), Number(inb.port), JSON.stringify(inb), nowIso());
    }

    const outStmt = db.prepare("INSERT INTO outbounds(id, tag, payload, updated_at) VALUES(?,?,?,?)");
    for (const out of state.outbounds) {
      outStmt.run(String(out.id), String(out.tag), JSON.stringify(out), nowIso());
    }

    const cStmt = db.prepare("INSERT INTO clients(id, name, payload, updated_at) VALUES(?,?,?,?)");
    for (const client of state.clients) {
      cStmt.run(String(client.id), String(client.name), JSON.stringify(client), nowIso());
    }

    const subStmt = db.prepare("INSERT INTO subscriptions(client_id, payload, updated_at) VALUES(?,?,?)");
    for (const [clientId, sub] of Object.entries(state.subClientSubscriptions || {})) {
      subStmt.run(clientId, JSON.stringify(sub), nowIso());
    }

    const rStmt = db.prepare("INSERT INTO routing_rules(id, match_rule, outbound, payload, updated_at) VALUES(?,?,?,?,?)");
    for (const rule of state.routingRules) {
      rStmt.run(String(rule.id), String(rule.match || ""), String(rule.outbound || ""), JSON.stringify(rule), nowIso());
    }

    db.prepare(
      "INSERT INTO security_policy(id, payload, updated_at) VALUES(1, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at"
    ).run(JSON.stringify(state.securityPolicyState || {}), nowIso());

    const q = state.quotaState || {};
    db.prepare(
      "INSERT INTO quota_counters(id, total_rx_gb, total_tx_gb, hours_used, extra_hours, updated_at) VALUES(1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET total_rx_gb=excluded.total_rx_gb, total_tx_gb=excluded.total_tx_gb, hours_used=excluded.hours_used, extra_hours=excluded.extra_hours, updated_at=excluded.updated_at"
    ).run(Number(q.totalRxGb || 0), Number(q.totalTxGb || 0), Number(q.hoursUsed || 0), Number(q.extraHours || 0), nowIso());
  });
  tx();
}

function renderXrayConfig(state) {
  return {
    log: { level: "warning" },
    inbounds: state.inbounds.map((i) => ({
      tag: i.tag,
      protocol: i.proto,
      port: Number(i.port),
      stream: { network: i.net, security: i.sec },
      sniffing: { enabled: !!i.sniff },
      settings: { flow: i.flow || "", secret: i.secret || "" }
    })),
    outbounds: state.outbounds.map((o) => ({
      tag: o.tag,
      protocol: o.proto,
      target: o.target,
      settings: { secret: o.secret || "" }
    })),
    routing: { rules: state.routingRules.map((r) => ({ match: r.match, outbound: r.outbound })) }
  };
}

function persistXrayConfig(state) {
  const cfg = renderXrayConfig(state);
  const cfgText = JSON.stringify(cfg, null, 2);
  const newHash = hashJson(cfg);

  if (fs.existsSync(XRAY_CONFIG_PATH)) {
    const prevText = fs.readFileSync(XRAY_CONFIG_PATH, "utf8");
    fs.writeFileSync(`${XRAY_CONFIG_PATH}.last-good`, prevText, "utf8");
  }

  fs.writeFileSync(XRAY_CONFIG_PATH, cfgText, "utf8");
  fs.writeFileSync(
    XRAY_STATE_PATH,
    JSON.stringify(
      {
        updatedAt: nowIso(),
        stateHash: hashJson(state),
        xrayConfigHash: newHash,
        desiredRunning: true
      },
      null,
      2
    ),
    "utf8"
  );
  return newHash;
}

function persistState(nextState, reason, skipXrayApply = false) {
  validateState(nextState);
  const normalized = normalizeState(nextState);
  const stateHash = hashJson(normalized);

  const tx = db.transaction(() => {
    db.prepare(
      "INSERT INTO state_snapshots(id, payload, state_hash, updated_at) VALUES(1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, state_hash=excluded.state_hash, updated_at=excluded.updated_at"
    ).run(JSON.stringify(normalized), stateHash, nowIso());
    writeDomainTables(normalized);
    db.prepare("INSERT INTO meta(key, value) VALUES('last_state_hash', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(stateHash);
  });
  tx();

  const cfgHash = persistXrayConfig(normalized);
  recordAudit("INFO", "state.persist", `${reason} hash=${stateHash} cfg=${cfgHash}`);
  broadcastEvent("state", { stateHash, reason, updatedAt: normalized.updatedAt });

  if (!skipXrayApply) {
    safeApplyXray("reload", `persist:${reason}`);
  }
  return normalized;
}

function parseXrayCommand() {
  const parts = XRAY_COMMAND.trim().split(/\s+/);
  return { cmd: parts[0], args: parts.slice(1) };
}

function ensureCooldown() {
  const now = Date.now();
  if (now < xrayCooldownUntil) {
    throw new Error("Xray control in cooldown window");
  }
}

function setCooldown(ms = 1500) {
  xrayCooldownUntil = Date.now() + ms;
}

function startXrayProcess(reason) {
  if (!XRAY_ENABLED) {
    recordAudit("INFO", "xray.start.skipped", `${reason}; XRAY_ENABLED=0`);
    return { status: "skipped", reason: "XRAY_ENABLED=0" };
  }
  if (xrayChild && !xrayChild.killed) {
    return { status: "already-running" };
  }
  const { cmd, args } = parseXrayCommand();
  xrayChild = spawn(cmd, args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  xrayChild.stdout.on("data", (buf) => {
    recordAudit("INFO", "xray.stdout", buf.toString("utf8").trim().slice(0, 500));
  });
  xrayChild.stderr.on("data", (buf) => {
    recordAudit("WARN", "xray.stderr", buf.toString("utf8").trim().slice(0, 500));
  });
  xrayChild.on("exit", (code, signal) => {
    recordAudit("WARN", "xray.exit", `code=${code} signal=${signal}`);
    xrayChild = null;
    broadcastEvent("xray", { running: false, code, signal });
  });
  recordAudit("INFO", "xray.start", reason);
  broadcastEvent("xray", { running: true });
  return { status: "started" };
}

function stopXrayProcess(reason) {
  if (!xrayChild) {
    return { status: "already-stopped" };
  }
  xrayChild.kill("SIGTERM");
  recordAudit("INFO", "xray.stop", reason);
  return { status: "stopping" };
}

function safeApplyXray(mode, reason) {
  if (xrayLock) {
    recordAudit("WARN", "xray.apply.skipped", "single-flight lock active");
    return { status: "locked" };
  }
  ensureCooldown();
  xrayLock = true;
  try {
    let result;
    if (mode === "restart") {
      stopXrayProcess(`restart:${reason}`);
      result = startXrayProcess(`restart:${reason}`);
    } else if (mode === "stop") {
      result = stopXrayProcess(`stop:${reason}`);
    } else {
      result = startXrayProcess(`reload:${reason}`);
    }
    setCooldown();
    return result;
  } finally {
    xrayLock = false;
  }
}

function withMutationLock(req, res, next) {
  const key = String(req.header("X-Idempotency-Key") || "");
  if (!key) return next();
  const existing = opLocks.get(key);
  if (existing && Date.now() - existing < 120000) {
    return res.status(409).json({ ok: false, error: "Duplicate operation key" });
  }
  opLocks.set(key, Date.now());
  db.prepare("INSERT INTO op_locks(op_key, created_at) VALUES(?, ?) ON CONFLICT(op_key) DO UPDATE SET created_at=excluded.created_at").run(key, nowIso());
  next();
}

function rotateTelemetry() {
  const q = db.prepare("SELECT total_rx_gb, total_tx_gb, hours_used, extra_hours FROM quota_counters WHERE id = 1").get() || {
    total_rx_gb: 0,
    total_tx_gb: 0,
    hours_used: 0,
    extra_hours: 0
  };

  const rxInc = Math.random() * 0.07;
  const txInc = Math.random() * 0.03;
  const hoursInc = 2 / 3600;
  const next = {
    totalRxGb: Number(q.total_rx_gb) + rxInc,
    totalTxGb: Number(q.total_tx_gb) + txInc,
    hoursUsed: Number(q.hours_used) + hoursInc,
    extraHours: Number(q.extra_hours || 0)
  };
  db.prepare(
    "UPDATE quota_counters SET total_rx_gb=?, total_tx_gb=?, hours_used=?, updated_at=? WHERE id=1"
  ).run(next.totalRxGb, next.totalTxGb, next.hoursUsed, nowIso());

  latestTelemetry = {
    totalRxGb: Number(next.totalRxGb.toFixed(3)),
    totalTxGb: Number(next.totalTxGb.toFixed(3)),
    connections: 40 + Math.floor(Math.random() * 20),
    cpuPct: Number((5 + Math.random() * 25).toFixed(1)),
    ramMb: Number((900 + Math.random() * 500).toFixed(0)),
    timestamp: nowIso()
  };
  broadcastEvent("telemetry", latestTelemetry);
}

function issueSubToken(clientId) {
  const secret = db.prepare("SELECT value FROM meta WHERE key='sub_secret'").get()?.value
    || crypto.randomBytes(24).toString("hex");
  db.prepare("INSERT INTO meta(key, value) VALUES('sub_secret', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(secret);
  const sig = crypto.createHmac("sha256", secret).update(clientId).digest("hex").slice(0, 24);
  return `${Buffer.from(clientId).toString("base64url")}.${sig}`;
}

function verifySubToken(token) {
  const [enc, sig] = String(token || "").split(".");
  if (!enc || !sig) return null;
  const clientId = Buffer.from(enc, "base64url").toString("utf8");
  const expect = issueSubToken(clientId).split(".")[1];
  return sig === expect ? clientId : null;
}

function reconcileOnStartup() {
  const state = getState();
  persistXrayConfig(state);
  safeApplyXray("reload", "startup-reconcile");
  recordAudit("INFO", "startup.reconcile", "state and xray config re-applied");
}

initSchema();
reconcileOnStartup();
setInterval(rotateTelemetry, 2000);

app.get("/", (_req, res) => {
  res.sendFile(PANEL_FILE);
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "g2leafy-panel", at: nowIso() });
});

app.get("/ready", (_req, res) => {
  const hasState = !!db.prepare("SELECT 1 AS ok FROM state_snapshots WHERE id=1").get();
  res.status(hasState ? 200 : 503).json({
    ok: hasState,
    xrayEnabled: XRAY_ENABLED,
    xrayRunning: !!xrayChild
  });
});

app.get("/state/hash", (_req, res) => {
  const row = db.prepare("SELECT state_hash, updated_at FROM state_snapshots WHERE id=1").get();
  res.json(row || { state_hash: null, updated_at: null });
});

app.get("/api/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();
  sseClients.add(res);
  res.write(`event: hello\ndata: ${JSON.stringify({ at: nowIso() })}\n\n`);
  req.on("close", () => sseClients.delete(res));
});

app.get("/api/state", (_req, res) => {
  res.json({ ok: true, state: getState(), telemetry: latestTelemetry });
});

app.put("/api/state", withMutationLock, (req, res) => {
  try {
    const payload = req.body?.state;
    if (!payload || typeof payload !== "object") {
      return res.status(400).json({ ok: false, error: "Missing state object" });
    }
    const state = persistState(payload, "api.put_state");
    return res.json({ ok: true, state });
  } catch (err) {
    recordAudit("ERROR", "api.put_state.failed", String(err.message || err));
    return res.status(400).json({ ok: false, error: String(err.message || err) });
  }
});

app.post("/api/backup", withMutationLock, (_req, res) => {
  const state = getState();
  const file = path.join(DATA_DIR, `backup-${Date.now()}.json`);
  fs.writeFileSync(file, JSON.stringify(state, null, 2), "utf8");
  recordAudit("INFO", "backup.create", file);
  res.json({ ok: true, file: path.basename(file) });
});

app.post("/api/quota/adjust", withMutationLock, (req, res) => {
  const extraHours = Number(req.body?.extraHours || 0);
  db.prepare("UPDATE quota_counters SET extra_hours=?, updated_at=? WHERE id=1").run(extraHours, nowIso());
  const state = getState();
  state.quotaState = state.quotaState || {};
  state.quotaState.extraHours = extraHours;
  persistState(state, "quota.adjust", true);
  res.json({ ok: true, extraHours });
});

app.get("/api/quota", (_req, res) => {
  const row = db.prepare("SELECT total_rx_gb, total_tx_gb, hours_used, extra_hours, updated_at FROM quota_counters WHERE id=1").get()
    || { total_rx_gb: 0, total_tx_gb: 0, hours_used: 0, extra_hours: 0, updated_at: nowIso() };
  res.json({
    ok: true,
    quota: {
      totalRxGb: Number(row.total_rx_gb),
      totalTxGb: Number(row.total_tx_gb),
      hoursUsed: Number(row.hours_used),
      extraHours: Number(row.extra_hours),
      updatedAt: row.updated_at
    }
  });
});

app.post("/api/xray/:action", withMutationLock, (req, res) => {
  const action = String(req.params.action || "");
  try {
    let result;
    if (action === "start") result = safeApplyXray("reload", "api.start");
    else if (action === "stop") result = safeApplyXray("stop", "api.stop");
    else if (action === "restart") result = safeApplyXray("restart", "api.restart");
    else return res.status(400).json({ ok: false, error: "Unknown xray action" });
    res.json({ ok: true, result });
  } catch (err) {
    recordAudit("ERROR", "api.xray.failed", String(err.message || err));
    res.status(409).json({ ok: false, error: String(err.message || err) });
  }
});

app.get("/sub/:token", (req, res) => {
  const clientId = verifySubToken(req.params.token);
  if (!clientId) return res.status(403).send("Invalid token");
  const state = getState();
  const client = state.clients.find((c) => String(c.id) === String(clientId));
  if (!client) return res.status(404).send("Client not found");

  const sub = state.subClientSubscriptions?.[clientId];
  if (!sub || !Array.isArray(sub.entries)) {
    return res.type("text/plain").send("");
  }
  const links = sub.entries
    .filter((e) => e.type === "proxy")
    .map((e) => `vless://${client.id}@${e.ip}:${e.port}?security=tls&type=xhttp&sni=auto-locked.github.dev#${encodeURIComponent(e.name || client.name)}`);
  res.type("text/plain").send(links.join("\n"));
});

app.get("/api/sub/link/:clientId", (req, res) => {
  const clientId = String(req.params.clientId);
  const token = issueSubToken(clientId);
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  res.json({ ok: true, link: `${proto}://${host}/sub/${token}` });
});

app.get("/api/logs", (_req, res) => {
  const rows = db.prepare("SELECT created_at, level, action, details FROM audit_logs ORDER BY id DESC LIMIT 500").all();
  res.json({ ok: true, logs: rows.reverse() });
});

app.listen(PORT, () => {
  recordAudit("INFO", "server.start", `listening on ${PORT}`);
});
