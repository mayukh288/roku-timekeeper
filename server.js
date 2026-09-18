import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const VERSION = '1.7.7';
const root = dirname(fileURLToPath(import.meta.url));
const host = process.env.HOST || '0.0.0.0';
const port = Number(process.env.PORT || 3030);
const dataDir = process.env.DATA_DIR || root;
const defaultRokuHost = process.env.ROKU_HOST || '';
const watchdogMs = Number(process.env.WATCHDOG_MS || 10_000);

const settingsPath = join(dataDir, 'settings.json');

function log(...args) {
  // stdout -> `docker logs` (TrueNAS Apps > roku-timekeeper > View logs).
  // Never pass a PIN here.
  console.log(new Date().toISOString(), ...args);
}

let settings = {
  rokuHost: defaultRokuHost,
  pinSalt: '',
  pinHash: '',
  locked: true,
  lockAction: 'poweroff',
  chromecastInput: 'InputHDMI1',
  wakeMac: '',
  castStart: '08:00',
  castEnd: '22:30',
  passkeys: {},
  sessions: {},
  extraOrigins: [],
  expiresAt: null,
  lastAction: 'Awaiting setup',
  lastWatchdog: null,
};
let lastWatchdogSaved = '';

async function load() {
  await mkdir(dataDir, { recursive: true });
  if (existsSync(settingsPath)) {
    settings = { ...settings, ...JSON.parse(await readFile(settingsPath, 'utf8')) };
  }
  if (!settings.rokuHost && defaultRokuHost) settings.rokuHost = defaultRokuHost;
  // Expired while we were down -> boot locked.
  if (settings.expiresAt && Date.now() >= settings.expiresAt) {
    settings.locked = true;
    settings.expiresAt = null;
    settings.lastAction = 'Timer expired while offline — locked on boot';
    await save();
  }
}

async function save() {
  await mkdir(dataDir, { recursive: true });
  await writeFile(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf8');
}

function hash(pin, salt = settings.pinSalt) {
  return createHash('sha256').update(`${salt}:${pin}`).digest('hex');
}

function authorized(pin) {
  if (!settings.pinHash || typeof pin !== 'string') return false;
  const a = Buffer.from(hash(pin));
  const b = Buffer.from(settings.pinHash);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function validPin(pin) {
  return typeof pin === 'string' && /^\d{4,12}$/.test(pin);
}

const timeZone = process.env.TIMEZONE || 'America/Los_Angeles';
const wakeBroadcast = process.env.WAKE_BROADCAST || '192.168.1.255';
const tlsPort = Number(process.env.TLS_PORT || 3443);
const tlsCertPath = process.env.TLS_CERT || join(dataDir, 'tls', 'cert.pem');
const tlsKeyPath = process.env.TLS_KEY || join(dataDir, 'tls', 'key.pem');
const publicHost = process.env.PUBLIC_HOST || '192.168.1.107';
const SESSION_TTL_MS = 12 * 3600 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const pendingChallenges = new Map();
export const DEFAULT_CAST_START = '08:00';
export const DEFAULT_CAST_END = '22:30';

export function parseHM(s) {
  const m = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(s || '');
  if (!m) return null;
  return Number(m[1]) * 60 + Number(m[2]);
}

export function minutesInWindow(mins, start, end) {
  if (start <= end) return mins >= start && mins < end;
  return mins >= start || mins < end;
}

// "Night" = outside the Chromecast window (default 10:30pm–8am).
export function isNight(d = new Date(), tz = timeZone, startHM = DEFAULT_CAST_START, endHM = DEFAULT_CAST_END) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(d);
  const num = (t) => Number(parts.find((p) => p.type === t).value);
  const mins = (num('hour') % 24) * 60 + num('minute');
  const start = parseHM(startHM) ?? parseHM(DEFAULT_CAST_START);
  const end = parseHM(endHM) ?? parseHM(DEFAULT_CAST_END);
  return !minutesInWindow(mins, start, end);
}

// Chromecast locks switch the input while inside the window; outside always powers off.
export function lockCommand(s, now = new Date(), tz = timeZone) {
  if ((s.lockAction || 'poweroff') === 'chromecast' && !isNight(now, tz, s.castStart, s.castEnd)) {
    return /^InputHDMI[1-4]$/.test(s.chromecastInput) ? s.chromecastInput : 'InputHDMI1';
  }
  return 'PowerOff';
}

// ---------- Face ID / passkey (WebAuthn, ES256, platform authenticator) ----------
export function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function b64uDecode(s) {
  return Buffer.from(String(s || ''), 'base64url');
}

export function decodeCbor(buf, off = 0) {
  const first = buf[off];
  const major = first >> 5;
  const minor = first & 31;
  let pos = off + 1;
  const readLen = () => {
    if (minor < 24) return minor;
    if (minor === 24) {
      const v = buf[pos];
      pos += 1;
      return v;
    }
    if (minor === 25) {
      const v = buf.readUInt16BE(pos);
      pos += 2;
      return v;
    }
    if (minor === 26) {
      const v = buf.readUInt32BE(pos);
      pos += 4;
      return v;
    }
    throw new Error('Unsupported CBOR length');
  };
  if (major === 0 || major === 1) {
    const v = readLen();
    return [major === 0 ? v : -(v + 1), pos];
  }
  if (major === 2 || major === 3) {
    const len = readLen();
    const slice = buf.slice(pos, pos + len);
    pos += len;
    return [major === 2 ? slice : slice.toString('utf8'), pos];
  }
  if (major === 4) {
    const len = readLen();
    const arr = [];
    for (let i = 0; i < len; i++) {
      const [v, next] = decodeCbor(buf, pos);
      arr.push(v);
      pos = next;
    }
    return [arr, pos];
  }
  if (major === 5) {
    const len = readLen();
    const obj = new Map();
    for (let i = 0; i < len; i++) {
      const [k, p1] = decodeCbor(buf, pos);
      const [v, p2] = decodeCbor(buf, p1);
      obj.set(k, v);
      pos = p2;
    }
    return [obj, pos];
  }
  if (major === 6) {
    readLen();
    return decodeCbor(buf, pos);
  }
  if (major === 7) {
    if (minor === 20) return [false, pos];
    if (minor === 21) return [true, pos];
    if (minor === 22) return [null, pos];
    throw new Error('Unsupported CBOR simple value');
  }
  throw new Error('Unsupported CBOR type');
}

function parseAuthData(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 37) throw new Error('authData too short');
  const rpIdHash = buf.slice(0, 32);
  const flags = buf[32];
  const counter = buf.readUInt32BE(33);
  let credId = null;
  let cose = null;
  let pos = 37;
  if (flags & 0x40) {
    pos += 16;
    const credIdLen = buf.readUInt16BE(pos);
    pos += 2;
    credId = buf.slice(pos, pos + credIdLen);
    pos += credIdLen;
    const [coseMap, next] = decodeCbor(buf, pos);
    pos = next;
    if (!(coseMap instanceof Map)) throw new Error('Bad credential key');
    cose = coseMap;
  }
  return { rpIdHash, flags, counter, credId, cose };
}

function coseToJwk(cose) {
  if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) {
    throw new Error('Only ES256 P-256 keys supported');
  }
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) {
    throw new Error('Bad EC coordinates');
  }
  return { kty: 'EC', crv: 'P-256', x: b64uEncode(x), y: b64uEncode(y) };
}

function allowedHosts() {
  const hosts = new Set([publicHost]);
  const extra = Array.isArray(settings.extraOrigins) ? settings.extraOrigins : [];
  for (const o of extra) {
    try {
      hosts.add(new URL(o).hostname);
    } catch {}
  }
  return hosts;
}

export function originAllowed(origin) {
  try {
    const u = new URL(origin);
    return u.protocol === 'https:' && allowedHosts().has(u.hostname);
  } catch {
    return false;
  }
}

function rawToDer(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 64) throw new Error('Bad signature length');
  const trim = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const t = b.slice(i);
    return t[0] & 0x80 ? Buffer.concat([Buffer.from([0]), t]) : t;
  };
  const r = trim(raw.slice(0, 32));
  const s = trim(raw.slice(32));
  return Buffer.concat([
    Buffer.from([0x30, 2 + r.length + 2 + s.length, 0x02, r.length]),
    r,
    Buffer.from([0x02, s.length]),
    s,
  ]);
}

export function derToRaw(der) {
  let p = 0;
  if (der[p++] !== 0x30) throw new Error('Bad DER');
  let len = der[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[p++];
  }
  const takeInt = () => {
    if (der[p++] !== 0x02) throw new Error('Bad DER integer');
    const l = der[p++];
    let v = der.slice(p, p + l);
    p += l;
    if (v.length && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error('Bad DER integer size');
    return Buffer.concat([Buffer.alloc(32 - v.length), v]);
  };
  return Buffer.concat([takeInt(), takeInt()]);
}

export function verifyRegistration({ rpId, origin, attestationObject, clientDataJSON }) {
  const cd = JSON.parse(b64uDecode(clientDataJSON).toString('utf8'));
  if (cd.type !== 'webauthn.create') throw new Error('Bad ceremony type');
  if (cd.origin !== origin || !originAllowed(origin)) throw new Error('Origin not allowed');
  const [attObj] = decodeCbor(b64uDecode(attestationObject));
  if (!(attObj instanceof Map) || attObj.get('fmt') !== 'none') {
    throw new Error('Only none attestation supported');
  }
  if (!(attObj.get('attStmt') instanceof Map) || attObj.get('attStmt').size !== 0) {
    throw new Error('Bad attestation statement');
  }
  const authData = attObj.get('authData');
  const parsed = parseAuthData(authData);
  if (!parsed.credId || !parsed.cose) throw new Error('Missing credential');
  if (!parsed.rpIdHash.equals(createHash('sha256').update(rpId).digest())) {
    throw new Error('rpId mismatch');
  }
  if ((parsed.flags & 0x05) !== 0x05) throw new Error('User verification required');
  const jwk = coseToJwk(parsed.cose);
  return { challenge: cd.challenge, credId: b64uEncode(parsed.credId), x: jwk.x, y: jwk.y };
}

export function verifyAssertion({
  rpId,
  origin,
  stored,
  credentialId,
  authenticatorData,
  clientDataJSON,
  signature,
}) {
  const cd = JSON.parse(b64uDecode(clientDataJSON).toString('utf8'));
  if (cd.type !== 'webauthn.get') throw new Error('Bad ceremony type');
  if (cd.origin !== origin || !originAllowed(origin)) throw new Error('Origin not allowed');
  if (!b64uDecode(credentialId).equals(b64uDecode(stored.credId))) {
    throw new Error('Unknown credential');
  }
  const authData = b64uDecode(authenticatorData);
  if (authData.length < 37) throw new Error('Bad authenticator data');
  if (!authData.slice(0, 32).equals(createHash('sha256').update(rpId).digest())) {
    throw new Error('rpId mismatch');
  }
  if ((authData[32] & 0x04) === 0) throw new Error('User verification required');
  const counter = authData.readUInt32BE(33);
  if (!(counter > stored.counter || (stored.counter === 0 && counter === 0))) {
    throw new Error('Stale counter');
  }
  const key = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: stored.x, y: stored.y },
    format: 'jwk',
  });
  const data = Buffer.concat([authData, createHash('sha256').update(b64uDecode(clientDataJSON)).digest()]);
  if (!verify('sha256', data, key, rawToDer(b64uDecode(signature)))) {
    throw new Error('Bad signature');
  }
  return counter;
}

function pruneSessions() {
  if (!settings.sessions || typeof settings.sessions !== 'object') settings.sessions = {};
  const now = Date.now();
  for (const [t, s] of Object.entries(settings.sessions)) {
    if (!s || s.expires <= now) delete settings.sessions[t];
  }
  const keys = Object.keys(settings.sessions);
  while (keys.length > 10) delete settings.sessions[keys.shift()];
}

function issueSession() {
  pruneSessions();
  const token = randomBytes(32).toString('hex');
  settings.sessions[token] = { created: Date.now(), expires: Date.now() + SESSION_TTL_MS };
  save().catch(() => {});
  return token;
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function sessionFromReq(req) {
  const t = parseCookies(req).tk;
  const s = t && settings.sessions ? settings.sessions[t] : null;
  if (!s) return null;
  if (s.expires <= Date.now()) {
    delete settings.sessions[t];
    return null;
  }
  return { token: t, expires: new Date(s.expires).toISOString() };
}

function isAuthorized(req, input) {
  if (authorized(input.pin)) return true;
  return sessionFromReq(req) !== null;
}

function hostOf(req) {
  return String(req.headers.host || '').split(':')[0];
}

function takeChallenge(ch, kind) {
  const p = pendingChallenges.get(ch);
  pendingChallenges.delete(ch);
  if (!p || p.kind !== kind || p.expires <= Date.now()) return null;
  return p;
}

function sendWithCookie(res, token, data) {
  res.writeHead(200, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'set-cookie': `tk=${token}; Max-Age=${SESSION_TTL_MS / 1000}; Path=/; HttpOnly; Secure; SameSite=Lax`,
  });
  res.end(JSON.stringify(data));
}

function clearSessionCookie(res, data) {
  res.writeHead(200, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'set-cookie': 'tk=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax',
  });
  res.end(JSON.stringify(data));
}

function validHost(hostname) {
  // Only allow a plain LAN hostname or IP; this prevents the dashboard becoming an SSRF proxy.
  return (
    typeof hostname === 'string' && /^[a-zA-Z0-9.-]+$/.test(hostname) && hostname.length <= 253
  );
}

async function rokuKey(key, timeoutMs = 10000) {
  if (!validHost(settings.rokuHost)) throw new Error('Add the Roku local IP address first.');
  const url = `http://${settings.rokuHost}:8060/keypress/${key}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const response = await fetch(url, { method: 'POST', signal: controller.signal });
    let bodyText = '';
    try {
      bodyText = await response.text();
    } catch {
      bodyText = '<unreadable body>';
    }
    log(
      `roku POST ${url} -> HTTP ${response.status} in ${Date.now() - started}ms` +
        (bodyText ? ` body=${JSON.stringify(bodyText.slice(0, 200))}` : ' (empty body)')
    );
    if (!response.ok) throw new Error(`Roku returned HTTP ${response.status}`);
  } catch (error) {
    log(`roku POST ${url} FAILED after ${Date.now() - started}ms: ${error.message}`);
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export function buildWakePacket(mac) {
  const bytes = mac.split(':').map((p) => parseInt(p, 16));
  if (bytes.length !== 6 || bytes.some((b) => Number.isNaN(b) || b < 0 || b > 255)) {
    throw new Error('Invalid MAC address for wake packet');
  }
  const pkt = Buffer.alloc(102);
  pkt.fill(0xff, 0, 6);
  const raw = Buffer.from(bytes);
  for (let i = 0; i < 16; i++) raw.copy(pkt, 6 + i * 6);
  return pkt;
}

export function parsePowerMode(xml) {
  const m = /<power-mode>\s*([^<]*)\s*<\/power-mode>/i.exec(xml || '');
  return (m ? m[1] : '').trim();
}

// true = screen on. Any other reported mode (ready/standby/suspend/off/...)
// means the screen is off and needs a wake first; null = field missing.
// Note: this TV reports "Ready" in low-power standby, not "PowerOff".
export function tvIsOn(xml) {
  const mode = parsePowerMode(xml).toLowerCase();
  if (!mode) return null;
  return mode === 'poweron' || mode === 'on' || mode === 'displayon';
}

async function rokuQuery(path, timeoutMs = 3000) {
  if (!validHost(settings.rokuHost)) throw new Error('Add the Roku local IP address first.');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`http://${settings.rokuHost}:8060/${path}`, {
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Roku returned HTTP ${response.status}`);
    return await response.text();
  } finally {
    clearTimeout(timeout);
  }
}

function validMac(mac) {
  return /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(mac || '');
}

export function extractWakeMac(xml) {
  if (!xml) return null;
  const tag = (name) => {
    const m = new RegExp(`<${name}>\\s*([^<]*)\\s*<\\/${name}>`, 'i').exec(xml);
    return (m ? m[1] : '').trim();
  };
  const net = tag('network-type').toLowerCase();
  const mac = (net === 'wifi' ? tag('wifi-mac') || tag('ethernet-mac') : tag('ethernet-mac') || tag('wifi-mac')) || '';
  return validMac(mac) ? mac : null;
}
async function ensureWakeMac() {
  if (validMac(settings.wakeMac)) return settings.wakeMac;
  const mac = extractWakeMac(await rokuQuery('query/device-info', 4000));
  if (!mac) throw new Error('Could not learn TV MAC address');
  settings.wakeMac = mac;
  await save();
  log(`wake: learned TV MAC ${mac}`);
  return mac;
}

async function sendWake(mac) {
  const pkt = buildWakePacket(mac);
  const targets = [wakeBroadcast, '255.255.255.255', settings.rokuHost].filter(Boolean);
  await new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let pending = targets.length + 1;
    const done = () => {
      if (--pending <= 0) {
        try {
          sock.close();
        } catch {}
        resolve();
      }
    };
    setTimeout(() => {
      try {
        sock.close();
      } catch {}
      resolve();
    }, 3000).unref?.();
    sock.on('error', () => done());
    sock.bind(() => {
      try {
        sock.setBroadcast(true);
      } catch {}
      done();
      for (const host of targets) {
        sock.send(pkt, 9, host, (err) => {
          if (err) log(`wake: send to ${host} failed: ${err.message}`);
          done();
        });
      }
    });
  });
  log(`wake: magic packet sent for ${mac}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function tvAppId(cmd) {
  return `tvinput.${String(cmd || '').replace(/^input/i, '').toLowerCase()}`;
}

export function parseActiveApp(xml) {
  const attr = /<app[^>]*\sid="([^"]*)"/i.exec(xml || '');
  if (attr) return attr[1];
  const child = /<app[^>]*>[\s\S]*?<id>([^<]*)<\/id>/i.exec(xml || '');
  return child ? child[1] : null;
}

// False only when the TV is verifiably on AND already on the wanted input.
export function shouldEnforceSwitch({ powerOn, activeAppId, wantAppId }) {
  return !(
    powerOn === true &&
    typeof activeAppId === 'string' &&
    activeAppId.length > 0 &&
    typeof wantAppId === 'string' &&
    activeAppId.toLowerCase() === wantAppId.toLowerCase()
  );
}

// Chromecast lock: verify state first; wake + switch only when needed.
// Returns { skipped: true } when the TV is already on the wanted input.
async function switchToChromecast(cmd) {
  const want = tvAppId(cmd);
  let needWake = false;
  try {
    const [infoXml, appXml] = await Promise.all([
      rokuQuery('query/device-info', 3000),
      rokuQuery('query/active-app', 3000),
    ]);
    const on = tvIsOn(infoXml);
    const active = parseActiveApp(appXml);
    log(`state check: power-mode=${parsePowerMode(infoXml) || '(unknown)'} active-app=${active || '(unknown)'} want=${want}`);
    const learned = extractWakeMac(infoXml);
    if (learned && learned !== settings.wakeMac) {
      settings.wakeMac = learned;
      try { await save(); } catch { /* best-effort: enforcement must not fail on persistence */ }
      log(`wake: learned TV MAC ${learned} during state check`);
    }
    if (!shouldEnforceSwitch({ powerOn: on, activeAppId: active, wantAppId: want })) {
      log('already on the Chromecast input, skipping wake+switch');
      return { skipped: true };
    }
    needWake = on === false;
  } catch (error) {
    log(`state check failed (${error.message}), waking then switching`);
    needWake = true;
  }
  if (needWake) {
    try {
      await sendWake(await ensureWakeMac());
    } catch (error) {
      log(`wake: ${error.message}, trying input switch anyway`);
    }
    await sleep(4000);
  }
  try {
    await rokuKey(cmd, 9000);
  } catch (error) {
    if (needWake) throw new Error(`TV unreachable after wake attempt: ${error.message}`);
    throw error;
  }
  return { skipped: false };
}

async function sendLockCommand(cmd) {
  if (cmd === 'PowerOff') return rokuKey(cmd, 9000);
  return switchToChromecast(cmd);
}

async function lockTv(reason) {
  const cmd = lockCommand(settings);
  log(`lockTv: ${reason || '(no reason)'} via ${cmd}`);
  settings.locked = true;
  settings.expiresAt = null;
  try {
    const result = await sendLockCommand(cmd);
    settings.lastAction =
      cmd === 'PowerOff'
        ? reason || 'TV powered off — locked'
        : result && result.skipped
          ? 'Already on Chromecast — locked'
          : 'TV switched to Chromecast — locked';
    log(result && result.skipped ? 'lockTv: already there, state=locked' : `lockTv: ${cmd} acknowledged, state=locked`);
  } catch (error) {
    settings.lastAction = `Locked, but ${cmd} command failed: ${error.message}`;
    log(`lockTv: ${cmd} FAILED, state=locked (TV may already be off/unreachable)`);
  }
  await save();
}

async function enforce() {
  if (settings.expiresAt && Date.now() >= settings.expiresAt) {
    log(`timer expired (expiresAt=${new Date(settings.expiresAt).toISOString()}), locking`);
    await lockTv('Bonus time ended — TV powered off');
  }
}

// Locked-state watchdog: while locked, keep sending PowerOff so the physical
// remote only buys a few seconds. An unpowered TV just refuses connections
// until it is reachable again.
let watchdogBusy = false;
async function watchdog() {
  if (!settings.pinHash || !validHost(settings.rokuHost) || !settings.locked) return;
  if (watchdogBusy) {
    log('watchdog: previous attempt still in flight, skipping this round');
    return;
  }
  watchdogBusy = true;
  const cmd = lockCommand(settings);
  log(`watchdog: locked, sending ${cmd}`);
  let ok = true;
  let detail = `${cmd} acknowledged`;
  try {
    const result = await sendLockCommand(cmd);
    if (result && result.skipped) detail = 'already on Chromecast input';
  } catch (error) {
    ok = false;
    detail = error.message || 'request failed';
  }
  log(ok ? `watchdog result: ${detail}` : `watchdog result: no ack (${detail})`);
  settings.lastWatchdog = { at: new Date().toISOString(), ok, detail };
  watchdogBusy = false;
  const stamp = ok ? 'ok' : `fail:${detail}`;
  if (stamp !== lastWatchdogSaved) {
    lastWatchdogSaved = stamp;
    try {
      await save();
    } catch {
      // Non-fatal; next attempt retries.
    }
  }
}

export function computeState(s) {
  const hasTimer = s.expiresAt !== null && s.expiresAt !== undefined;
  const remainingMs = hasTimer ? Math.max(0, s.expiresAt - Date.now()) : 0;
  const locked = s.locked || (hasTimer && remainingMs === 0);
  return {
    configured: Boolean(s.pinHash && s.rokuHost),
    rokuHost: s.rokuHost,
    locked,
    mode: locked ? 'locked' : hasTimer ? 'timed' : 'open',
    lockAction: s.lockAction || 'poweroff',
    chromecastInput: /^InputHDMI[1-4]$/.test(s.chromecastInput) ? s.chromecastInput : 'InputHDMI1',
    night: isNight(),
    extraOrigins: Array.isArray(s.extraOrigins) ? s.extraOrigins : [],
    castStart: parseHM(s.castStart) === null ? DEFAULT_CAST_START : s.castStart,
    castEnd: parseHM(s.castEnd) === null ? DEFAULT_CAST_END : s.castEnd,
    remainingSeconds: hasTimer ? Math.ceil(remainingMs / 1000) : null,
    lastAction: s.lastAction,
    watchdog: {
      intervalMs: watchdogMs,
      lastAttemptAt: s.lastWatchdog?.at || null,
      lastOk: s.lastWatchdog?.ok ?? null,
      lastDetail: s.lastWatchdog?.detail || null,
    },
  };
}

function state() {
  return computeState(settings);
}

function send(res, status, data) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(data));
}

async function body(req) {
  let text = '';
  for await (const part of req) text += part;
  return JSON.parse(text || '{}');
}

async function handleRequest(req, res) {
  try {
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(await readFile(join(root, 'public', 'index.html')));
    }
    if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: true });
    if (req.method === 'GET' && req.url === '/api/state') {
      const sess = sessionFromReq(req);
      return send(res, 200, { ...state(), session: sess ? { expiresAt: sess.expires } : null });
    }
    if (req.method !== 'POST' || !req.url.startsWith('/api/')) {
      return send(res, 404, { error: 'Not found' });
    }
    const input = await body(req);
    if (req.url === '/api/setup') {
      const rokuHost = (input.rokuHost || defaultRokuHost || '').trim();
      log(`api setup: rokuHost=${rokuHost || '(missing)'}`);
      if (!validHost(rokuHost) || !validPin(input.pin)) {
        return send(res, 400, { error: 'Use a Roku IP/hostname and a 4–12 digit PIN.' });
      }
      settings.rokuHost = rokuHost;
      settings.pinSalt = randomBytes(16).toString('hex');
      settings.pinHash = hash(input.pin);
      await lockTv('Setup complete — TV powered off and locked');
      return send(res, 200, state());
    }
    if (req.url === '/api/webauthn/register/start') {
      if (!authorized(input.pin)) return send(res, 401, { error: 'Incorrect parent PIN.' });
      const rpId = hostOf(req);
      const challenge = randomBytes(32).toString('base64url');
      pendingChallenges.set(challenge, { kind: 'reg', rpId, expires: Date.now() + CHALLENGE_TTL_MS });
      return send(res, 200, { challenge, rpId, userId: Buffer.from('parent').toString('base64url') });
    }
    if (req.url === '/api/webauthn/register/finish') {
      let cd;
      try {
        cd = JSON.parse(b64uDecode(input.clientDataJSON).toString('utf8'));
      } catch {
        return send(res, 400, { error: 'Bad client data.' });
      }
      const pend = takeChallenge(cd.challenge, 'reg');
      if (!pend) return send(res, 400, { error: 'Challenge expired, retry.' });
      try {
        const cred = verifyRegistration({
          rpId: pend.rpId,
          origin: cd.origin,
          attestationObject: input.attestationObject,
          clientDataJSON: input.clientDataJSON,
        });
        if (!settings.passkeys || typeof settings.passkeys !== 'object') settings.passkeys = {};
        settings.passkeys[pend.rpId] = {
          credId: cred.credId,
          x: cred.x,
          y: cred.y,
          counter: 0,
          enrolledAt: new Date().toISOString(),
        };
        await save();
        log(`webauthn: Face ID enrolled for ${pend.rpId}`);
        return sendWithCookie(res, issueSession(), { ok: true });
      } catch (error) {
        return send(res, 400, { error: error.message });
      }
    }
    if (req.url === '/api/webauthn/auth/start') {
      const rpId = hostOf(req);
      const stored = settings.passkeys ? settings.passkeys[rpId] : null;
      if (!stored) {
        return send(res, 404, { error: 'Face ID is not enrolled on this address. Use PIN or enroll first.' });
      }
      const challenge = randomBytes(32).toString('base64url');
      pendingChallenges.set(challenge, { kind: 'auth', rpId, expires: Date.now() + CHALLENGE_TTL_MS });
      return send(res, 200, { challenge, rpId, allowCredentialId: stored.credId });
    }
    if (req.url === '/api/webauthn/auth/finish') {
      let cd;
      try {
        cd = JSON.parse(b64uDecode(input.clientDataJSON).toString('utf8'));
      } catch {
        return send(res, 400, { error: 'Bad client data.' });
      }
      const pend = takeChallenge(cd.challenge, 'auth');
      if (!pend) return send(res, 400, { error: 'Challenge expired, retry.' });
      const stored = settings.passkeys ? settings.passkeys[pend.rpId] : null;
      if (!stored) return send(res, 404, { error: 'Not enrolled.' });
      try {
        const counter = verifyAssertion({
          rpId: pend.rpId,
          origin: cd.origin,
          stored,
          credentialId: input.credentialId,
          authenticatorData: input.authenticatorData,
          clientDataJSON: input.clientDataJSON,
          signature: input.signature,
        });
        stored.counter = counter;
        await save();
        log(`webauthn: Face ID session started for ${pend.rpId}`);
        return sendWithCookie(res, issueSession(), { ok: true });
      } catch (error) {
        return send(res, 400, { error: error.message });
      }
    }
    if (req.url === '/api/webauthn/status') {
      const rpId = hostOf(req);
      return send(res, 200, { rpId, enrolled: Boolean(settings.passkeys && settings.passkeys[rpId]) });
    }
    if (req.url === '/api/webauthn/logout') {
      const sess = sessionFromReq(req);
      if (sess) delete settings.sessions[sess.token];
      await save().catch(() => {});
      return clearSessionCookie(res, { ok: true });
    }
    if (req.url === '/api/webauthn/forget') {
      if (!authorized(input.pin)) return send(res, 401, { error: 'Incorrect parent PIN.' });
      if (settings.passkeys) delete settings.passkeys[hostOf(req)];
      await save();
      return send(res, 200, { ok: true });
    }
    if (!isAuthorized(req, input)) {
      log(`api ${req.url}: rejected (bad PIN, no session)`);
      return send(res, 401, { error: 'Incorrect parent PIN.' });
    }
    if (req.url === '/api/bonus') {
      const minutes = Number(input.minutes);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 720) {
        return send(res, 400, { error: 'Bonus time must be 1–720 whole minutes.' });
      }
      settings.locked = false;
      settings.expiresAt = Date.now() + minutes * 60_000;
      settings.lastAction = `${minutes} minute(s) granted`;
      log(`api bonus: granted ${minutes} min, expiresAt=${new Date(settings.expiresAt).toISOString()}`);
      await save();
      return send(res, 200, state());
    }
    if (req.url === '/api/unlock') {
      settings.locked = false;
      settings.expiresAt = null;
      settings.lastAction = 'Unlocked by parent — no timer';
      log('api unlock: TV unlocked with no expiry (stays on until bonus time or lock)');
      await save();
      return send(res, 200, state());
    }
    if (req.url === '/api/pin') {
      if (!validPin(input.newPin)) {
        return send(res, 400, { error: 'New PIN must be 4–12 digits.' });
      }
      settings.pinSalt = randomBytes(16).toString('hex');
      settings.pinHash = hash(input.newPin);
      settings.lastAction = 'Parent PIN changed';
      log('api pin: parent PIN changed (lock state unchanged)');
      await save();
      return send(res, 200, state());
    }
    if (req.url === '/api/settings') {
      const beforeLock = { lockAction: settings.lockAction, chromecastInput: settings.chromecastInput, castStart: settings.castStart, castEnd: settings.castEnd };
      if (input.lockAction !== undefined) {
        if (input.lockAction !== 'poweroff' && input.lockAction !== 'chromecast') {
          return send(res, 400, { error: 'lockAction must be poweroff or chromecast.' });
        }
        settings.lockAction = input.lockAction;
      }
      if (input.chromecastInput !== undefined) {
        if (!/^InputHDMI[1-4]$/.test(input.chromecastInput)) {
          return send(res, 400, { error: 'chromecastInput must be InputHDMI1–InputHDMI4.' });
        }
        settings.chromecastInput = input.chromecastInput;
      }
      if (input.extraOrigins !== undefined) {
        const list = input.extraOrigins;
        const bad =
          !Array.isArray(list) ||
          list.length > 5 ||
          list.some((o) => {
            try {
              return new URL(o).protocol !== 'https:';
            } catch {
              return true;
            }
          });
        if (bad) return send(res, 400, { error: 'extraOrigins must be up to 5 https URLs.' });
        settings.extraOrigins = list;
      }
      for (const key of ['castStart', 'castEnd']) {
        if (input[key] !== undefined) {
          if (parseHM(input[key]) === null) {
            return send(res, 400, { error: 'Cast window times must be HH:MM (24h).' });
          }
          settings[key] = input[key];
        }
      }
      log(`api settings: lockAction=${settings.lockAction} chromecastInput=${settings.chromecastInput} window=${settings.castStart}-${settings.castEnd}`);
      await save();
      const lockChanged = beforeLock.lockAction !== settings.lockAction || beforeLock.chromecastInput !== settings.chromecastInput || beforeLock.castStart !== settings.castStart || beforeLock.castEnd !== settings.castEnd;
      if (lockChanged && settings.locked) {
        log(`api settings: lock-relevant change while locked, re-enforcing ${lockCommand(settings)}`);
        void watchdog().catch(() => {});
      }
      return send(res, 200, state());
    }
    if (req.url === '/api/lock') {
      log('api lock: requested by parent');
      await lockTv('Locked by parent');
      return send(res, 200, state());
    }
    return send(res, 404, { error: 'Not found' });
  } catch (error) {
    return send(res, 500, { error: error.message || 'Unexpected error' });
  }
}

const server = http.createServer(handleRequest);

await load();

// Importing this module (e.g. from tests) must not start timers or bind the port.
export const isMain =
  !process.argv[1] || process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
server.listen(port, host, () => {
  console.log(`Roku Timekeeper v${VERSION} on http://${host}:${port}`);
  log(
    `startup: rokuHost=${settings.rokuHost || '(none)'} locked=${settings.locked} ` +
      `expiresAt=${settings.expiresAt ? new Date(settings.expiresAt).toISOString() : 'none'} ` +
      `configured=${Boolean(settings.pinHash && settings.rokuHost)} ` +
      `watchdogMs=${watchdogMs} dataDir=${dataDir} lockAction=${settings.lockAction} ` +
      `chromecastInput=${settings.chromecastInput} timezone=${timeZone}`
  );
});
  if (existsSync(tlsCertPath) && existsSync(tlsKeyPath)) {
    try {
      https
        .createServer({ key: await readFile(tlsKeyPath), cert: await readFile(tlsCertPath) }, handleRequest)
        .listen(tlsPort, host, () => {
          log(`startup: https on port ${tlsPort} (Face ID works on the https address)`);
        });
    } catch (error) {
      log(`startup: https disabled, cert read failed: ${error.message}`);
    }
  } else {
    log('startup: https disabled (no cert in DATA_DIR/tls) — Face ID needs the https address');
  }
  setInterval(enforce, 1000).unref();
  setInterval(watchdog, watchdogMs).unref();
}
