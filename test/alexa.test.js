import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { computeState, encryptSecret, decryptSecret, buildAnnounceBody, postAnnouncement, bonusWarnDue, autoWarnDue, alexaLockSpeech, ALEXA_WARN_MS, ALEXA_MAX_SPEECH } from '../server.js';

describe('alexa vault (AES-256-GCM)', () => {
  it('round-trips a token', () => {
    const key = randomBytes(32);
    const enc = encryptSecret('vm-secret-token', key);
    assert.equal(decryptSecret(enc, key), 'vm-secret-token');
  });

  it('accepts a hex-string key too', () => {
    const key = randomBytes(32).toString('hex');
    assert.equal(decryptSecret(encryptSecret('abc', key), key), 'abc');
  });

  it('rejects the wrong key and tampered ciphertext', () => {
    const enc = encryptSecret('vm-secret-token', randomBytes(32));
    assert.throws(() => decryptSecret(enc, randomBytes(32)));
    assert.throws(() => decryptSecret({ ...enc, tag: Buffer.from('tampereddiv12').toString('base64') }, randomBytes(32)));
    const tampered = { ...enc, data: Buffer.from('x'.repeat(Buffer.from(enc.data, 'base64').length)).toString('base64') };
    assert.throws(() => decryptSecret(tampered, randomBytes(32)));
  });

  it('rejects short keys and missing secrets', () => {
    assert.throws(() => encryptSecret('x', randomBytes(16)));
    assert.throws(() => decryptSecret(null, randomBytes(32)));
  });

  it('never leaves the plaintext inside the stored blob', () => {
    const enc = encryptSecret('vm-secret-token', randomBytes(32));
    assert.ok(!JSON.stringify(enc).includes('vm-secret-token'));
  });
});

describe('bonus 5-minute warning gate', () => {
  const now = Date.now();
  const base = { locked: false, expiresAt: now + 4 * 60_000, warnedFor: null, nowMs: now };

  it('fires inside the window', () => {
    assert.equal(bonusWarnDue(base), true);
  });

  it('stays quiet far out, at/after expiry, when locked, or when already warned', () => {
    assert.equal(bonusWarnDue({ ...base, expiresAt: now + 6 * 60_000 }), false);
    assert.equal(bonusWarnDue({ ...base, expiresAt: now }), false);
    assert.equal(bonusWarnDue({ ...base, locked: true }), false);
    assert.equal(bonusWarnDue({ ...base, warnedFor: base.expiresAt }), false);
    assert.equal(bonusWarnDue({ ...base, expiresAt: null }), false);
  });

  it('fires again for a fresh timer after the old one warned', () => {
    assert.equal(bonusWarnDue({ ...base, expiresAt: now + 3 * 60_000, warnedFor: base.expiresAt }), true);
  });
});

describe('auto-lock 5-minute warning gate', () => {
  const at = (h, m) => new Date(Date.UTC(2026, 5, 15, h, m));
  const base = { locked: false, autoLockAt: '21:30', firedFor: null, warnedFor: null, tz: 'UTC' };

  it('fires within 5 minutes of the scheduled lock', () => {
    const r = autoWarnDue({ ...base, now: at(21, 25) });
    assert.equal(r.due, true);
    assert.equal(r.key, '2026-06-15 21:30');
  });

  it('stays quiet far out, at/after the time, once fired, once warned, or when locked', () => {
    assert.equal(autoWarnDue({ ...base, now: at(21, 24) }).due, false);
    assert.equal(autoWarnDue({ ...base, now: at(21, 30) }).due, false);
    assert.equal(autoWarnDue({ ...base, now: at(21, 25), firedFor: '2026-06-15' }).due, false);
    assert.equal(autoWarnDue({ ...base, now: at(21, 25), warnedFor: '2026-06-15 21:30' }).due, false);
    assert.equal(autoWarnDue({ ...base, now: at(21, 25), locked: true }).due, false);
    assert.equal(autoWarnDue({ ...base, now: at(21, 25), autoLockAt: null }).due, false);
    assert.equal(autoWarnDue({ ...base, now: at(21, 25), autoLockAt: 'bogus' }).due, false);
  });

  it('warns again the next day', () => {
    const r = autoWarnDue({ ...base, now: new Date(Date.UTC(2026, 5, 16, 21, 27)), warnedFor: '2026-06-15 21:30' });
    assert.equal(r.due, true);
    assert.equal(r.key, '2026-06-16 21:30');
  });
});

describe('lock announcement speech', () => {
  it('says shut off for PowerOff, switch for Chromecast', () => {
    assert.match(alexaLockSpeech('PowerOff'), /Turning off/);
    assert.match(alexaLockSpeech('InputHDMI1'), /Chromecast/);
  });
});

describe('announcement POST', () => {
  it('sends token/device/speech JSON and caps speech length', async () => {
    let seen;
    const stub = async (url, opts) => {
      seen = { url, opts: { ...opts, body: JSON.parse(opts.body) } };
      return { ok: true, text: async () => '{"success":true}' };
    };
    await postAnnouncement({ url: 'https://x.test/announce', token: 'tok', device: 'dev', speech: 'y'.repeat(ALEXA_MAX_SPEECH + 50) }, stub);
    assert.equal(seen.url, 'https://x.test/announce');
    assert.equal(seen.opts.method, 'POST');
    assert.deepEqual(Object.keys(seen.opts.body).sort(), ['device', 'speech', 'token']);
    assert.equal(seen.opts.body.speech.length, ALEXA_MAX_SPEECH);
  });

  it('builds the v3 body shape', () => {
    assert.deepEqual(buildAnnounceBody('tok', 'dev', 'hi'), { token: 'tok', device: 'dev', speech: 'hi' });
  });

  it('throws on HTTP errors and on timeout', async () => {
    const failing = async () => ({ ok: false, status: 401, text: async () => 'bad token' });
    await assert.rejects(postAnnouncement({ url: 'https://x/announce', token: 't', device: 'd', speech: 's' }, failing), /HTTP 401/);
    const hanging = (_url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('aborted'))));
    await assert.rejects(postAnnouncement({ url: 'https://x/announce', token: 't', device: 'd', speech: 's', timeoutMs: 30 }, hanging), /aborted/);
  });
});

describe('alexa state contract', () => {
  const base = { rokuHost: 'h', pinSalt: 's', pinHash: 'h', locked: true, expiresAt: null, lastAction: '', lastWatchdog: null };

  it('reports configured only with device + encrypted token, never the secret', () => {
    const st = computeState({ ...base, alexa: { enabled: true, device: 'living-room-echo-x', tokenEnc: { iv: 'a', tag: 'b', data: 'c' } }, lastAlexa: { at: new Date().toISOString(), ok: true, detail: 'announcement sent' } });
    assert.equal(st.alexa.configured, true);
    assert.equal(st.alexa.device, 'living-room-echo-x');
    assert.ok(!('token' in st.alexa) && !('tokenEnc' in st.alexa));
    const bare = computeState({ ...base });
    assert.equal(bare.alexa.configured, false);
    assert.equal(bare.alexa.lastOk, null);
  });

  it('warn window constant is 5 minutes', () => {
    assert.equal(ALEXA_WARN_MS, 300_000);
  });
});
