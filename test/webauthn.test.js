import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, createSign, generateKeyPairSync } from 'node:crypto';
import {
  b64uEncode,
  b64uDecode,
  derToRaw,
  verifyAssertion,
  verifyRegistration,
} from '../server.js';

// Minimal CBOR encoder (test-local) to build authenticator artifacts.
function encLen(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}
const encBytes = (b) => Buffer.concat([encLen(2, b.length), b]);
const encText = (s) => {
  const b = Buffer.from(s, 'utf8');
  return Buffer.concat([encLen(3, b.length), b]);
};
const encUint = (n) => encLen(0, n);
const encNeg = (n) => encLen(1, -1 - n); // n negative
const encArr = (items) => Buffer.concat([encLen(4, items.length), ...items]);
const encMap = (pairs) =>
  Buffer.concat([encLen(5, pairs.length), ...pairs.flatMap(([k, v]) => [k, v])]);

const RP = '192.168.1.107';
const ORIGIN = 'https://192.168.1.107:3443';
const { publicKey, privateKey } = generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});
const { x, y } = createPublicKey({ key: publicKey, format: 'der', type: 'spki' }).export({ format: 'jwk' });
const CRED_ID = Buffer.from('test-credential-id-0001 quar');
const CHALLENGE = 'test-challenge-0001';
const clientData = (type, origin = ORIGIN) =>
  b64uEncode(JSON.stringify({ type, challenge: CHALLENGE, origin }));

function coseKey() {
  return encMap([
    [encUint(1), encUint(2)],
    [encUint(3), encNeg(-7)],
    [encNeg(-1), encUint(1)],
    [encNeg(-2), encBytes(Buffer.from(x, 'base64url'))],
    [encNeg(-3), encBytes(Buffer.from(y, 'base64url'))],
  ]);
}

function attestationObject() {
  const rpIdHash = createHash('sha256').update(RP).digest();
  const flags = Buffer.from([0x45]);
  const counter = Buffer.alloc(4);
  const aaguid = Buffer.alloc(16);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(CRED_ID.length);
  const authData = Buffer.concat([rpIdHash, flags, counter, aaguid, credIdLen, CRED_ID, coseKey()]);
  return b64uEncode(
    encMap([
      [encText('fmt'), encText('none')],
      [encText('authData'), encBytes(authData)],
      [encText('attStmt'), encMap([])],
    ])
  );
}

function signAssertion(authData, clientDataB64u) {
  const data = Buffer.concat([authData, createHash('sha256').update(b64uDecode(clientDataB64u)).digest()]);
  return b64uEncode(derToRaw(createSign('sha256').update(data).sign({ key: privateKey, format: 'der', type: 'pkcs8' })));
}

describe('webauthn verification', () => {
  it('accepts a well-formed registration', () => {
    const cred = verifyRegistration({
      rpId: RP,
      origin: ORIGIN,
      attestationObject: attestationObject(),
      clientDataJSON: clientData('webauthn.create'),
    });
    assert.equal(cred.challenge, CHALLENGE);
    assert.equal(cred.credId, b64uEncode(CRED_ID));
    assert.equal(cred.x, x);
    assert.equal(cred.y, y);
  });

  it('rejects registration on a wrong origin', () => {
    assert.throws(
      () =>
        verifyRegistration({
          rpId: RP,
          origin: 'https://evil.example',
          attestationObject: attestationObject(),
          clientDataJSON: clientData('webauthn.create', 'https://evil.example'),
        }),
      /Origin not allowed/
    );
  });

  it('accepts a well-formed assertion and enforces the counter', () => {
    const stored = { credId: b64uEncode(CRED_ID), x, y, counter: 0 };
    const authData = Buffer.concat([
      createHash('sha256').update(RP).digest(),
      Buffer.from([0x05]),
      Buffer.from([0, 0, 0, 2]),
    ]);
    const cd = clientData('webauthn.get');
    const next = verifyAssertion({
      rpId: RP,
      origin: ORIGIN,
      stored: { ...stored },
      credentialId: b64uEncode(CRED_ID),
      authenticatorData: b64uEncode(authData),
      clientDataJSON: cd,
      signature: signAssertion(authData, cd),
    });
    assert.equal(next, 2);
    assert.throws(
      () =>
        verifyAssertion({
          rpId: RP,
          origin: ORIGIN,
          stored: { ...stored, counter: 2 },
          credentialId: b64uEncode(CRED_ID),
          authenticatorData: b64uEncode(authData),
          clientDataJSON: cd,
          signature: signAssertion(authData, cd),
        }),
      /Stale counter/
    );
  });

  it('rejects a tampered signature', () => {
    const stored = { credId: b64uEncode(CRED_ID), x, y, counter: 0 };
    const authData = Buffer.concat([
      createHash('sha256').update(RP).digest(),
      Buffer.from([0x05]),
      Buffer.from([0, 0, 0, 3]),
    ]);
    const cd = clientData('webauthn.get');
    const sig = Buffer.from(signAssertion(authData, cd), 'base64url');
    sig[10] ^= 0xff;
    assert.throws(
      () =>
        verifyAssertion({
          rpId: RP,
          origin: ORIGIN,
          stored: { ...stored },
          credentialId: b64uEncode(CRED_ID),
          authenticatorData: b64uEncode(authData),
          clientDataJSON: cd,
          signature: b64uEncode(sig),
        }),
      /Bad signature/
    );
  });
});
