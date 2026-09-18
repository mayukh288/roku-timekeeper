import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeState, validPin, isNight, lockCommand, buildWakePacket, parsePowerMode, tvIsOn, tvAppId, parseActiveApp, shouldEnforceSwitch, parseHM, minutesInWindow, extractWakeMac } from '../server.js';

const base = {
  rokuHost: '192.168.1.112',
  pinSalt: 'salt',
  pinHash: 'hash',
  locked: true,
  expiresAt: null,
  lastAction: 'Locked by parent',
  lastWatchdog: null,
};

describe('unlock-forever (open) mode', () => {
  it('reports open with null remaining when unlocked and no expiry', () => {
    const st = computeState({ ...base, locked: false, expiresAt: null });
    assert.equal(st.locked, false);
    assert.equal(st.mode, 'open');
    assert.equal(st.remainingSeconds, null);
    assert.equal(st.configured, true);
  });

  it('does not flip an open TV back to locked on zero remaining', () => {
    // Regression: remainingMs is 0 without a timer, which must not imply locked.
    const st = computeState({ ...base, locked: false, expiresAt: null });
    assert.equal(st.locked, false);
  });

  it('reports timed mode with a countdown while bonus time remains', () => {
    const st = computeState({ ...base, locked: false, expiresAt: Date.now() + 60_000 });
    assert.equal(st.locked, false);
    assert.equal(st.mode, 'timed');
    assert.ok(st.remainingSeconds >= 59 && st.remainingSeconds <= 60);
  });

  it('reads locked the moment bonus time hits zero, before the enforcer runs', () => {
    const st = computeState({ ...base, locked: false, expiresAt: Date.now() - 1000 });
    assert.equal(st.locked, true);
    assert.equal(st.mode, 'locked');
  });

  it('locked wins even with no expiry set', () => {
    const st = computeState({ ...base, locked: true, expiresAt: null });
    assert.equal(st.locked, true);
    assert.equal(st.mode, 'locked');
  });

  it('unconfigured without a PIN', () => {
    const st = computeState({ ...base, pinSalt: '', pinHash: '' });
    assert.equal(st.configured, false);
  });
});

describe('parent PIN format (setup and PIN change share this rule)', () => {
  it('accepts 4–12 digits', () => {
    assert.equal(validPin('1234'), true);
    assert.equal(validPin('123456789012'), true);
  });

  it('rejects short, long, and non-digit PINs', () => {
    assert.equal(validPin('123'), false);
    assert.equal(validPin('1234567890123'), false);
    assert.equal(validPin('12ab'), false);
    assert.equal(validPin(''), false);
    assert.equal(validPin(undefined), false);
  });
});

describe('lock action (chromecast by day, power off 10:30pm–8am)', () => {
  const at = (h, m) => new Date(Date.UTC(2026, 5, 15, h, m));
  const cfg = (over = {}) => ({ lockAction: 'chromecast', chromecastInput: 'InputHDMI2', ...over });

  it('switches to the configured input on a weekday afternoon', () => {
    assert.equal(lockCommand(cfg(), at(14, 0), 'UTC'), 'InputHDMI2');
  });

  it('powers off at night even in chromecast mode', () => {
    assert.equal(lockCommand(cfg(), at(23, 0), 'UTC'), 'PowerOff');
    assert.equal(lockCommand(cfg(), at(7, 59), 'UTC'), 'PowerOff');
  });

  it('boundary: 22:29 switches, 22:30 powers off, 08:00 switches', () => {
    assert.equal(lockCommand(cfg(), at(22, 29), 'UTC'), 'InputHDMI2');
    assert.equal(lockCommand(cfg(), at(22, 30), 'UTC'), 'PowerOff');
    assert.equal(lockCommand(cfg(), at(8, 0), 'UTC'), 'InputHDMI2');
  });

  it('powers off by day in poweroff mode', () => {
    assert.equal(lockCommand(cfg({ lockAction: 'poweroff' }), at(14, 0), 'UTC'), 'PowerOff');
  });

  it('falls back to HDMI1 on a bad stored input', () => {
    assert.equal(lockCommand(cfg({ chromecastInput: 'bogus' }), at(14, 0), 'UTC'), 'InputHDMI1');
  });

  it('defaults to poweroff when unset', () => {
    assert.equal(lockCommand({}, at(14, 0), 'UTC'), 'PowerOff');
  });
});

describe('wake-then-switch support', () => {
  it('builds a valid 102-byte magic packet', () => {
    const pkt = buildWakePacket('01:23:45:67:89:ab');
    assert.equal(pkt.length, 102);
    assert.deepEqual([...pkt.slice(0, 6)], [255, 255, 255, 255, 255, 255]);
    assert.deepEqual([...pkt.slice(6, 12)], [1, 35, 69, 103, 137, 171]);
    assert.deepEqual([...pkt.slice(96, 102)], [1, 35, 69, 103, 137, 171]);
  });

  it('rejects malformed MACs', () => {
    assert.throws(() => buildWakePacket('bogus'), /Invalid MAC/);
    assert.throws(() => buildWakePacket('01:02:03:04:05'), /Invalid MAC/);
    assert.throws(() => buildWakePacket('gg:23:45:67:89:ab'), /Invalid MAC/);
  });

  it('reads power-mode as on / off / unknown', () => {
    assert.equal(parsePowerMode('<power-mode>PowerOn</power-mode>'), 'PowerOn');
    assert.equal(tvIsOn('<power-mode>PowerOn</power-mode>'), true);
    assert.equal(tvIsOn('<power-mode>poweron</power-mode>'), true);
    assert.equal(tvIsOn('<power-mode>PowerOff</power-mode>'), false);
    assert.equal(tvIsOn('<power-mode>Standby</power-mode>'), false);
    assert.equal(tvIsOn('<power-mode>Ready</power-mode>'), false);
    assert.equal(tvIsOn('<power-mode>DisplayOff</power-mode>'), false);
    assert.equal(tvIsOn('<device-info></device-info>'), null);
  });
});

describe('skip wake+switch when already on the input', () => {
  it('maps InputHDMI keys to tvinput app ids', () => {
    assert.equal(tvAppId('InputHDMI3'), 'tvinput.hdmi3');
    assert.equal(tvAppId('InputHDMI1'), 'tvinput.hdmi1');
  });

  it('reads the active app id from attribute or child form', () => {
    assert.equal(
      parseActiveApp('<active-app><app id="tvinput.hdmi3" type="tvin">chromecast</app></active-app>'),
      'tvinput.hdmi3'
    );
    assert.equal(parseActiveApp('<app><id>tvinput.hdmi1</id></app>'), 'tvinput.hdmi1');
    assert.equal(parseActiveApp('<active-app></active-app>'), null);
  });

  it('parses HH:MM window bounds', () => {
    assert.equal(parseHM('08:00'), 480);
    assert.equal(parseHM('22:30'), 1350);
    assert.equal(parseHM('24:00'), null);
    assert.equal(parseHM('8:00'), null);
    assert.equal(parseHM(''), null);
    assert.equal(parseHM(undefined), null);
  });

  it('handles day and overnight windows', () => {
    assert.equal(minutesInWindow(14 * 60, 480, 1350), true);
    assert.equal(minutesInWindow(23 * 60, 480, 1350), false);
    assert.equal(minutesInWindow(23 * 60, 1200, 120), true);
    assert.equal(minutesInWindow(3 * 60, 1200, 120), false);
    assert.equal(minutesInWindow(12 * 60, 1200, 120), false);
  });

  it('follows a custom chromecast window', () => {
    const at = (h, m) => new Date(Date.UTC(2026, 5, 15, h, m));
    const cfg = { lockAction: 'chromecast', chromecastInput: 'InputHDMI2', castStart: '09:00', castEnd: '10:00' };
    assert.equal(lockCommand(cfg, at(9, 30), 'UTC'), 'InputHDMI2');
    assert.equal(lockCommand(cfg, at(14, 0), 'UTC'), 'PowerOff');
  });

  it('skips only when verifiably on the wanted input', () => {
    assert.equal(
      shouldEnforceSwitch({ powerOn: true, activeAppId: 'tvinput.hdmi3', wantAppId: 'tvinput.hdmi3' }),
      false
    );
    assert.equal(
      shouldEnforceSwitch({ powerOn: true, activeAppId: 'TVINPUT.HDMI3', wantAppId: 'tvinput.hdmi3' }),
      false
    );
    assert.equal(
      shouldEnforceSwitch({ powerOn: true, activeAppId: 'tvinput.hdmi1', wantAppId: 'tvinput.hdmi3' }),
      true
    );
    assert.equal(
      shouldEnforceSwitch({ powerOn: false, activeAppId: 'tvinput.hdmi3', wantAppId: 'tvinput.hdmi3' }),
      true
    );
    assert.equal(
      shouldEnforceSwitch({ powerOn: null, activeAppId: 'tvinput.hdmi3', wantAppId: 'tvinput.hdmi3' }),
      true
    );
    assert.equal(
      shouldEnforceSwitch({ powerOn: true, activeAppId: null, wantAppId: 'tvinput.hdmi3' }),
      true
    );
  });
});

describe('wake MAC learning (mode change while locked must be enforceable)', () => {
  const info = (net, wifi, eth) =>
    `<device-info><network-type>${net}</network-type><wifi-mac>${wifi}</wifi-mac><ethernet-mac>${eth}</ethernet-mac><power-mode>PowerOn</power-mode></device-info>`;

  it('prefers the wifi MAC on a wifi connection', () => {
    assert.equal(extractWakeMac(info('wifi', 'aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02')), 'aa:bb:cc:dd:ee:01');
  });

  it('prefers the ethernet MAC on a wired connection', () => {
    assert.equal(extractWakeMac(info('ethernet', 'aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02')), 'aa:bb:cc:dd:ee:02');
  });

  it('falls back to whichever MAC is present', () => {
    assert.equal(extractWakeMac(info('wifi', '', 'aa:bb:cc:dd:ee:02')), 'aa:bb:cc:dd:ee:02');
    assert.equal(extractWakeMac(info('ethernet', 'aa:bb:cc:dd:ee:01', '')), 'aa:bb:cc:dd:ee:01');
  });

  it('returns null for missing, malformed, or absent XML', () => {
    assert.equal(extractWakeMac(info('wifi', '', '')), null);
    assert.equal(extractWakeMac(info('wifi', 'bogus', '')), null);
    assert.equal(extractWakeMac('<device-info></device-info>'), null);
    assert.equal(extractWakeMac(''), null);
    assert.equal(extractWakeMac(null), null);
  });

  it('a poweroff-to-chromecast flip is reflected in the next command computed', () => {
    const at = new Date(Date.UTC(2026, 5, 15, 14, 0));
    const s = { lockAction: 'poweroff', chromecastInput: 'InputHDMI3' };
    assert.equal(lockCommand(s, at, 'UTC'), 'PowerOff');
    s.lockAction = 'chromecast';
    assert.equal(lockCommand(s, at, 'UTC'), 'InputHDMI3');
  });
});
