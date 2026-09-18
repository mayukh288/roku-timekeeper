# Roku Timekeeper (TrueNAS edition)

Parental control for the living room TV. The timer lives on TrueNAS, so the TV
shuts off even if the parent's iPhone is off or away.

## How it works

- iPhone (over Tailscale) → `http://192.168.1.107:3030` → TrueNAS container → Roku TV (`192.168.1.112:8060`)
- Grant 1–720 bonus minutes with the parent PIN; on expiry the server sends Roku `PowerOff`.
- While locked, a watchdog re-sends the lock command every 10s, so the physical remote only buys a few seconds.
- Daytime locks can switch the TV to the Chromecast HDMI instead of powering off; 10:30pm–8am
  always powers off. Toggle it in the dashboard (needs PIN) and set the Chromecast HDMI port.
  `TIMEZONE` (default `America/Los_Angeles`, taken from the TrueNAS server) sets what the night window means.
- Chromecast locks wake a switched-off TV first: the server checks the TV power state, sends a
  Wake-on-LAN magic packet when it is off, then switches the input. `WAKE_BROADCAST`
  (default `192.168.1.255`) sets the broadcast address for the wake packet.
- State persists in `/mnt/datapool/apps/roku-timekeeper/data/settings.json`; only a salted PIN hash is stored.

## First-time setup (parent)

1. Open `http://192.168.1.107:3030` (at home) or the TrueNAS Tailscale IP/hostname `:3030` (away).
2. Enter the Roku address (default `192.168.1.112`) and choose a 4–12 digit parent PIN.
3. Submit → the TV powers off and the system is locked. Grant time with the +15/+30/+60 buttons,
   open it with no timer via Unlock TV, or shut it down immediately with Lock now.

## iPhone Home Screen app

Safari → Share → Add to Home Screen. No signing, no expiry.

## Optional one-tap Shortcut

iOS Shortcuts → Get Contents of URL:
`POST http://<truenas>:3030/api/bonus` with JSON body
`{"minutes": 30, "pin": "YOUR_PIN"}`.

## Files on the NAS

- Code (read-only mount): `/mnt/datapool/apps/roku-timekeeper/code`
- Data: `/mnt/datapool/apps/roku-timekeeper/data`
- TrueNAS App name: `roku-timekeeper` (Custom App via `custom_compose_config`)
- Local sources: `server.js`, `public/index.html`, `truenas-compose.yaml`

## Face ID (no Tailscale needed at home)

Face ID uses passkeys (WebAuthn), which Safari only allows over HTTPS:

- At home with Tailscale off: open `https://192.168.1.107:3443` (note `https`, port 3443).
  The server uses a private home certificate, so first install the CA profile on the iPhone
  (AirDrop the CA file, install it in Settings, then enable full trust under
  Settings → General → About → Certificate Trust Settings).
- Away with Tailscale on: use the `https://` tailnet address instead.
- On each address, enroll once with the parent PIN ("Enroll Face ID on this device"),
  then "Approve with Face ID" gives a 12-hour session where every button works without the PIN.
- The plain `http://` address keeps working with the PIN everywhere. Face ID failing
  (new phone, mask, no HTTPS) always falls back to PIN — nothing is locked out.

`test/webauthn.test.js` covers registration/assertion verification with generated vectors.

## Tests

`node --test` (Node 20+) runs `test/state.test.js`, covering the
locked/timed/open state contract — including the unlock-forever regression
(an open TV with zero remaining must not read back as locked).

## Limits

- Roku supports remote PowerOff, not dependable remote PowerOn: wake with the normal remote.
- Not tamper-proof against unplugging the NAS/router or changing TV networking.
