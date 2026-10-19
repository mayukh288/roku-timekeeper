# Roku Timekeeper (TrueNAS edition)

Parental control for the living room TV. The timer lives on TrueNAS, so the TV
shuts off even if the parent's iPhone is off or away.

## How it works

- iPhone (over Tailscale) → `http://192.168.1.107:3030` → TrueNAS container → Roku TV (`192.168.1.112:8060`)
- Grant 1–720 bonus minutes with the parent PIN; on expiry the server sends Roku `PowerOff`.
- While locked, a guard senses the TV about every second and fires the lock command the moment it is out of its desired state, so the physical remote only buys a couple of seconds.
- Daytime locks can switch the TV to the Chromecast HDMI instead of powering off; outside the
  Chromecast window (default 08:00–22:30, i.e. night is 10:30pm–8am) locks always power off.
  Toggle it in the dashboard (needs PIN), set the Chromecast HDMI port and the active window
  in the Configuration section.
  `TIMEZONE` (default `America/Los_Angeles`, taken from the TrueNAS server) sets what the night window means.
- Chromecast locks wake a switched-off TV first: the server checks the TV power state, sends a
  Wake-on-LAN magic packet when it is off, then switches the input. `WAKE_BROADCAST`
  (default `192.168.1.255`) sets the broadcast address for the wake packet.
  When the TV is already on the wanted input, the round is skipped (logged, no commands sent).
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

## Alexa voice announcements (Voice Monkey)

The living-room Echo warns "The TV will turn off in 5 minutes", then announces
at lock time ("Turning off the TV now" / "Switching to Chromecast"). Scheduled
auto-lock also gets a 5-minute warning. Announcements need internet
(TrueNAS → Voice Monkey → Amazon → Echo) and play at the Echo's own volume —
use a scheduled Alexa routine (8pm volume 3, 9am volume 6) for quiet evenings.

One-time Alexa-side setup (iPhone):

1. Alexa app → More → Skills → search "Voice Monkey" → Enable, and link the
   same Amazon account as the Echo ("Login with Amazon" — Voice Monkey never
   sees the password).
2. Sign in at `app.voicemonkey.io/speakers` → Add New Speaker (e.g.
   `Living Room Echo`).
3. Alexa app → More → Routines → + : When *Smart Home → Alexa Voice Monkey
   v3 → VM Speakers → Living Room Echo*; action *Custom → "open Voice
   Monkey"*; From → the living-room Echo. Save.
4. In the dashboard Configuration section: tick Alexa announcements, enter the
   Speaker device ID (e.g. `living-room-echo-…`, listed in the Voice Monkey
   console), paste the API token, Save with the parent PIN, then Send test
   announcement.

Security: the token (revocable in the Voice Monkey console, one per
integration) is stored AES-256-GCM encrypted in `settings.json`; the vault key
is a separate 0600 file (`DATA_DIR/.alexa-key`) — back up `/data` to keep both.
The token is never logged and never sent to the browser; saving needs the
parent PIN. `test/alexa.test.js` covers the vault and the warning gates.

## Tests

`node --test` (Node 20+) runs `test/state.test.js`, covering the
locked/timed/open state contract — including the unlock-forever regression
(an open TV with zero remaining must not read back as locked).

## Limits

- Roku supports remote PowerOff, not dependable remote PowerOn: wake with the normal remote.
- Not tamper-proof against unplugging the NAS/router or changing TV networking.
