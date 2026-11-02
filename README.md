# Adnesia

A self-owned, system-wide ad blocker for Windows.

It does what desktop blockers like Adblocker Ultimate / AdGuard do — block ads
**everywhere, including YouTube, with no browser extension** — but **you** own
every part of it. The root certificate is generated on your machine and never
leaves it, the filtering proxy is code you can read end to end, and nothing
phones home. No third party is ever in the trust chain. That is the whole
point: the only party that can see your traffic is local code you control.

## How it works

1. On first run it generates a local **root CA** and installs it into your
   Windows trust store.
2. It runs a local **MITM proxy** and points the Windows system proxy at it.
3. For each HTTPS host it mints a short-lived leaf certificate signed by your
   local CA, so it can inspect and (in later phases) filter that connection.
4. Ad/tracker requests are dropped; page content is rewritten to hide leftover
   ad elements; YouTube ads are stripped by injected script.
5. Pinned hosts (banks, some apps) are **tunneled through untouched** via the
   bypass list, so they keep working and Adnesia never sees inside them.

## Status

| Phase | What | State |
|------:|------|-------|
| 0 | Scaffolding, config, logging | ✅ done |
| 1 | Root CA + MITM proxy core + system-proxy toggle | ✅ done |
| 2 | Network filtering (EasyList etc.) | ✅ done |
| 3 | Cosmetic filtering (CSS injection) | ✅ done |
| 4 | YouTube ad stripping | ✅ done* |
| 5 | Bypass list + pinning robustness | ✅ done |
| 6 | Tray icon + web dashboard + login auto-start | ✅ done** |
| 7 | Kernel Mode: WinDivert driver-level capture (apps/games) | ⚠️ built, unverified*** |

It now intercepts HTTPS, **blocks ad/tracker network requests** against ~185k
rules, and **injects cosmetic-hiding CSS** into HTML pages to remove leftover
ad containers (~73k cosmetic rules). Lists come from EasyList, EasyPrivacy,
Peter Lowe's list and AdGuard Base, cached under `%AppData%\Adnesia\lists`.
It does not yet strip YouTube's in-stream video ads — that is Phase 4.

The network engine supports domain-anchored rules (`||ads.example^`),
hosts-format lists, generic path patterns, exception (`@@`) rules, and the
`third-party`, `domain=` and resource-type options, matched quickly via a
hostname fast path plus token-bucketed, lazily compiled patterns.

Cosmetic hiding (`internal/cosmetic` + `internal/rewrite`) parses `##`/`#@#`
element-hiding rules, decompresses HTML responses (gzip/deflate/brotli), and
splices a `<style>` before `</head>`, adding a CSP nonce so the injection is
not blocked. Domain-specific selectors are always applied; the much larger
pool of generic selectors is opt-in (`-cosmetic-generic` / `cosmetic_generic`
in config) because it adds page weight. Procedural (`:has-text`) and scriptlet
(`##+js`) rules are skipped.

YouTube in-stream ads (`internal/youtube`) are stripped two ways at once:
server-side it deletes the ad fields (`adPlacements`, `playerAds`, `adSlots`,
…) from the `/youtubei/v1/player` JSON response in flight; client-side it
injects a script into YouTube pages that sanitises the embedded
`ytInitialPlayerResponse`, hooks `fetch`/`JSON.parse` to scrub player
responses the SPA loads later, and skips any ad that still plays.

\* **Verified by unit tests and by confirming the script injects and the JSON
strip removes the right fields — but not yet against a live playing video in a
browser.** YouTube changes these shapes frequently, so this is the part most
likely to need periodic updates; it is isolated in `internal/youtube` so those
updates don't touch the rest of the app.

Pinned/sensitive hosts (`internal/bypass`) are tunneled through **without**
interception, so apps that pin certificates keep working and Adnesia never
sees inside that traffic. A curated default list targets native desktop apps
that pin (game launchers, password managers, messaging apps, OS services);
you add your own via config or the CLI, persisted to `%AppData%\Adnesia\
bypass.txt`. When Adnesia does intercept, it fully verifies the upstream
server's real certificate, so a site with a genuinely bad certificate still
fails rather than being silently re-signed as trusted.

A **tray icon** (`internal/tray`) gives a quick on/off toggle, an "open
dashboard" item and quit; the **web dashboard** (`internal/web`, on
`127.0.0.1:8081`) is a full control panel — a master on/off, per-feature
toggles, per-category block counts, a recent-blocks log, and passthrough-list
editing — served locally and never exposed to the network. **Login auto-start**
(`internal/autostart`) registers Adnesia in the per-user `Run` key.

**Per-feature toggles.** Filter rules are tagged by category so each dashboard
switch controls a real class of rules, persisted across restarts:

| Toggle | What it controls |
|--------|------------------|
| Ad Blocking | ad servers/scripts/banners (EasyList, AdGuard Base, Peter Lowe) + cosmetic hiding |
| Privacy Protection | trackers / analytics (EasyPrivacy) |
| Web Protection | malware / phishing domains (URLhaus) |
| Annoyances Blocking | cookie notices, nags, social widgets (AdGuard Annoyances) |
| Ghost Mode | strips the Referer header, sends `DNT: 1`, drops tracking query params (`utm_*`, `fbclid`, `gclid`, …) |
| Generic Cosmetics | the large site-agnostic cosmetic set (heavier; off by default) |
| Kernel Mode | experimental WinDivert driver-level system-wide capture (the `transparent` setting); starts/stops at runtime and shows "needs administrator" / "WinDivert not installed" when it can't engage |

\*\* Dashboard and auto-start are verified (HTTP API and registry); the tray
compiles and is wired but its GUI event loop is only exercised on a real
interactive desktop, not in automated testing.

**Why login auto-start, not a Windows service:** the system proxy Adnesia sets
lives in the per-user hive (HKCU) and the tray needs an interactive desktop —
neither of which a session-0 service has. A per-user login launch is the
correct model.

System-wide capture of apps that ignore the system proxy (`internal/windivert`
+ `internal/redirect` + `internal/transparent`, enabled with `-transparent`)
uses **WinDivert**: our own thin wrapper over the official, signed
`WinDivert.dll` / `WinDivert64.sys` — no third-party Go binding and no unsigned
kernel code of our own. The redirector captures outbound TCP to :80/:443 and
loops it to a local transparent listener, which MITMs with the same CA and
runs the same filter/cosmetic/YouTube pipeline, then restores the return path.

\*\*\* **Built and compiles, but NOT verified at runtime.** It needs WinDivert
installed (from the official release), administrator rights, and real traffic —
none of which exist in automated testing. The wiring and graceful fallback
(it logs "transparent capture disabled" and keeps running when WinDivert is
absent) are verified; the packet capture / NAT / transparent MITM are not.
Treat `-transparent` as experimental until tested on real hardware. You do not
need it for browser or YouTube blocking — the system proxy already covers those.

Get WinDivert with `powershell -ExecutionPolicy Bypass -File fetch-windivert.ps1`:
it downloads WinDivert 2.2.2 from the official release, verifies its SHA-256,
checks the driver signature, and drops `WinDivert.dll` + `WinDivert64.sys` next
to `adnesia.exe` (not committed to the repo). The 2.2.2 driver is validly
signed, but by a third-party vendor (`成都密思听科技有限公司`); Windows enforces
that signature at load — decide if you're comfortable before enabling it.

### Dependencies

All third-party modules are **vendored** into `vendor/` and pinned, so builds
are reproducible and need no network (`go build` works with `GOPROXY=off`).
They are goproxy (MITM engine), andybalholm/brotli (Brotli decode),
fyne.io/systray (tray), and the Go team's `golang.org/x/{net,sys,text}`. The
WinDivert kernel driver is the only component not vendored — it is installed
separately from its official signed release.

## Build

Requires Go 1.27+. Dependencies are vendored, so it builds offline.

```
go build -o adnesia.exe ./cmd/adnesia
```

For the shippable build — **no console window** and the app icon on the exe —
use the build script (fully offline; the icon resource is generated by our own
stdlib tool, `tools/mksyso`, so no external tool is needed):

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

Logs always go to `%AppData%\Adnesia\adnesia.log` (the no-console build has no
terminal to print to).

## Run

```
# Full run: installs the CA, sets the system proxy, shows the tray icon.
# Then open the dashboard at http://127.0.0.1:8081
adnesia.exe

# Verbose logging.
adnesia.exe -v

# Headless (no tray), e.g. for a quick test; Ctrl+C to stop.
adnesia.exe -no-tray -v

# Testing without touching your system:
adnesia.exe -no-tray -no-install -no-sysproxy -v

# Start automatically at login (and the reverse).
adnesia.exe -install-autostart
adnesia.exe -uninstall-autostart

# Clean up: remove the CA from the trust store and reset the system proxy.
adnesia.exe -uninstall
```

The dashboard (live block log, on/off switch, passthrough editing) is at
**http://127.0.0.1:8081** whenever Adnesia is running.

| Flag | Effect |
|------|--------|
| `-v` | Debug logging |
| `-no-sysproxy` | Don't change the Windows system proxy |
| `-no-install` | Don't install the CA into the trust store |
| `-no-tray` | Run headless (no tray icon); stop with Ctrl+C |
| `-transparent` | EXPERIMENTAL: also capture apps that ignore the system proxy (needs WinDivert + admin) |
| `-cosmetic-generic` | Inject generic cosmetic selectors on every page |
| `-bypass-list` | Print the passthrough (non-intercepted) host list and exit |
| `-bypass-add <pattern>` | Add a host pattern to the passthrough list and exit |
| `-bypass-remove <pattern>` | Remove a runtime-added passthrough pattern and exit |
| `-install-autostart` | Register Adnesia to start at login, then exit |
| `-uninstall-autostart` | Remove the login auto-start entry, then exit |
| `-autostart-status` | Report whether login auto-start is enabled, then exit |
| `-reset-proxy` | Clear Adnesia's system-proxy settings (restore direct internet), then exit |
| `-uninstall` | Remove CA + reset system proxy, then exit |

Settings, the CA, and (later) cached filter lists live in
`%AppData%\Adnesia\`.

## Verifying Phase 1

With the proxy running, a request through it should succeed using only the
generated CA, proving the interception + signing chain:

```
curl.exe --ssl-no-revoke -x http://127.0.0.1:8080 ^
  --cacert "%AppData%\Adnesia\ca.crt" https://example.com/ -o NUL -w "%{http_code}\n"
```

Expect `200`. (`--ssl-no-revoke` only silences Schannel's revocation check for
curl's locally-minted test cert; browsers with the CA installed are
unaffected.)

## Connectivity safety (never leaves you offline)

Adnesia sets the Windows system proxy to `127.0.0.1:8080` (the "Manual proxy
setup" you can see in Settings) and routes everything through it — a fixed
proxy is what reliably filters sites like YouTube. The safety nets:

- A **crash watchdog**: a tiny detached helper waits for the main process and
  clears the system proxy the instant it exits for any reason, so a crash can
  never leave the browser pointed at a dead proxy.
- Turning Adnesia **off** (dashboard or tray) removes the proxy entirely.
- The proxy is only ever switched on when Windows **trusts Adnesia's
  certificate**; otherwise it stays off and the dashboard says so.
- Clearing the proxy also deletes the binary connection-settings blob that
  Chrome/Edge/Discord read, which can otherwise keep a stale proxy alive.
- `adnesia.exe -reset-proxy` clears everything instantly as a manual rescue.

## Diagnosing a broken site

The dashboard footer shows the **build stamp** of the running copy. The
recent-blocks log shows what was blocked. To ask the filter engine why:

```
go run ./tools/checkurl "%AppData%\Adnesia\lists" https://example.com/some/request xmlhttprequest site.com
```

Two YouTube-specific lessons baked into the code: blocked requests are answered
with an empty 200 (`{}` for XHR, with CORS headers) rather than an error,
because YouTube hangs on a failed `pagead/id`; and Adnesia never adds its CSP
nonce to a directive that allows inline scripts via `'unsafe-inline'`, because
a nonce would switch that off and block the page's own scripts.

## Honest caveats

- **Admin rights** are needed to install the CA / set the system proxy (and
  later for WinDivert).
- **Firefox** keeps its own cert store and needs the CA installed there too —
  not yet wired up.
- **Certificate pinning**: some apps reject any proxied cert; the bypass list
  tunnels those through.
- **YouTube is an arms race** — Google breaks blockers regularly; the YouTube
  logic is isolated so it can be updated without touching the core.
- **Windows Defender / SmartScreen** may warn about an unsigned binary that
  installs a root cert — expected for a self-built tool.

## Layout

```
cmd/adnesia        entrypoint: lifecycle + wiring
internal/config    settings (JSON in %AppData%\Adnesia)
internal/ca        root CA gen, leaf signing, trust-store install
internal/proxy     MITM proxy (goproxy) + bypass + request filtering + injection
internal/filter    network filter-list parsing + tokenized match engine (+ tests)
internal/cosmetic  element-hiding (##/#@#) rules + per-host CSS (+ tests)
internal/rewrite   body decompress + HTML/JSON transform + CSP nonce (+ tests)
internal/youtube   player-API JSON strip + injected strip script (+ tests)
internal/lists     filter-list download + on-disk cache
internal/stats     block counters + recent-blocks ring buffer
internal/sysproxy  Windows system-proxy set/restore
internal/bypass    passthrough matcher + managed default/user/learned list (+ tests)
internal/web       local dashboard: embedded UI + JSON API
internal/tray      system-tray icon (generated) + menu
internal/autostart login auto-start via the per-user Run key
internal/windivert thin wrapper over the official signed WinDivert.dll
internal/redirect  WinDivert capture + NAT redirect to the transparent listener
internal/transparent  transparent MITM listener reusing the filter pipeline
internal/ca        (+ signer.go) per-host leaf minting for the transparent path
```

All three of `windivert`, `redirect`, `transparent` are experimental (Phase 7)
and gated behind `-transparent`.
