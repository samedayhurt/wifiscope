# wifiscope 📡

Interactive **802.11 pcap triage** for `tshark`. Point it at a monitor-mode capture and it
answers the questions you actually ask in wireless forensics — who's on the network, what gear,
what crypto, which handshakes, what keys — then harvests key material and feeds it back into
`tshark` so you can decrypt and slice further.

It's a single, heavily-commented Bash script. Analysis, key management/derivation, export, and the
public map commands remain Bash/AWK; Python3 is resolved only by `report` for its rich diagram.
Every action prints the exact `tshark` command it runs as a multiline, pasteable command, so the
tool doubles as a way to learn the queries.

```
  wifiscope  pcap:capture.pcapng  target:HomeNet  decrypt:on  keys:9
  ──────────────────────────────────────────────────────────
   ANALYZE  1 recon   2 bands   3 crypto   4 hardware
            5 clients 6 keys    7 topology 8 hosts
            9 probes  0 handshakes
   CRACK    p pmkid   x export22000  (hashcat -m 22000)
   KEYS     k passphrase  h harvest  g scrapegtk  j keymaterial
            a addkey  i import  K show  d delkey  c clearkey
   SESSION  s select-ssid  m map  M mapall  r report  q quit
```

## Features

- **Fast start** — name the target on the command line (`./wifiscope.sh cap.pcapng SSID [pass]`) and
  startup skips both prompts *and* the whole-capture SSID enumeration behind the picker. The
  existence check stops reading at the first matching beacon instead of scanning to EOF, and the
  whole-capture BSSID index is built only when a command actually needs it. ~2x faster to the menu.
- **Recon** — protocol hierarchy + every SSID/BSSID/channel/band in the capture (2.4 / 5 / **6 GHz**).
- **Per-network analysis** — bands/channels, encryption (full RSN AKM verdict: WPA2/WPA3-Personal,
  **Enterprise 802.1X**, OWE, Suite-B, transition, WPA1/WEP/open), make/model (from WPS), wireless
  clients, PSK/PTK/GTK counts, and mesh topology (ESS vs backhaul "fake mesh").
- **Complete client discovery** — stations are found from association requests, EAPOL, **and** data
  frames (ToDS/FromDS), not handshakes alone — so clients that associated before the capture began
  still show up. Hidden SSIDs are surfaced and their names recovered from probe responses.
- **Host inventory** (post-decryption) — subnet/gateway, IPv4 **and IPv6** (ARP + ICMPv6 ND / DHCPv6),
  IP↔MAC, hostnames, OS/software versions.
- **Device fingerprinting** (`fingerprint`) — what the clients *are*, not just their addresses:
  802.11 capability profile (vendor OUI, **randomized-vs-hardware MAC**, Wi-Fi 4/5/6/6E generation)
  with **no keys required**, plus — once decrypting — the **DHCP option-55** parameter-request
  signature, **TLS SNI + JA3/JA4**, DNS-SD/mDNS service and `model=` strings, and a TTL-based
  stack hint. Every pass runs concurrently.
- **WPA3 / SAE** — SAE, FT-SAE, **SAE group-dependent hash (R3)**, OWE, Suite-B-192 and FILS in the
  AKM verdict; AKM and cipher selectors decoded to names (`SAE`, `GCMP-256`) instead of bare
  numbers; **PMF/802.11w** state called out (and flagged when SAE is advertised without it); the SAE
  Commit/Confirm exchange listed from Authentication frames; H2E and transition-disable detection.
  Critically, it **tells you a passphrase cannot decrypt an SAE-only BSS** — the SAE PMK comes from
  the elliptic-curve exchange, not `PBKDF2(passphrase, SSID)` — instead of silently decrypting nothing.
- **Key harvesting & keyring** — derive the PSK, compute each client's PTK-TK, scrape GTKs, and
  persist them to a per-capture keyring that auto-applies to every later query. Import/add keys from
  other tools (hcxtools, hostapd, oxide) to decrypt BSSes whose handshake you didn't capture.
- **Cracking hand-off** — list PMKIDs and export a `hashcat -m 22000` file.
- **Profiling** — probe-request mapping (what SSIDs each client is hunting for) and a per-client
  handshake-completeness / crackability table.
- **Network map** — auto-generate a `.drawio` diagram from Bash/AWK: physical AP units (clustered from the
  **observed 4-address WDS backhaul**, not just a MAC-prefix guess), clients grouped under the AP
  they joined, wired hosts, and an evidence-qualified default gateway — each labeled with IP / MAC / hostname / OS /
  protocols. Dashed **L3 edges** show observed intra-LAN "who talks to whom".
- **Whole-network map** (`mapall`) — map the *entire* capture at once: every physical AP appears
  once with all the SSIDs it radiates (main / guest / IoT), so you see the deployment, not one
  ESSID at a time.
- **Mission reports** — an Obsidian-ready Markdown report that **answers the operational questions
  first**: Survey Imagery, Router Info (make / model / firmware / per-band MACs / channels /
  frequencies / encryption / estimated location / strongest RSSI), Handshakes, and Selectors of
  Interest (**Associated**, **Wired**, and **Probing** MACs, each annotated with OUI, randomized-or-
  hardware, and times seen), plus operator `Actions Taken` / `Notes` blocks. Every block carries the
  exact tshark commands that produced it. A `# Detailed evidence` half then follows with 12 numbered
  sections — executive summary, capture hash/timing, radio/security/WPS/OUI evidence, EAPOL + PMKID
  + **SAE** analysis, decryption validation, **full key inventory (PSK/PMK, PTK-TK, GTK) with a
  plain-English "what it is" column**, L3/host/DNS inventory, device fingerprinting, management
  events, quality checks and open questions — with a linked table of contents.
- **Evidence-qualified maps** — the diagram distinguishes observed links from inferred roles. An
  AP is called a gateway only after an exact DHCP-router-IP → ARP-MAC → beacon-BSSID match; a
  DHCP default gateway is never mislabeled as an Internet/ISP address.
- **UX** — color + emoji + clickable (OSC-8) MAC→vendor links and role-colored addresses, all of
  which **auto-disable** when piped, redirected, or `NO_COLOR` is set (reports stay plain).

## Requirements

- `tshark` (Wireshark ≥ 3.x; developed against 4.6)
- shell tools: `awk`, `sort`, `grep`, `tr`, `sed`
- `openssl` 3.x + `xxd` — only for PMK/PTK harvesting and SSID hex conversion
- `python3` — **report only**, for the richer report-linked draw.io generator. If unavailable,
  `report` falls back to the Bash/AWK map; every non-report command remains Python-free.
- Optional: `hcxpcapngtool` for full EAPOL → 22000 export (PMKID export works without it)
- Optional (tests only): `python3-scapy`, to build the synthetic capture in `tests/`

A **monitor-mode** capture with radiotap headers is assumed. Managed-mode captures only see your
own decrypted traffic and most filters will come back empty.

## Install

```bash
git clone <this-repo> && cd wifiscope
chmod +x wifiscope.sh
./wifiscope.sh                 # or put it on your PATH
```

## Usage

**Interactive** (menu, with filename tab-completion at the prompts):

```bash
./wifiscope.sh                             # asks for a pcap, then shows the menu
./wifiscope.sh capture.pcapng              # pcap preloaded, picker + passphrase prompt
./wifiscope.sh capture.pcapng HomeNet          # FAST: skip the picker, straight to the menu
./wifiscope.sh capture.pcapng HomeNet hunter2  # FAST: also skip the passphrase prompt
```

Naming the target skips `pick_ssid`, which otherwise reads the whole capture twice (once for beacon
SSIDs, once for hidden-AP BSSIDs) plus one more full pass per hidden AP — just to draw a list you
already answered. The SSID is still verified to exist, with a probe that stops at the first match.

**One-shot** (scriptable — first arg is the command):

```bash
./wifiscope.sh recon     capture.pcapng
./wifiscope.sh crypto    capture.pcapng HomeNet
./wifiscope.sh keys      capture.pcapng HomeNet hunter2      # passphrase enables decryption
./wifiscope.sh harvest   capture.pcapng HomeNet hunter2      # PSK + PTK-TKs + GTKs -> keyring
./wifiscope.sh scrapegtk capture.pcapng HomeNet hunter2      # sweep whole capture for GTKs
./wifiscope.sh keymaterial capture.pcapng HomeNet hunter2    # deliberately print TK/GTK context
./wifiscope.sh export22000 capture.pcapng HomeNet            # -> capture.hc22000
./wifiscope.sh report    capture.pcapng HomeNet hunter2      # full markdown report
```

### Commands

| Command | What it does |
|---|---|
| `recon` | Protocol mix + all networks in the capture |
| `bands` | Channel/band per BSSID of the target |
| `crypto` | Encryption verdict from the RSN/AKM element |
| `hardware` | Make/model/serial from WPS |
| `clients` | Wireless station candidates from association, EAPOL, and data evidence |
| `keys` | PSK / recoverable PTK-context / GTK counts (M1-only stations are not PTKs) |
| `topology` | AP count + 802.11 WDS backhaul (mesh detection) |
| `hosts` | Subnet, IP↔MAC, hostnames, versions (needs a key) |
| `probes` | Directed probe requests: client → SSID sought |
| `handshakes` | Per-client 4-way completeness + crackable flag, **and the WPA3 SAE Commit/Confirm exchange** |
| `fingerprint` | Device identification: 802.11 capability profile (vendor, randomized MAC, Wi-Fi generation) + DHCP option-55, TLS SNI/JA3/JA4, DNS-SD `model=`, TTL stack hint |
| `pmkid` | List RSN PMKIDs (offline-crackable) |
| `export22000` | Write a `hashcat -m 22000` file |
| `harvest` | Derive PSK + compute PTK-TKs + scrape GTKs → keyring |
| `scrapegtk` | Sweep the whole capture for GTKs → keyring |
| `keymaterial` | Deliberately print PMK/KCK/KEK/TK and GTK/IGTK/BIGTK with frame, BSSID, station, and replay context |
| `addkey` / `import` | Add external key material to the keyring |
| `keyring` / `delkey` / `clearkey` | Manage the keyring |
| `map` | draw.io diagram for one SSID (AP units, clients, wired hosts, qualified gateway, L3 links) |
| `mapall` | draw.io diagram of the **whole capture** — every AP + every SSID at once |
| `report` | Everything → Markdown **and** a matching `.drawio` map |
| `selftest` | Run the built-in pure-logic tests (no pcap needed) |

### Environment

| Variable | Effect |
|---|---|
| `TSHARK` | Path to the `tshark` binary if it isn't on `$PATH` |
| `NO_COLOR` | Disable all color/emoji/links (also auto-off when output isn't a TTY) |
| `WIFISCOPE_FORCE_COLOR=1` | Force color on even when piped (e.g. into `less -R`) |
| `OPENSSL` | Path to OpenSSL 3.x for Bash-orchestrated PMK/PTK derivation |
| `XXD` | Path to `xxd` for hex/binary stream conversion |
| `PYTHON3` | Python3 executable used only inside `report` |
| `WIFISCOPE_REPORT_ROW_LIMIT=N` | Cap long event tables in a report (default `500`; summary counts still use all frames) |
| `WIFISCOPE_NO_PROGRESS=1` | Suppress the live progress line (it is already off automatically whenever stderr is not a terminal) |
| `WIFISCOPE_JOBS=N` | Max concurrent `tshark` passes in `report`/`fingerprint`. Default is derived from cpu count, free memory, **and capture size** (~capture+256 MB budgeted per pass, spending at most 70% of free RAM). Raise it on a big host; lower it to `1`–`2` on a small VM |
| `WIFISCOPE_REPORT_SECRETS=0` | Redact key values in the report (counts only). Keys are **included by default** — an autopsy of your own lab capture is not much use without them |
| `WIFISCOPE_AUTHOR` | `author:` in the report frontmatter (default: `$USER`) |
| `WIFISCOPE_OPNAME` | Operation name — becomes `<OPNAME> Mission Report` in the title (default: the SSID) |

```bash
TSHARK=/opt/wireshark/bin/tshark ./wifiscope.sh recon capture.pcapng
NO_COLOR=1 ./wifiscope.sh crypto capture.pcapng HomeNet     # plain text
WIFISCOPE_REPORT_ROW_LIMIT=1000 ./wifiscope.sh report capture.pcapng HomeNet
WIFISCOPE_JOBS=2 ./wifiscope.sh report big.pcapng HomeNet   # memory-tight box
WIFISCOPE_REPORT_SECRETS=0 ./wifiscope.sh report capture.pcapng HomeNet  # redact key material
WIFISCOPE_AUTHOR='J. Doe' WIFISCOPE_OPNAME=NIGHTJAR \
  ./wifiscope.sh report capture.pcapng HomeNet hunter2   # -> "NIGHTJAR Mission Report"
```

## Why `report` limits its own concurrency

`report` and `fingerprint` fan their independent `tshark` passes out in parallel —
but every pass dissects the **whole** capture, so each one costs real memory. Around
29 passes over a 4 MB file is free; the same fan-out over a 255 MB capture will
exhaust a small VM and wedge it. So the number in flight is capped, sized from cpu
count, free memory, and the size of the capture actually loaded (roughly
capture + 256 MB budgeted per concurrent pass, spending at most 70% of free RAM).
Override with `WIFISCOPE_JOBS`.

While the passes run, a live line on **stderr** shows how many have finished, with a
spinner and elapsed time, so a multi-minute run on a large capture is visibly
working rather than indistinguishable from a hang:

```
  collecting evidence: 29 tshark passes over 254 MB, 4 at a time — leave it running
  \ ━━━━━━━━━━━━━━━━━━━━━━━···  26/29 passes  01:12
  ✓ evidence collected (29 passes) in 01:19
  · assembling tables and diagram…
```

It is stderr-only and terminal-only, so reports, pipes and redirects stay byte-clean.
`WIFISCOPE_NO_PROGRESS=1` turns it off explicitly.

Concurrency never changes the output — the report is assembled from the completed
passes afterwards, so `WIFISCOPE_JOBS=1` and `WIFISCOPE_JOBS=16` produce identical
files, just at different speeds.

## The keyring & decryption model

Keys live in `<pcap>.keys` (one per capture) and rebuild `tshark`'s decryption args on every run:

- **PSK/PMK** — `PBKDF2-SHA1(passphrase, ssid, 4096, 32)` → a `wpa-psk` entry.
- **PTK-TK** (per client) — modern TShark builds may expose selected components as
  `wlan.analysis.kck`, `wlan.analysis.kek`, and `wlan.analysis.tk`. For harvesting across versions,
  wifiscope computes it from the captured nonces using Bash/AWK plus OpenSSL HMAC-SHA1:
  `PTK = PRF-384(PMK, "Pairwise key expansion", min/max(MACs)‖min/max(nonces))`, `TK = PTK[32:48]`.
  A recovered TK alone decrypts that client's unicast.
- **GTK** (per BSS) — scraped from the decrypted key data of msg3 / group-key rekeys. A GTK alone
  decrypts that BSS's broadcast/multicast — the way to read a BSS whose handshake you couldn't
  complete but whose GTK you obtained elsewhere.

Because Wireshark's UAT has no dedicated GTK type, both PTK-TKs and GTKs are stored as `tk` entries
(the `tk` type decrypts pairwise **and** group frames).

`import` is forgiving about format — Wireshark UAT lines (`"tk","…"`), `type,value`, `type value`,
bare 32-hex (→ `tk`), bare 64-hex (→ `wpa-psk`), and `#` comments.

See [`docs/tshark_wifi_playbook.md`](docs/tshark_wifi_playbook.md) for the raw one-liners behind
each command.

## Report trust model

WiFiScope reports intentionally use three evidence levels:

- **Observed** — the PCAP contains the stated frame or field.
- **Inferred/correlated** — multiple observations support a role, but the role is not directly
  proven. The draw.io map labels these nodes `ROOT CANDIDATE` and prints the inference basis.
- **Not observed** — the evidence was not present in this capture. This never means the feature,
  host, or activity did not exist.

Reports **include** the recovered key material by default — passphrase, PSK/PMK, PTK-TK and GTK —
in section 6, each row labelled with what that key actually is and what it decrypts. That is the
point of an autopsy of your own capture. Set `WIFISCOPE_REPORT_SECRETS=0` to redact before sharing
outside a controlled artifact: the inventory then shows per-type counts instead of values, and the
TShark command blocks keep the full decryption-option structure with a `<passphrase>:<SSID>`
placeholder in place of real records.

## Tests

```bash
./wifiscope.sh selftest      # logic/filter checks + optional OpenSSL PMK vector — no pcap/tshark
./tests/run_tests.sh         # end-to-end: builds a synthetic capture (scapy) and asserts output
```

`tests/make_fixture.py` synthesises a small monitor-mode capture (a 2-node mesh, WPA2/WPA3/
Enterprise nets, a hidden SSID, a full 4-way handshake, and a WDS backhaul link); `run_tests.sh`
runs wifiscope against it and checks recon, crypto verdicts, bands, client discovery, handshakes,
OpenSSL harvesting, the Python boundary, topology, both map paths, and report redaction. If `scapy`
isn't installed the pcap-based tests are skipped and only the built-in selftest runs.

## Legal & ethics

For **authorized** use only — your own networks, lab captures, CTFs, and engagements you have
written permission to test. Decrypting or analyzing traffic you aren't authorized to touch is
illegal in most jurisdictions. You are responsible for how you use this.

## License

MIT — see [LICENSE](LICENSE).
