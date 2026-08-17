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

- **Recon** — protocol hierarchy + every SSID/BSSID/channel/band in the capture (2.4 / 5 / **6 GHz**).
- **Per-network analysis** — bands/channels, encryption (full RSN AKM verdict: WPA2/WPA3-Personal,
  **Enterprise 802.1X**, OWE, Suite-B, transition, WPA1/WEP/open), make/model (from WPS), wireless
  clients, PSK/PTK/GTK counts, and mesh topology (ESS vs backhaul "fake mesh").
- **Complete client discovery** — stations are found from association requests, EAPOL, **and** data
  frames (ToDS/FromDS), not handshakes alone — so clients that associated before the capture began
  still show up. Hidden SSIDs are surfaced and their names recovered from probe responses.
- **Host inventory** (post-decryption) — subnet/gateway, IPv4 **and IPv6** (ARP + ICMPv6 ND / DHCPv6),
  IP↔MAC, hostnames, OS/software versions.
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
- **Evidence reports** — generate an Obsidian-ready Markdown autopsy plus a matching map. Reports
  contain an executive summary, capture hash/timing, radio/security/WPS/OUI evidence, EAPOL and
  PMKID analysis, decryption validation, TK/GTK context, L3/host/DNS inventory, management events,
  quality checks, limitations, open questions, and the exact command beside every result.
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
./wifiscope.sh                 # asks for a pcap, then shows the menu
./wifiscope.sh capture.pcapng  # pcap preloaded
```

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
| `handshakes` | Per-client 4-way completeness + crackable flag |
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
| `WIFISCOPE_REPORT_SECRETS=1` | Include literal keys in a controlled training report; default reports redact values |

```bash
TSHARK=/opt/wireshark/bin/tshark ./wifiscope.sh recon capture.pcapng
NO_COLOR=1 ./wifiscope.sh crypto capture.pcapng HomeNet     # plain text
WIFISCOPE_REPORT_ROW_LIMIT=1000 ./wifiscope.sh report capture.pcapng HomeNet
WIFISCOPE_REPORT_SECRETS=1 ./wifiscope.sh report capture.pcapng HomeNet  # training artifact only
```

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

Normal reports never print passphrases, PSKs, TKs, or GTKs. The TShark command blocks preserve the
full decryption-option structure but replace values with `REDACTED`. Use `keymaterial`, or opt in
with `WIFISCOPE_REPORT_SECRETS=1`, only for a controlled training artifact.

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
