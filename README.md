# wifiscope 📡

Interactive **802.11 pcap triage** for `tshark`. Point it at a monitor-mode capture and it
answers the questions you actually ask in wireless forensics — who's on the network, what gear,
what crypto, which handshakes, what keys — then harvests key material and feeds it back into
`tshark` so you can decrypt and slice further.

It's a single, heavily-commented Bash script (tshark + coreutils only). Every action **prints the
exact `tshark` command it runs**, so it doubles as a way to learn the queries.

```
  wifiscope  pcap:capture.pcapng  target:HomeNet  decrypt:on  keys:9
  ──────────────────────────────────────────────────────────
   ANALYZE  1 recon   2 bands   3 crypto   4 hardware
            5 clients 6 keys    7 topology 8 hosts
            9 probes  0 handshakes
   CRACK    p pmkid   x export22000  (hashcat -m 22000)
   KEYS     k passphrase  h harvest  g scrapegtk
            a addkey  i import  K show  d delkey  c clearkey
   SESSION  s select-ssid  r report  q quit
```

## Features

- **Recon** — protocol hierarchy + every SSID/BSSID/channel/band in the capture.
- **Per-network analysis** — bands/channels, encryption (WPA2 / WPA3 / transition), make/model
  (from WPS), wireless clients, PSK/PTK/GTK counts, and mesh topology (ESS vs backhaul "fake mesh").
- **Host inventory** (post-decryption) — subnet/gateway, IP↔MAC, hostnames, OS/software versions.
- **Key harvesting & keyring** — derive the PSK, compute each client's PTK-TK, scrape GTKs, and
  persist them to a per-capture keyring that auto-applies to every later query. Import/add keys from
  other tools (hcxtools, hostapd, oxide) to decrypt BSSes whose handshake you didn't capture.
- **Cracking hand-off** — list PMKIDs and export a `hashcat -m 22000` file.
- **Profiling** — probe-request mapping (what SSIDs each client is hunting for) and a per-client
  handshake-completeness / crackability table.
- **Reports** — dump everything to a clean Markdown file.
- **UX** — color + emoji + clickable (OSC-8) MAC→vendor links and role-colored addresses, all of
  which **auto-disable** when piped, redirected, or `NO_COLOR` is set (reports stay plain).

## Requirements

- `tshark` (Wireshark ≥ 3.x; developed against 4.6)
- coreutils: `awk`, `sort`, `grep`, `tr`, `sed`
- `python3` — only for key derivation (`harvest`) and PMKID export
- Optional: `hcxpcapngtool` for full EAPOL → 22000 export (PMKID export works without it)

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
| `clients` | Wireless stations (from 4-way handshakes) |
| `keys` | PSK / PTK / GTK counts (in use vs recoverable) |
| `topology` | AP count + 802.11 WDS backhaul (mesh detection) |
| `hosts` | Subnet, IP↔MAC, hostnames, versions (needs a key) |
| `probes` | Directed probe requests: client → SSID sought |
| `handshakes` | Per-client 4-way completeness + crackable flag |
| `pmkid` | List RSN PMKIDs (offline-crackable) |
| `export22000` | Write a `hashcat -m 22000` file |
| `harvest` | Derive PSK + compute PTK-TKs + scrape GTKs → keyring |
| `scrapegtk` | Sweep the whole capture for GTKs → keyring |
| `addkey` / `import` | Add external key material to the keyring |
| `keyring` / `delkey` / `clearkey` | Manage the keyring |
| `report` | Everything → Markdown |

## The keyring & decryption model

Keys live in `<pcap>.keys` (one per capture) and rebuild `tshark`'s decryption args on every run:

- **PSK/PMK** — `PBKDF2-SHA1(passphrase, ssid, 4096, 32)` → a `wpa-psk` entry.
- **PTK-TK** (per client) — `tshark` never emits the PTK it derives, so wifiscope computes it:
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

## Legal & ethics

For **authorized** use only — your own networks, lab captures, CTFs, and engagements you have
written permission to test. Decrypting or analyzing traffic you aren't authorized to touch is
illegal in most jurisdictions. You are responsible for how you use this.

## License

MIT — see [LICENSE](LICENSE).
