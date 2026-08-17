# 802.11 pcap post-processing playbook (tshark)

This is the command-level companion to WiFiScope's `report` output. The report mirrors the WIBOC
workflow: capture integrity → radio identity → crypto/hardware → EAPOL/PMKID → decryption sanity →
TK/GTK context → L3 inventory → management/topology → protocols → capture quality → limitations.
Each generated result includes its expanded, pasteable TShark command and a matching `.drawio`
map. Key values are redacted unless `WIFISCOPE_REPORT_SECRETS=1` is explicitly set.

Runtime boundary: recon, analysis, harvesting, PMKID export, `map`, and `mapall` are Bash/AWK.
OpenSSL/xxd provide cryptographic and binary-stream primitives. Python3 is resolved only while
`report` is producing its richer report-linked diagram; if absent, the report uses the Bash/AWK map.

## Setup

```bash
PCAP="oxide_20260303_183032_1.pcapng"

# WPA decryption bundle
DEC=(-o wlan.enable_decryption:TRUE -o 'uat:80211_keys:"wpa-pwd","PASSPHRASE:SSID"')
```

Load these once when copying commands out of a report:

```bash
tsv_columns() {
  if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi
}
table_rows() { tsv_columns; }
table_unique() {
  local header
  IFS= read -r header || return 0
  { printf '%s\n' "$header"; LC_ALL=C sort -u; } | tsv_columns
}
table_count() {
  local header
  IFS= read -r header || return 0
  { printf 'COUNT\t%s\n' "$header"; LC_ALL=C sort | uniq -c |
    sed -E 's/^[[:space:]]*([0-9]+)[[:space:]]+/\1\t/'; } | tsv_columns
}
```

For clean field output, use this shape consistently:

```bash
tshark -r "$PCAP" "${DEC[@]}" \
  -Y 'DISPLAY_FILTER' \
  -T fields \
  -E separator=/t \
  -E occurrence=f \
  -E header=y \
  -e frame.number \
  -e frame.time \
  | table_rows
```

Field names that bite: handshake key data is `wlan_rsna_eapol.keydes.*` not `eapol.keydes.*`.
`wlan.ssid` exists only in beacon/probe/assoc frames, never in data/EAPOL. Verify any field with
`tshark -G fields | grep <name>`.

Capture needs monitor mode (`iw dev wlan0 set type monitor` / `airmon-ng start wlan0`) and a
locked channel (`iw dev wlan0mon set channel N`) or hopping leaves client lists incomplete.

## Recon

```bash
# protocol hierarchy — what's in the capture
tshark -r "$PCAP" -q -z io,phs

# every beacon: bssid, ssid, 2.4 channel, 5 channel, freq
tshark -r "$PCAP" -Y 'wlan.fc.type_subtype==8' -T fields \
  -e wlan.bssid -e wlan.ssid -e wlan.ds.current_channel \
  -e wlan.ht.info.primarychannel -e radiotap.channel.freq | sort -u

# SSID -> BSSID for one network
tshark -r "$PCAP" -Y 'wlan.fc.type_subtype==8 && wlan.ssid=="SSID"' \
  -T fields -e wlan.bssid | sort -u

# IP <-> MAC vendor inventory
tshark -r "$PCAP" -N m -Y 'ip' -T fields -e eth.src -e eth.src_resolved -e ip.src | sort -u
```

## Band / channel

2.4 GHz = freq 24xx / DSSS channel 1-14 (`wlan.ds.current_channel`).
5 GHz = freq 5150-5895 / HT primary channel (`wlan.ht.info.primarychannel`).
6 GHz = freq 5925-7125 (WiFi 6E/7) — emits neither the DSSS nor HT tag, so derive the channel
from the radiotap frequency: `ch = (freq-5950)/5` (2.4: `(freq-2407)/5`, ch14=2484; 5: `(freq-5000)/5`).

```bash
tshark -r "$PCAP" -Y 'wlan.fc.type_subtype==8 && wlan.bssid==BSSID' \
  -T fields -e wlan.ds.current_channel -e wlan.ht.info.primarychannel -e radiotap.channel.freq | sort -u
```

## Encryption (RSN / AKM)

Read the whole AKM suite set, not just 2/8 — an Enterprise net has neither and must not be
misread as open. AKM suite types (OUI 00-0F-AC): 1 = 802.1X/EAP (Enterprise), 2 = PSK (WPA2),
3 = FT-802.1X, 4 = FT-PSK, 5 = 802.1X-SHA256, 6 = PSK-SHA256, 8 = SAE (WPA3), 9 = FT-SAE,
11/12 = 802.1X Suite-B (→ WPA3-Enterprise), 13 = FT-802.1X-SHA384, 14-17 = FILS, 18 = OWE
(Enhanced Open), 19/20 = PSK-SHA384. SAE+PSK together (usually with MFP) = WPA2/WPA3 transition.
No RSN AKM → check `wlan.wfa.ie.wpa.version` (WPA1) then `wlan.fixed.capabilities.privacy`
(set = WEP, unset = open).

```bash
tshark -r "$PCAP" -Y 'wlan.fc.type_subtype==8' -T fields \
  -e wlan.bssid -e wlan.ssid -e wlan.rsn.akms.type \
  -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr | sort -u

# words, from one beacon
tshark -r "$PCAP" -Y 'frame.number==N' -V | grep -iE 'Group Cipher|Pairwise|AKM type|Protection Capable'
```

## Make / model (WPS)

```bash
tshark -r "$PCAP" -Y 'wps.model_name || wps.manufacturer' -T fields \
  -e wlan.bssid -e wps.manufacturer -e wps.model_name \
  -e wps.model_number -e wps.device_name -e wps.serial_number | sort -u
```

## Clients

Assoc requests are cleanest but often not captured; fall back to handshakes.

```bash
# assoc/reassoc requests (carry SSID)
tshark -r "$PCAP" -Y '(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid=="SSID"' \
  -T fields -e wlan.sa -e wlan.bssid | sort -u

# handshakes: station, AP, msg number
tshark -r "$PCAP" -Y 'eapol' -T fields \
  -e frame.number -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr

# distinct client MACs (exclude AP BSSIDs)
tshark -r "$PCAP" -Y 'eapol' -T fields -e wlan.sa -e wlan.da \
  | tr '\t' '\n' | sort -u | grep -Ev '^(AP_BSSID_PREFIXES):'

# confirm via decrypted L2 (a device seen here but never in a handshake = wired)
tshark -r "$PCAP" "${DEC[@]}" -Y 'wlan.fc.type==2 && (ip||arp)' \
  -T fields -e wlan.sa -e wlan.da | tr '\t' '\n' | sort -u
```

Complete station discovery = the UNION of all four signals (a client already associated before the
capture has no handshake, but its data frames are everywhere). Strip group-addressed MACs (2nd hex
digit odd) and known BSSIDs afterward:

```bash
{ tshark -r "$PCAP" -Y '(wlan.fc.type_subtype==0||wlan.fc.type_subtype==2) && wlan.ssid=="SSID"' -T fields -e wlan.sa
  tshark -r "$PCAP" -Y 'eapol && wlan.bssid==BSSID' -T fields -e wlan.sa -e wlan.da | tr '\t' '\n'
  tshark -r "$PCAP" -Y 'wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && wlan.bssid==BSSID' -T fields -e wlan.sa
  tshark -r "$PCAP" -Y 'wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && wlan.bssid==BSSID' -T fields -e wlan.da
} | tr '\t' '\n' | sort -u | grep .
```

A station seen only receiving M1 is a station observation, not a recovered PTK. Count a
recoverable/crackable station↔BSSID context only when `(M1 && M2) || (M2 && M3)` is present.

## PMKID

Do not require EAPOL. PMKID evidence is normally carried in association RSN information:

```bash
tshark -r "$PCAP" \
  -Y 'wlan.bssid==BSSID && (wlan.pmkid.akms || wlan.rsn.ie.pmkid)' \
  -T fields -E separator=/t -E occurrence=f -E header=y \
  -e frame.number -e frame.time -e wlan.fc.type_subtype \
  -e wlan.sa -e wlan.da -e wlan.bssid \
  -e wlan.pmkid.akms -e wlan.rsn.ie.pmkid \
  | table_rows
```

## Hidden SSIDs

Hidden APs beacon with a zero-length SSID; recover the name from frames that carry it:

```bash
tshark -r "$PCAP" -Y 'wlan.bssid==BSSID && (wlan.fc.type_subtype==5||wlan.fc.type_subtype==0) && wlan.ssid!=""' \
  -T fields -e wlan.ssid | sort -u
```

## IPv6 hosts

ARP is IPv4-only; IPv6 hosts appear via ICMPv6 neighbor discovery and DHCPv6:

```bash
# IPv6 <-> MAC from the ND link-layer option (NS/NA/RS/RA)
tshark -r "$PCAP" "${DEC[@]}" -Y 'icmpv6 && icmpv6.opt.linkaddr' -T fields \
  -e ipv6.src -e icmpv6.opt.linkaddr -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address | sort -u

# DHCPv6 client MAC (DUID-LL)
tshark -r "$PCAP" "${DEC[@]}" -Y 'dhcpv6' -T fields -e ipv6.src -e dhcpv6.duidll.link_layer_addr | sort -u
```

## Keys

- PSK count = distinct passphrase+SSID pairs (usually 1).
- Recoverable PTK-context count = distinct station↔BSSID contexts with M1+M2 or M2+M3.
- GTK in use = fronthaul BSSes = APs × active bands (per-BSS key).
- GTK recoverable = handshakes complete enough to derive the PTK (blank if msg1 missing).

```bash
# GTK per AP (msg3), decrypted
tshark -r "$PCAP" "${DEC[@]}" -Y 'wlan_rsna_eapol.keydes.msgnr==3' \
  -T fields -e wlan.sa -e wlan.rsn.ie.gtk_kde.gtk | sort -u

# distinct recovered GTK values
tshark -r "$PCAP" "${DEC[@]}" -Y 'wlan_rsna_eapol.keydes.msgnr==3' \
  -T fields -e wlan.rsn.ie.gtk_kde.gtk | sort -u | grep .

# GTK field name from a decrypted msg3
tshark -r "$PCAP" "${DEC[@]}" -Y 'frame.number==N' -V | grep -iE 'GTK|Key ID'
```

Modern Wireshark/TShark builds can expose the PTK components selected for a decoded context. Keep
the BSSID, station, message, and replay counter attached; a bare key list loses attribution:

```bash
tshark -r "$PCAP" "${DEC[@]}" \
  -Y 'wlan.analysis.kck || wlan.analysis.kek || wlan.analysis.tk' \
  -T fields -E separator=/t -E occurrence=f -E header=y \
  -e frame.number -e frame.time -e wlan.bssid -e wlan.staa \
  -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
  -e wlan.analysis.pmk -e wlan.analysis.kck -e wlan.analysis.kek -e wlan.analysis.tk \
  | table_unique
```

Extract GTK/IGTK/BIGTK from decrypted M3 with its full context:

```bash
tshark -r "$PCAP" "${DEC[@]}" \
  -Y 'eapol && wlan_rsna_eapol.keydes.msgnr==3 && (wlan.rsn.ie.gtk_kde.gtk || wlan.rsn.ie.igtk.kde.igtk || wlan.rsn.ie.bigtk_kde.bigtk)' \
  -T fields -E separator=/t -E occurrence=f -E header=y \
  -e frame.number -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid \
  -e eapol.keydes.replay_counter \
  -e wlan.rsn.ie.gtk_kde.key_id -e wlan.rsn.ie.gtk_kde.tx -e wlan.rsn.ie.gtk_kde.gtk \
  -e wlan.rsn.ie.igtk.kde.keyid -e wlan.rsn.ie.igtk.kde.ipn -e wlan.rsn.ie.igtk.kde.igtk \
  -e wlan.rsn.ie.bigtk_kde.key_id -e wlan.rsn.ie.bigtk_kde.bipn -e wlan.rsn.ie.bigtk_kde.bigtk \
  | table_unique
```

If M3 exists but the GTK is empty, check for a valid passphrase/PMK, both nonce contexts, a derived
KEK, encrypted key-data length, and version compatibility. A supplied `tk` can decrypt some
pairwise traffic but cannot by itself unwrap the GTK KDE in M3.

## Topology (mesh AP count)

Count physical units by backhaul evidence, not OUI prefix — packs use consecutive factory MACs.

```bash
# 4-address WDS backhaul: satellite backhaul-STA <-> root radio
tshark -r "$PCAP" -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' \
  -T fields -e wlan.ta -e wlan.ra | sort -u
tshark -r "$PCAP" -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' | wc -l

# fronthaul BSS count (= GTKs in use)
tshark -r "$PCAP" -Y 'wlan.fc.type_subtype==8 && wlan.ssid=="SSID"' \
  -T fields -e wlan.bssid | sort -u | wc -l

# RSSI per BSSID to separate co-located radios from distinct units
tshark -r "$PCAP" -Y 'wlan.bssid==BSSID && wlan.fc.type_subtype==8' \
  -T fields -e radiotap.dbm_antsignal | head -200 | awk '{s+=$1;n++} END{print s/n" dBm n="n}'
```

Backhaul ESS ("fake mesh") = same SSID on multiple nodes + 4-addr WDS backhaul, no mesh IE.
802.11s true mesh = mesh IE / mesh action frames.

## Decrypted host data

```bash
# decryption sanity
tshark -r "$PCAP" "${DEC[@]}" -Y 'arp || ip' | wc -l

# subnet / gateway (DHCP option 1 + 3)
tshark -r "$PCAP" "${DEC[@]}" -Y 'dhcp' -T fields \
  -e dhcp.ip.your -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname | sort -u

# DHCP fingerprint (client mac / ip / hostname / vendor class)
tshark -r "$PCAP" "${DEC[@]}" -Y 'dhcp' -T fields \
  -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
  -e dhcp.option.hostname -e dhcp.option.vendor_class_id | sort -u

# ARP IP<->MAC
tshark -r "$PCAP" "${DEC[@]}" -Y 'arp' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u

# identify one host
tshark -r "$PCAP" "${DEC[@]}" -Y 'ip.src==IP && mdns' -T fields -e dns.resp.name | tr ',' '\n' | sort -u
tshark -r "$PCAP" "${DEC[@]}" -Y 'browser && ip.src==IP' -T fields -e browser.server -e browser.comment | sort -u
tshark -r "$PCAP" "${DEC[@]}" -Y 'nbns && ip.addr==IP' -T fields -e nbns.name | sort -u

# hostnames sweep
tshark -r "$PCAP" "${DEC[@]}" -Y 'dhcp.option.hostname || nbns || mdns || llmnr' -T fields \
  -e ip.src -e dhcp.option.hostname -e nbns.name -e dns.qry.name | sort -u

# software versions
tshark -r "$PCAP" "${DEC[@]}" -Y 'http.user_agent || http.server || ssh.protocol' -T fields \
  -e ip.src -e http.user_agent -e http.server -e ssh.protocol | sort -u

# per-host protocols
tshark -r "$PCAP" "${DEC[@]}" -Y 'ip.src==IP' -T fields -e ip.src -e _ws.col.protocol | sort -u
```

## Capture quality

```bash
# Truncated frames: payload conclusions may be incomplete.
tshark -r "$PCAP" -Y 'frame.cap_len < frame.len' \
  -T fields -E separator=/t -E occurrence=f -E header=y \
  -e frame.number -e frame.time -e frame.cap_len -e frame.len -e wlan.bssid \
  | table_rows

# Target retries: useful RF/contention evidence, but not unique traffic.
tshark -r "$PCAP" -Y 'wlan.bssid==BSSID && wlan.fc.retry==1' \
  -T fields -E separator=/t -E occurrence=f -E header=y \
  -e frame.number -e frame.time -e wlan.fc.type_subtype \
  -e wlan.sa -e wlan.da -e wlan.seq -e radiotap.dbm_antsignal \
  | table_rows
```

## Report and draw.io evidence rules

Run the full evidence pass with:

```bash
./wifiscope.sh report "$PCAP" "SSID" "PASSPHRASE"
```

The report and diagram use the same evidence model:

- **Observed:** a matching frame/field exists in the capture.
- **Inferred/correlated:** multiple observations support a role, but do not directly prove it.
- **Not observed:** no matching evidence was captured; this is not proof of absence.
- A node is labeled `GATEWAY / AP (confirmed)` only after an exact DHCP router IP → ARP MAC →
  beacon BSSID match. Similar MAC ranges, WDS degree, or client count produce `ROOT CANDIDATE`.
- A DHCP option 3 value is a LAN default gateway, not automatically an Internet/ISP or WAN IP.
- Four-address/WDS rows are capture-wide when no ordinary BSSID is available and must be correlated
  before assigning them to the target ESS.
- Normal reports redact passphrases, PSKs, TKs, and GTKs. `keymaterial` deliberately prints them;
  `WIFISCOPE_REPORT_SECRETS=1` opts a controlled training report into literal values.
