# 802.11 pcap post-processing playbook (tshark)

## Setup

```bash
PCAP="oxide_20260303_183032_1.pcapng"

# WPA decryption bundle
DEC=(-o wlan.enable_decryption:TRUE -o 'uat:80211_keys:"wpa-pwd","PASSPHRASE:SSID"')
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
5 GHz = freq 5xxx / HT primary channel (`wlan.ht.info.primarychannel`).

```bash
tshark -r "$PCAP" -Y 'wlan.fc.type_subtype==8 && wlan.bssid==BSSID' \
  -T fields -e wlan.ds.current_channel -e wlan.ht.info.primarychannel -e radiotap.channel.freq | sort -u
```

## Encryption (RSN / AKM)

AKM type 2 = PSK (WPA2), 8 = SAE (WPA3), both + MFP = transition.

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

## Keys

- PSK count = distinct passphrase+SSID pairs (usually 1).
- PTK count = distinct client↔AP handshakes.
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
