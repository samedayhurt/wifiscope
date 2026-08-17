#!/usr/bin/env bash
#
# wifiscope.sh — interactive 802.11 pcap triage with tshark
# -----------------------------------------------------------------------------
# Answers the usual wifi-forensics questions from a monitor-mode capture:
#   SSID/channel/band, encryption, make/model, clients, PSK/PTK/GTK counts,
#   mesh AP count, and (after decryption) subnet + host inventory.
#
# Two ways to run it:
#   Interactive :  ./wifiscope.sh                 # asks for a pcap, shows a menu
#                  ./wifiscope.sh capture.pcapng  # same, pcap pre-loaded
#   One-shot    :  ./wifiscope.sh <command> capture.pcapng [SSID] [passphrase]
#                  e.g. ./wifiscope.sh crypto capture.pcapng Ahmed_Shebakah
#
# Commands (also the menu items): recon bands crypto hardware clients keys
#                                 topology hosts report
#
# Only needs: tshark, plus coreutils (awk, sort, grep, tr, sed). Nothing else.
# -----------------------------------------------------------------------------

# We deliberately do NOT use `set -e`: many tshark|grep pipelines exit non-zero
# simply because a filter matched nothing, and that must not kill the script.
# `set -u` (error on unset var) + pipefail still catch real mistakes.
set -uo pipefail

# ---- globals ----------------------------------------------------------------
VERSION="1.1.0"

# Override the tshark path if it isn't on $PATH:  TSHARK=/opt/wireshark/bin/tshark ./wifiscope.sh
TSHARK="${TSHARK:-tshark}"

# Pick a WORKING python: prefer python3, but fall back to `python` when python3 is
# the Windows Store stub (it only prints an install message and exits non-zero).
# Used by key derivation (harvest) and the draw.io map generator.
PYBIN="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYBIN" ] || ! "$PYBIN" -c 'pass' >/dev/null 2>&1; then
  PYBIN="$(command -v python 2>/dev/null || true)"
fi

PCAP=""              # capture file we're working on
SSID=""             # the target network name (once selected)
PASS=""             # WPA passphrase (optional, for decryption)
DEC=()              # tshark decryption args, REBUILT from the keyring (empty = off)
KEYRING=""          # path to <pcap>.keys — the harvested key store (UAT lines)
TGT_BSSIDS=()       # every BSSID advertising the target SSID
ALL_BSSIDS=()       # every BSSID in the whole capture (used to spot non-AP MACs)

# ---- color / UX -------------------------------------------------------------
# Color + clickable links turn ON for a real terminal (or WIFISCOPE_FORCE_COLOR=1)
# and OFF when piped or NO_COLOR is set — so the report export and any pipes stay
# clean, plain text. This is why we can decorate freely without breaking parsing.
if [ -n "${WIFISCOPE_FORCE_COLOR:-}" ] || { [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; }; then
  C_RESET=$'\e[0m'; C_B=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_BLU=$'\e[34m'; C_MAG=$'\e[35m'; C_CYN=$'\e[36m'; C_ORG=$'\e[38;5;208m'
  UX_LINKS=1
else
  C_RESET=; C_B=; C_DIM=; C_RED=; C_GRN=; C_YEL=; C_BLU=; C_MAG=; C_CYN=; C_ORG=; UX_LINKS=0
fi

# hlink URL TEXT: an OSC-8 clickable terminal hyperlink (plain TEXT if links off).
hlink() {
  if [ "$UX_LINKS" = 1 ]; then printf '\e]8;;%s\e\\%s\e]8;;\e\\' "$1" "$2"; else printf '%s' "$2"; fi
}

# ---- output helpers ---------------------------------------------------------
# section: a bold, colored, skimmable header (emoji lives in the passed string).
section() { printf '\n%s── %s ──%s\n' "$C_B$C_CYN" "$*" "$C_RESET"; }
# note/ok/die: status lines to stderr, so they never pollute piped data or reports.
note()    { printf '%s  · %s%s\n' "$C_DIM$C_YEL" "$*" "$C_RESET" >&2; }
ok()      { printf '%s  ✔ %s%s\n' "$C_GRN" "$*" "$C_RESET" >&2; }
die()     { printf '%s✖ %s%s\n' "$C_B$C_RED" "$*" "$C_RESET" >&2; exit 1; }

# need: bail early with a clear message if a required program is missing.
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

# paint: colorize a DATA stream for display — MACs by role (target BSSID = bold
# cyan, other AP = blue, client = green) each linked to a vendor OUI lookup, and
# IPv4 in yellow. A no-op when color is off, so it's only ever applied to output
# we're about to show (never to data we parse). Portable regex (no {n} intervals
# for mawk). Used at the dispatch layer on read-only display commands.
paint() {
  [ -n "$C_RESET" ] || { cat; return; }
  awk -v T="${TGT_BSSIDS[*]}" -v A="${ALL_BSSIDS[*]}" -v links="$UX_LINKS" \
      -v cyn="$C_B$C_CYN" -v blu="$C_BLU" -v grn="$C_GRN" -v yel="$C_YEL" -v rst="$C_RESET" '
    BEGIN{ h="[0-9A-Fa-f][0-9A-Fa-f]"; RE=h":"h":"h":"h":"h":"h;
           n=split(T,x," "); for(i=1;i<=n;i++) TT[tolower(x[i])]=1;
           m=split(A,y," "); for(i=1;i<=m;i++) AA[tolower(y[i])]=1; }
    {
      s=$0; out="";
      while (match(s, RE)) {
        pre=substr(s,1,RSTART-1); mac=substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH);
        lm=tolower(mac);
        col=(lm in TT)?cyn:((lm in AA)?blu:grn);
        if (links=="1")
          out=out pre col "\033]8;;https://maclookup.app/search/result?mac=" mac "\033\\" mac "\033]8;;\033\\" rst;
        else
          out=out pre col mac rst;
      }
      out=out s;
      gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, yel"&"rst, out);
      print out;
    }'
}

# banner: a little launch flourish (color only).
banner() {
  [ -n "$C_RESET" ] || return
  printf '%s\n  📡 %swifiscope%s%s — 802.11 pcap triage & key harvesting%s\n' \
    "$C_CYN" "$C_B" "$C_RESET$C_CYN" "$C_DIM" "$C_RESET"
}

# ---- tshark wrappers --------------------------------------------------------
# ts:  run tshark on the loaded pcap WITHOUT decryption keys.
#      It first echoes the exact command (to stderr) so you can read/copy/learn
#      it, then actually runs it. Use this for anything in cleartext management
#      frames: beacons, WPS, RSN, association, 4-address backhaul.
ts() {
  printf '%s  $ tshark -r %q %s%s\n' "$C_DIM$C_GRN" "$PCAP" "$*" "$C_RESET" >&2
  # `tr -d '\r'` strips carriage returns so sort -u/grep behave when the pcap is
  # read by a Windows tshark.exe (CRLF output). On Linux it's a harmless no-op.
  "$TSHARK" -r "$PCAP" "$@" | tr -d '\r'
}

# tsd: like ts() but ALSO passes the decryption keys ("${DEC[@]}").
#      Use this for anything that only exists once traffic is decrypted:
#      ARP, DHCP, mDNS, the GTK inside handshake message 3, host inventory.
#      If no key has been set it warns and just runs in the clear.
tsd() {
  if [ "${#DEC[@]}" -eq 0 ]; then
    note "no decryption key set — run 'k' (menu) or pass a passphrase; results may be empty"
  fi
  printf '%s  $ tshark -r %q [+keys] %s%s\n' "$C_DIM$C_GRN" "$PCAP" "$*" "$C_RESET" >&2
  "$TSHARK" -r "$PCAP" "${DEC[@]}" "$@" | tr -d '\r'
}

# ---- filter helpers ---------------------------------------------------------
# beacons_of_target: display filter for "beacon frames of the chosen SSID".
#   subtype 8 == beacon.  wlan.ssid only exists in beacon/probe/assoc frames.
beacons_of_target() { printf 'wlan.fc.type_subtype==8 && wlan.ssid=="%s"' "$SSID"; }

# bssid_filter: OR-together every target BSSID -> "(wlan.bssid==a || wlan.bssid==b)".
#   EAPOL/data frames carry no SSID, so we scope them by the AP's BSSIDs instead.
bssid_filter() {
  local out="" b
  for b in "${TGT_BSSIDS[@]}"; do out+="${out:+ || }wlan.bssid==$b"; done
  printf '(%s)' "${out:-wlan.bssid==00:00:00:00:00:00}"
}

# dessid [COL]: decode a hex-encoded SSID in TAB column COL (default 2) to text.
#   tshark renders wlan.ssid as hex under -T fields, so "Ahmed_Shebakah" comes out
#   as 41686d65...; this makes it human-readable (and, in pick_ssid, selectable).
#   Portable — builds a hex table in awk instead of using gawk-only strtonum().
dessid() {
  awk -F'\t' -v col="${1:-2}" 'BEGIN{OFS="\t"; for(i=0;i<16;i++){c=sprintf("%x",i);H[c]=i;H[toupper(c)]=i}}
    { v=$col;
      if(length(v)>0 && length(v)%2==0 && v ~ /^[0-9A-Fa-f]+$/){ s="";
        for(i=1;i<=length(v);i+=2) s=s sprintf("%c", H[substr(v,i,1)]*16+H[substr(v,i+1,1)]);
        $col=s }
      print }'
}

# ---- loading / selection ----------------------------------------------------
# load_pcap: validate the file and cache every BSSID in the capture (used later
#            to tell APs apart from client stations).
load_pcap() {
  PCAP="$1"
  [ -f "$PCAP" ] || die "no such file: $PCAP"
  note "indexing capture (one pass to list all BSSIDs)..."
  mapfile -t ALL_BSSIDS < <(
    "$TSHARK" -r "$PCAP" -Y 'wlan.fc.type_subtype==8' -T fields -e wlan.bssid 2>/dev/null \
      | tr -d '\r' | sort -u | grep .
  )
  note "capture has ${#ALL_BSSIDS[@]} beaconing BSSIDs"
  # The keyring lives next to the pcap and persists between runs.
  KEYRING="${PCAP}.keys"
  rebuild_dec
  [ -s "$KEYRING" ] && note "loaded $(grep -c . "$KEYRING") key(s) from $KEYRING"
}

# pick_ssid: list the SSIDs in the capture (with how many BSSIDs each spans) and
#            let the user choose the target. This is the "single network" scope:
#            you must see the names before you can focus on one.
# resolve_hidden BSSID: recover a hidden AP's SSID from the frames that DO carry it —
#   probe responses (subtype 5) and association requests (subtype 0) referencing that
#   BSSID. Returns the most-seen name, or empty if the SSID was never disclosed.
resolve_hidden() {
  local b="$1"
  "$TSHARK" -r "$PCAP" \
    -Y "wlan.bssid==$b && (wlan.fc.type_subtype==5 || wlan.fc.type_subtype==0) && wlan.ssid != \"\"" \
    -T fields -e wlan.ssid 2>/dev/null | tr -d '\r' | dessid 1 \
    | grep -v '<MISSING>' | grep . | sort | uniq -c | sort -rn | sed 's/^ *[0-9]* *//' | head -1
}

pick_ssid() {
  section "networks in this capture"
  # Build a numbered list of unique, non-empty SSIDs.
  mapfile -t names < <(
    "$TSHARK" -r "$PCAP" -Y 'wlan.fc.type_subtype==8' -T fields -e wlan.ssid 2>/dev/null \
      | tr -d '\r' | dessid 1 | sort | uniq -c | sort -rn | sed 's/^ *//' \
      | grep -v '^[0-9]* *$' | grep -v '<MISSING>'   # named nets; hidden ones handled below
  )
  # Hidden APs beacon with a zero-length SSID; list them too (with any recovered
  # name) so a hidden target can still be selected — it scopes by BSSID afterward.
  mapfile -t hidden < <(
    "$TSHARK" -r "$PCAP" -Y 'wlan.fc.type_subtype==8 && (wlan.ssid=="" || wlan.ssid=="<MISSING>")' \
      -T fields -e wlan.bssid 2>/dev/null | tr -d '\r' | sort -u | grep .
  )
  local i=1 line b nm; local -a hnames=()
  for line in "${names[@]}"; do printf '  %2d) %s\n' "$i" "$line"; i=$((i+1)); done
  for b in "${hidden[@]}"; do
    nm="$(resolve_hidden "$b")"; hnames+=("$nm")
    if [ -n "$nm" ]; then printf '  %2d) %s %s(hidden, %s)%s\n' "$i" "$nm" "$C_DIM" "$b" "$C_RESET"
    else                 printf '  %2d) %s<hidden>%s  %s\n' "$i" "$C_DIM" "$C_RESET" "$b"; fi
    i=$((i+1))
  done
  printf 'select target SSID number (or type a name): '
  read -r choice || die "no input"
  local nn="${#names[@]}" nh="${#hidden[@]}"
  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$((nn+nh))" ]; then
    if [ "$choice" -le "$nn" ]; then
      SSID="$(printf '%s\n' "${names[$((choice-1))]}" | sed 's/^[0-9]* *//')"   # strip count
      load_target_bssids
    else
      local hb="${hidden[$((choice-nn-1))]}"
      SSID="${hnames[$((choice-nn-1))]:-$hb}"
      TGT_BSSIDS=("$hb")                        # hidden: beacons carry no name, scope by BSSID
      note "hidden network: scoping by BSSID $hb"
    fi
  else
    SSID="$choice"; load_target_bssids
  fi
  [ -n "$SSID" ] || die "no SSID selected"
  note "target SSID: $SSID  (${#TGT_BSSIDS[@]} BSSIDs)"
}

# load_target_bssids: cache the BSSIDs that advertise the chosen SSID.
load_target_bssids() {
  mapfile -t TGT_BSSIDS < <(
    "$TSHARK" -r "$PCAP" -Y "$(beacons_of_target)" -T fields -e wlan.bssid 2>/dev/null \
      | tr -d '\r' | sort -u | grep .
  )
}

# set_key: ask for the WPA passphrase, store it in the keyring, and rebuild DEC.
#   The wpa-pwd entry lets tshark derive the PMK and every client PTK on its own.
#   The PMK depends on passphrase AND SSID, which is why the SSID is chosen first.
set_key() {
  [ -n "$SSID" ] || { note "choose an SSID first (needed to derive the key)"; return; }
  printf 'WPA passphrase for "%s" (blank = skip): ' "$SSID"
  read -r PASS || PASS=""
  if [ -n "$PASS" ]; then
    kr_add wpa-pwd "$PASS:$SSID"
    rebuild_dec
    note "decryption enabled (wpa-pwd added to keyring)"
  else
    note "no passphrase entered"
  fi
}

# =============================================================================
#  KEYRING  — harvest key material (PSK / PTK-TK / GTK) and feed it back into
#  tshark so later passes decrypt more. All keys live in one per-pcap file and
#  every tshark call rebuilds its decryption args from it.
# =============================================================================

# kr_add TYPE VALUE: append a key to the keyring, skipping exact duplicates.
#   TYPE is a tshark UAT key type: wpa-pwd | wpa-psk | tk | wep | msk.
#   Stored as "type<TAB>value" so values containing ':' (wpa-pwd) stay intact.
kr_add() {
  local line; line="$(printf '%s\t%s' "$1" "$2")"
  [ -n "$KEYRING" ] || { note "no keyring path set (load a pcap first)"; return; }
  touch "$KEYRING"
  grep -Fxq "$line" "$KEYRING" 2>/dev/null || printf '%s\n' "$line" >> "$KEYRING"
}

# rebuild_dec: turn the keyring file into tshark args in DEC[].
#   Each key becomes its own  -o uat:80211_keys:"type","value"  (tshark APPENDS
#   one UAT record per -o), plus a single enable-decryption switch up front.
rebuild_dec() {
  DEC=()
  [ -n "$KEYRING" ] && [ -s "$KEYRING" ] || return
  DEC=(-o wlan.enable_decryption:TRUE)
  local t v
  while IFS=$'\t' read -r t v; do
    [ -n "$t" ] || continue
    DEC+=(-o "uat:80211_keys:\"$t\",\"$v\"")
  done < "$KEYRING"
}

# pmk_hex: compute the 256-bit PMK/PSK from passphrase + SSID (WPA2-PSK).
#   PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096 iters, 32 bytes). Deterministic,
#   so this IS the network's PSK in raw hex — usable as a wpa-psk key.
pmk_hex() {
  "$PYBIN" - "$PASS" "$SSID" <<'PY'
import sys, hashlib, binascii
print(binascii.hexlify(hashlib.pbkdf2_hmac('sha1', sys.argv[1].encode(),
      sys.argv[2].encode(), 4096, 32)).decode())
PY
}

# derive_psk: harvest the PSK/PMK into the keyring as a wpa-psk entry.
derive_psk() {
  [ -n "$PASS" ] && [ -n "$SSID" ] || { note "need passphrase+SSID for PSK"; return; }
  local pmk; pmk="$(pmk_hex)"
  [ -n "$pmk" ] && { kr_add wpa-psk "$pmk"; note "PSK/PMK: $pmk"; }
}

# harvest_ptk: compute each client's PTK-TK and add it to the keyring as a tk.
#   tshark never prints the PTK it derives, so we compute it ourselves:
#     B   = min(AA,SPA)||max(AA,SPA)||min(ANonce,SNonce)||max(ANonce,SNonce)
#     PTK = PRF-384(PMK, "Pairwise key expansion", B)   (HMAC-SHA1 blocks)
#     TK  = PTK[32:48]   (KCK16 | KEK16 | TK16, CCMP)
#   ANonce comes from msg1/msg3 (AP side), SNonce from msg2 (STA side) — all
#   cleartext in the EAPOL frames, so no decryption is needed to read them.
harvest_ptk() {
  [ -n "$PASS" ] && [ -n "$SSID" ] || { note "need passphrase+SSID for PTKs"; return; }
  local pmk; pmk="$(pmk_hex)"
  # IMPORTANT: python must read the tshark rows on STDIN, so the program cannot
  # also come from stdin — `python3 -` would consume the here-doc instead of the
  # piped data. Load the script into a variable and pass it with `python3 -c`.
  local PTK_PY
  read -r -d '' PTK_PY <<'PY'
import sys, hmac, hashlib, binascii
pmk = binascii.unhexlify(sys.argv[1])
mac = lambda m: binascii.unhexlify(m.replace(':', ''))
def prf(key, A, B, n):                       # IEEE 802.11 PRF using HMAC-SHA1
    R = b''; i = 0
    while len(R) < n:
        R += hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1).digest(); i += 1
    return R[:n]
S = {}
for ln in sys.stdin:
    p = ln.rstrip('\n').split('\t')
    if len(p) < 4 or not p[3]:               # need a nonce
        continue
    sa, da, m, nh = p[0], p[1], p[2], p[3]
    try: n = binascii.unhexlify(nh)
    except Exception: continue
    if m in ('1', '3'): ap, sta, an, sn = sa, da, n, None   # AP sends ANonce
    elif m == '2':      ap, sta, an, sn = da, sa, None, n    # STA sends SNonce
    else: continue
    e = S.setdefault((ap, sta), {'an': None, 'sn': None})
    if an: e['an'] = an
    if sn: e['sn'] = sn
for (ap, sta), e in S.items():
    if not (e['an'] and e['sn']): continue   # need both nonces
    aa, spa = mac(ap), mac(sta)
    B = min(aa, spa) + max(aa, spa) + min(e['an'], e['sn']) + max(e['an'], e['sn'])
    tk = prf(pmk, b'Pairwise key expansion', B, 48)[32:48]
    print('%s\t%s\t%s' % (sta, ap, binascii.hexlify(tk).decode()))
PY
  local out
  out="$(ts -Y "wlan_rsna_eapol.keydes.msgnr in {1,2,3} && $(bssid_filter)" -T fields \
        -e wlan.sa -e wlan.da -e wlan_rsna_eapol.keydes.msgnr -e wlan_rsna_eapol.keydes.nonce \
        | "$PYBIN" -c "$PTK_PY" "$pmk")"
  [ -n "$out" ] || { note "no complete handshakes (need both nonces) to derive PTKs"; return; }
  local sta ap tk
  while IFS=$'\t' read -r sta ap tk; do
    [ -n "$tk" ] || continue
    kr_add tk "$tk"
    note "PTK-TK  $sta @ $ap  ->  $tk"
  done <<< "$out"
}

# harvest_gtk: extract every recoverable GTK for the TARGET SSID as a tk.
#   Filters on the GTK KDE itself (not just 4-way msg3), so it also catches GTKs
#   handed out in group-key REKEY handshakes. Needs decryption already working
#   (a key must decrypt the KEK-encrypted key data first).
harvest_gtk() {
  rebuild_dec
  local g
  g="$(tsd -Y "wlan.rsn.ie.gtk_kde.gtk && $(bssid_filter)" -T fields \
       -e wlan.rsn.ie.gtk_kde.gtk 2>/dev/null | sort -u | grep .)"
  [ -n "$g" ] || { note "no GTKs recoverable (need a decryptable handshake)"; return; }
  local gtk
  while read -r gtk; do
    [ -n "$gtk" ] || continue
    kr_add tk "$gtk"
    note "GTK -> $gtk"
  done <<< "$g"
}

# scrapegtk: sweep the WHOLE capture (every SSID/BSS) for any recoverable GTK and
#   add each unique one to the keyring. Broader than harvest_gtk, which is scoped
#   to the chosen network. Same requirement: a working key must decrypt the GTK
#   KDE (the group key is carried encrypted inside the handshake). Reports which
#   BSS each GTK came from so you know what it unlocks.
scrapegtk() {
  section "scraping GTKs from whole capture"
  local rows
  rows="$(tsd -Y 'wlan.rsn.ie.gtk_kde.gtk' -T fields \
          -e wlan.sa -e wlan.rsn.ie.gtk_kde.gtk 2>/dev/null | sort -u | grep .)"
  [ -n "$rows" ] || { note "no GTKs recoverable — add the passphrase/PMK or a TK first (k/harvest/addkey)"; return; }
  local sa gtk
  while IFS=$'\t' read -r sa gtk; do
    [ -n "$gtk" ] || continue
    kr_add tk "$gtk"
    note "GTK  from $sa  ->  $gtk"
  done <<< "$rows"
  rebuild_dec
  local ngtk; ngtk="$(printf '%s\n' "$rows" | awk -F'\t' '{print $2}' | sort -u | grep -c .)"
  note "scraped $ngtk unique GTK(s); keyring now holds $(grep -c . "$KEYRING") key(s)"
}

# harvest: do all three (PSK, PTK, GTK), then reload DEC so everything after
#   this point decrypts with the full keyring.
harvest() {
  [ -n "$PASS" ] || { note "set a passphrase first ('k') — needed to derive PSK/PTK"; return; }
  section "harvesting keys for $SSID"
  derive_psk
  rebuild_dec           # PSK usable now, so GTK extraction can decrypt msg3
  harvest_ptk
  harvest_gtk
  rebuild_dec
  keyring
}

# keyring: show the current key store.
keyring() {
  section "🗝️  keyring: $(hlink "file://$KEYRING" "${KEYRING:-<none>}")"
  if [ -n "$KEYRING" ] && [ -s "$KEYRING" ]; then
    awk -F'\t' -v c="$C_MAG" -v r="$C_RESET" '{printf "  %s%-8s%s %s\n", c,$1,r,$2}' "$KEYRING"
    printf '%stotal keys:%s %s\n' "$C_B" "$C_RESET" "$(grep -c . "$KEYRING")"
  else
    echo "  (empty — set a passphrase 'k' or run harvest 'h')"
  fi
}

# is_hex STR: true if STR is only hex digits (used to sanity-check key material).
is_hex() { [[ "$1" =~ ^[0-9a-fA-F]+$ ]]; }

# addkey TYPE VALUE: add an EXTERNALLY-supplied key to the keyring.
#   Use this when another tool (oxide, hcxtools, a hostapd log, a vendor dump)
#   gives you key material the capture itself can't yield — e.g. a GTK for a BSS
#   whose handshake wasn't captured. Combined with the passphrase, that GTK lets
#   you decrypt that BSS's broadcast/multicast and see more of the network.
#   TYPE is a tshark UAT type: wpa-pwd | wpa-psk | tk | wep | msk.
#     tk       = 128-bit temporal key, 32 hex chars (a client PTK-TK *or* a GTK)
#     wpa-psk  = 256-bit PMK, 64 hex chars
#     wpa-pwd  = passphrase[:ssid] (free-form)
addkey() {
  local type="${1:-}" val="${2:-}"
  if [ -z "$type" ] || [ -z "$val" ]; then          # interactive prompt
    printf 'key type (wpa-pwd|wpa-psk|tk|wep|msk): '; read -r type || return
    printf 'value: '; read -r val || return
  fi
  case "$type" in
    tk)      is_hex "$val" && [ "${#val}" -eq 32 ] || { note "tk must be 32 hex chars (128-bit)"; return; } ;;
    wpa-psk) is_hex "$val" && [ "${#val}" -eq 64 ] || { note "wpa-psk must be 64 hex chars (256-bit)"; return; } ;;
    wep|msk) is_hex "$val" || { note "$type expects hex"; return; } ;;
    wpa-pwd) : ;;                                    # passphrase[:ssid], anything goes
    *)       note "unknown key type '$type' (use wpa-pwd|wpa-psk|tk|wep|msk)"; return ;;
  esac
  kr_add "$type" "$val"
  rebuild_dec
  note "added $type key — keyring now holds $(grep -c . "$KEYRING") key(s)"
}

# import FILE: bulk-load keys from a file. Forgiving about format, one key/line:
#     - "tk","38548d..."        (Wireshark UAT export style)
#     - tk,38548d...   /  tk 38548d...   /  tk<TAB>38548d...
#     - 38548d3d1b3c...         (bare 32-hex  -> assumed tk / GTK)
#     - 6689e1...<64 hex>       (bare 64-hex  -> assumed wpa-psk / PMK)
#     - lines starting with #   (comments, ignored)
#   Anything it can't classify is reported and skipped, never guessed wrongly.
import() {
  local f="${1:-}"
  [ -z "$f" ] && { printf 'key file to import: '; read -e -r f || return; }
  [ -f "$f" ] || { note "no such file: $f"; return; }
  local added=0 type val line
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"                                            # strip CR
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"  # trim
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac                          # comment
    type=""; val=""
    if [[ "$line" =~ ^\"?(wpa-pwd|wpa-psk|tk|wep|msk)\"?[[:space:],]+\"?(.+)$ ]]; then
      type="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]%\"}"       # explicit type,value
    elif is_hex "$line" && [ "${#line}" -eq 32 ]; then type=tk;      val="$line"
    elif is_hex "$line" && [ "${#line}" -eq 64 ]; then type=wpa-psk; val="$line"
    else note "skip (unrecognized): $line"; continue
    fi
    kr_add "$type" "$val"; added=$((added+1))
  done < "$f"
  rebuild_dec
  note "imported $added key(s)"
  keyring
}

# =============================================================================
#  ANALYSIS FUNCTIONS  — one per question type. Each says what it answers,
#  which frames/fields it reads, and why.
# =============================================================================

# recon: whole-capture survey. Protocol mix + every beacon's identity/channel.
#   WHY: orient yourself before drilling in — see all SSIDs, BSSIDs, bands.
recon() {
  section "🛰️  protocol hierarchy"
  ts -q -z io,phs
  section "📇 all beacons: bssid / ssid / 2.4ch / 5ch / freq"
  ts -Y 'wlan.fc.type_subtype==8' -T fields \
     -e wlan.bssid -e wlan.ssid -e wlan.ds.current_channel \
     -e wlan.ht.info.primarychannel -e radiotap.channel.freq | dessid 2 | sort -u
}

# bands: channel + band for each BSSID of the target SSID.
#   WHY: 2.4GHz carries channel in the DSSS tag (wlan.ds.current_channel), 5GHz in
#        the HT tag (wlan.ht.info.primarychannel). 6GHz (WiFi 6E/7) emits neither —
#        it uses the HE Operation element — so we derive the channel straight from
#        the radiotap frequency when the band-specific tag is blank. Band comes from
#        frequency: 2400s=2.4GHz, 5150-5895=5GHz, 5925-7125=6GHz.
bands() {
  section "📶 bands / channels for $SSID"
  ts -Y "$(beacons_of_target)" -T fields \
     -e wlan.bssid -e wlan.ds.current_channel -e wlan.ht.info.primarychannel \
     -e radiotap.channel.freq \
    | sort -u \
    | awk 'BEGIN{FS=OFS="\t"}
        {
          split($4,ff,","); freq=ff[1]+0
          if      (freq>=5925) band="6GHz"
          else if (freq>=5150) band="5GHz"
          else if (freq>0)     band="2.4GHz"
          else                 band="?"
          ch=(freq>5000)?$3:$2                       # band-specific beacon tag
          if (ch=="" || ch=="0") {                   # derive from frequency
            if      (band=="2.4GHz") ch=(freq==2484)?14:int((freq-2407)/5)
            else if (band=="5GHz")   ch=int((freq-5000)/5)
            else if (band=="6GHz")   ch=int((freq-5950)/5)
          }
          printf "%-20s ch%-4s %-6s (%s MHz)\n",$1,ch,band,ff[1]
        }'
}

# crypto: read the RSN element and translate AKM suites into a plain verdict.
#   WHY: the AKM suite type (00-0F-AC:<n>) names the auth+key-mgmt method. Reading
#        only types 2 (PSK) and 8 (SAE) mislabels everything else — most damagingly,
#        an 802.1X/EAP (Enterprise) network has no PSK/SAE AKM and used to fall
#        through to "open/WEP?". The full suite table (IEEE 802.11-2020 Table 9-151):
#          1  802.1X (EAP)            2  PSK               3  FT-802.1X
#          4  FT-PSK                  5  802.1X-SHA256     6  PSK-SHA256
#          8  SAE                     9  FT-SAE           11  802.1X Suite-B
#         12  802.1X Suite-B-384     13  FT-802.1X-SHA384 14-17 FILS
#         18  OWE                    19  FT-PSK-SHA384    20  PSK-SHA384
#        When no RSN AKM is present we fall back to the WPA1 vendor IE, then the
#        Privacy capability bit to tell WEP (1) from truly open (0).

# classify_akm: pure verdict engine — reads the set of AKM suite numbers (one per
#   line on stdin) plus two flags, privacy-bit-seen ($1) and wpa1-IE-seen ($2), and
#   prints "class<TAB>verdict". class ∈ strong|trans|ent|weak|open picks the colour.
#   No tshark, no globals — so the classification is unit-testable on its own.
classify_akm() {
  awk -v priv="${1:-}" -v wpa1="${2:-}" '
    { t=$1+0
      if      (t==8||t==9)                          sae=1
      else if (t==2||t==4||t==6||t==19||t==20)      psk=1
      else if (t==1||t==3||t==5)                    eap=1
      else if (t==11||t==12||t==13)               { eap=1; sb=1 }   # Suite-B/SHA384
      else if (t>=14&&t<=17)                        eap=1          # FILS
      else if (t==18)                               owe=1 }
    END{
      if      (sae&&psk) print "trans\tWPA2/WPA3-Personal transition (PSK + SAE)"
      else if (sae&&eap) print "ent\tWPA3-Enterprise + SAE"
      else if (sae)      print "strong\tWPA3-Personal (SAE)"
      else if (owe)      print "strong\tWPA3-OWE (Enhanced Open)"
      else if (eap&&sb)  print "ent\tWPA3-Enterprise (802.1X Suite-B)"
      else if (eap&&psk) print "trans\tmixed Enterprise + PSK"
      else if (eap)      print "ent\tWPA2/WPA3-Enterprise (802.1X/EAP)"
      else if (psk)      print "weak\tWPA2-Personal (PSK)"
      else if (wpa1!="") print "weak\tWPA1 (legacy TKIP, vendor IE)"
      else if (priv!="") print "weak\tWEP / legacy (Privacy bit set, no RSN)"
      else               print "open\topen (no encryption)"
    }'
}

crypto() {
  section "🔐 encryption for $SSID"
  ts -Y "$(beacons_of_target)" -T fields \
     -e wlan.bssid -e wlan.rsn.akms.type \
     -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr | sort -u
  # Collapse all AKM suite numbers seen across the target's beacons into one verdict.
  local akms
  akms="$(ts -Y "$(beacons_of_target)" -T fields -e wlan.rsn.akms.type 2>/dev/null \
          | tr ',' '\n' | tr -d ' ' | sort -u | grep .)"
  # Privacy bit (open vs WEP when no RSN) and WPA1 vendor IE (legacy, but not open).
  local priv wpa1
  priv="$(ts -Y "$(beacons_of_target)" -T fields -e wlan.fixed.capabilities.privacy 2>/dev/null \
          | tr -d ' ' | sort -u | grep -m1 1)"
  wpa1="$(ts -Y "$(beacons_of_target) && wlan.wfa.ie.wpa.version" -T fields -e wlan.bssid 2>/dev/null | grep -m1 .)"
  local cls txt
  IFS=$'\t' read -r cls txt < <(printf '%s\n' "$akms" | classify_akm "$priv" "$wpa1")
  local col
  case "$cls" in
    strong) col="$C_GRN" ;; trans) col="$C_YEL" ;; ent) col="$C_MAG" ;;
    weak|open) col="$C_RED" ;; *) col="$C_B" ;;
  esac
  printf '%s🔒 verdict:%s %s%s%s\n' "$C_B" "$C_RESET" "$col" "$txt" "$C_RESET"
}

# hardware: pull make/model out of the WPS information element in beacons.
#   WHY: APs advertise Manufacturer / Model Name / Model Number in WPS. These
#        map directly to "make" and "model" questions.
hardware() {
  section "🏷️  make / model (WPS) for $SSID"
  ts -Y "wps.model_name && $(bssid_filter)" -T fields \
     -e wlan.bssid -e wps.manufacturer -e wps.model_name \
     -e wps.model_number -e wps.device_name -e wps.serial_number | sort -u
}

# drop_group: filter out group-addressed (broadcast/multicast) MACs from a stream
#   of one-MAC-per-line. The I/G bit is the low bit of the first octet, so a MAC is
#   group-addressed exactly when the 2nd hex digit is odd (1,3,5,7,9,b,d,f) — e.g.
#   ff:.. (broadcast), 01:00:5e:.. (IPv4 mcast), 33:33:.. (IPv6 mcast).
drop_group() { awk '{ if (tolower(substr($0,2,1)) ~ /[13579bdf]/) next; print }'; }

# no_aps: remove any known BSSID from a one-MAC-per-line stream (leaving stations).
no_aps() {
  if [ "${#ALL_BSSIDS[@]}" -gt 0 ]; then grep -vwiF -f <(printf '%s\n' "${ALL_BSSIDS[@]}"); else cat; fi
}

# station_macs: the UNION of every signal that a MAC is a client of the target
#   network, not just the 4-way handshake:
#     - association / reassociation requests (subtype 0/2) — carry the SSID, so we
#       scope by name; the source is the client (works even for hidden SSIDs).
#     - EAPOL frames scoped by the target BSSIDs (either side may be the client).
#     - data uplink to the AP  (ToDS=1,FromDS=0): the transmitter is the client.
#     - data downlink from the AP (ToDS=0,FromDS=1): the receiver is the client.
#   WHY: handshake-only discovery (the old method) missed any client that was
#        already associated before the capture began, or whose handshake landed in
#        a channel-hop gap — yet those clients' data frames are all over the capture.
#        Group-addressed MACs and known BSSIDs are stripped, leaving real stations.
station_macs() {
  {
    ts -Y "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"" \
       -T fields -e wlan.sa 2>/dev/null
    ts -Y "eapol && $(bssid_filter)" -T fields -e wlan.sa -e wlan.da 2>/dev/null | tr '\t' '\n'
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" \
       -T fields -e wlan.sa 2>/dev/null
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" \
       -T fields -e wlan.da 2>/dev/null
  } | tr '\t' '\n' | sort -u | grep . | drop_group | no_aps
}

# clients: list the wireless stations on the target network.
#   WHY: see station_macs — we no longer trust handshakes alone. The per-frame
#        EAPOL table is still shown (it's the ground truth for key derivation), but
#        the distinct-client list is the full union of association + data + EAPOL.
clients() {
  section "👥 wireless clients on $SSID (assoc + data + EAPOL)"
  ts -Y "eapol && $(bssid_filter)" -T fields \
     -e frame.number -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr
  section "distinct client MACs (all sources)"
  station_macs
}

# keys: count PSKs, PTKs, and GTKs — and explain each number.
#   WHY:
#     PSK  = passphrase+SSID pairs -> one network, one passphrase = 1 PSK.
#     PTK  = per client<->AP session -> one per distinct handshake/client.
#     GTK-in-use   = per BSS (fronthaul BSSID) -> APs x active bands.
#     GTK-recovered= only handshakes complete enough to derive the PTK/KEK; a
#                    handshake missing msg1 leaves the GTK blank.
keys() {
  section "🔑 keys for $SSID"
  printf '%sPSK:%s 1  (single passphrase + single ESSID %s)\n' "$C_B" "$C_RESET" "$SSID"

  local nptk
  nptk="$(ts -Y "eapol && $(bssid_filter)" -T fields -e wlan.sa -e wlan.da 2>/dev/null \
          | tr '\t' '\n' | sort -u | grep . | drop_group | no_aps | wc -l | tr -d ' ')"
  echo "PTK: $nptk  (one per client that completed a 4-way handshake)"
  local nsta
  nsta="$(station_macs | wc -l | tr -d ' ')"
  echo "stations seen: $nsta  (all sources — assoc + data + EAPOL; ≥ PTK count)"

  echo "GTK in use: ${#TGT_BSSIDS[@]}  (one per fronthaul BSS = APs x active bands)"

  section "GTKs actually recovered (decrypted msg3)"
  tsd -Y "wlan_rsna_eapol.keydes.msgnr==3 && $(bssid_filter)" -T fields \
      -e wlan.sa -e wlan.rsn.ie.gtk_kde.gtk | sort -u
  local grec
  grec="$(tsd -Y "wlan_rsna_eapol.keydes.msgnr==3 && $(bssid_filter)" -T fields \
          -e wlan.rsn.ie.gtk_kde.gtk 2>/dev/null | sort -u | grep -c .)"
  echo "GTK recovered: $grec"
}

# topology: is it one AP, several in an ESS, or a mesh? And how many physical units?
#   WHY: same SSID on many BSSIDs = an ESS. Count PHYSICAL units by the wireless
#        backhaul, not by OUI — vendors ship packs with consecutive factory MACs,
#        so two boxes can share a prefix. 4-address frames (ToDS=1 & FromDS=1) are
#        the WDS backhaul; a satellite's backhaul-STA joining the root proves a
#        distinct unit. No mesh IE + backhaul = "backhaul ESS" (fake mesh), not 802.11s.
topology() {
  section "🕸️  fronthaul BSSes for $SSID (= GTKs in use)"
  printf '%s\n' "${TGT_BSSIDS[@]}"
  echo "count: ${#TGT_BSSIDS[@]}"
  section "802.11 WDS backhaul (4-address) links: transmitter -> receiver"
  # Drop 4-address frames to a group-addressed receiver (multicast/broadcast) —
  # a real backhaul peer is unicast; the I/G bit (2nd hex digit odd) flags a group.
  ts -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' -T fields -e wlan.ta -e wlan.ra \
    | awk -F'\t' '$1!="" && $2!="" && tolower(substr($1,2,1)) !~ /[13579bdf]/ && tolower(substr($2,2,1)) !~ /[13579bdf]/' \
    | sort -u
  section "backhaul frame count"
  ts -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' | wc -l
  note "count physical APs = distinct units in the backhaul (root + each satellite backhaul-STA)"
}

# hosts: everything that needs decryption — subnet, IP<->MAC, names, versions.
#   WHY: broadcast/multicast (ARP, DHCP, mDNS) decrypt with the GTK, and that's
#        where subnet and device identity live. A device seen here but never in a
#        handshake is WIRED, not a wireless client.
hosts() {
  section "🏠 decryption sanity (ARP / IPv4 / IPv6 frames after decrypt)"
  tsd -Y 'arp || ip || ipv6' | wc -l
  section "subnet / gateway (DHCP options 1 & 3)"
  tsd -Y 'dhcp' -T fields \
      -e dhcp.ip.your -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname | sort -u
  section "DHCP fingerprint (mac / ip / hostname / vendor-class)"
  tsd -Y 'dhcp' -T fields \
      -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.hostname -e dhcp.option.vendor_class_id | sort -u
  section "ARP IPv4 <-> MAC"
  tsd -Y 'arp' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u
  # IPv6 is invisible to ARP; neighbor discovery is its equivalent. The link-layer
  # address option in NS/NA/RS/RA carries IPv6<->MAC, and DHCPv6's DUID-LL carries
  # the client MAC — without these, every IPv6-only host is missed.
  section "IPv6 neighbors (ICMPv6 ND link-layer option)"
  tsd -Y 'icmpv6 && icmpv6.opt.linkaddr' -T fields \
      -e ipv6.src -e icmpv6.opt.linkaddr \
      -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address | sort -u
  section "DHCPv6 (client IPv6 / DUID link-layer MAC)"
  tsd -Y 'dhcpv6' -T fields -e ipv6.src -e dhcpv6.duidll.link_layer_addr | sort -u
  section "hostname sweep (DHCP / NBNS / mDNS / LLMNR)"
  # dns.resp.name (answers) carries the real host.local a device advertises; qry.name
  # is what a device is *looking for*. Include both — the map keys names off resp.name.
  tsd -Y 'dhcp.option.hostname || nbns || mdns || llmnr' -T fields \
      -e ip.src -e dhcp.option.hostname -e nbns.name -e dns.resp.name -e dns.qry.name | sort -u
  section "software versions (HTTP / SSH banners)"
  tsd -Y 'http.user_agent || http.server || ssh.protocol' -T fields \
      -e ip.src -e http.user_agent -e http.server -e ssh.protocol | sort -u
}

# pmkid: list RSN PMKIDs (carried in EAPOL msg1). A PMKID cracks OFFLINE with no
#   client traffic needed — it's the fastest path to the passphrase. Zeroed
#   PMKIDs (all-00) are filtered out.
pmkid() {
  section "🪪 PMKIDs (offline-crackable, client-less)"
  ts -Y "eapol && wlan.rsn.ie.pmkid && $(bssid_filter)" -T fields \
     -e wlan.sa -e wlan.da -e wlan.rsn.ie.pmkid | awk -F'\t' '$3 !~ /^0*$/' | sort -u
}

# export22000: write a hashcat-22000 file to crack with:  hashcat -m 22000 <file>
#   Uses hcxpcapngtool when present (handles PMKID *and* EAPOL handshakes fully).
#   Without it, falls back to building PMKID (WPA*01) lines directly — reliable,
#   though EAPOL (*02) lines then need hcxpcapngtool.
export22000() {
  local out="${1:-${PCAP%.*}.hc22000}"
  if command -v hcxpcapngtool >/dev/null 2>&1; then
    hcxpcapngtool -o "$out" "$PCAP" >/dev/null 2>&1
    [ -s "$out" ] && ok "wrote $(hlink "file://$out" "$out")  (hcxpcapngtool: PMKID + EAPOL)" \
                  || note "hcxpcapngtool found nothing to export"
    return
  fi
  note "hcxpcapngtool not installed — exporting PMKID (WPA*01) lines only"
  local ehex; ehex="$("$PYBIN" -c 'import sys;print(sys.argv[1].encode().hex())' "$SSID")"
  ts -Y "eapol && wlan.rsn.ie.pmkid && $(bssid_filter)" -T fields \
     -e wlan.sa -e wlan.da -e wlan.rsn.ie.pmkid \
    | awk -F'\t' -v e="$ehex" '$3 !~ /^0*$/ {ap=$1;sta=$2;gsub(/:/,"",ap);gsub(/:/,"",sta);
        printf "WPA*01*%s*%s*%s*%s***\n",$3,ap,sta,e}' | sort -u > "$out"
  if [ -s "$out" ]; then ok "wrote $(hlink "file://$out" "$out")  ($(grep -c . "$out") PMKID line(s))"
  else note "no PMKIDs in this capture to export"; rm -f "$out"; fi
}

# probes: what SSIDs each client is actively looking for (directed probe requests).
#   Reveals networks a device has joined before — strong profiling/tracking signal.
#   Whole-capture (probes aren't tied to one AP); wildcard/blank probes skipped.
probes() {
  section "🔎 probe requests: client → SSID sought"
  ts -Y 'wlan.fc.type_subtype==4 && wlan.ssid != ""' -T fields -e wlan.sa -e wlan.ssid \
    | awk -F'\t' 'NF==2 && $2!=""' | dessid 2 | sort -u
}

# handshakes: per client, which 4-way messages were captured and whether that's
#   enough to derive keys / crack. (m1&m2) or (m2&m3) => PTK-derivable & crackable.
handshakes() {
  section "🤝 handshake completeness (per client)"
  ts -Y "eapol && $(bssid_filter)" -T fields \
     -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr \
   | awk -v aps="${ALL_BSSIDS[*]}" '
       BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
       { if($4=="")next; sa=tolower($1); sta=(sa in AP)?$2:$1; k=sta"|"$3; M[k]=M[k] $4 }
       END{ for(k in M){ split(k,p,"|"); s=M[k];
              h1=index(s,"1")>0;h2=index(s,"2")>0;h3=index(s,"3")>0;h4=index(s,"4")>0;
              crack=((h1&&h2)||(h2&&h3))?"YES":"no";
              printf "%-18s @ %-18s  msgs:%s%s%s%s  crackable:%s\n",
                     p[1],p[2], h1?"1":"·",h2?"2":"·",h3?"3":"·",h4?"4":"·", crack } }' | sort
}

# delkey VALUE|all: remove key(s) from the keyring by matching value (or wipe all).
delkey() {
  local v="${1:-}"
  [ -n "$KEYRING" ] && [ -s "$KEYRING" ] || { note "keyring empty"; return; }
  [ -z "$v" ] && { keyring; printf 'value to remove (or "all"): '; read -e -r v || return; }
  if [ "$v" = all ]; then : > "$KEYRING"; rebuild_dec; ok "cleared keyring"; return; fi
  grep -vF "$v" "$KEYRING" > "$KEYRING.tmp" 2>/dev/null && mv "$KEYRING.tmp" "$KEYRING"
  rebuild_dec; ok "removed keys matching '$v' — $(grep -c . "$KEYRING" 2>/dev/null || echo 0) left"
}

# clearkey: wipe the whole keyring.
clearkey() { [ -n "$KEYRING" ] && : > "$KEYRING"; rebuild_dec; ok "keyring cleared"; }

# map: draw a draw.io network diagram of the selected SSID -> <ssid>.drawio.
#   Physical AP units (clustered best-effort: TP-Link/most vendors keep a BSSID's
#   last 4 octets across its virtual BSSIDs, so we key on octets 3-6 with the last
#   octet's low 2 bits masked), wireless clients grouped under the AP they joined,
#   wired hosts, and the WAN/gateway. Full host labels (IP/host/OS/proto) need the
#   keyring; without keys it still draws the L2 layer (APs + associations + backhaul).
map() {
  local all="${MAP_ALL:-0}"
  [ "$all" = 1 ] || [ -n "$SSID" ] || { note "select an SSID first (s), or use mapall"; return; }
  local out="${1:-${SSID:-network}.drawio}" wd; wd="$(mktemp -d)"
  # In whole-capture mode we scope to EVERY beaconing BSSID and every SSID; a single
  # physical unit that radiates main/guest/IoT SSIDs then appears once, with all its
  # SSIDs listed — that's the "entire network", not one ESSID at a time.
  local bfilt afilt title
  if [ "$all" = 1 ]; then
    bfilt='wlan.fc.type_subtype==8'
    afilt='(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2)'
    title='whole capture'
  else
    bfilt="$(beacons_of_target)"
    afilt="(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\""
    title="$SSID"
  fi
  section "🗺️  drawing network map for $title"
  # --- collect data into TSV files the generator reads ---
  # beacons carry a 5th column now: the (hex-decoded) SSID, so the generator can
  # label each physical unit with the SSIDs it radiates.
  ts  -Y "$bfilt" -T fields -e wlan.bssid -e wlan.ds.current_channel \
      -e wlan.ht.info.primarychannel -e radiotap.channel.freq -e wlan.ssid 2>/dev/null \
      | dessid 5 | sort -u > "$wd/beacons.tsv"
  ts  -Y "wps.model_name && $(bssid_filter)" -T fields -e wlan.bssid -e wps.manufacturer -e wps.model_name 2>/dev/null \
      | sort -u > "$wd/wps.tsv"
  # client<->AP association pairs, unioned across all discovery sources (assoc /
  # EAPOL / ToDS uplink / FromDS downlink) so the map shows clients that never
  # completed a captured handshake — see station_macs() for the rationale.
  {
    ts -Y "$afilt" -T fields -e wlan.sa -e wlan.bssid 2>/dev/null
    ts -Y "eapol && $(bssid_filter)" -T fields -e wlan.sa -e wlan.da -e wlan.bssid 2>/dev/null \
      | awk -v aps="${ALL_BSSIDS[*]}" 'BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
          {sa=tolower($1); sta=(sa in AP)?$2:$1; if(sta!="")print sta"\t"$3}'
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" \
       -T fields -e wlan.sa -e wlan.bssid 2>/dev/null
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" \
       -T fields -e wlan.da -e wlan.bssid 2>/dev/null
  } | awk -F'\t' -v aps="${ALL_BSSIDS[*]}" 'BEGIN{OFS="\t";n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
        { c=tolower($1); b=tolower($2);
          if(c==""||b=="") next;
          if(c in AP) next;                                 # client column is an AP
          if(tolower(substr(c,2,1)) ~ /[13579bdf]/) next;   # group-addressed
          print c,b }' | sort -u > "$wd/clients.tsv"
  ts  -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' -T fields -e wlan.ta -e wlan.ra 2>/dev/null | sort -u > "$wd/backhaul.tsv"
  tsd -Y 'dhcp' -T fields -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.hostname -e dhcp.option.vendor_class_id 2>/dev/null | sort -u > "$wd/dhcp.tsv"
  tsd -Y 'dhcp.option.router' -T fields -e dhcp.option.router 2>/dev/null | sort -u | grep -v '^$' | head -1 > "$wd/gw.txt"
  tsd -Y 'arp' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac 2>/dev/null | sort -u > "$wd/arp.tsv"
  tsd -Y 'icmpv6 && icmpv6.opt.linkaddr' -T fields -e icmpv6.opt.linkaddr -e ipv6.src 2>/dev/null | sort -u > "$wd/nd.tsv"
  tsd -Y 'mdns || nbns' -T fields -e ip.src -e nbns.name -e dns.resp.name 2>/dev/null | sort -u > "$wd/names.tsv"
  { tsd -Y 'ip'   -T fields -e ip.src   -e _ws.col.protocol 2>/dev/null
    tsd -Y 'ipv6' -T fields -e ipv6.src -e _ws.col.protocol 2>/dev/null; } | sort -u > "$wd/proto.tsv"
  # observed L3 conversations (v4+v6) — drawn as dashed edges between hosts that
  # both appear on the map, i.e. real intra-LAN "who talks to whom".
  { tsd -Y 'ip'   -T fields -e ip.src   -e ip.dst   2>/dev/null
    tsd -Y 'ipv6' -T fields -e ipv6.src -e ipv6.dst 2>/dev/null; } | sort -u > "$wd/conv.tsv"
  printf '%s' "$title" > "$wd/ssid.txt"
  # --- generate the .drawio (python; script in a var so stdin stays free) ---
  local GEN_PY; read -r -d '' GEN_PY <<'PY'
import sys, os
from collections import defaultdict
wd, out = sys.argv[1], sys.argv[2]
def rd(f):
    p=os.path.join(wd,f); R=[]
    if os.path.exists(p):
        for ln in open(p,encoding='utf-8',errors='replace'):
            ln=ln.rstrip('\r\n')
            if ln.strip(): R.append(ln.split('\t'))
    return R
def one(f):
    R=rd(f); return R[0] if R else []
def txt(f):
    p=os.path.join(wd,f); return open(p,encoding='utf-8').read().strip() if os.path.exists(p) else ''
def esc(s): return (s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')
def ukey(b):
    o=b.lower().split(':')
    return b.lower() if len(o)!=6 else ':'.join(o[2:5])+':%02x'%(int(o[5],16)&0xFC)
def is_group(m):                       # I/G bit set = broadcast/multicast, not a real peer
    try: return int(m.split(':')[0],16)&1
    except Exception: return True
ssid=txt('ssid.txt'); gwip=txt('gw.txt')
def freq2chan(f, bnd):
    if not f: return ''
    if bnd=='2.4G': return '14' if f==2484 else str((f-2407)//5)
    if bnd=='5G':   return str((f-5000)//5)
    if bnd=='6G':   return str((f-5950)//5)     # WiFi 6E/7: HT tag absent, derive from freq
    return ''
band={}; chan={}; ssid_of=defaultdict(set)
for r in rd('beacons.tsv'):
    b=r[0].lower(); f=0
    try: f=int(str(r[3]).split(',')[0])
    except: pass
    if   f>=5925: bnd='6G'
    elif f>=5150: bnd='5G'
    elif f>0:     bnd='2.4G'
    else:         bnd='?'
    band[b]=bnd
    c=(r[2] if f>5000 else r[1]) if len(r)>2 else ''
    if not c or c=='0': c=freq2chan(f,bnd)
    chan[b]=c
    nm=(r[4] if len(r)>4 else '').strip()          # SSID this BSSID radiates
    if nm and nm!='<MISSING>': ssid_of[b].add(nm)
# make/model per BSSID (from WPS): "<mfr> <model>". Falls back to a single global
# make when the capture only had one WPS record.
wps_of={}
for r in rd('wps.tsv'):
    if not r: continue
    bb=r[0].lower(); mm=' '.join(x for x in r[1:] if x).strip()
    if bb and mm: wps_of[bb]=mm
# Only ever attribute a make to a unit whose OWN BSSID advertised it (unit_make);
# a generic 'AP' otherwise. Never brand every unit with one stray neighbor's WPS.
mk_default='AP'
dhcp={}
for r in rd('dhcp.tsv'):
    # tshark joins repeated field occurrences with commas (e.g. the mac appears
    # twice) — take the first value of each so the mac key matches cleanly.
    mac=(r[0].split(',')[0] if r else '').lower()
    if not mac: continue
    d=dhcp.setdefault(mac,{'ip':'','host':'','vc':''})
    ipv=r[2] if len(r)>2 and r[2] and r[2]!='0.0.0.0' else (r[1] if len(r)>1 and r[1] and r[1]!='0.0.0.0' else '')
    ipv=ipv.split(',')[0]
    if ipv: d['ip']=ipv
    if len(r)>3 and r[3]: d['host']=r[3].split(',')[0]
    if len(r)>4 and r[4]: d['vc']=r[4].split(',')[0]
mac2ip={}; ip2mac={}
for r in rd('arp.tsv'):
    if len(r)>=2 and r[0] and r[1]: ip2mac[r[0]]=r[1].lower(); mac2ip[r[1].lower()]=r[0]
# IPv6 neighbor discovery: link-layer option pairs a MAC with its IPv6 address, so
# IPv6-only hosts (no ARP, no DHCPv4) still land on the map.
mac2ip6={}
for r in rd('nd.tsv'):
    if len(r)>=2 and r[0] and r[1]: mac2ip6.setdefault(r[0].lower(), r[1])
def anyip(mac): return mac2ip.get(mac) or mac2ip6.get(mac,'')
ipname={}
for r in rd('names.tsv'):
    if not r: continue
    ip=r[0]
    nb=(r[1] if len(r)>1 else '').split(',')[0].split('<')[0].strip()   # NBNS: drop <00> suffix + dup
    md=''
    if len(r)>2 and r[2]:
        for t in r[2].split(','):                                       # mDNS: prefer a real host.local
            t=t.strip()
            if t.endswith('.local') and '_' not in t: md=t[:-6]; break
    nm=nb or md
    if ip and nm and ip not in ipname: ipname[ip]=nm
proto=defaultdict(set)
for r in rd('proto.tsv'):
    if len(r)>=2: proto[r[0]].add(r[1])
cli=defaultdict(set)
for r in rd('clients.tsv'):
    if len(r)>=2: cli[r[0].lower()].add(r[1].lower())
apb=set(band)
units=defaultdict(set)
for b in apb: units[ukey(b)].add(b)
# --- WDS 4-address backhaul: the ground truth for physical topology ----------
# Each row is a transmitter/receiver pair of backhaul RADIO macs. We (a) fold each
# backhaul radio into a physical unit (keyed like the fronthaul BSSIDs, so a
# satellite whose backhaul radio shares its NIC-portion collapses into one unit,
# and a satellite we never heard beacon still becomes a node), and (b) keep the
# real inter-unit links so the map draws the OBSERVED mesh (chain or star) instead
# of a synthesized root→everything star.
bh_pairs=[]
for r in rd('backhaul.tsv'):
    # A real WDS backhaul link is unicast<->unicast; a 4-address frame to a
    # group-addressed RA (e.g. 01:0b:85:.. multicast) is not an AP-to-AP peer.
    if len(r)>=2 and r[0] and r[1] and not is_group(r[0]) and not is_group(r[1]):
        bh_pairs.append((r[0].lower(), r[1].lower()))
# Associate each backhaul RADIO mac with a fronthaul unit by its octets 3-5 (the
# stable NIC base ukey() already clusters on) — a box's backhaul radio and its
# fronthaul BSSIDs almost always share that base. A radio that matches no beaconing
# unit is a satellite we only ever saw on backhaul, so it becomes its own node.
def near(m): return ':'.join(m.split(':')[2:5])
near2unit={}
for k in list(units):
    for b in units[k]: near2unit.setdefault(near(b), k)
def bh_unit(m):
    u=near2unit.get(near(m))
    if u is None:
        u=ukey(m); _=units[u]; near2unit[near(m)]=u
    return u
bh_macs=set()
for ta,ra in bh_pairs: bh_macs.add(ta); bh_macs.add(ra)
bh_edges=set()
for ta,ra in bh_pairs:
    ka,kb=bh_unit(ta),bh_unit(ra)
    if ka!=kb: bh_edges.add(tuple(sorted((ka,kb))))
gwmac=ip2mac.get(gwip,'')
rootk=ukey(gwmac) if (gwmac and ukey(gwmac) in units) else None
if rootk is None and gwmac:
    g4=gwmac.split(':')[2:]
    for k in units:
        if any(x.split(':')[2:]== g4 or x.split(':')[3:]==gwmac.split(':')[3:] for x in units[k]): rootk=k; break
# No gateway match? The root of a mesh is the node with the most backhaul links.
if rootk is None and bh_edges:
    deg=defaultdict(int)
    for a,b in bh_edges: deg[a]+=1; deg[b]+=1
    rootk=max(deg,key=deg.get)
if rootk not in units:
    rootk=max(units,key=lambda k:sum(1 for s in cli for b in cli[s] if b in units[k])) if units else None
def enrich(mac):
    mac=mac.lower(); d=dhcp.get(mac,{})
    ip=d.get('ip') or anyip(mac)
    host=d.get('host') or ipname.get(ip,'')
    return ip, host, d.get('vc',''), sorted(proto.get(ip,[]))[:6]
cl_unit={}
for sta,bs in cli.items():
    k=next((ukey(b) for b in bs if b in apb), ukey(sorted(bs)[0]))
    cl_unit[sta]=(k, sorted(bs)[0])
known=set(apb)|set(cli)|{b for k in units for b in units[k]}|bh_macs
# wired = decrypted L2 devices that aren't clients or APs — but NOT the gateway
# (its MAC/IP is the router itself, drawn as the WAN uplink, not a host).
wired=[m for m in (set(mac2ip)|set(mac2ip6)) if m not in known and m!=gwmac and anyip(m) and anyip(m)!=gwip]
cells=[]; nid=[1]
def cell(label,x,y,w,h,style):
    i='n%d'%nid[0]; nid[0]+=1
    v=esc(label).replace(chr(10),'&#10;')
    cells.append('<mxCell id="%s" value="%s" style="%s" vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>'%(i,v,style,x,y,w,h))
    return i
def edge(s,t,label,style):
    i='e%d'%nid[0]; nid[0]+=1
    cells.append('<mxCell id="%s" value="%s" style="%s" edge="1" parent="1" source="%s" target="%s"><mxGeometry relative="1" as="geometry"/></mxCell>'%(i,esc(label),style,s,t))
AP_R='rounded=1;fillColor=#dae8fc;strokeColor=#6c8ebf;whiteSpace=wrap;html=1;fontSize=11;'
AP_S='rounded=1;fillColor=#d5e8d4;strokeColor=#82b366;whiteSpace=wrap;html=1;fontSize=11;'
CLI ='rounded=1;fillColor=#e1d5e7;strokeColor=#9673a6;whiteSpace=wrap;html=1;fontSize=10;'
WIR ='rounded=1;fillColor=#ffe6cc;strokeColor=#d79b00;whiteSpace=wrap;html=1;fontSize=10;'
WAN ='ellipse;shape=cloud;fillColor=#f5f5f5;strokeColor=#666666;whiteSpace=wrap;html=1;'
EBH ='endArrow=none;dashed=1;strokeColor=#b85450;strokeWidth=2;html=1;fontSize=9;'
ECL ='endArrow=none;strokeColor=#9673a6;html=1;fontSize=9;'
EWI ='endArrow=none;strokeColor=#d79b00;strokeWidth=2;html=1;fontSize=9;'
EWA ='endArrow=none;strokeColor=#666666;strokeWidth=2;html=1;'
ip2cell={}                                        # ip -> host cell, for the L3 layer
def unit_make(k):
    for b in sorted(units[k]):
        if b in wps_of: return wps_of[b]
    return mk_default
def unit_ssids(k):
    s=set()
    for b in units[k]: s|=ssid_of.get(b,set())
    return sorted(s)
ordered=([rootk]+[k for k in units if k!=rootk]) if rootk in units else list(units)
uid={}; ux={}; x=80
for k in ordered:
    if k is None: continue
    bs=sorted(units[k])
    head=('ROOT / GATEWAY' if k==rootk else 'satellite')
    radios='  '.join('%s %s ch%s'%(':'.join(b.split(':')[3:]),band.get(b,'?'),chan.get(b,'?')) for b in bs[:2]) \
           or '(backhaul-only radio)'
    sl=unit_ssids(k)
    ssline=('SSIDs: '+'  '.join(sl[:4])+(' +%d'%(len(sl)-4) if len(sl)>4 else '')) if sl else ''
    body='\n'.join(p for p in (head, unit_make(k), ssline, radios) if p)
    uid[k]=cell(body, x,190,250,104, AP_R if k==rootk else AP_S); ux[k]=x; x+=290
if rootk in ux and gwip:
    w=cell('Internet / ISP\n(uplink %s)'%gwip, ux[rootk]+45,40,160,70, WAN); edge(w,uid[rootk],'',EWA)
# Draw the OBSERVED backhaul topology from the 4-address frames (chain or star).
drawn_bh=False
for a,b in sorted(bh_edges):
    if a in uid and b in uid: edge(uid[a],uid[b],'WDS backhaul',EBH); drawn_bh=True
# Only fall back to a root→satellite star when NO backhaul frames were captured
# (same-SSID multi-AP with wired/unseen backhaul = "backhaul ESS", not a real mesh).
if not drawn_bh:
    for k in ordered:
        if k in uid and rootk in uid and k!=rootk: edge(uid[rootk],uid[k],'ESS (no backhaul seen)',EBH)
percol=defaultdict(int)
for sta,(k,b) in sorted(cl_unit.items()):
    if k not in ux: continue
    c=percol[k]; percol[k]+=1
    ip,host,vc,pr=enrich(sta)
    lbl='\n'.join(x for x in [host or '(client)', ip, sta, vc, ' '.join(pr)] if x)
    ci=cell(lbl, ux[k], 380+c*100, 230, 86, CLI)
    if ip: ip2cell.setdefault(ip,ci)
    edge(uid[k],ci,'%s ch%s'%(band.get(b,''),chan.get(b,'')),ECL)
wx=80
for m in sorted(wired):
    ip,host,vc,pr=enrich(m)
    if not ip: continue
    lbl='\n'.join(x for x in [host or '(wired host)', ip, m, ' '.join(pr)] if x)
    wi=cell(lbl, wx, 690, 230, 86, WIR)
    if ip: ip2cell.setdefault(ip,wi)
    if rootk in uid: edge(uid[rootk],wi,'wired',EWI)
    wx+=250
# --- L3 layer: observed intra-LAN conversations between hosts already on the map.
# Only pairs where BOTH endpoints are drawn hosts get an edge — host<->gateway and
# host<->Internet are intentionally skipped (the WAN uplink already shows egress),
# leaving the real "who talks to whom" without clutter. Capped so a busy capture
# can't produce thousands of edges.
L3='endArrow=none;dashed=1;strokeColor=#666666;opacity=45;html=1;'
seen_l3=set(); n_l3=0; L3_CAP=80
for r in rd('conv.tsv'):
    if len(r)<2 or not r[0] or not r[1] or r[0]==r[1]: continue
    a,b=r[0],r[1]
    if a in ip2cell and b in ip2cell:
        kk=tuple(sorted((a,b)))
        if kk in seen_l3: continue
        seen_l3.add(kk)
        if n_l3>=L3_CAP: continue
        edge(ip2cell[a],ip2cell[b],'',L3); n_l3+=1
if n_l3>=L3_CAP: sys.stderr.write('note: L3 edges capped at %d\n'%L3_CAP)
cell('%s — network map  (physical AP units; backhaul + L3 from observed frames)'%ssid, 80,150,620,24,'text;html=1;fontStyle=1;fontSize=13;')
xml='<mxfile><diagram name="%s"><mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" page="1" pageWidth="1600" pageHeight="1100"><root><mxCell id="0"/><mxCell id="1" parent="0"/>%s</root></mxGraphModel></diagram></mxfile>'%(esc(ssid or 'net'),''.join(cells))
open(out,'w',encoding='utf-8').write(xml)
print('units=%d backhaul_links=%d clients=%d wired=%d l3_links=%d'%(len([k for k in units if k]),len(bh_edges),len(cl_unit),sum(1 for m in wired if anyip(m)),n_l3))
PY
  local summary; summary="$("$PYBIN" -c "$GEN_PY" "$wd" "$out" 2>&1)"
  rm -rf "$wd"
  if [ -s "$out" ]; then ok "wrote $(hlink "file://$PWD/$out" "$out") ($summary) — open at app.diagrams.net"
  else note "map generation produced nothing"; fi
}

# mapall: map the WHOLE capture — every SSID and every physical AP unit at once.
#   A real deployment usually radiates several SSIDs (main / guest / IoT) from the
#   same hardware; mapping one ESSID at a time can't show that. This scopes the map
#   to every beaconing BSSID, so each physical unit appears once with all the SSIDs
#   it advertises. Decryption still needs the relevant keys in the keyring.
mapall() {
  [ "${#ALL_BSSIDS[@]}" -gt 0 ] || { note "no beaconing BSSIDs in this capture"; return; }
  local out="${1:-network.drawio}"
  # Widen the BSSID scope to the entire capture for the duration of the draw, then
  # restore whatever single-SSID target the session had.
  local _ssid="$SSID"; local -a _tgt=(); [ "${#TGT_BSSIDS[@]}" -gt 0 ] && _tgt=("${TGT_BSSIDS[@]}")
  TGT_BSSIDS=("${ALL_BSSIDS[@]}")
  MAP_ALL=1 map "$out"
  SSID="$_ssid"; TGT_BSSIDS=(); [ "${#_tgt[@]}" -gt 0 ] && TGT_BSSIDS=("${_tgt[@]}")
}

# report: run every section into a markdown file. tshark's teaching lines go to
#         stderr, so 2>/dev/null keeps the report clean (data only).
report() {
  local out="${1:-wifiscope_${SSID:-report}.md}"
  # Dynamic scope: blanking the color vars here makes every called function emit
  # PLAIN text, so the markdown never contains ANSI escapes.
  local C_RESET= C_B= C_DIM= C_RED= C_GRN= C_YEL= C_BLU= C_MAG= C_CYN= C_ORG= UX_LINKS=0
  {
    echo "# wifiscope report — ${SSID:-unknown}"
    echo
    echo "- pcap: \`$PCAP\`"
    echo "- generated by wifiscope.sh"
    for fn in recon bands crypto hardware clients handshakes keys topology hosts probes; do
      echo; echo "## $fn"; echo '```'
      "$fn"
      echo '```'
    done
  } > "$out" 2>/dev/null
  ok "wrote $out"
  # also emit the matching draw.io network map next to the report
  map "${out%.md}.drawio" >/dev/null
}

# =============================================================================
#  SELFTEST  — exercises the pure-logic pieces (no pcap, no tshark needed) so the
#  correctness-critical classification can be regression-checked anywhere. The
#  end-to-end pipeline test that builds a synthetic capture lives in tests/.
# =============================================================================
selftest() {
  local fail=0 got exp
  section "🧪 wifiscope $VERSION selftest (pure logic, no pcap needed)"
  check_akm() {                         # <akms space-sep> <priv> <wpa1> <want-substr>
    local a="$1" p="$2" w="$3" want="$4" out
    out="$(printf '%s\n' $a | classify_akm "$p" "$w" | cut -f2)"
    if [[ "$out" == *"$want"* ]]; then ok "akm{$a}${p:+ priv}${w:+ wpa1} -> $out"
    else note "FAIL akm{$a}: got '$out', want '*$want*'"; fail=1; fi
  }
  check_akm "2"   "" ""    "WPA2-Personal (PSK)"
  check_akm "2 8" "" ""    "transition"
  check_akm "8"   "" ""    "WPA3-Personal (SAE)"
  check_akm "1"   "" ""    "Enterprise (802.1X/EAP)"     # regression: was "open/WEP?"
  check_akm "5 1" "" ""    "Enterprise (802.1X/EAP)"
  check_akm "12"  "" ""    "Suite-B"
  check_akm "18"  "" ""    "OWE"
  check_akm "6"   "" ""    "WPA2-Personal (PSK)"
  check_akm ""    "1" ""   "WEP"
  check_akm ""    "" "yes" "WPA1"
  check_akm ""    "" ""    "open"

  got="$(printf 'de:ad:be:ef:00:01\nff:ff:ff:ff:ff:ff\n01:00:5e:00:00:fb\n33:33:00:00:00:01\naa:bb:cc:dd:ee:00\n' \
         | drop_group | tr '\n' ',')"
  exp="de:ad:be:ef:00:01,aa:bb:cc:dd:ee:00,"
  [ "$got" = "$exp" ] && ok "drop_group keeps only unicast" || { note "FAIL drop_group: $got"; fail=1; }

  [ $fail = 0 ] && ok "all selftests passed" || die "selftests FAILED"
}

# =============================================================================
#  DRIVER
# =============================================================================

# menu: the interactive loop. Each letter/number maps to one analysis function.
menu() {
  banner
  while true; do
    # Read-only ANALYZE/CRACK items are piped through `paint` (role-colored MACs +
    # vendor links). State-changing KEYS/SESSION items run direct — a pipe would
    # run them in a subshell and lose the globals they set.
    local kn; kn="$([ -s "${KEYRING:-/dev/null}" ] && grep -c . "$KEYRING" || echo 0)"
    cat <<EOF

  ${C_B}wifiscope${C_RESET}  pcap:${C_CYN}${PCAP##*/}${C_RESET}  target:${C_B}${SSID:-<none>}${C_RESET}  decrypt:$([ ${#DEC[@]} -gt 0 ] && printf "%son%s" "$C_GRN" "$C_RESET" || printf "%soff%s" "$C_DIM" "$C_RESET")  keys:${C_MAG}${kn}${C_RESET}
  ${C_DIM}──────────────────────────────────────────────────────────${C_RESET}
   ${C_CYN}ANALYZE${C_RESET}  1 recon   2 bands   3 crypto   4 hardware
            5 clients 6 keys    7 topology 8 hosts
            9 probes  0 handshakes
   ${C_CYN}CRACK${C_RESET}    p pmkid   x export22000  ${C_DIM}(hashcat -m 22000)${C_RESET}
   ${C_CYN}KEYS${C_RESET}     k passphrase  h harvest  g scrapegtk
            a addkey  i import  K show  d delkey  c clearkey
   ${C_CYN}SESSION${C_RESET}  s select-ssid  m map  M mapall  r report  q quit
  ${C_DIM}──────────────────────────────────────────────────────────${C_RESET}
EOF
    # `|| break` exits cleanly on end-of-input instead of spinning on empty reads.
    printf "${C_B}wifiscope›${C_RESET} "; read -r c || break
    case "$c" in
      1|recon)      recon | paint ;;
      2|bands)      bands | paint ;;
      3|crypto)     crypto | paint ;;
      4|hardware)   hardware | paint ;;
      5|clients)    clients | paint ;;
      6|keys)       keys | paint ;;
      7|topology)   topology | paint ;;
      8|hosts)      hosts | paint ;;
      9|probes)     probes | paint ;;
      0|handshakes) handshakes | paint ;;
      p|pmkid)      pmkid | paint ;;
      x|export*)    printf 'output file [%s]: ' "${PCAP%.*}.hc22000"; read -e -r f; export22000 "${f:-}" ;;
      h|harvest)    harvest ;;
      g|scrapegtk)  scrapegtk ;;
      s)            pick_ssid ;;
      k)            set_key ;;
      a|addkey)     addkey ;;
      i|import)     printf 'key file to import: '; read -e -r f; import "${f:-}" ;;
      K|keyring)    keyring ;;
      d|delkey)     delkey ;;
      c|clearkey)   clearkey ;;
      m|map)        printf 'drawio file [%s.drawio]: ' "${SSID:-net}"; read -e -r f; map "${f:-}" ;;
      M|mapall)     printf 'drawio file [network.drawio]: '; read -e -r f; mapall "${f:-}" ;;
      r)            printf 'report file [wifiscope_%s.md]: ' "${SSID:-report}"; read -e -r f; report "${f:-}" ;;
      q|quit)       break ;;
      *)            note "unknown choice: $c" ;;
    esac
  done
}

# main: decide between one-shot (first arg is a command) and interactive.
main() {
  # Meta commands that need neither tshark nor a pcap.
  case "${1:-}" in
    -V|--version|version) printf 'wifiscope %s\n' "$VERSION"; return ;;
    -h|--help|help)       banner; printf 'usage: wifiscope.sh [command] [pcap] [ssid] [passphrase]\n'
                          printf 'commands: recon bands crypto hardware clients keys topology hosts\n'
                          printf '          probes handshakes pmkid export22000 map mapall report\n'
                          printf '          harvest scrapegtk keyring addkey import delkey clearkey\n'
                          printf '          selftest version   (run with no args for the interactive menu)\n'; return ;;
    selftest)             selftest; return ;;
  esac

  need "$TSHARK"

  # One-shot forms that take their own args (not ssid/passphrase):
  case "${1:-}" in
    addkey)   shift; [ -n "${1:-}" ] || die "usage: wifiscope.sh addkey <pcap> <type> <value>"
              load_pcap "$1"; addkey "${2:-}" "${3:-}"; return ;;
    import)   shift; [ -n "${1:-}" ] || die "usage: wifiscope.sh import <pcap> <keyfile>"
              load_pcap "$1"; import "${2:-}"; return ;;
    delkey)   shift; [ -n "${1:-}" ] || die "usage: wifiscope.sh delkey <pcap> <value|all>"
              load_pcap "$1"; delkey "${2:-}"; return ;;
    clearkey) shift; [ -n "${1:-}" ] || die "usage: wifiscope.sh clearkey <pcap>"
              load_pcap "$1"; clearkey; return ;;
  esac

  # One-shot form:  wifiscope.sh <command> <pcap> [ssid] [passphrase]
  case "${1:-}" in
    recon|bands|crypto|hardware|clients|keys|topology|hosts|report|harvest|scrapegtk|keyring|pmkid|probes|handshakes|export22000|map|mapall)
      local cmd="$1"; shift
      [ -n "${1:-}" ] || die "usage: wifiscope.sh $cmd <pcap> [ssid] [passphrase]"
      load_pcap "$1"
      SSID="${2:-}"
      [ -n "$SSID" ] && load_target_bssids
      if [ -n "${3:-}" ] && [ -n "$SSID" ]; then
        PASS="$3"; kr_add wpa-pwd "$PASS:$SSID"; rebuild_dec
      fi
      # bands/crypto/etc need an SSID; nudge if it's missing (recon/mapall don't).
      [ -z "$SSID" ] && [ "$cmd" != recon ] && [ "$cmd" != mapall ] && note "no SSID given — pass one as arg 2 for scoped results"
      # Paint the read-only display commands; run the rest (report/harvest/…) direct.
      # mapall takes no SSID, so its arg-2 (if any) is the output .drawio filename.
      case " recon bands crypto hardware clients keys topology hosts pmkid probes handshakes " in
        *" $cmd "*) "$cmd" | paint ;;
        *) if [ "$cmd" = mapall ]; then mapall "${2:-}"; else "$cmd"; fi ;;
      esac
      return
      ;;
  esac

  # Interactive form: optional pcap as $1, else ask.
  if [ -n "${1:-}" ]; then
    load_pcap "$1"
  else
    # `read -e` turns on readline, giving filename TAB-completion + line editing.
    printf 'pcap file: '; read -e -r p; load_pcap "$p"
  fi
  pick_ssid
  set_key
  menu
}

main "$@"
