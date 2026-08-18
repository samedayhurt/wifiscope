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
# Core analysis needs tshark + common shell tools. Harvesting additionally uses
# OpenSSL 3.x and xxd. Python3 is resolved only inside report generation.
# -----------------------------------------------------------------------------

# We deliberately do NOT use `set -e`: many tshark|grep pipelines exit non-zero
# simply because a filter matched nothing, and that must not kill the script.
# `set -u` (error on unset var) + pipefail still catch real mistakes.
set -uo pipefail

# ---- globals ----------------------------------------------------------------
VERSION="1.3.0"

# Override the tshark path if it isn't on $PATH:  TSHARK=/opt/wireshark/bin/tshark ./wifiscope.sh
TSHARK="${TSHARK:-tshark}"

# Non-report operations stay Bash-only. OpenSSL performs the cryptographic
# primitives for PMK/PTK harvesting; xxd only converts between text hex and
# binary streams (Bash variables cannot safely hold NUL bytes).
OPENSSL="${OPENSSL:-openssl}"
XXD="${XXD:-xxd}"

PCAP=""              # capture file we're working on
SSID=""             # the target network name (once selected)
PASS=""             # WPA passphrase (optional, for decryption)
DEC=()              # tshark decryption args, REBUILT from the keyring (empty = off)
KEYRING=""          # path to <pcap>.keys — the harvested key store (UAT lines)
TGT_BSSIDS=()       # every BSSID advertising the target SSID
ALL_BSSIDS=()       # every BSSID in the whole capture (used to spot non-AP MACs)
TSHARK_FIELD_NAMES="" # lazily cached `tshark -G fields` abbreviations
TSHARK_FIELDS_LOADED=0

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
# print_tshark_command DECRYPT ARGS...
#   Render the real command as a pasteable, playbook-style block.  Decryption
#   options are expanded instead of being hidden behind the old, ambiguous
#   "[+keys]" marker.  Reports redact key values unless the operator explicitly
#   sets WIFISCOPE_REPORT_SECRETS=1; interactive teaching output remains exact.
print_tshark_command() {
  local decrypt="$1" redact="${2:-0}"; shift 2
  local -a argv=(-r "$PCAP")
  # In report context REPORT_KEYSET_TOKEN holds a placeholder (e.g. "${KEYS[@]}")
  # that stands in for the whole decryption key set, so each of the ~13 decrypting
  # reproduce blocks references the keys once instead of re-printing every record.
  if [ "$decrypt" = 1 ]; then
    if [ -n "${REPORT_KEYSET_TOKEN:-}" ]; then argv+=("$REPORT_KEYSET_TOKEN"); else argv+=("${DEC[@]}"); fi
  fi
  argv+=("$@")

  printf '$ tshark'
  local i=0 a v q chunk
  while [ "$i" -lt "${#argv[@]}" ]; do
    a="${argv[$i]}"; i=$((i+1)); chunk=""
    if [ -n "${REPORT_KEYSET_TOKEN:-}" ] && [ "$a" = "$REPORT_KEYSET_TOKEN" ]; then
      printf ' \\\n  %s' "$a"; continue   # emit the key-set placeholder verbatim
    fi
    case "$a" in
      -r|-o|-Y|-T|-E|-e|-z|-N|-c|-a)
        if [ "$i" -lt "${#argv[@]}" ]; then
          v="${argv[$i]}"; i=$((i+1))
          if [ "$redact" = 1 ] && [ "$a" = -o ] && [[ "$v" == uat:80211_keys:* ]]; then
            local kt="key"
            [[ "$v" =~ uat:80211_keys:\\?\"([^\"]+) ]] && kt="${BASH_REMATCH[1]}"
            v="uat:80211_keys:\"$kt\",\"REDACTED\""
          fi
          q="$(shell_quote_human "$v")"; chunk="$a $q"
        else
          chunk="$a"
        fi
        ;;
      *) chunk="$(shell_quote_human "$a")" ;;
    esac
    printf ' \\\n  %s' "$chunk"
  done
  printf '\n'
}

# Readable Bash quoting for generated playbook commands.  `%q` is correct but
# turns display filters into a wall of backslashes; single quotes keep them both
# pasteable and recognizable. Embedded single quotes use the standard '\'' form.
shell_quote_human() {
  local s="$1"
  if [[ -n "$s" && "$s" =~ ^[A-Za-z0-9_./:@%+=,-]+$ ]]; then printf '%s' "$s"
  else s="${s//\'/\'\\\'\'}"; printf "'%s'" "$s"; fi
}

# ts:  run tshark on the loaded pcap WITHOUT decryption keys.
#      It first echoes the exact command (to stderr) so you can read/copy/learn
#      it, then actually runs it. Use this for anything in cleartext management
#      frames: beacons, WPS, RSN, association, 4-address backhaul.
ts() {
  printf '%s' "$C_DIM$C_GRN" >&2
  print_tshark_command 0 0 "$@" >&2
  printf '%s' "$C_RESET" >&2
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
  printf '%s' "$C_DIM$C_GRN" >&2
  print_tshark_command 1 0 "$@" >&2
  printf '%s' "$C_RESET" >&2
  "$TSHARK" -r "$PCAP" "${DEC[@]}" "$@" | tr -d '\r'
}

# Quiet query helpers used by the report generator.  These deliberately do not
# emit teaching lines because the corresponding command is printed beside each
# report result by report_command().
tq()  { "$TSHARK" -r "$PCAP" "$@" 2>/dev/null | tr -d '\r'; }
tqd() { "$TSHARK" -r "$PCAP" "${DEC[@]}" "$@" 2>/dev/null | tr -d '\r'; }

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

# kr_normalize TYPE VALUE: the single source of truth for what tshark will accept
#   as a  -o uat:80211_keys:"type","value"  record. On success it prints the
#   normalized "type<TAB>value" and returns 0; on failure it prints a human reason
#   and returns non-zero. This exists because tshark does NOT skip a bad UAT record
#   — it rejects the -o flag and ABORTS the whole invocation, silently disabling
#   EVERY key. So one 1-char passphrase, stray ANSI byte, CRLF, or wrong-length hex
#   would blank all decryption. Enforcing the same rules on read (rebuild_dec) and
#   write (kr_add) means a legacy/hand-edited keyring can never take the tool down.
kr_normalize() {
  local t="$1" v="$2" pass ssid
  t="${t%$'\r'}"; v="${v%$'\r'}"                       # tolerate CRLF keyrings
  case "$t" in ''|'#'*) printf 'blank or comment line'; return 1 ;; esac
  case "$v" in *[$'\001'-$'\037'$'\177']*) printf 'value contains a control character'; return 1 ;; esac
  case "$v" in *'"'*|*'\'*) printf 'value contains a quote or backslash'; return 1 ;; esac
  case "$t" in
    wpa-pwd)
      # passphrase[:ssid], at most one ':'. tshark requires 8..63-char passphrase;
      # colons inside the SSID must be %3a-encoded or the -o flag is rejected.
      pass="${v%%:*}"; [ "$pass" = "$v" ] && ssid="" || ssid="${v#*:}"
      if [ "${#pass}" -lt 8 ] || [ "${#pass}" -gt 63 ]; then
        printf 'wpa-pwd passphrase must be 8-63 chars (got %d)' "${#pass}"; return 1
      fi
      [ -n "$ssid" ] && v="$pass:${ssid//:/%3a}" || v="$pass"
      ;;
    wpa-psk) [[ "$v" =~ ^[0-9a-fA-F]{64}$ ]]            || { printf 'wpa-psk must be 64 hex chars'; return 1; } ;;
    tk)      [[ "$v" =~ ^([0-9a-fA-F]{32}|[0-9a-fA-F]{64})$ ]] || { printf 'tk must be 32 or 64 hex chars'; return 1; } ;;
    wep)     [[ "$v" =~ ^([0-9a-fA-F]{10}|[0-9a-fA-F]{26}|[0-9a-fA-F]{32})$ ]] || { printf 'wep must be 10/26/32 hex chars'; return 1; } ;;
    msk)     { [[ "$v" =~ ^[0-9a-fA-F]+$ ]] && [ $(( ${#v} % 2 )) -eq 0 ] && [ "${#v}" -ge 32 ] && [ "${#v}" -le 256 ]; } \
                                                        || { printf 'msk must be 32-256 hex chars'; return 1; } ;;
    *) printf "unknown key type '%s'" "$t"; return 1 ;;
  esac
  printf '%s\t%s' "$t" "$v"
}

# kr_add TYPE VALUE: append a key to the keyring, validating it FIRST (so garbage
#   never reaches disk) and skipping exact duplicates. Stored as "type<TAB>value".
kr_add() {
  [ -n "$KEYRING" ] || { note "no keyring path set (load a pcap first)"; return 1; }
  local norm; norm="$(kr_normalize "$1" "$2")" \
    || { note "refusing to store invalid $1 key — $norm"; return 1; }
  touch "$KEYRING"
  grep -Fxq "$norm" "$KEYRING" 2>/dev/null || printf '%s\n' "$norm" >> "$KEYRING"
}

# rebuild_dec: turn the keyring file into tshark args in DEC[]. Each valid key
#   becomes its own  -o uat:80211_keys:"type","value"  (tshark APPENDS one UAT
#   record per -o), plus a single enable-decryption switch up front. Invalid lines
#   are skipped with a reason instead of aborting the whole run (see kr_normalize).
rebuild_dec() {
  DEC=()
  [ -n "$KEYRING" ] && [ -s "$KEYRING" ] || return
  DEC=(-o wlan.enable_decryption:TRUE)
  local t v norm skipped=0
  while IFS=$'\t' read -r t v; do
    [ -n "$t$v" ] || continue
    if norm="$(kr_normalize "$t" "$v")"; then
      DEC+=(-o "uat:80211_keys:\"${norm%%$'\t'*}\",\"${norm#*$'\t'}\"")
    else
      note "keyring: ignoring entry ($norm)"; skipped=$((skipped+1))
    fi
  done < "$KEYRING"
  [ "$skipped" -gt 0 ] && note "keyring: $skipped bad entr$([ "$skipped" = 1 ] && echo y || echo ies) ignored — decryption still uses the valid keys"
  return 0
}

# pmk_hex: compute the 256-bit PMK/PSK from passphrase + SSID (WPA2-PSK).
#   PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096 iters, 32 bytes). Deterministic,
#   so this IS the network's PSK in raw hex — usable as a wpa-psk key. OpenSSL
#   performs PBKDF2; Python is intentionally forbidden in analysis/key paths.
pmk_hex() {
  need "$OPENSSL"; need "$XXD"
  local salt_hex
  salt_hex="$(printf '%s' "$SSID" | "$XXD" -p -c 999999 | tr -d '\r\n')"
  "$OPENSSL" kdf -keylen 32 -kdfopt digest:SHA1 -kdfopt "pass:$PASS" \
    -kdfopt "hexsalt:$salt_hex" -kdfopt iter:4096 PBKDF2 2>/dev/null \
    | tr -d ':\r\n' | tr 'A-F' 'a-f'
}

# derive_psk: harvest the PSK/PMK into the keyring as a wpa-psk entry.
derive_psk() {
  [ -n "$PASS" ] && [ -n "$SSID" ] || { note "need passphrase+SSID for PSK"; return; }
  local pmk; pmk="$(pmk_hex)"
  [ -n "$pmk" ] && { kr_add wpa-psk "$pmk"; note "PSK/PMK: $pmk"; }
}

# harvest_ptk: compute each client's PTK-TK and add it to the keyring as a tk.
#   Some modern builds expose wlan.analysis.tk, but direct derivation keeps
#   harvesting portable and independent of analysis-field availability:
#     B   = min(AA,SPA)||max(AA,SPA)||min(ANonce,SNonce)||max(ANonce,SNonce)
#     PTK = PRF-384(PMK, "Pairwise key expansion", B)   (HMAC-SHA1 blocks)
#     TK  = PTK[32:48]   (KCK16 | KEK16 | TK16, CCMP)
#   ANonce comes from msg1/msg3 (AP side), SNonce from msg2 (STA side) — all
#   cleartext in the EAPOL frames, so no decryption is needed to read them.
harvest_ptk() {
  [ -n "$PASS" ] && [ -n "$SSID" ] || { note "need passphrase+SSID for PTKs"; return; }
  need "$OPENSSL"; need "$XXD"
  local pmk contexts
  pmk="$(pmk_hex)"
  [ "${#pmk}" -eq 64 ] || { note "OpenSSL could not derive a 32-byte PMK (OpenSSL 3.x with 'kdf' is required)"; return; }

  # AWK pairs the AP's ANonce (M1/M3) with the station's SNonce (M2). Bash then
  # assembles the binary PRF input as a stream and asks OpenSSL for each HMAC-SHA1
  # block. No binary material is stored in a Bash variable.
  contexts="$(ts -Y "wlan_rsna_eapol.keydes.msgnr in {1,2,3} && $(bssid_filter)" -T fields \
      -e wlan.sa -e wlan.da -e wlan_rsna_eapol.keydes.msgnr -e wlan_rsna_eapol.keydes.nonce \
    | awk -F'\t' -v OFS='\t' '
        $4!="" && ($3==1||$3==3){k=tolower($1) SUBSEP tolower($2);ap[k]=tolower($1);sta[k]=tolower($2);an[k]=$4}
        $4!="" && $3==2{k=tolower($2) SUBSEP tolower($1);ap[k]=tolower($2);sta[k]=tolower($1);sn[k]=$4}
        END{for(k in ap)if(an[k]!=""&&sn[k]!="")print sta[k],ap[k],an[k],sn[k]}')"
  [ -n "$contexts" ] || { note "no complete handshakes (need both nonces) to derive PTKs"; return; }

  local sta ap an sn aa spa mac_lo mac_hi nonce_lo nonce_hi bhex prfhex block tk i ctr derived=0
  local LC_ALL=C
  while IFS=$'\t' read -r sta ap an sn; do
    aa="${ap//:/}"; spa="${sta//:/}"; an="${an//[: ]/}"; sn="${sn//[: ]/}"
    [[ "$aa$spa" =~ ^[0-9a-fA-F]{24}$ && "$an$sn" =~ ^[0-9a-fA-F]{128}$ ]] || continue
    mac_lo="$aa"; mac_hi="$spa"; if [[ "$mac_lo" > "$mac_hi" ]]; then mac_lo="$spa"; mac_hi="$aa"; fi
    nonce_lo="$an"; nonce_hi="$sn"; if [[ "$nonce_lo" > "$nonce_hi" ]]; then nonce_lo="$sn"; nonce_hi="$an"; fi
    bhex="${mac_lo}${mac_hi}${nonce_lo}${nonce_hi}"; prfhex=""
    for i in 0 1 2; do
      printf -v ctr '%02x' "$i"
      block="$({ printf 'Pairwise key expansion\0'; printf '%s%s' "$bhex" "$ctr" | "$XXD" -r -p; } \
        | "$OPENSSL" dgst -sha1 -mac HMAC -macopt "hexkey:$pmk" -binary 2>/dev/null \
        | "$XXD" -p -c 999999 | tr -d '\r\n')"
      [ "${#block}" -eq 40 ] || { prfhex=""; break; }
      prfhex+="$block"
    done
    [ "${#prfhex}" -ge 96 ] || continue
    tk="${prfhex:64:32}"                         # bytes 32..47 of the 48-byte PTK
    kr_add tk "$tk"
    note "PTK-TK  $sta @ $ap  ->  $tk"
    derived=$((derived+1))
  done <<< "$contexts"
  [ "$derived" -gt 0 ] || note "handshake rows were present, but no PTK passed validation"
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
     -e wlan.ht.info.primarychannel -e radiotap.channel.freq | dessid 2 | sort -u \
     | tcol $'BSSID\tSSID\t2.4GHz ch\t5GHz ch\tFreq MHz'
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

# hardware: identify the router — make / model / model# / device / serial /
#   firmware — primarily from the WPS information element (beacons AND probe
#   responses; TP-Link and many others only put the full identity in probe
#   responses, not beacons). WHY the extra sources: some APs advertise an EMPTY
#   WPS IE (no identity at all), so a bare WPS query returns a blank wall. When the
#   target has no WPS identity we (a) say so explicitly, (b) list the WPS identities
#   that DO exist in the capture (neighbors), and (c) sweep decrypted HTTP/UPnP
#   banners, where router firmware/model frequently leaks from the admin page.
hardware() {
  local hdr=$'BSSID\tMake\tModel\tModel #\tDevice\tSerial\tFirmware (WPS OS)'
  local wps_all wps_tgt
  # Pull every populated WPS identity in the capture once, then split target vs rest.
  wps_all="$(ts -Y '(wps.manufacturer || wps.model_name || wps.model_number || wps.device_name || wps.serial_number || wps.os_version)' \
     -T fields -E occurrence=f -e wlan.bssid -e wps.manufacturer -e wps.model_name \
     -e wps.model_number -e wps.device_name -e wps.serial_number -e wps.os_version \
     | awk -F'\t' 'tolower($2 $3 $4 $5 $6 $7)!=""' | sort -u)"
  local -a tgt=(); [ "${#TGT_BSSIDS[@]}" -gt 0 ] && tgt=("${TGT_BSSIDS[@]}")
  wps_tgt="$(printf '%s\n' "$wps_all" | awk -F'\t' -v t="${tgt[*]}" 'BEGIN{n=split(tolower(t),a," ");for(i=1;i<=n;i++)T[a[i]]=1} (tolower($1) in T)')"

  # The router's OWN LAN IP (DHCP default-gateway option) and the banners it serves.
  # A TP-Link/whatever whose beacon WPS IE carries only version/state still reveals
  # its model+firmware in its UPnP/HTTP server string (e.g. "UPnP/1.0 TL-WR841N/9.0").
  local gw gw_ident
  gw="$(tsd -Y "$(bssid_filter) && dhcp.option.router" -T fields -E occurrence=f -e dhcp.option.router 2>/dev/null \
       | tr ',' '\n' | grep -m1 -E '^[0-9]+\.[0-9]')"
  [ -n "$gw" ] && gw_ident="$(tsd -Y "ip.src==$gw && http.server" -T fields -E occurrence=f -e http.server 2>/dev/null \
       | awk 'NF' | sort -u)"

  section "🏷️  router / device identity for $SSID"
  if [ -n "$wps_tgt" ]; then
    echo "Source: WPS information element (authoritative)"
    { printf '%s\n' "$hdr"; printf '%s\n' "$wps_tgt"; } | md_table_or_tsv
  elif [ -n "$gw_ident" ]; then
    printf 'Router at DHCP gateway %s (= this network'\''s AP):\n' "$gw"
    printf '%s\n' "$gw_ident" | tcol 'Model / firmware (from the router'\''s UPnP/HTTP server string)'
    note "$SSID's beacon WPS IE carries version/state only — model/firmware taken from the router's own banner above"
  else
    note "no make/model for $SSID via WPS; $([ "${#DEC[@]}" -gt 0 ] && echo 'and its UPnP/HTTP banner was not observed' || echo 'enable decryption (k/harvest) to read its UPnP/HTTP banner')"
  fi

  # Context: other WPS-identified devices in the capture (neighbors / upstream gear).
  if [ -n "$wps_all" ] && [ "$wps_all" != "$wps_tgt" ]; then
    section "other WPS device identities in this capture (neighbors / upstream)"
    { printf '%s\n' "$hdr"; printf '%s\n' "$wps_all"; } | md_table_or_tsv
  fi

  # Full LAN banner sweep — fingerprints the router AND other local devices.
  local banners
  banners="$(tsd -Y "$(bssid_filter) && (http.server || http.user_agent)" \
     -T fields -E occurrence=f -e ip.src -e http.server -e http.user_agent 2>/dev/null \
     | awk -F'\t' 'tolower($2 $3)!="" && $1 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/' | sort -u | head -n 20)"
  if [ -n "$banners" ]; then
    section "all decrypted HTTP/UPnP banners (LAN devices)"
    printf '%s\n' "$banners" | tcol $'Source IP\tHTTP Server\tUser-Agent'
  fi
}

# md_table_or_tsv: align a header+rows TSV with `column` when available, else pass
#   through — a terminal convenience shared by the identity view.
md_table_or_tsv() { if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi; }

# tcol HEADER: label + align a raw TSV data stream so each column is discernible
#   and the block is clean to copy-paste. Prints the tab-separated HEADER first,
#   then aligns everything on tabs (falls back to plain TSV without `column`). An
#   empty data stream prints a dim "(none observed)" instead of a lonely header, so
#   a section never reads as broken. Colorization still happens later via paint().
tcol() {
  local header="$1" body n; body="$(cat)"
  if printf '%s' "$body" | grep -q '[^[:space:]]'; then
    n="$(printf '%s\n' "$body" | grep -c '[^[:space:]]')"
    { printf '%s\n' "$header"; printf '%s\n' "$body"; } | md_table_or_tsv
    printf '%s  — %d row%s%s\n' "$C_DIM" "$n" "$([ "$n" = 1 ] || printf s)" "$C_RESET"
  else
    printf '%s  (none observed)%s\n' "$C_DIM" "$C_RESET"
  fi
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
  # -E occurrence=f collapses A-MSDU frames (which repeat wlan.sa/wlan.da per
  # subframe) to one MAC; the final `tr ',\t'` also splits any comma-joined value
  # so an aggregated frame can never inflate the distinct-station count.
  {
    ts -Y "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"" \
       -T fields -E occurrence=f -e wlan.sa 2>/dev/null
    ts -Y "eapol && $(bssid_filter)" -T fields -E occurrence=f -e wlan.sa -e wlan.da 2>/dev/null | tr ',\t' '\n'
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" \
       -T fields -E occurrence=f -e wlan.sa 2>/dev/null
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" \
       -T fields -E occurrence=f -e wlan.da 2>/dev/null
  } | tr ',\t' '\n' | sort -u | grep . | drop_group | no_aps
}

# clients: list the wireless stations on the target network.
#   WHY: see station_macs — we no longer trust handshakes alone. The per-frame
#        EAPOL table is still shown (it's the ground truth for key derivation), but
#        the distinct-client list is the full union of association + data + EAPOL.
clients() {
  section "👥 wireless station candidates on $SSID (assoc + data + EAPOL)"
  ts -Y "eapol && $(bssid_filter)" -T fields \
     -e frame.number -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr \
     | tcol $'Frame\tSource\tDestination\tBSSID\tEAPOL msg'
  section "distinct client MACs (all sources)"
  station_macs | tcol 'Station MAC'
}

# _hs_mask: reads  sa<TAB>da<TAB>bssid<TAB>msgnr  on stdin and prints the
#   per-station handshake summary. Split out so report() can feed it the shared
#   EAPOL buffer instead of running another tshark pass.
_hs_mask() {
  awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" '
       BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
       { if($4=="")next; sa=tolower($1); da=tolower($2); b=tolower($3);
         sta=(sa in AP)?da:sa; if(sta==""||b=="")next; M[sta SUBSEP b SUBSEP $4]=1 }
       END{ for(k in M){split(k,p,SUBSEP); seen[p[1] SUBSEP p[2]]=1}
            for(k in seen){split(k,p,SUBSEP); mask="";
              for(i=1;i<=4;i++) mask=mask (((p[1] SUBSEP p[2] SUBSEP i) in M)?i:"·");
              good=(((p[1] SUBSEP p[2] SUBSEP 1) in M)&&((p[1] SUBSEP p[2] SUBSEP 2) in M)) ||
                   (((p[1] SUBSEP p[2] SUBSEP 2) in M)&&((p[1] SUBSEP p[2] SUBSEP 3) in M));
              print p[1],p[2],mask,(good?"YES":"no") } }' | sort
}

# handshake_summary: station<TAB>bssid<TAB>message-mask<TAB>recoverable.
#   A lone M1 is evidence that an AP tried to start a handshake, not evidence of
#   a recovered PTK.  (M1+M2) or (M2+M3) supplies a crackable/derivable context.
handshake_summary() {
  ts -Y "eapol && $(bssid_filter)" -T fields \
     -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr | _hs_mask
}

# _collapse KEYCOLS NFIELDS: read a TSV, dedupe rows whose KEYCOLS (comma-listed,
#   1-based) match, keep the FIRST occurrence's fields, and append a trailing
#   "copies" count. Used to fold the many identical retransmissions a merged
#   capture records for each management/EAPOL frame into one legible row.
_collapse() {
  awk -F'\t' -v OFS='\t' -v kc="$1" -v nf="$2" '
    BEGIN{n=split(kc,c,",")}
    {k=""; for(i=1;i<=n;i++) k=k SUBSEP $(c[i]);
     if(!(k in seen)){seen[k]=1; order[++m]=k; for(i=1;i<=nf;i++) cell[k,i]=$i}
     cnt[k]++}
    END{for(j=1;j<=m;j++){k=order[j]; line=cell[k,1];
          for(i=2;i<=nf;i++) line=line OFS cell[k,i]; print line OFS cnt[k]}}'
}

# keys: count PSKs, recoverable PTK contexts, and GTKs — and explain each number.
#   WHY:
#     PSK  = passphrase+SSID pairs -> one network, one passphrase = 1 PSK.
#     PTK  = per client<->AP session -> one per distinct handshake/client.
#     GTK-in-use   = per BSS (fronthaul BSSID) -> APs x active bands.
#     GTK-recovered= only handshakes complete enough to derive the PTK/KEK; a
#                    handshake missing msg1 leaves the GTK blank.
keys() {
  section "🔑 keys for $SSID"
  local kv expected_psk=0 stored_psk=0
  kv="$(crypto_verdict_text)"; [[ "$kv" == *PSK* ]] && expected_psk=1
  [ -s "$KEYRING" ] && stored_psk="$(awk -F'\t' '$1=="wpa-pwd"||$1=="wpa-psk"{n++}END{print n+0}' "$KEYRING")"
  printf '%sPSK credential expected:%s %s  (%s)\n' "$C_B" "$C_RESET" "$expected_psk" "$kv"
  echo "PSK/passphrase entries supplied: $stored_psk  (keyring inventory, not proof the key works)"

  local nptk
  nptk="$(handshake_summary | awk -F'\t' '$4=="YES"' | wc -l | tr -d ' ')"
  echo "recoverable PTK contexts: $nptk  (station/BSSID pairs with M1+M2 or M2+M3)"
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
    | sort -u | tcol $'Transmitter\tReceiver'
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
      -e dhcp.ip.your -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname | sort -u \
      | tcol $'Assigned IP\tSubnet mask\tRouter\tHostname'
  section "DHCP fingerprint (mac / ip / hostname / vendor-class)"
  tsd -Y 'dhcp' -T fields \
      -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.hostname -e dhcp.option.vendor_class_id | sort -u \
      | tcol $'Client MAC\tRequested IP\tAssigned IP\tHostname\tVendor class'
  section "ARP IPv4 <-> MAC"
  tsd -Y 'arp' -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u \
      | tcol $'IPv4\tMAC'
  # IPv6 is invisible to ARP; neighbor discovery is its equivalent. The link-layer
  # address option in NS/NA/RS/RA carries IPv6<->MAC, and DHCPv6's DUID-LL carries
  # the client MAC — without these, every IPv6-only host is missed.
  section "IPv6 neighbors (ICMPv6 ND link-layer option)"
  tsd -Y 'icmpv6 && icmpv6.opt.linkaddr' -T fields \
      -e ipv6.src -e icmpv6.opt.linkaddr \
      -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address | sort -u \
      | tcol $'IPv6 source\tLink-layer MAC\tNS target\tNA target'
  section "DHCPv6 (client IPv6 / DUID link-layer MAC)"
  tsd -Y 'dhcpv6' -T fields -e ipv6.src -e dhcpv6.duidll.link_layer_addr | sort -u \
      | tcol $'IPv6 source\tDUID link-layer MAC'
  section "hostname sweep (DHCP / NBNS / mDNS / LLMNR)"
  # dns.resp.name (answers) carries the real host.local a device advertises; qry.name
  # is what a device is *looking for*. Include both — the map keys names off resp.name.
  tsd -Y 'dhcp.option.hostname || nbns || mdns || llmnr' -T fields \
      -e ip.src -e dhcp.option.hostname -e nbns.name -e dns.resp.name -e dns.qry.name | sort -u \
      | tcol $'Source IP\tDHCP hostname\tNBNS name\tmDNS response\tDNS query'
  section "software versions (HTTP / SSH banners)"
  tsd -Y 'http.user_agent || http.server || ssh.protocol' -T fields \
      -e ip.src -e http.user_agent -e http.server -e ssh.protocol | sort -u \
      | tcol $'Source IP\tHTTP User-Agent\tHTTP Server\tSSH protocol'
}

# pmkid: list RSN PMKID evidence.  PMKIDs are commonly carried in association RSN
#   information, so requiring EAPOL here silently misses valid client-less data.
#   Zero-valued PMKIDs are filtered out.
pmkid() {
  section "🪪 PMKIDs (offline-crackable, client-less)"
  ts -Y "(wlan.pmkid.akms || wlan.rsn.ie.pmkid) && $(bssid_filter)" -T fields \
     -e frame.number -e wlan.sa -e wlan.da -e wlan.bssid \
     -e wlan.pmkid.akms -e wlan.rsn.ie.pmkid \
    | awk -F'\t' '$5!="" || ($6!="" && $6 !~ /^0*$/)' | sort -u \
    | tcol $'Frame\tSource\tDestination\tBSSID\tPMKID AKM\tPMKID'
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
  need "$XXD"
  local ehex; ehex="$(printf '%s' "$SSID" | "$XXD" -p -c 999999 | tr -d '\r\n')"
  ts -Y "(wlan.pmkid.akms || wlan.rsn.ie.pmkid) && $(bssid_filter)" -T fields \
     -e wlan.bssid -e wlan.staa -e wlan.rsn.ie.pmkid \
    | awk -F'\t' -v e="$ehex" '$3!="" && $3 !~ /^0*$/ {ap=$1;sta=$2;gsub(/:/,"",ap);gsub(/:/,"",sta);
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
    | awk -F'\t' 'NF==2 && $2!=""' | dessid 2 | sort -u | tcol $'Station\tSSID sought'
}

# handshakes: per client, which 4-way messages were captured and whether that's
#   enough to derive keys / crack. (m1&m2) or (m2&m3) => PTK-derivable & crackable.
handshakes() {
  section "🤝 handshake completeness (per client)"
  handshake_summary | awk -F'\t' '{printf "%-18s @ %-18s  msgs:%s  crackable:%s\n",$1,$2,$3,$4}'
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

# _report_map_python: rich draw.io generator used only from report(). Python is
#   deliberately resolved here—not globally—so every non-report command remains
#   Bash-only. The public map/mapall commands use the AWK generator below.
#   Physical AP units (clustered best-effort: TP-Link/most vendors keep a BSSID's
#   last 4 octets across its virtual BSSIDs, so we key on octets 3-6 with the last
#   octet's low 2 bits masked), wireless clients grouped under the AP they joined,
#   wired hosts, and an evidence-qualified default gateway. Full host labels need
#   keyring; without keys it still draws the L2 layer (APs + associations + backhaul).
_report_map_python() {
  [ "${WIFISCOPE_REPORT_CONTEXT:-0}" = 1 ] || { note "internal report map called outside report context"; return; }
  local report_python="${PYTHON3:-python3}"
  command -v "$report_python" >/dev/null 2>&1 || { note "python3 unavailable — using Bash/AWK report map"; map "$1"; return; }
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
  # When called from report() (MAP_PREFILL set) the beacon / WPS / client TSVs are
  # handed over from evidence report() already collected, so we skip re-scanning the
  # whole capture for them. Standalone map/mapall extract here as before.
  if [ -n "${MAP_PREFILL:-}" ] && [ -f "$MAP_PREFILL/beacons.tsv" ]; then
    cp "$MAP_PREFILL/beacons.tsv" "$wd/beacons.tsv"
    cp "$MAP_PREFILL/wps.tsv"     "$wd/wps.tsv"
    cp "$MAP_PREFILL/clients.tsv" "$wd/clients.tsv"
  else
  # beacons carry a 5th column: the (hex-decoded) SSID, so the generator can label
  # each physical unit with the SSIDs it radiates.
  ts  -Y "$bfilt" -T fields -e wlan.bssid -e wlan.ds.current_channel \
      -e wlan.ht.info.primarychannel -e radiotap.channel.freq -e wlan.ssid \
      -e radiotap.dbm_antsignal 2>/dev/null \
      | dessid 5 > "$wd/beacons.tsv"
  ts  -Y "(wps.manufacturer || wps.model_name || wps.model_number || wps.device_name || wps.serial_number || wps.os_version) && $(bssid_filter)" \
      -T fields -e wlan.bssid -e wps.manufacturer -e wps.model_name -e wps.model_number \
      -e wps.device_name -e wps.serial_number -e wps.os_version 2>/dev/null \
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
  fi
  ts  -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' -T fields -e wlan.ta -e wlan.ra 2>/dev/null | sort -u > "$wd/backhaul.tsv"
  # ONE decrypt pass feeds every L3 layer of the map (dhcp/gateway/arp/ND/names/
  # protocols/conversations). Each tsd pass re-decrypts the whole capture, so nine
  # separate passes were the dominant cost of an in-report map; split one buffer in
  # AWK instead. Fields: 1 proto  2 ip.src 3 ip.dst  4 ipv6.src 5 ipv6.dst
  #   6-10 dhcp(mac,reqip,your,host,vendor)  11 dhcp.router  12-13 arp(src ip,mac)
  #   14 icmpv6.linkaddr  15 nbns.name  16 dns.resp.name
  tsd -Y 'ip || ipv6 || arp' -T fields \
      -e _ws.col.protocol -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
      -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.hostname -e dhcp.option.vendor_class_id -e dhcp.option.router \
      -e arp.src.proto_ipv4 -e arp.src.hw_mac -e icmpv6.opt.linkaddr \
      -e nbns.name -e dns.resp.name 2>/dev/null > "$wd/_l3.raw"
  awk -F'\t' -v OFS='\t' 'tolower($1)~/dhcp|bootp/{print $6,$7,$8,$9,$10}' "$wd/_l3.raw" | sort -u > "$wd/dhcp.tsv"
  awk -F'\t'             '$11!=""{print $11}'                              "$wd/_l3.raw" | sort -u | grep -v '^$' | head -1 > "$wd/gw.txt"
  awk -F'\t' -v OFS='\t' 'tolower($1)~/arp/{print $12,$13}'                "$wd/_l3.raw" | sort -u > "$wd/arp.tsv"
  awk -F'\t' -v OFS='\t' '$14!=""{print $14,$4}'                          "$wd/_l3.raw" | sort -u > "$wd/nd.tsv"
  awk -F'\t' -v OFS='\t' 'tolower($1)~/mdns|nbns/{print $2,$15,$16}'       "$wd/_l3.raw" | sort -u > "$wd/names.tsv"
  awk -F'\t' -v OFS='\t' '{if($2!="")print $2,$1; if($4!="")print $4,$1}'  "$wd/_l3.raw" | sort -u > "$wd/proto.tsv"
  # observed L3 conversations (v4+v6) — drawn as dashed edges between hosts that
  # both appear on the map, i.e. real intra-LAN "who talks to whom".
  awk -F'\t' -v OFS='\t' '{if($2!="")print $2,$3; if($4!="")print $4,$5}'  "$wd/_l3.raw" | sort -u > "$wd/conv.tsv"
  rm -f "$wd/_l3.raw"
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
band={}; chan={}; ssid_of=defaultdict(set); rssi_sum=defaultdict(float); rssi_n=defaultdict(int)
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
    if len(r)>5 and r[5]:
        try: rssi_sum[b]+=float(r[5].split(',')[0]); rssi_n[b]+=1
        except: pass
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
rootk=None; root_basis='unresolved'
# Only an exact DHCP-gateway-IP -> ARP-MAC -> beacon-BSSID match earns the word
# "gateway".  Similar MACs are useful correlation, but remain an inference.
if gwmac and gwmac in apb:
    rootk=ukey(gwmac); root_basis='confirmed DHCP+ARP identity'
if rootk is None and gwmac:
    g4=gwmac.split(':')[2:]
    for k in units:
        if any(x.split(':')[2:]==g4 or x.split(':')[3:]==gwmac.split(':')[3:] for x in units[k]):
            rootk=k; root_basis='gateway-correlated MAC family'; break
# No gateway match? The root of a mesh is the node with the most backhaul links.
if rootk is None and bh_edges:
    deg=defaultdict(int)
    for a,b in bh_edges: deg[a]+=1; deg[b]+=1
    rootk=max(deg,key=deg.get); root_basis='inferred from WDS degree'
if rootk not in units:
    rootk=max(units,key=lambda k:sum(1 for s in cli for b in cli[s] if b in units[k])) if units else None
    if rootk is not None:
        root_basis=('only observed AP unit; role unconfirmed' if len(units)==1 else 'inferred from station observations')
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
# wired = decrypted L2 devices that aren't clients or APs — but NOT the gateway.
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
GW  ='rounded=1;fillColor=#f5f5f5;strokeColor=#666666;whiteSpace=wrap;html=1;fontSize=10;'
EBH ='endArrow=none;dashed=1;strokeColor=#b85450;strokeWidth=2;html=1;fontSize=9;'
ECL ='endArrow=none;strokeColor=#9673a6;html=1;fontSize=9;'
EWI ='endArrow=none;strokeColor=#d79b00;strokeWidth=2;html=1;fontSize=9;'
EGW ='endArrow=none;dashed=1;strokeColor=#666666;strokeWidth=2;html=1;fontSize=9;'
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
    if k==rootk:
        head=('GATEWAY / AP (confirmed)' if root_basis.startswith('confirmed') else 'AP UNIT / ROOT CANDIDATE')
        head+='\nBasis: '+root_basis
    else: head='AP UNIT / PEER'
    radios='\n'.join('%s  %s ch%s%s'%(b,band.get(b,'?'),chan.get(b,'?'),
             (' avg %.1f dBm'%(rssi_sum[b]/rssi_n[b])) if rssi_n[b] else '') for b in bs) \
           or '(backhaul-only radio)'
    sl=unit_ssids(k)
    ssline=('SSIDs: '+'  '.join(sl[:4])+(' +%d'%(len(sl)-4) if len(sl)>4 else '')) if sl else ''
    body='\n'.join(p for p in (head, unit_make(k), ssline, radios) if p)
    uid[k]=cell(body, x,190,275,135, AP_R if k==rootk else AP_S); ux[k]=x; x+=315
if gwip:
    gl='DEFAULT GATEWAY (DHCP)\n%s%s'%(gwip, ('\n'+gwmac) if gwmac else '\nMAC not observed')
    gx=(ux[rootk]+55) if rootk in ux else 80
    g=cell(gl,gx,40,180,75,GW)
    if rootk in uid and (root_basis.startswith('confirmed') or root_basis.startswith('gateway-correlated')):
        edge(g,uid[rootk],root_basis,EGW)
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
    lbl='\n'.join(x for x in [host or '(station observed)', ip, sta, vc, ' '.join(pr)] if x)
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
# host<->gateway and host<->external edges are intentionally skipped, leaving the
# real intra-LAN "who talks to whom" without clutter. Capped so a busy capture
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
cell('%s — evidence-qualified network map'%ssid, 80,145,620,24,'text;html=1;fontStyle=1;fontSize=13;')
cell('SOLID = observed association/data relation   DASHED RED = observed WDS   DASHED GRAY = inferred/correlated relation\nA DHCP default gateway is not automatically an ISP/WAN address.  "Candidate" labels are not confirmed roles.',
     80,335,760,38,'text;html=1;fontSize=9;fontColor=#666666;')
xml='<mxfile><diagram name="%s"><mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" page="1" pageWidth="1600" pageHeight="1100"><root><mxCell id="0"/><mxCell id="1" parent="0"/>%s</root></mxGraphModel></diagram></mxfile>'%(esc(ssid or 'net'),''.join(cells))
open(out,'w',encoding='utf-8').write(xml)
print('units=%d backhaul_links=%d clients=%d wired=%d l3_links=%d'%(len([k for k in units if k]),len(bh_edges),len(cl_unit),sum(1 for m in wired if anyip(m)),n_l3))
PY
  local summary py_status=0
  : > "$out"                         # prevent a stale diagram masking generator failure
  summary="$("$report_python" -c "$GEN_PY" "$wd" "$out" 2>&1)" || py_status=$?
  rm -rf "$wd"
  if [ "$py_status" -eq 0 ] && [ -s "$out" ]; then
    ok "wrote $(hlink "file://$PWD/$out" "$out") ($summary) — open at app.diagrams.net"
  else
    note "report-only python3 map failed (${summary:-exit $py_status}) — using Bash/AWK map"
    map "$out"
  fi
}

# map: public, Bash/AWK-only draw.io generator. It deliberately shares the same
# evidence vocabulary as the report map, but never resolves or invokes Python.
# TShark collects the evidence; portable AWK groups physical units and writes XML.
map() {
  local all="${MAP_ALL:-0}"
  [ "$all" = 1 ] || [ -n "$SSID" ] || { note "select an SSID first (s), or use mapall"; return; }
  local out="${1:-${SSID:-network}.drawio}" wd; wd="$(mktemp -d)"
  local bfilt afilt title
  if [ "$all" = 1 ]; then
    bfilt='wlan.fc.type_subtype==8'; afilt='(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2)'; title='whole capture'
  else
    bfilt="$(beacons_of_target)"; afilt="(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\""; title="$SSID"
  fi
  section "🗺️  drawing Bash/AWK network map for $title"

  ts -Y "$bfilt" -T fields -e wlan.bssid -e wlan.ds.current_channel \
    -e wlan.ht.info.primarychannel -e radiotap.channel.freq -e wlan.ssid \
    -e radiotap.dbm_antsignal | dessid 5 > "$wd/beacons.tsv"
  ts -Y "(wps.manufacturer || wps.model_name || wps.model_number || wps.device_name || wps.serial_number || wps.os_version) && $(bssid_filter)" \
    -T fields -e wlan.bssid -e wps.manufacturer -e wps.model_name -e wps.model_number \
    -e wps.device_name -e wps.serial_number -e wps.os_version | sort -u > "$wd/wps.tsv"
  {
    ts -Y "$afilt" -T fields -E occurrence=f -e wlan.sa -e wlan.bssid
    ts -Y "eapol && $(bssid_filter)" -T fields -E occurrence=f -e wlan.sa -e wlan.da -e wlan.bssid \
      | awk -v aps="${ALL_BSSIDS[*]}" 'BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
          {sa=tolower($1);sta=(sa in AP)?$2:$1;if(sta!="")print sta"\t"$3}'
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" -T fields -E occurrence=f -e wlan.sa -e wlan.bssid
    ts -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" -T fields -E occurrence=f -e wlan.da -e wlan.bssid
  } | awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" '
      BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
      {c=tolower($1);b=tolower($2);if(c==""||b==""||c in AP||tolower(substr(c,2,1))~/[13579bdf]/)next;print c,b}' \
    | sort -u > "$wd/clients.tsv"
  ts -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' -T fields -e wlan.ta -e wlan.ra | sort -u > "$wd/backhaul.tsv"
  # One decrypt pass for every L3 layer (see _report_map_python for the rationale):
  # fields 1 proto 2 ip.src 3 ip.dst 4 ipv6.src 5 ipv6.dst 6-10 dhcp 11 dhcp.router
  #        12-13 arp 14 icmpv6.linkaddr 15 nbns.name 16 dns.resp.name
  tsd -Y 'ip || ipv6 || arp' -T fields \
      -e _ws.col.protocol -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
      -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.hostname -e dhcp.option.vendor_class_id -e dhcp.option.router \
      -e arp.src.proto_ipv4 -e arp.src.hw_mac -e icmpv6.opt.linkaddr \
      -e nbns.name -e dns.resp.name > "$wd/_l3.raw"
  awk -F'\t' -v OFS='\t' 'tolower($1)~/dhcp|bootp/{print $6,$7,$8,$9,$10}' "$wd/_l3.raw" | sort -u > "$wd/dhcp.tsv"
  awk -F'\t'             '$11!=""{print $11}'                              "$wd/_l3.raw" | sort -u | grep -v '^$' | head -1 > "$wd/gw.txt"
  awk -F'\t' -v OFS='\t' 'tolower($1)~/arp/{print $12,$13}'                "$wd/_l3.raw" | sort -u > "$wd/arp.tsv"
  awk -F'\t' -v OFS='\t' '$14!=""{print $14,$4}'                          "$wd/_l3.raw" | sort -u > "$wd/nd.tsv"
  awk -F'\t' -v OFS='\t' 'tolower($1)~/mdns|nbns/{print $2,$15,$16}'       "$wd/_l3.raw" | sort -u > "$wd/names.tsv"
  awk -F'\t' -v OFS='\t' '{if($2!="")print $2,$1; if($4!="")print $4,$1}'  "$wd/_l3.raw" | sort -u > "$wd/proto.tsv"
  awk -F'\t' -v OFS='\t' '{if($2!="")print $2,$3; if($4!="")print $4,$5}'  "$wd/_l3.raw" | sort -u > "$wd/conv.tsv"
  rm -f "$wd/_l3.raw"

  awk -F'\t' -v title="$title" -v summaryfile="$wd/summary.txt" \
    -v beaconfile="$wd/beacons.tsv" -v wpsfile="$wd/wps.tsv" -v clientfile="$wd/clients.tsv" \
    -v bhfile="$wd/backhaul.tsv" -v dhcpfile="$wd/dhcp.tsv" -v gwfile="$wd/gw.txt" \
    -v arpfile="$wd/arp.tsv" -v ndfile="$wd/nd.tsv" -v namefile="$wd/names.tsv" \
    -v protofile="$wd/proto.tsv" -v convfile="$wd/conv.tsv" '
  function first(v,a){split(v,a,",");return a[1]}
  function hval(c){return index("0123456789abcdef",tolower(c))-1}
  function hbyte(s){return hval(substr(s,1,1))*16+hval(substr(s,2,1))}
  function hx2(n,d){d="0123456789abcdef";return substr(d,int(n/16)+1,1) substr(d,(n%16)+1,1)}
  function unitkey(m,o,n,v){m=tolower(m);n=split(m,o,":");if(n!=6)return m;v=int(hbyte(o[6])/4)*4;return o[3]":"o[4]":"o[5]":"hx2(v)}
  function nearkey(m,o,n){m=tolower(m);n=split(m,o,":");return n==6?o[3]":"o[4]":"o[5]:m}
  function isgroup(m,o){split(tolower(m),o,":");return hbyte(o[1])%2}
  function xml(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);gsub(/"/,"\\&quot;",s);gsub(/\n/,"\\&#10;",s);return s}
  function cell(label,x,y,w,h,style,id){id="n" ++nid;cells=cells sprintf("<mxCell id=\"%s\" value=\"%s\" style=\"%s\" vertex=\"1\" parent=\"1\"><mxGeometry x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" as=\"geometry\"/></mxCell>",id,xml(label),style,x,y,w,h);return id}
  function edge(s,t,label,style,id){id="e" ++nid;cells=cells sprintf("<mxCell id=\"%s\" value=\"%s\" style=\"%s\" edge=\"1\" parent=\"1\" source=\"%s\" target=\"%s\"><mxGeometry relative=\"1\" as=\"geometry\"/></mxCell>",id,xml(label),style,s,t)}
  function bhunit(m,k){k=near2unit[nearkey(m)];if(k==""){k=unitkey(m);units[k]=1;near2unit[nearkey(m)]=k}return k}
  function unitmake(k,p,a,b){for(p in ub){split(p,a,SUBSEP);if(a[1]==k){b=a[2];if(wps[b]!="")return wps[b]}}return "AP"}
  function unitssids(k,p,a,s,nm){s="";for(p in ub){split(p,a,SUBSEP);if(a[1]==k){nm=ssid[a[2]];if(nm!=""&&!ssdone[k SUBSEP nm]++){s=s (s?"  ":"") nm}}}return s}
  function unitradios(k,p,a,b,s,av){s="";for(p in ub){split(p,a,SUBSEP);if(a[1]==k){b=a[2];av=(rn[b]?sprintf(" avg %.1f dBm",rs[b]/rn[b]):"");s=s (s?"\n":"") b "  " band[b] " ch" chan[b] av}}return s?s:"(backhaul-only radio)"}
  function anyip(m){return dhcpip[m]!=""?dhcpip[m]:(mac2ip[m]!=""?mac2ip[m]:mac2ip6[m])}
  function protos(ip,p,a,s){s="";for(p in proto){split(p,a,SUBSEP);if(a[1]==ip)s=s (s?" ":"") a[2]}return s}
  function hostlabel(m,role,ip,h,v,p){ip=anyip(m);h=dhcphost[m];if(h==""&&ip!="")h=ipname[ip];v=dhcpvc[m];p=protos(ip);return (h!=""?h:role) (ip!=""?"\n"ip:"") "\n"m (v!=""?"\n"v:"") (p!=""?"\n"p:"")}
  function drawunit(k,x,head,body,sl){if(k==root){head=(rootbasis~/^confirmed/?"GATEWAY / AP (confirmed)":"AP UNIT / ROOT CANDIDATE") "\nBasis: " rootbasis}else head="AP UNIT / PEER";sl=unitssids(k);body=head "\n" unitmake(k) (sl!=""?"\nSSIDs: "sl:"") "\n" unitradios(k);uid[k]=cell(body,x,190,275,135,k==root?APR:APS);ux[k]=x}

  FILENAME==beaconfile {b=tolower($1);if(b=="")next;units[unitkey(b)]=1;ub[unitkey(b) SUBSEP b]=1;bssid[b]=1;near2unit[nearkey(b)]=unitkey(b);f=$4+0;band[b]=(f>=5925?"6G":(f>=5150?"5G":(f>0?"2.4G":"?")));c=(f>5000?$3:$2);if(c==""||c==0)c=(band[b]=="6G"?int((f-5950)/5):(band[b]=="5G"?int((f-5000)/5):(f==2484?14:int((f-2407)/5))));chan[b]=c;if($5!=""&&$5!="<MISSING>")ssid[b]=$5;if($6!=""){rs[b]+=$6;rn[b]++};next}
  FILENAME==wpsfile {b=tolower($1);m=$2 " " $3;if(m!=" ")wps[b]=m;next}
  FILENAME==clientfile {s=tolower($1);b=tolower($2);if(s!=""&&b!="")cli[s SUBSEP b]=1;next}
  FILENAME==bhfile {ta=tolower($1);ra=tolower($2);if(ta==""||ra==""||isgroup(ta)||isgroup(ra))next;ka=bhunit(ta);kb=bhunit(ra);bhradio[ta]=bhradio[ra]=1;if(ka!=kb){ek=(ka<kb?ka SUBSEP kb:kb SUBSEP ka);if(!bhedge[ek]++){deg[ka]++;deg[kb]++;nbh++}}next}
  FILENAME==dhcpfile {m=tolower(first($1));if(m=="")next;ip=first($3);if(ip==""||ip=="0.0.0.0")ip=first($2);if(ip!=""&&ip!="0.0.0.0")dhcpip[m]=ip;if($4!="")dhcphost[m]=first($4);if($5!="")dhcpvc[m]=first($5);allmac[m]=1;next}
  FILENAME==gwfile {if($1!="")gwip=first($1);next}
  FILENAME==arpfile {ip=first($1);m=tolower(first($2));if(ip!=""&&m!=""){ip2mac[ip]=m;mac2ip[m]=ip;allmac[m]=1};next}
  FILENAME==ndfile {m=tolower(first($1));ip=first($2);if(m!=""&&ip!=""){mac2ip6[m]=ip;allmac[m]=1};next}
  FILENAME==namefile {ip=$1;nm=first($2);if(nm==""&&$3!="")nm=first($3);sub(/<.*/,"",nm);sub(/\.local$/,"",nm);if(ip!=""&&nm!=""&&ipname[ip]=="")ipname[ip]=nm;next}
  FILENAME==protofile {if($1!=""&&$2!="")proto[$1 SUBSEP $2]=1;next}
  FILENAME==convfile {if($1!=""&&$2!=""&&$1!=$2)conv[$1 SUBSEP $2]=1;next}
  END{
    for(p in cli){split(p,a,SUBSEP);s=a[1];b=a[2];k=unitkey(b);units[k]=1;clunit[s]=k;clb[s]=b;clientseen[s]=1;stationcount[k]++}
    for(k in units){nunits++;if(firstunit=="")firstunit=k}
    gwmac=ip2mac[gwip]
    if(gwmac!=""&&bssid[gwmac]){root=unitkey(gwmac);rootbasis="confirmed DHCP+ARP identity"}
    else if(gwmac!=""&&near2unit[nearkey(gwmac)]!=""){root=near2unit[nearkey(gwmac)];rootbasis="gateway-correlated MAC family"}
    if(root==""&&nbh){best=-1;for(k in units)if(deg[k]>best){best=deg[k];root=k}rootbasis="inferred from WDS degree"}
    if(root==""&&nunits==1){root=firstunit;rootbasis="only observed AP unit; role unconfirmed"}
    if(root==""){best=-1;for(k in units)if(stationcount[k]>best){best=stationcount[k];root=k}rootbasis="inferred from station observations"}

    APR="rounded=1;fillColor=#dae8fc;strokeColor=#6c8ebf;whiteSpace=wrap;html=1;fontSize=11;"
    APS="rounded=1;fillColor=#d5e8d4;strokeColor=#82b366;whiteSpace=wrap;html=1;fontSize=11;"
    CL="rounded=1;fillColor=#e1d5e7;strokeColor=#9673a6;whiteSpace=wrap;html=1;fontSize=10;"
    WI="rounded=1;fillColor=#ffe6cc;strokeColor=#d79b00;whiteSpace=wrap;html=1;fontSize=10;"
    GW="rounded=1;fillColor=#f5f5f5;strokeColor=#666666;whiteSpace=wrap;html=1;fontSize=10;"
    EBH="endArrow=none;dashed=1;strokeColor=#b85450;strokeWidth=2;html=1;fontSize=9;"
    ECL="endArrow=none;strokeColor=#9673a6;html=1;fontSize=9;"
    EINF="endArrow=none;dashed=1;strokeColor=#666666;html=1;fontSize=9;"
    EWI="endArrow=none;strokeColor=#d79b00;strokeWidth=2;html=1;fontSize=9;"
    L3="endArrow=none;dashed=1;strokeColor=#666666;opacity=45;html=1;"
    x=80;if(root!=""){drawunit(root,x);x+=315}for(k in units)if(k!=root){drawunit(k,x);x+=315}
    if(gwip!=""){gl="DEFAULT GATEWAY (DHCP)\n"gwip (gwmac!=""?"\n"gwmac:"\nMAC not observed");gx=((root in ux)?ux[root]+55:80);gid=cell(gl,gx,40,180,75,GW);if((root in uid)&&(rootbasis~/^confirmed/||rootbasis~/^gateway-correlated/))edge(gid,uid[root],rootbasis,EINF)}
    for(p in bhedge){split(p,a,SUBSEP);if((a[1] in uid)&&(a[2] in uid))edge(uid[a[1]],uid[a[2]],"WDS backhaul",EBH)}
    if(!nbh&&(root in uid))for(k in units)if(k!=root)edge(uid[root],uid[k],"ESS (no backhaul seen)",EINF)
    for(s in clunit){nclients++;k=clunit[s];if(!(k in ux))continue;y=390+(percol[k]++)*100;cid=cell(hostlabel(s,"(station observed)"),ux[k],y,230,86,CL);ip=anyip(s);if(ip!="")ipcell[ip]=cid;edge(uid[k],cid,band[clb[s]]" ch"chan[clb[s]],ECL)}
    wx=80;for(m in allmac){ip=anyip(m);if(ip==""||ip==gwip||m==gwmac||bssid[m]||clientseen[m]||bhradio[m])continue;wid=cell(hostlabel(m,"(wired host)"),wx,690,230,86,WI);ipcell[ip]=wid;if(root in uid)edge(uid[root],wid,"wired",EWI);wx+=250;nwired++}
    for(p in conv){split(p,a,SUBSEP);u=a[1];v=a[2];if((u in ipcell)&&(v in ipcell)){ek=(u<v?u SUBSEP v:v SUBSEP u);if(!l3seen[ek]++&&nl3<80){edge(ipcell[u],ipcell[v],"",L3);nl3++}}}
    cell(title " — evidence-qualified network map (Bash/AWK)",80,145,680,24,"text;html=1;fontStyle=1;fontSize=13;")
    cell("SOLID = observed station relation   DASHED RED = observed WDS   DASHED GRAY = inferred/correlated\nA DHCP default gateway is not automatically an ISP/WAN address. Candidate roles are not confirmed.",80,335,790,38,"text;html=1;fontSize=9;fontColor=#666666;")
    print "<mxfile><diagram name=\"" xml(title) "\"><mxGraphModel dx=\"1200\" dy=\"800\" grid=\"1\" gridSize=\"10\" guides=\"1\" page=\"1\" pageWidth=\"1600\" pageHeight=\"1100\"><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/>" cells "</root></mxGraphModel></diagram></mxfile>"
    print "units=" (nunits+0) " backhaul_links=" (nbh+0) " clients=" (nclients+0) " wired=" (nwired+0) " l3_links=" (nl3+0) > summaryfile
  }' "$wd/beacons.tsv" "$wd/wps.tsv" "$wd/clients.tsv" "$wd/backhaul.tsv" "$wd/dhcp.tsv" \
     "$wd/gw.txt" "$wd/arp.tsv" "$wd/nd.tsv" "$wd/names.tsv" "$wd/proto.tsv" "$wd/conv.tsv" > "$out"

  local summary=""; [ -s "$wd/summary.txt" ] && summary="$(cat "$wd/summary.txt")"
  rm -rf "$wd"
  if [ -s "$out" ]; then ok "wrote $(hlink "file://$PWD/$out" "$out") ($summary) — Bash/AWK only"
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
  return 0
}

# tshark_has_field ABBREV: feature-detect fields added by newer Wireshark builds.
# Reports remain useful on older 3.x/4.x releases instead of failing an entire
# extraction because wlan.analysis.tk (for example) is unavailable.
tshark_has_field() {
  if [ "$TSHARK_FIELDS_LOADED" = 0 ]; then
    TSHARK_FIELD_NAMES="$("$TSHARK" -G fields 2>/dev/null | tr -d '\r' | awk -F'\t' '$1=="F"{print $3}')"
    TSHARK_FIELDS_LOADED=1
  fi
  printf '%s\n' "$TSHARK_FIELD_NAMES" | grep -Fx "$1" >/dev/null
}

# md_table HEADER_TSV: turn tab-separated rows into a clean GitHub/Obsidian table.
# Empty cells are rendered as an em dash and an empty result is stated explicitly.
md_table() {
  local header="$1" data
  data="$(cat)"
  if ! printf '%s\n' "$data" | grep -q '[^[:space:]]'; then
    echo "_No matching evidence observed._"
    return
  fi
  printf '%s\n' "$data" | awk -F'\t' -v H="$header" '
    function clean(v){gsub(/\|/,"\\|",v);gsub(/\r|\n/," ",v);return v==""?"—":v}
    BEGIN{n=split(H,h,"\t");printf "|";for(i=1;i<=n;i++)printf " %s |",h[i];print "";
          printf "|";for(i=1;i<=n;i++)printf " --- |";print ""}
    {printf "|";for(i=1;i<=n;i++)printf " %s |",clean($i);print ""}'
}

# report_command DECRYPT PIPELINE ARGS...: print the command that produced the
# adjacent report block.  PIPELINE is documentary (e.g. "LC_ALL=C sort -u").
# Key values are redacted by default; WIFISCOPE_REPORT_SECRETS=1 opts in.
report_command() {
  local decrypt="$1" pipeline="$2" redact=1 rendered; shift 2
  [ "${WIFISCOPE_REPORT_SECRETS:-0}" = 1 ] && redact=0
  rendered="$(print_tshark_command "$decrypt" "$redact" "$@")"
  echo '<details><summary>Reproduce with TShark</summary>'
  echo
  echo '```bash'
  if [ -n "$pipeline" ]; then
    printf '%s\n' "$rendered" | sed '1s/^\$ //' | sed '$s/$/ \\/'
    printf '  | %s\n' "$pipeline"
  else
    printf '%s\n' "$rendered" | sed '1s/^\$ //'
  fi
  echo '```'
  echo '</details>'
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$PCAP" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$PCAP" | awk '{print $1}'
  else printf 'not calculated'; fi
}

crypto_verdict_text() {
  local akms priv wpa1
  akms="$(tq -Y "$(beacons_of_target)" -T fields -e wlan.rsn.akms.type | tr ',' '\n' | tr -d ' ' | sort -u | grep .)"
  priv="$(tq -Y "$(beacons_of_target)" -T fields -e wlan.fixed.capabilities.privacy | tr -d ' ' | sort -u | grep -m1 1)"
  wpa1="$(tq -Y "$(beacons_of_target) && wlan.wfa.ie.wpa.version" -T fields -e wlan.bssid | grep -m1 .)"
  printf '%s\n' "$akms" | classify_akm "$priv" "$wpa1" | cut -f2
}

# keymaterial: explicit secret-bearing view for an operator at the terminal.
# The normal report calls the same fields but redacts values unless opted in.
keymaterial() {
  section "⚠ secret key material with BSSID/station context"
  note "this command deliberately prints keys; do not paste its output into a normal report or ticket"
  if tshark_has_field wlan.analysis.tk; then
    tsd -Y 'wlan.analysis.kck || wlan.analysis.kek || wlan.analysis.tk' -T fields \
      -e frame.number -e frame.time -e wlan.bssid -e wlan.staa \
      -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
      -e wlan.analysis.pmk -e wlan.analysis.kck -e wlan.analysis.kek -e wlan.analysis.tk | sort -u
  else
    note "this tshark build does not expose wlan.analysis.tk/kck/kek; use harvest plus keyring"
  fi
  section "GTK / IGTK / BIGTK KDE context"
  tsd -Y 'eapol && wlan_rsna_eapol.keydes.msgnr==3 && (wlan.rsn.ie.gtk_kde.gtk || wlan.rsn.ie.igtk.kde.igtk || wlan.rsn.ie.bigtk_kde.bigtk)' \
    -T fields -e frame.number -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid \
    -e eapol.keydes.replay_counter -e wlan.rsn.ie.gtk_kde.key_id -e wlan.rsn.ie.gtk_kde.tx \
    -e wlan.rsn.ie.gtk_kde.gtk -e wlan.rsn.ie.igtk.kde.keyid -e wlan.rsn.ie.igtk.kde.ipn \
    -e wlan.rsn.ie.igtk.kde.igtk -e wlan.rsn.ie.bigtk_kde.key_id \
    -e wlan.rsn.ie.bigtk_kde.bipn -e wlan.rsn.ie.bigtk_kde.bigtk | sort -u
  keyring
}

# report: evidence-first autopsy that mirrors the course playbook.  It separates
# observations from inferences, emits readable tables, includes every extraction
# command beside its result, redacts secrets by default, and writes a matching
# evidence-qualified draw.io diagram.
report() {
  local out="${1:-wifiscope_${SSID:-report}.md}" mapout="${1:-wifiscope_${SSID:-report}.md}"
  mapout="${mapout%.md}.drawio"
  local generated row_limit secrets_label decrypt_label
  # Dynamically scoped so report_command -> print_tshark_command renders the key set
  # as a single "${KEYS[@]}" placeholder; unset everywhere else (interactive teaching
  # output keeps showing the real per-key records).
  local REPORT_KEYSET_TOKEN='"${KEYS[@]}"'
  generated="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date)"
  row_limit="${WIFISCOPE_REPORT_ROW_LIMIT:-500}"
  secrets_label="redacted"; [ "${WIFISCOPE_REPORT_SECRETS:-0}" = 1 ] && secrets_label="included"
  decrypt_label="no"; [ "${#DEC[@]}" -gt 0 ] && decrypt_label="yes"

  # Collect each evidence family once.  Event tables are bounded, while counts
  # and unique inventories always use the complete capture.
  local frame_stats capture_bytes capture_hash truncated_count retry_count
  frame_stats="$(tq -T fields -E occurrence=f -e frame.number -e frame.time_epoch -e frame.time -e frame.cap_len -e frame.len \
    | awk -F'\t' 'NR==1{first=$2;firstt=$3} {n++;last=$2;lastt=$3;cap+=$4;wire+=$5;if($4<$5)tr++}
        END{if(n)printf "%d\t%s\t%s\t%.3f\t%d\t%d\t%d",n,firstt,lastt,last-first,cap,wire,tr+0}')"
  capture_bytes="$(wc -c < "$PCAP" | tr -d ' ')"; capture_hash="$(sha256_file)"
  truncated_count="$(printf '%s' "$frame_stats" | awk -F'\t' '{print $7+0}')"
  retry_count="$(tq -Y "wlan.fc.retry==1 && $(bssid_filter)" -T fields -e frame.number | grep -c .)"

  local beacon_rows security_rows wps_rows oui_rows gps_rows verdict _bcn _akms _priv _wpa1
  # ONE beacon pass feeds identity, security, OUI, and the crypto verdict (was seven
  # separate re-dissections). Aggregator '|' (not the default ',') keeps a field's own
  # commas — vendor strings, SSID text — intact while multi-value fields like
  # wlan.rsn.akms.type (one entry per AKM suite) stay splittable. Taking the first
  # '|'-token per field reproduces tshark's -E occurrence=f exactly.
  #  1 time 2 bssid 3 vendor 4 ssid 5 ds-ch 6 ht-ch 7 freq 8 dbm | 9 privacy
  #  10 gcs 11 pcs 12 akms 13 mfpc 14 mfpr | 15 oui-vendor 16 wpa1.version
  _bcn="$(tq -Y "$(beacons_of_target)" -T fields -E aggregator='|' \
      -e frame.time -e wlan.bssid -e wlan.bssid_resolved -e wlan.ssid \
      -e wlan.ds.current_channel -e wlan.ht.info.primarychannel \
      -e radiotap.channel.freq -e radiotap.dbm_antsignal \
      -e wlan.fixed.capabilities.privacy -e wlan.rsn.gcs.type -e wlan.rsn.pcs.type \
      -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr \
      -e wlan.bssid.oui_resolved -e wlan.wfa.ie.wpa.version)"
  beacon_rows="$(printf '%s\n' "$_bcn" | dessid 4 \
    | awk -F'\t' -v OFS='\t' '
      {for(i=1;i<=8;i++){k=index($i,"|");if(k)$i=substr($i,1,k-1)}
       b=tolower($2); if(b=="")next; vendor[b]=$3;ssid[b]=$4;c=($5!=""?$5:$6);if(c!="")ch[b]=c;
       f=$7+0;if(f){freq[b]=f;band[b]=(f>=5925?"6 GHz":(f>=5150?"5 GHz":"2.4 GHz"))}
       if($8!=""){r=$8+0;sum[b]+=r;n[b]++;if(!(b in lo)||r<lo[b])lo[b]=r;if(!(b in hi)||r>hi[b])hi[b]=r}}
      END{for(b in ssid)printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n",b,ssid[b],vendor[b],band[b],ch[b],freq[b],
          n[b]?sprintf("%.1f",sum[b]/n[b]):"",n[b]?lo[b]:"",n[b]?hi[b]:"",n[b]+0}' | sort)"
  security_rows="$(printf '%s\n' "$_bcn" \
    | awk -F'\t' -v OFS='\t' '{for(i=1;i<=NF;i++){k=index($i,"|");if(k)$i=substr($i,1,k-1)} print $2,$9,$10,$11,$12,$13,$14}' | sort -u | grep .)"
  wps_rows="$(tq -Y "$(bssid_filter) && (wps.manufacturer || wps.model_name || wps.model_number || wps.device_name || wps.serial_number || wps.os_version)" \
      -T fields -E occurrence=f -e frame.number -e wlan.bssid -e wps.manufacturer \
      -e wps.model_name -e wps.model_number -e wps.device_name -e wps.serial_number \
      -e wps.os_version | sort -u)"
  oui_rows="$(printf '%s\n' "$_bcn" \
    | awk -F'\t' -v OFS='\t' '{for(i=1;i<=NF;i++){k=index($i,"|");if(k)$i=substr($i,1,k-1)} print $2,$3,$15}' | sort -u)"
  gps_rows=""
  if tshark_has_field ppi_gps.lat; then
    gps_rows="$(tq -Y "ppi_gps.lat && ppi_gps.lon && $(beacons_of_target)" -T fields -E occurrence=f \
      -e frame.time -e wlan.bssid -e ppi_gps.lat -e ppi_gps.lon -e ppi_gps.alt \
      -e ppi_gps.eph -e ppi.80211-common.dbm.antsignal | head -n "$row_limit")"
  fi
  # Verdict reads the SAME beacon buffer: all AKM suites (split on '|'), the privacy
  # bit, and whether a WPA1 vendor IE was present — fed straight to classify_akm.
  _akms="$(printf '%s\n' "$_bcn" | cut -f12 | tr '|' '\n' | tr -d ' ' | sort -u | grep .)"
  _priv="$(printf '%s\n' "$_bcn" | cut -f9  | tr '|' '\n' | tr -d ' ' | sort -u | grep -m1 1)"
  _wpa1="$(printf '%s\n' "$_bcn" | awk -F'\t' '$16!=""{print $2; exit}')"
  verdict="$(printf '%s\n' "$_akms" | classify_akm "$_priv" "$_wpa1" | cut -f2)"

  local eapol_rows hs_rows pmkid_rows pmkid_count m3_count _eapol
  # ONE eapol pass feeds the frame table, the per-station handshake mask, the M3
  # count, and the station-inventory EAPOL contribution (all shared the filter).
  _eapol="$(tq -Y "eapol && $(bssid_filter)" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid \
      -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
      -e wlan_rsna_eapol.keydes.key_info)"
  # Collapse identical retransmissions (same sa/da/bssid/msg/replay/key-info): a
  # merged capture records each handshake frame several times, so the raw table hid
  # the two real handshakes behind ~80 duplicate rows. Keep the first frame#/time and
  # append a "Copies" count.
  eapol_rows="$(printf '%s\n' "$_eapol" | grep . | _collapse 3,4,5,6,7,8 8 | head -n "$row_limit")"
  hs_rows="$(printf '%s\n' "$_eapol" | awk -F'\t' -v OFS='\t' '$1!=""{print $3,$4,$5,$6}' | _hs_mask)"
  pmkid_rows="$(tq -Y "$(bssid_filter) && (wlan.pmkid.akms || wlan.rsn.ie.pmkid)" \
      -T fields -E occurrence=f -e frame.number -e frame.time -e wlan.fc.type_subtype \
      -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.pmkid.akms -e wlan.rsn.ie.pmkid \
    | awk -F'\t' '$7!="" || ($8!="" && $8 !~ /^0*$/)' | sort -u)"
  pmkid_count="$(printf '%s\n' "$pmkid_rows" | grep -c '[^[:space:]]')"
  m3_count="$(printf '%s\n' "$_eapol" | awk -F'\t' '$6=="3"{n++}END{print n+0}')"

  local decrypt_count dhcp_rows arp_rows nd_rows names_rows dns_rows software_rows _l3
  decrypt_count="$(tqd -Y "$(bssid_filter) && (dhcp || arp || ip || ipv6)" -T fields -e frame.number | grep -c .)"
  # ONE decrypt pass feeds all six L3/name/service tables below. Each tqd pass
  # re-dissects (and re-decrypts) the whole capture, so collapsing six passes into
  # one — then routing rows by protocol/field in AWK — is the biggest report saving.
  # Fields: 1 frame  2 proto | dhcp 3-9 | arp 10-14 | nd 15-18 | ip.src/dst 19-20
  #         nbns 21  dns.resp 22  dns.qry 23  dns.a 24  dns.aaaa 25 | http/ssh 26-28
  _l3="$(tqd -Y "$(bssid_filter) && (dhcp || arp || (icmpv6 && icmpv6.opt.linkaddr) || nbns || mdns || llmnr || dns.qry.name || dns.resp.name || http.user_agent || http.server || ssh.protocol)" \
      -T fields -E occurrence=f \
      -e frame.number -e _ws.col.protocol \
      -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname -e dhcp.option.vendor_class_id \
      -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
      -e ipv6.src -e icmpv6.opt.linkaddr -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address \
      -e ip.src -e ip.dst -e nbns.name -e dns.resp.name -e dns.qry.name -e dns.a -e dns.aaaa \
      -e http.user_agent -e http.server -e ssh.protocol)"
  dhcp_rows="$(printf '%s\n' "$_l3"     | awk -F'\t' -v OFS='\t' 'tolower($2)~/dhcp|bootp/{print $1,$3,$4,$5,$6,$7,$8,$9}'    | sort -u | grep .)"
  arp_rows="$(printf '%s\n' "$_l3"      | awk -F'\t' -v OFS='\t' 'tolower($2)~/arp/{print $1,$10,$11,$12,$13,$14}'            | sort -u | grep .)"
  nd_rows="$(printf '%s\n' "$_l3"       | awk -F'\t' -v OFS='\t' '$16!=""{print $1,$15,$16,$17,$18}'                          | sort -u | grep .)"
  names_rows="$(printf '%s\n' "$_l3"    | awk -F'\t' -v OFS='\t' '$8!=""||tolower($2)~/nbns|mdns|llmnr/{print $1,$19,$8,$21,$22,$23}' | sort -u | grep .)"
  dns_rows="$(printf '%s\n' "$_l3"      | awk -F'\t' -v OFS='\t' '$23!=""||$22!=""{print $1,$19,$20,$23,$22,$24,$25}'         | sort -u | grep . | head -n "$row_limit")"
  software_rows="$(printf '%s\n' "$_l3" | awk -F'\t' -v OFS='\t' '$26!=""||$27!=""||$28!=""{print $1,$19,$20,$26,$27,$28}'    | sort -u | grep .)"

  local station_rows assoc_rows action_rows wds_rows probe_rows
  station_rows="$({
      tq -Y "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"" -T fields -E occurrence=f -e wlan.sa -e wlan.bssid | awk -F'\t' 'BEGIN{OFS="\t"}$1&&$2{print tolower($1),tolower($2),"association"}'
      printf '%s\n' "$_eapol" | awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" 'BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}$1!=""{sa=tolower($3);da=tolower($4);b=tolower($5);s=(sa in AP)?da:sa;if(s&&b)print s,b,"EAPOL"}'
      tq -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" -T fields -E occurrence=f -e wlan.sa -e wlan.bssid | awk -F'\t' 'BEGIN{OFS="\t"}$1&&$2{print tolower($1),tolower($2),"uplink data"}'
      tq -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" -T fields -E occurrence=f -e wlan.da -e wlan.bssid | awk -F'\t' 'BEGIN{OFS="\t"}$1&&$2{print tolower($1),tolower($2),"downlink data"}'
    } | awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" '
         BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
         {c=tolower($1); if(c=="" || c in AP || tolower(substr(c,2,1)) ~ /[13579bdf]/)next;
          k=c SUBSEP tolower($2); if(!seen[k SUBSEP $3]++){ev[k]=ev[k] (ev[k]?", ":"") $3}}
         END{for(k in ev){split(k,p,SUBSEP);print p[1],p[2],ev[k]}}' | sort)"
  # Collapse retransmissions: key on the meaningful tuple (not frame#/time/RSSI).
  assoc_rows="$(tq -Y "$(bssid_filter) && wlan.fc.type_subtype in {0,1,2,3,11}" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.fc.type_subtype -e wlan.sa -e wlan.da \
      -e wlan.bssid -e wlan.fixed.status_code -e wlan.fixed.aid | grep . | _collapse 3,4,5,6,7,8 8 | head -n "$row_limit")"
  action_rows="$(tq -Y "$(bssid_filter) && wlan.fc.type_subtype in {10,12}" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.fc.type_subtype -e wlan.sa -e wlan.da \
      -e wlan.bssid -e wlan.fixed.reason_code -e radiotap.dbm_antsignal | grep . | _collapse 3,4,5,6,7 8 | head -n "$row_limit")"
  wds_rows="$(tq -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.ta -e wlan.ra -e wlan.sa -e wlan.da | head -n "$row_limit")"
  probe_rows="$(tq -Y 'wlan.fc.type_subtype==4 && wlan.ssid!=""' -T fields -E occurrence=f \
      -e wlan.sa -e wlan.ssid | dessid 2 | sort -u)"

  local keyring_rows key_analysis_rows gtk_rows gtk_count report_secrets
  report_secrets="${WIFISCOPE_REPORT_SECRETS:-0}"
  keyring_rows=""
  if [ -s "$KEYRING" ]; then
    if [ "$report_secrets" = 1 ]; then
      keyring_rows="$(awk -F'\t' 'BEGIN{OFS="\t"}$1!=""{print $1,$2}' "$KEYRING" | sort -u)"
    else
      keyring_rows="$(awk -F'\t' 'BEGIN{OFS="\t"}$1!=""{n[$1]++}END{for(k in n)print k,n[k]" stored value(s) (redacted)"}' "$KEYRING" | sort)"
    fi
  fi
  key_analysis_rows=""
  if tshark_has_field wlan.analysis.tk; then
    key_analysis_rows="$(tqd -Y "$(bssid_filter) && (wlan.analysis.kck || wlan.analysis.kek || wlan.analysis.tk)" \
      -T fields -E occurrence=f -e frame.number -e frame.time -e wlan.bssid -e wlan.staa \
      -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
      -e wlan.analysis.pmk -e wlan.analysis.kck -e wlan.analysis.kek -e wlan.analysis.tk \
      | awk -F'\t' -v OFS='\t' -v show="$report_secrets" '{if(!show)for(i=7;i<=10;i++)if($i!="")$i="REDACTED";print}' | sort -u)"
  fi
  gtk_rows="$(tqd -Y "$(bssid_filter) && eapol && wlan_rsna_eapol.keydes.msgnr==3 && (wlan.rsn.ie.gtk_kde.gtk || wlan.rsn.ie.igtk.kde.igtk || wlan.rsn.ie.bigtk_kde.bigtk)" \
      -T fields -E occurrence=f -e frame.number -e frame.time -e wlan.sa -e wlan.da \
      -e wlan.bssid -e eapol.keydes.replay_counter -e wlan.rsn.ie.gtk_kde.key_id \
      -e wlan.rsn.ie.gtk_kde.tx -e wlan.rsn.ie.gtk_kde.gtk \
      -e wlan.rsn.ie.igtk.kde.keyid -e wlan.rsn.ie.igtk.kde.ipn -e wlan.rsn.ie.igtk.kde.igtk \
      -e wlan.rsn.ie.bigtk_kde.key_id -e wlan.rsn.ie.bigtk_kde.bipn -e wlan.rsn.ie.bigtk_kde.bigtk \
    | awk -F'\t' -v OFS='\t' -v show="$report_secrets" '{if(!show){if($9!="")$9="REDACTED";if($12!="")$12="REDACTED";if($15!="")$15="REDACTED"}print}' | sort -u)"
  gtk_count="$(printf '%s\n' "$gtk_rows" | grep -c '[^[:space:]]')"

  local gateway gateway_mac handshake_good station_count wds_count
  gateway="$(printf '%s\n' "$dhcp_rows" | awk -F'\t' '$6!=""{print $6;exit}')"
  gateway_mac="$(printf '%s\n' "$arp_rows" | awk -F'\t' -v g="$gateway" '$3==g{print $4;exit}')"
  handshake_good="$(printf '%s\n' "$hs_rows" | awk -F'\t' '$4=="YES"{n++}END{print n+0}')"
  station_count="$(printf '%s\n' "$station_rows" | grep -c '[^[:space:]]')"
  wds_count="$(printf '%s\n' "$wds_rows" | grep -c '[^[:space:]]')"

  # Dynamic scope: the report is always plain Markdown, independent of terminal UX.
  local C_RESET= C_B= C_DIM= C_RED= C_GRN= C_YEL= C_BLU= C_MAG= C_CYN= C_ORG= UX_LINKS=0
  {
    echo '---'
    printf "title: 'WiFiScope autopsy — %s'\n" "${SSID//\'/\'\'}"
    printf "ssid: '%s'\n" "${SSID//\'/\'\'}"
    printf "pcap: '%s'\n" "${PCAP//\'/\'\'}"
    printf "generated_utc: '%s'\n" "$generated"
    printf "wifiscope_version: '%s'\n" "$VERSION"
    printf "decryption_enabled: '%s'\n" "$decrypt_label"
    printf "secret_values: '%s'\n" "$secrets_label"
    printf "row_limit_per_event_table: %s\n" "$row_limit"
    printf "diagram: '%s'\n" "${mapout##*/}"
    echo 'tags: [wiboc, wifi, pcap, autopsy, wifiscope]'
    echo '---'
    echo
    echo "# WiFiScope autopsy — $SSID"
    echo
    echo "> Evidence scope: packet observations from \`$PCAP\`. **Observed** means a field/frame is present; **inferred** means a role is derived from multiple observations; **not observed** is not proof of absence."
    echo
    echo "Matching diagram: [${mapout##*/}](${mapout##*/})"
    echo
    echo '<details><summary>Paste once: table helpers + key set used by the commands below</summary>'
    echo
    echo '```bash'
    cat <<'REPORT_HELPERS'
# Align TSV when util-linux `column` is installed; otherwise preserve plain TSV.
tsv_columns() {
  if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi
}
table_rows() { tsv_columns; }
table_unique() {
  local header
  IFS= read -r header || return 0
  { printf '%s\n' "$header"; LC_ALL=C sort -u; } | tsv_columns
}
REPORT_HELPERS
    # The decrypting reproduce commands below reference the key set once, as
    # "${KEYS[@]}", instead of repeating every -o record in each block.
    if [ "${WIFISCOPE_REPORT_SECRETS:-0}" = 1 ] && [ "${#DEC[@]}" -gt 0 ]; then
      echo '# Decryption key set recovered for this capture:'
      printf 'KEYS=(\n'
      local _i=0
      while [ "$_i" -lt "${#DEC[@]}" ]; do
        printf '  %s %s\n' "${DEC[$_i]}" "$(shell_quote_human "${DEC[$((_i+1))]}")"
        _i=$((_i+2))
      done
      printf ')\n'
    else
      cat <<KEYS_TMPL
# Decryption key set — fill in from this capture's keyring file
#   ${PCAP##*/}.keys   (one  type<TAB>value  line per key), e.g.:
KEYS=(
  -o wlan.enable_decryption:TRUE
  -o 'uat:80211_keys:"wpa-pwd","<passphrase>:<SSID>"'
  # ...one  -o 'uat:80211_keys:"<type>","<value>"'  per keyring entry
)
KEYS_TMPL
    fi
    echo '```'
    echo '</details>'
    echo
    echo '## Executive summary'
    echo
    printf '| Item | Result | Confidence |\n| --- | --- | --- |\n'
    printf '| Target | %s (%d beaconing BSSID(s)) | Observed |\n' "$SSID" "${#TGT_BSSIDS[@]}"
    printf '| Security | %s | Observed RSN/privacy fields; interpretation by WiFiScope |\n' "$verdict"
    printf '| Wireless stations | %s station/BSSID observation(s) | Observed; evidence source shown below |\n' "$station_count"
    printf '| Recoverable handshakes | %s station/BSSID context(s) | M1+M2 or M2+M3 observed |\n' "$handshake_good"
    printf '| Decrypted L3 sanity | %s matching DHCP/ARP/IP/IPv6 frame(s) | %s |\n' "$decrypt_count" "$([ "$decrypt_count" -gt 0 ] && echo 'Validated' || echo 'Not validated')"
    printf '| Default gateway | %s%s | %s |\n' "${gateway:-not observed}" "${gateway_mac:+ ($gateway_mac)}" "$([ -n "$gateway" ] && echo 'DHCP observed; MAC only if ARP-correlated' || echo 'Not observed')"
    printf '| Four-address frames | %s row(s), whole capture | Observed; target ownership may require correlation |\n' "$wds_count"
    printf '| PMKID evidence | %s row(s) | Observed or not observed |\n' "$pmkid_count"
    echo
    echo '## 1. Capture overview and integrity'
    echo
    { printf '%s\t%s\t%s\t%s\n' "${PCAP##*/}" "$capture_bytes" "$capture_hash" "$frame_stats"; } \
      | md_table $'File\tFile bytes\tSHA-256\tFrames\tFirst frame time\tLast frame time\tDuration seconds\tCaptured bytes\tWire bytes\tTruncated frames'
    echo
    echo '_SHA-256 is calculated with `sha256sum` (or `shasum -a 256`); file bytes use `wc -c`._'
    report_command 0 '' -T fields -E occurrence=f -e frame.number -e frame.time_epoch -e frame.time -e frame.cap_len -e frame.len
    echo
    echo '### Protocol hierarchy before decryption'
    echo
    echo '```text'; tq -q -z io,phs; echo '```'
    report_command 0 '' -q -z io,phs

    echo; echo '## 2. Router identity, band, channel, frequency, and signal'
    echo
    printf '%s\n' "$beacon_rows" | md_table $'BSSID\tSSID\tResolved BSSID\tBand\tAdvertised channel\tCapture frequency MHz\tAvg beacon RSSI dBm\tMin RSSI\tMax RSSI\tRSSI samples'
    echo
    echo '_Advertised DS/HT channel is AP evidence. Radiotap frequency is collector metadata and can vary during channel hopping._'
    report_command 0 'table_rows  # then group by BSSID; WiFiScope calculates RSSI min/avg/max' \
      -Y "$(beacons_of_target)" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e frame.time -e wlan.bssid -e wlan.bssid_resolved -e wlan.ssid \
      -e wlan.ds.current_channel -e wlan.ht.info.primarychannel \
      -e radiotap.channel.freq -e radiotap.dbm_antsignal

    echo; echo '## 3. Encryption, ciphers, PMF, and hardware identity'
    echo
    echo "**Interpreted verdict:** $verdict"
    echo
    printf '%s\n' "$security_rows" | md_table $'BSSID\tPrivacy bit\tGroup cipher\tPairwise cipher\tAKM suites\tPMF capable\tPMF required'
    report_command 0 'table_unique' -Y "$(beacons_of_target)" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e wlan.bssid -e wlan.fixed.capabilities.privacy -e wlan.rsn.gcs.type \
      -e wlan.rsn.pcs.type -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr
    echo; echo '### WPS-advertised identity'
    printf '%s\n' "$wps_rows" | md_table $'Frame\tBSSID\tManufacturer\tModel name\tModel number\tDevice name\tSerial\tOS version'
    report_command 0 'table_unique' -Y "$(bssid_filter) && (wps.manufacturer || wps.model_name || wps.model_number || wps.device_name || wps.serial_number || wps.os_version)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e wlan.bssid \
      -e wps.manufacturer -e wps.model_name -e wps.model_number -e wps.device_name \
      -e wps.serial_number -e wps.os_version
    echo; echo '### OUI/vendor fallback'
    printf '%s\n' "$oui_rows" | md_table $'BSSID\tResolved BSSID\tOUI vendor'
    report_command 0 'table_unique' -Y "$(beacons_of_target)" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e wlan.bssid -e wlan.bssid_resolved -e wlan.bssid.oui_resolved

    echo; echo '## 4. GPS collection evidence'
    printf '%s\n' "$gps_rows" | md_table $'Time\tBSSID\tCollector latitude\tCollector longitude\tAltitude\tEstimated horizontal error\tSignal dBm'
    echo
    echo '_GPS describes the collector location, not automatically the AP location._'
    if tshark_has_field ppi_gps.lat; then
      report_command 0 "head -n $row_limit | table_rows" -Y "ppi_gps.lat && ppi_gps.lon && $(beacons_of_target)" \
        -T fields -E separator=/t -E occurrence=f -E header=y -e frame.time -e wlan.bssid \
        -e ppi_gps.lat -e ppi_gps.lon -e ppi_gps.alt -e ppi_gps.eph -e ppi.80211-common.dbm.antsignal
    fi

    echo; echo '## 5. EAPOL handshake and PMKID evidence'
    echo; echo '### EAPOL frames'
    printf '%s\n' "$eapol_rows" | md_table $'Frame\tTime\tSource\tDestination\tBSSID\tMessage\tReplay counter\tKey info\tCopies'
    echo "_Event table limited to the first $row_limit matching rows; summary below uses the complete capture._"
    report_command 0 "head -n $row_limit | table_rows" -Y "eapol && $(bssid_filter)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
      -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr \
      -e eapol.keydes.replay_counter -e wlan_rsna_eapol.keydes.key_info
    echo; echo '### Message completeness by station/BSSID'
    printf '%s\n' "$hs_rows" | md_table $'Station\tBSSID\tMessages 1–4\tPTK/offline-check context usable'
    echo; echo '### PMKID evidence'
    printf '%s\n' "$pmkid_rows" | md_table $'Frame\tTime\tSubtype\tSource\tDestination\tBSSID\tPMKID AKM\tPMKID'
    report_command 0 'table_unique' -Y "$(bssid_filter) && (wlan.pmkid.akms || wlan.rsn.ie.pmkid)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
      -e wlan.fc.type_subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.pmkid.akms -e wlan.rsn.ie.pmkid

    echo; echo '## 6. Decryption validation and key inventory'
    echo
    printf '| Check | Result |\n| --- | --- |\n| Decryption options loaded | %s |\n| Target DHCP/ARP/IP/IPv6 frames decoded | %s |\n| Secret values in this report | %s |\n' \
      "$decrypt_label" "$decrypt_count" "$secrets_label"
    report_command 1 'wc -l' -Y "$(bssid_filter) && (dhcp || arp || ip || ipv6)"
    echo; echo '### Stored keyring inventory'
    printf '%s\n' "$keyring_rows" | md_table $'Key type\tValue or count'
    echo
    echo "> [!warning] Secret output is redacted by default. Set \`WIFISCOPE_REPORT_SECRETS=1\` only for a controlled training artifact. The \`keymaterial\` command deliberately prints full values with context."
    echo; echo '### PTK components selected/derived by Wireshark'
    printf '%s\n' "$key_analysis_rows" | md_table $'Frame\tTime\tBSSID\tStation\tMessage\tReplay counter\tPMK\tKCK\tKEK\tTK'
    if tshark_has_field wlan.analysis.tk; then
      report_command 1 'table_unique' -Y "$(bssid_filter) && (wlan.analysis.kck || wlan.analysis.kek || wlan.analysis.tk)" \
        -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
        -e wlan.bssid -e wlan.staa -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
        -e wlan.analysis.pmk -e wlan.analysis.kck -e wlan.analysis.kek -e wlan.analysis.tk
    fi
    echo; echo '### GTK / IGTK / BIGTK context from decrypted M3'
    printf '%s\n' "$gtk_rows" | md_table $'Frame\tTime\tSource\tDestination\tBSSID\tReplay counter\tGTK key ID\tGTK Tx\tGTK\tIGTK ID\tIGTK IPN\tIGTK\tBIGTK ID\tBIGTK IPN\tBIGTK'
    report_command 1 'table_unique' -Y "$(bssid_filter) && eapol && wlan_rsna_eapol.keydes.msgnr==3 && (wlan.rsn.ie.gtk_kde.gtk || wlan.rsn.ie.igtk.kde.igtk || wlan.rsn.ie.bigtk_kde.bigtk)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
      -e wlan.sa -e wlan.da -e wlan.bssid -e eapol.keydes.replay_counter \
      -e wlan.rsn.ie.gtk_kde.key_id -e wlan.rsn.ie.gtk_kde.tx -e wlan.rsn.ie.gtk_kde.gtk \
      -e wlan.rsn.ie.igtk.kde.keyid -e wlan.rsn.ie.igtk.kde.ipn -e wlan.rsn.ie.igtk.kde.igtk \
      -e wlan.rsn.ie.bigtk_kde.key_id -e wlan.rsn.ie.bigtk_kde.bipn -e wlan.rsn.ie.bigtk_kde.bigtk

    echo; echo '## 7. DHCP, subnet, gateway, ARP, IPv6, and names'
    echo; echo '### DHCP fingerprint and router options'
    printf '%s\n' "$dhcp_rows" | md_table $'Frame\tClient MAC\tRequested IP\tOffered IP\tSubnet mask\tRouter\tHostname\tVendor class'
    report_command 1 'table_unique' -Y "$(bssid_filter) && dhcp" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e frame.number -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname -e dhcp.option.vendor_class_id
    echo; echo '### ARP IPv4 mapping'
    printf '%s\n' "$arp_rows" | md_table $'Frame\tOpcode\tSource IPv4\tSource MAC\tDestination IPv4\tDestination MAC'
    report_command 1 'table_unique' -Y "$(bssid_filter) && arp" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e frame.number -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac
    echo; echo '### IPv6 neighbor mapping'
    printf '%s\n' "$nd_rows" | md_table $'Frame\tIPv6 source\tLink-layer MAC\tNS target\tNA target'
    report_command 1 'table_unique' -Y "$(bssid_filter) && icmpv6 && icmpv6.opt.linkaddr" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ipv6.src \
      -e icmpv6.opt.linkaddr -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address
    echo; echo '### Hostname and service-name evidence'
    printf '%s\n' "$names_rows" | md_table $'Frame\tSource IP\tDHCP hostname\tNBNS name\tmDNS response name\tDNS/LLMNR query'
    report_command 1 'table_unique' -Y "$(bssid_filter) && (dhcp.option.hostname || nbns || mdns || llmnr)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ip.src \
      -e dhcp.option.hostname -e nbns.name -e dns.resp.name -e dns.qry.name

    echo; echo '## 8. Wireless station, management-action, and topology evidence'
    echo; echo '### Station inventory with evidence source'
    printf '%s\n' "$station_rows" | md_table $'Station\tBSSID\tEvidence source(s)'
    echo '_WiFiScope unions the four result sets below, then removes group-addressed MACs and known AP BSSIDs._'
    report_command 0 'table_unique' -Y "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e wlan.sa -e wlan.bssid
    report_command 0 'table_unique' -Y "eapol && $(bssid_filter)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e wlan.sa -e wlan.da -e wlan.bssid
    report_command 0 'table_unique' -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e wlan.sa -e wlan.bssid
    report_command 0 'table_unique' -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e wlan.da -e wlan.bssid
    echo; echo '### Association and authentication events'
    printf '%s\n' "$assoc_rows" | md_table $'Frame\tTime\tSubtype\tSource\tDestination\tBSSID\tStatus\tAID\tCopies'
    report_command 0 "head -n $row_limit | table_rows" -Y "$(bssid_filter) && wlan.fc.type_subtype in {0,1,2,3,11}" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
      -e wlan.fc.type_subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.fixed.status_code -e wlan.fixed.aid
    echo; echo '### Deauthentication and disassociation frames'
    printf '%s\n' "$action_rows" | md_table $'Frame\tTime\tSubtype\tSource\tDestination\tBSSID\tReason\tRSSI dBm\tCopies'
    echo '_These are observed on-air frames. The PCAP alone does not attribute them to an operator._'
    report_command 0 "head -n $row_limit | table_rows" -Y "$(bssid_filter) && wlan.fc.type_subtype in {10,12}" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
      -e wlan.fc.type_subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.fixed.reason_code -e radiotap.dbm_antsignal
    echo; echo '### Four-address/WDS frames (whole capture)'
    printf '%s\n' "$wds_rows" | md_table $'Frame\tTime\tTransmitter\tReceiver\tSource\tDestination'
    echo '_Four-address frames often lack a normal target BSSID. They are reported capture-wide and require MAC/timing correlation before assignment to this ESS._'
    report_command 0 "head -n $row_limit | table_rows" -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time -e wlan.ta -e wlan.ra -e wlan.sa -e wlan.da
    echo; echo '### Directed probe requests (whole capture)'
    printf '%s\n' "$probe_rows" | md_table $'Station\tSSID sought'
    report_command 0 'table_unique' -Y 'wlan.fc.type_subtype==4 && wlan.ssid!=""' \
      -T fields -E separator=/t -E occurrence=f -E header=y -e wlan.sa -e wlan.ssid

    echo; echo '## 9. Decrypted DNS and software evidence'
    echo; echo '### DNS/mDNS/LLMNR names and answers'
    printf '%s\n' "$dns_rows" | md_table $'Frame\tSource IP\tDestination IP\tQuery\tResponse name\tA\tAAAA'
    report_command 1 "sort -u | head -n $row_limit | table_rows" -Y "$(bssid_filter) && (dns.qry.name || dns.resp.name)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ip.src -e ip.dst \
      -e dns.qry.name -e dns.resp.name -e dns.a -e dns.aaaa
    echo; echo '### HTTP and SSH version strings'
    printf '%s\n' "$software_rows" | md_table $'Frame\tSource IP\tDestination IP\tHTTP User-Agent\tHTTP Server\tSSH protocol'
    report_command 1 'table_unique' -Y "$(bssid_filter) && (http.user_agent || http.server || ssh.protocol)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ip.src -e ip.dst \
      -e http.user_agent -e http.server -e ssh.protocol
    # One decrypt pass emits all four statistics tables (tshark accepts repeated
    # -z), instead of re-dissecting the whole capture four times.
    echo; echo '### Decrypted L3 statistics (protocol hierarchy, IP endpoints, TCP/UDP conversations)'
    local l3stats; l3stats="$(tqd -Y "$(bssid_filter)" -q -z io,phs -z endpoints,ip -z conv,tcp -z conv,udp)"
    if printf '%s' "$l3stats" | grep -q '[^[:space:]]'; then
      echo '```text'; printf '%s\n' "$l3stats"; echo '```'
      report_command 1 '' -Y "$(bssid_filter)" -q -z io,phs -z endpoints,ip -z conv,tcp -z conv,udp
    else
      echo '_No matching evidence observed (decryption produced no L3 traffic for this target)._'
    fi

    echo; echo '## 10. Capture-quality checks'
    printf '| Check | Count | Interpretation |\n| --- | ---: | --- |\n'
    printf '| Truncated frames | %s | cap_len < frame.len |\n' "$truncated_count"
    printf '| Target retry frames | %s | Retries may reflect RF loss/contention; not unique traffic |\n' "$retry_count"
    report_command 0 'wc -l' -Y 'frame.cap_len < frame.len'
    report_command 0 'wc -l' -Y "$(bssid_filter) && wlan.fc.retry==1"

    echo; echo '## 11. Limitations, gaps, and questions'
    echo
    [ "$decrypt_count" -gt 0 ] || echo '- **Gap:** Decryption was not validated. Do not treat absent DHCP, ARP, DNS, hostname, endpoint, or banner rows as evidence of absence.'
    [ -n "$gateway" ] || echo '- **Gap:** No DHCP default-router option was observed after decryption; no AP may be labeled a confirmed gateway.'
    [ -n "$wps_rows" ] || echo '- **Gap:** No WPS identity attributes were observed; OUI is only a vendor-family clue, not a model identification.'
    [ -n "$gps_rows" ] || echo '- **Gap:** No PPI GPS rows were observed; signal strength alone cannot establish AP coordinates.'
    [ "$pmkid_count" -gt 0 ] || echo '- **Gap:** No non-zero PMKID evidence was observed with the association-aware filter.'
    [ "$m3_count" -gt 0 ] || echo '- **Gap:** No target EAPOL M3 was observed; this capture cannot expose a GTK KDE even if M1/M2 supports an offline password check.'
    if [ "$m3_count" -gt 0 ] && [ "$gtk_count" -eq 0 ]; then echo '- **Gap:** M3 exists but no GTK KDE decoded. Verify the passphrase/PMK, nonce context, KEK derivation, and Wireshark version.'; fi
    [ "$truncated_count" -eq 0 ] || echo "- **Quality:** $truncated_count frame(s) were truncated; payload conclusions may be incomplete."
    echo '- **Question:** Was the collector channel-locked or hopping, and what dwell schedule was used?'
    echo '- **Question:** Were capture-clock synchronization, antenna, adapter, interface mode, and physical collection position documented?'
    echo '- **Question:** Which management actions were intentionally performed during the exercise, at what times, and from which transmitter MAC?'
    echo '- **Question:** Are other PCAPs/key logs needed to cover missing channels, M3/group-key rekeys, wired-only traffic, or a DHCP exchange?'
    echo
    echo '## Diagram interpretation'
    echo
    echo '- AP nodes show full BSSIDs, advertised channel/band, and beacon RSSI average where available.'
    echo '- A node says **GATEWAY / AP (confirmed)** only for an exact DHCP-router-IP → ARP-MAC → beacon-BSSID match.'
    echo '- **ROOT CANDIDATE** is explicitly inferred from a MAC-family correlation, WDS degree, or station observations.'
    echo '- The DHCP default gateway is not labeled as an Internet/ISP address.'
    echo '- Solid client edges are observed association/EAPOL/data relationships; WDS is observed capture-wide; gray gateway edges are qualified correlations.'
  } > "$out"

  ok "wrote $out (secrets: $secrets_label)"
  # Hand the map the beacon / WPS / client evidence the report already collected so
  # it doesn't re-scan the whole capture for them (saves ~6 full-capture passes).
  # Only plain L2 families are reused; the map still runs its own decrypt L3 pass.
  local _pf; _pf="$(mktemp -d)"
  # One row per beacon frame (NOT sort -u) so the map's RSSI average stays weighted.
  printf '%s\n' "$_bcn" | awk -F'\t' -v OFS='\t' '{for(i=1;i<=8;i++){k=index($i,"|");if(k)$i=substr($i,1,k-1)} if($2!="")print $2,$5,$6,$7,$4,$8}' | dessid 5 > "$_pf/beacons.tsv"
  printf '%s\n' "$wps_rows" | awk -F'\t' -v OFS='\t' 'NF>1{print $2,$3,$4,$5,$6,$7,$8}' | sort -u > "$_pf/wps.tsv"
  printf '%s\n' "$station_rows" | awk -F'\t' -v OFS='\t' '$1!=""&&$2!=""{print $1,$2}' | sort -u > "$_pf/clients.tsv"
  MAP_PREFILL="$_pf" WIFISCOPE_REPORT_CONTEXT=1 _report_map_python "$mapout" >/dev/null
  rm -rf "$_pf"
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

  # rebuild_dec must NEVER emit a key that makes tshark abort (one bad key would
  # otherwise silently disable ALL decryption). Every class tshark rejects — short/
  # long passphrase, control byte, wrong-length hex, bad type, unescaped quote — must
  # be dropped, a colon-bearing SSID must be %3a-encoded, and CRLF must be tolerated,
  # while every valid key survives. Each fixture below is a real abort class.
  local old_kr="$KEYRING" old_dec_n="${#DEC[@]}"; local -a old_dec=("${DEC[@]:-}")
  KEYRING="$(mktemp)"
  {
    printf 'wpa-pwd\t29536399:TP-LINK_C6A0\n'          # valid, one colon
    printf 'wpa-pwd\t29536399:2a:0b:8b:88:6c:18\n'     # SSID is a MAC: colons -> %3a
    printf 'wpa-pwd\t1:\033[F\n'                       # 1-char pass + ANSI escape (the shipped bug)
    printf 'wpa-pwd\t%s:net\n' "$(printf 'a%.0s' $(seq 64))"  # 64-char passphrase (>63)
    printf 'wpa-psk\tnothexZZ\n'                       # junk PMK
    printf 'tk\teb4b4390b81147bdb93f05382461926e\n'    # valid 128-bit TK
    printf 'tk\teb4b4390b81147bd\n'                    # 16 hex = wrong TK length
    printf 'wep\tabcd\n'                               # wrong WEP length
    printf 'bogus\txx\n'                               # unknown type
    printf 'wpa-psk\t9d9ec2f803cbafda75480beec881f2af537f1fadeb131f39406fa2f89d0ca2e1\r\n'  # valid PSK, CRLF
  } > "$KEYRING"
  rebuild_dec 2>/dev/null
  local dec_str="${DEC[*]}"
  rm -f "$KEYRING"; KEYRING="$old_kr"; DEC=(); [ "$old_dec_n" -gt 0 ] && DEC=("${old_dec[@]}")
  local kr_ok=1
  # the three valid keys survive (CRLF stripped)...
  for good in '"wpa-pwd","29536399:TP-LINK_C6A0"' \
              '"wpa-pwd","29536399:2a%3a0b%3a8b%3a88%3a6c%3a18"' \
              '"tk","eb4b4390b81147bdb93f05382461926e"' \
              '"wpa-psk","9d9ec2f803cbafda75480beec881f2af537f1fadeb131f39406fa2f89d0ca2e1"'; do
    [[ "$dec_str" == *"$good"* ]] || kr_ok=0
  done
  # ...and every abort class is gone (no ESC, no short/long pass, no bad hex/type/CR).
  case "$dec_str" in *$'\033'*|*'"1:'*|*aaaaaaaa*|*nothex*|*'"tk","eb4b4390b81147bd"'*|*'"wep"'*|*bogus*|*$'\r'*) kr_ok=0 ;; esac
  [ "$kr_ok" = 1 ] && ok "rebuild_dec drops every tshark-abort key class and keeps the valid ones" \
                   || { note "FAIL rebuild_dec sanitize: $dec_str"; fail=1; }

  # IEEE WPA PBKDF2 test vector. This exercises the Bash/OpenSSL derivation path
  # without a pcap and proves Python is not part of key generation.
  if command -v "$OPENSSL" >/dev/null 2>&1 && command -v "$XXD" >/dev/null 2>&1 \
     && "$OPENSSL" kdf -help >/dev/null 2>&1; then
    local old_pass="$PASS" old_ssid="$SSID"
    PASS=password; SSID=IEEE; got="$(pmk_hex)"
    PASS="$old_pass"; SSID="$old_ssid"
    exp="f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    [ "$got" = "$exp" ] && ok "OpenSSL PMK matches IEEE WPA test vector" \
                         || { note "FAIL OpenSSL PMK test vector"; fail=1; }
  else
    note "OpenSSL 3.x/xxd unavailable — PMK selftest skipped"
  fi

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
   ${C_CYN}KEYS${C_RESET}     k passphrase  h harvest  g scrapegtk  j keymaterial
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
      j|keymaterial) keymaterial | paint ;;
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
                          printf '          harvest scrapegtk keymaterial keyring addkey import delkey clearkey\n'
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
    recon|bands|crypto|hardware|clients|keys|topology|hosts|report|harvest|scrapegtk|keymaterial|keyring|pmkid|probes|handshakes|export22000|map|mapall)
      local cmd="$1"; shift
      [ -n "${1:-}" ] || die "usage: wifiscope.sh $cmd <pcap> [ssid] [passphrase]"
      load_pcap "$1"
      # mapall has no SSID/passphrase operands: arg 2 is an optional output path.
      if [ "$cmd" = mapall ]; then SSID=""; mapall "${2:-}"; return; fi
      SSID="${2:-}"
      [ -n "$SSID" ] && load_target_bssids
      if [ -n "${3:-}" ] && [ -n "$SSID" ]; then
        PASS="$3"; kr_add wpa-pwd "$PASS:$SSID"; rebuild_dec
      fi
      # bands/crypto/etc need an SSID; nudge if it's missing (recon/mapall don't).
      [ -z "$SSID" ] && [ "$cmd" != recon ] && [ "$cmd" != mapall ] && note "no SSID given — pass one as arg 2 for scoped results"
      # Paint the read-only display commands; run the rest (report/harvest/…) direct.
      # mapall takes no SSID, so its arg-2 (if any) is the output .drawio filename.
      case " recon bands crypto hardware clients keys topology hosts pmkid probes handshakes keymaterial " in
        *" $cmd "*) "$cmd" | paint ;;
        *) "$cmd" ;;
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
