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
#                  ./wifiscope.sh capture.pcapng SSID [passphrase]
#                        # FAST START: naming the target skips both startup prompts
#                        # and the whole-capture SSID enumeration behind the picker.
#   One-shot    :  ./wifiscope.sh <command> capture.pcapng [SSID] [passphrase]
#                  e.g. ./wifiscope.sh crypto capture.pcapng Ahmed_Shebakah
#
# Commands (also the menu items): recon bands crypto hardware clients keys
#                                 topology hosts fingerprint report
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
ALL_BSSIDS_LOADED=0 # ALL_BSSIDS is built on FIRST USE, not at load time (see need_all_bssids)
TSHARK_FIELD_NAMES="" # lazily cached `tshark -G fields` abbreviations
TSHARK_FIELDS_LOADED=0
TGT_AKMS=""         # cached AKM suite numbers advertised by the target (lazy, see target_akms)
TGT_AKMS_LOADED=0

# ---- tshark log noise --------------------------------------------------------
# tshark writes dissector complaints to STDERR mid-run, e.g.
#   ** (tshark:3393) [packet-ssh WARNING] ... NOT SUPPORTED OR UNKNOWN KEX DETECTED
# Those are about the CAPTURE's traffic, not about anything we did, and because our
# teaching output also goes to stderr the two interleave and shred each other
# mid-line. `--log-level critical` drops them while still surfacing real failures
# (an invalid -e field, an unreadable file), which we very much want to see.
# Gated on support so an older tshark that lacks the flag still runs.
TSHARK_QUIET=()
if "$TSHARK" --help 2>&1 | grep -q -- '--log-level'; then
  TSHARK_QUIET=(--log-level critical)
fi

# ---- concurrency budget -----------------------------------------------------
# report/fingerprint fan their INDEPENDENT tshark passes out concurrently. Each of
# those passes dissects the ENTIRE capture, so each one costs real memory - and on a
# 255 MB capture, launching all ~27 at once was enough to exhaust a VM's RAM and wedge
# the machine. Cap the number in flight instead of trusting the box to cope.
# Sized by BOTH cpus and available memory, because memory is what actually runs out:
# roughly 512 MB of headroom per concurrent tshark. WIFISCOPE_JOBS overrides.
WS_JOBS="${WIFISCOPE_JOBS:-0}"
case "$WS_JOBS" in ''|*[!0-9]*) WS_JOBS=0 ;; esac
if [ "$WS_JOBS" -le 0 ]; then
  WS_JOBS="$( { nproc; } 2>/dev/null || echo 4 )"
  case "$WS_JOBS" in ''|*[!0-9]*) WS_JOBS=4 ;; esac
  [ "$WS_JOBS" -gt 8 ] && WS_JOBS=8          # past this, tshark passes just thrash I/O
  _ws_memmb="$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
  case "$_ws_memmb" in ''|*[!0-9]*) _ws_memmb=0 ;; esac
  if [ "$_ws_memmb" -gt 0 ]; then
    _ws_memjobs=$((_ws_memmb / 512))
    [ "$_ws_memjobs" -lt 1 ] && _ws_memjobs=1
    [ "$_ws_memjobs" -lt "$WS_JOBS" ] && WS_JOBS="$_ws_memjobs"
  fi
  unset _ws_memmb _ws_memjobs
fi
[ "$WS_JOBS" -lt 1 ] && WS_JOBS=1

# ws_size_jobs: tighten WS_JOBS for the capture actually loaded. Capture size is the
# variable that turned a working fan-out into a wedged machine: ~27 passes over 4 MB
# is nothing, the same 27 over 255 MB is not. Budget roughly (capture + 256 MB) of
# resident memory per concurrent tshark, spend at most 70% of what is available, and
# never exceed the global WS_JOBS. An explicit WIFISCOPE_JOBS always wins.
ws_size_jobs() {
  [ -n "${WIFISCOPE_JOBS:-}" ] && return 0        # operator override, leave it alone
  [ -n "$PCAP" ] && [ -f "$PCAP" ] || return 0
  local mb per avail budget
  mb=$(( $(stat -c %s "$PCAP" 2>/dev/null || echo 0) / 1024 / 1024 ))
  per=$(( mb + 256 ))
  avail="$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
  case "$avail" in ''|*[!0-9]*) return 0 ;; esac
  [ "$avail" -gt 0 ] || return 0
  budget=$(( (avail * 70 / 100) / per ))
  [ "$budget" -lt 1 ] && budget=1
  if [ "$budget" -lt "$WS_JOBS" ]; then
    note "capture is ${mb} MB and ${avail} MB is free — limiting to $budget concurrent tshark pass(es) (WIFISCOPE_JOBS overrides)"
    WS_JOBS="$budget"
  fi
}

# ---- progress ---------------------------------------------------------------
# A capped fan-out over a large capture legitimately runs for minutes with nothing
# on screen, which is indistinguishable from a hang - the honest answer to "is it
# stuck?" was previously "no idea, wait and see". So render a live line while the
# passes run. Rules: STDERR only (so reports, pipes and redirects stay byte-clean),
# real terminal only, and its own colour globals - report() deliberately blanks
# C_* to keep its Markdown plain, and that must not reach into this.
PG_ON=0
[ -t 2 ] && [ -z "${WIFISCOPE_NO_PROGRESS:-}" ] && PG_ON=1
if [ "$PG_ON" = 1 ] && [ -z "${NO_COLOR:-}" ]; then
  PG_DIM=$'\e[2m'; PG_CYN=$'\e[36m'; PG_GRN=$'\e[32m'; PG_RST=$'\e[0m'
else
  PG_DIM=''; PG_CYN=''; PG_GRN=''; PG_RST=''
fi
PG_TOTAL=0        # passes expected in the current fan-out
PG_T0=0           # SECONDS at fan-out start
PG_SPIN=0
WS_LAUNCHED=0     # passes launched so far (incremented by _jobgate)

# _progress_start TOTAL LABEL: announce a fan-out and say plainly that it is
# expected to take a while, so nobody kills it thinking it wedged.
_progress_start() {
  PG_TOTAL="$1"; PG_T0=$SECONDS; PG_SPIN=0; WS_LAUNCHED=0
  [ "$PG_ON" = 1 ] || return 0
  local mb=0
  [ -n "$PCAP" ] && [ -f "$PCAP" ] &&
    mb=$(( $(stat -c %s "$PCAP" 2>/dev/null || echo 0) / 1024 / 1024 ))
  printf '%s  %s: %d tshark passes over %d MB, %d at a time — leave it running%s\n' \
    "$PG_DIM" "${2:-collecting evidence}" "$PG_TOTAL" "$mb" "$WS_JOBS" "$PG_RST" >&2
}

# _progress_tick DONE: repaint the single status line in place.
_progress_tick() {
  [ "$PG_ON" = 1 ] || return 0
  [ "$PG_TOTAL" -gt 0 ] || return 0
  local done="$1" w=26 i f bar el sp
  [ "$done" -lt 0 ] && done=0
  [ "$done" -gt "$PG_TOTAL" ] && done="$PG_TOTAL"
  f=$(( done * w / PG_TOTAL ))
  bar=''
  for ((i = 0; i < w; i++)); do
    if [ "$i" -lt "$f" ]; then bar+='━'; else bar+='·'; fi
  done
  sp='|/-\'
  PG_SPIN=$(( (PG_SPIN + 1) % 4 ))
  el=$(( SECONDS - PG_T0 ))
  printf '\r\033[2K%s  %s %s%s%s  %d/%d passes  %02d:%02d%s' \
    "$PG_DIM" "${sp:$PG_SPIN:1}" "$PG_CYN" "$bar" "$PG_DIM" \
    "$done" "$PG_TOTAL" "$((el / 60))" "$((el % 60))" "$PG_RST" >&2
}

# _progress_done MSG: clear the status line and leave one settled summary behind.
_progress_done() {
  [ "$PG_ON" = 1 ] || return 0
  local el=$(( SECONDS - PG_T0 ))
  printf '\r\033[2K%s  ✓ %s in %02d:%02d%s\n' \
    "$PG_GRN" "${1:-all passes complete}" "$((el / 60))" "$((el % 60))" "$PG_RST" >&2
}

# _progress_phase MSG: name the stage that runs after the passes, so the last
# stretch (awk assembly, diagram generation) is not silent either.
_progress_phase() {
  [ "$PG_ON" = 1 ] || return 0
  printf '%s  · %s%s\n' "$PG_DIM" "$1" "$PG_RST" >&2
}

# _jobgate: block until fewer than WS_JOBS background jobs remain, so a fan-out of
# any size runs at a bounded width. Call it immediately before each `... &` launch.
#   It polls rather than using `wait -n` so the progress line keeps animating while
#   we are at capacity - which is where nearly the whole run is spent. The 0.25s
#   granularity is irrelevant next to multi-second passes.
_jobgate() {
  local n
  while :; do
    n="$(jobs -rp | grep -c .)"
    [ "$n" -lt "$WS_JOBS" ] && break
    _progress_tick "$(( WS_LAUNCHED - n ))"
    sleep 0.25
  done
  WS_LAUNCHED=$((WS_LAUNCHED + 1))
  _progress_tick "$(( WS_LAUNCHED - 1 - n ))"
}

# _wait_progress: drain the remaining jobs, still animating, then reap them.
_wait_progress() {
  local n
  while :; do
    n="$(jobs -rp | grep -c .)"
    [ "$n" -eq 0 ] && break
    _progress_tick "$(( WS_LAUNCHED - n ))"
    sleep 0.25
  done
  wait
}

# ---- color / UX -------------------------------------------------------------
# Color + clickable links turn ON for a real terminal (or WIFISCOPE_FORCE_COLOR=1)
# and OFF when piped or NO_COLOR is set — so the report export and any pipes stay
# clean, plain text. This is why we can decorate freely without breaking parsing.
if [ -n "${WIFISCOPE_FORCE_COLOR:-}" ] || { [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; }; then
  C_RESET=$'\e[0m'
  C_B=$'\e[1m'
  C_DIM=$'\e[2m'
  C_RED=$'\e[31m'
  C_GRN=$'\e[32m'
  C_YEL=$'\e[33m'
  C_BLU=$'\e[34m'
  C_MAG=$'\e[35m'
  C_CYN=$'\e[36m'
  C_ORG=$'\e[38;5;208m'
  UX_LINKS=1
  # ---- semantic layer -------------------------------------------------------
  # One structural accent (cyan) and everything else strictly meaning-bearing, so
  # colour on screen is always information rather than decoration. Call sites use
  # THESE names; the raw C_* above are just the ink.
  C_ACCENT="$C_B$C_CYN"   # structure: headings, the target BSSID
  C_GOOD="$C_GRN"         # strong / verified / complete
  C_WARN="$C_YEL"         # caution: dated crypto, partial evidence, caveats
  C_BAD="$C_RED"          # weak / absent / exploitable
  C_SECRET="$C_MAG"       # key material, and only key material
  C_META="$C_DIM"
else
  C_RESET=
  C_B=
  C_DIM=
  C_RED=
  C_GRN=
  C_YEL=
  C_BLU=
  C_MAG=
  C_CYN=
  C_ORG=
  C_ACCENT=
  C_GOOD=
  C_WARN=
  C_BAD=
  C_SECRET=
  C_META=
  UX_LINKS=0
fi

# hlink URL TEXT: an OSC-8 clickable terminal hyperlink (plain TEXT if links off).
hlink() {
  if [ "$UX_LINKS" = 1 ]; then printf '\e]8;;%s\e\\%s\e]8;;\e\\' "$1" "$2"; else printf '%s' "$2"; fi
}

# ---- output helpers ---------------------------------------------------------
# section: a bold, colored, skimmable header (emoji lives in the passed string).
# UX_WIDTH: how wide to draw rules. A real terminal reports its size; a pipe or a
# report has no width, so fall back to a fixed 76 and keep the output reproducible.
UX_WIDTH="${COLUMNS:-0}"
if [ "$UX_WIDTH" -le 0 ] 2>/dev/null; then
  UX_WIDTH="$( { tput cols; } 2>/dev/null || echo 0 )"
fi
case "$UX_WIDTH" in ''|*[!0-9]*) UX_WIDTH=76 ;; esac
[ "$UX_WIDTH" -lt 40 ] && UX_WIDTH=76
[ "$UX_WIDTH" -gt 100 ] && UX_WIDTH=100

SECTION_W=56          # target width of a section heading incl. its trailing rule

# hr [CHAR]: a full-width rule. Kept for the menu frame; sections use a short rule.
hr() {
  local ch="${1:-─}" i out=''
  for ((i = 0; i < UX_WIDTH; i++)); do out+="$ch"; done
  printf '%s%s%s\n' "$C_DIM" "$out" "$C_RESET"
}
# section: a top-level heading with a rule under it. The rule is what separates one
# command's output from the next when you scroll back through a long session.
# section: heading with a short trailing rule sized to the text. The rule used to
#   span the whole terminal, which made it the loudest thing on screen and pushed
#   wide tables around; hugging the title keeps the separation without the shouting.
section() {
  local title="$*" pad n plain wide
  # Most headings carry an emoji, which counts as one character but occupies two
  # columns, so a naive ${#title} makes those rules overshoot. Count the non-ASCII
  # characters and charge them double.
  plain="${title//[! -~]/}"
  wide=$(( ${#title} - ${#plain} ))
  n=$(( SECTION_W - ${#plain} - wide * 2 - 4 ))   # 4 = "── " plus a trailing space
  [ "$n" -lt 6 ] && n=6                           # never degenerate to nothing
  # NOT tr: it substitutes byte-for-byte and '─' is three UTF-8 bytes, which produced
  # a run of invalid characters instead of a rule.
  pad=''
  while [ "${#pad}" -lt "$n" ]; do pad+='─'; done
  printf '\n%s── %s %s%s\n' "$C_ACCENT" "$title" "$pad" "$C_RESET"
}
# subsection: a lighter heading for a group inside a section.
subsection() { printf '\n%s  %s%s\n' "$C_B" "$*" "$C_RESET"; }
# kv LABEL VALUE: an aligned "label : value" line for single facts, so a screen of
# verdicts lines up instead of drifting with each label's length. Goes to STDOUT —
# these are results, not status, and belong in a piped/exported capture of the run.
kv() { printf '   %s%-14s%s %s\n' "$C_META" "$1" "$C_RESET" "$2"; }
# note/ok/die: status lines to stderr, so they never pollute piped data or reports.
# note = neutral progress/metadata. warn = something the reader must weigh. Keeping
# those apart is the whole point of a semantic palette: amber that fires on "indexing
# capture..." teaches you to ignore amber.
note() { printf '%s  · %s%s\n' "$C_META" "$*" "$C_RESET" >&2; }
warn() { printf '%s  ! %s%s\n' "$C_WARN" "$*" "$C_RESET" >&2; }
ok() { printf '%s  ✔ %s%s\n' "$C_GOOD" "$*" "$C_RESET" >&2; }
die() {
  printf '%s✖ %s%s\n' "$C_B$C_BAD" "$*" "$C_RESET" >&2
  exit 1
}

# need: bail early with a clear message if a required program is missing.
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

# paint: colorize a DATA stream for display — MACs by role (target BSSID = bold
# cyan, other AP = blue, client = green) each linked to a vendor OUI lookup, and
# IPv4 in yellow. A no-op when color is off, so it's only ever applied to output
# we're about to show (never to data we parse). Portable regex (no {n} intervals
# for mawk). Used at the dispatch layer on read-only display commands.
paint() {
  [ -n "$C_RESET" ] || {
    cat
    return
  }
  awk -v T="${TGT_BSSIDS[*]}" -v A="${ALL_BSSIDS[*]}" -v links="$UX_LINKS" \
    -v cyn="$C_ACCENT" -v blu="$C_META" -v grn="" -v yel="$C_WARN" -v rst="$C_RESET" '
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

  # Accumulate and emit ONCE. This used to be a dozen separate printf calls, and
  # ts()/tsd() send them to stderr while section() writes to stdout - two streams
  # with different buffering, so the writes interleaved and shredded each other
  # mid-line: "$ tshark" landing above a heading, orphan " \" continuations, and a
  # heading with its first characters eaten.
  local _out='$ tshark'
  local i=0 a v q chunk
  while [ "$i" -lt "${#argv[@]}" ]; do
    a="${argv[$i]}"; i=$((i+1)); chunk=""
    if [ -n "${REPORT_KEYSET_TOKEN:-}" ] && [ "$a" = "$REPORT_KEYSET_TOKEN" ]; then
      _out+=' \'$'\n'"  $a"; continue   # the key-set placeholder, verbatim
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
    _out+=' \'$'\n'"  $chunk"
  done
  printf '%s\n' "$_out"
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
  printf '%s%s%s\n' "$C_META" "$(print_tshark_command 0 0 "$@")" "$C_RESET" >&2
  # `tr -d '\r'` strips carriage returns so sort -u/grep behave when the pcap is
  # read by a Windows tshark.exe (CRLF output). On Linux it's a harmless no-op.
  "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" "$@" | tr -d '\r'
}

# tsd: like ts() but ALSO passes the decryption keys ("${DEC[@]}").
#      Use this for anything that only exists once traffic is decrypted:
#      ARP, DHCP, mDNS, the GTK inside handshake message 3, host inventory.
#      If no key has been set it warns and just runs in the clear.
tsd() {
  if [ "${#DEC[@]}" -eq 0 ]; then
    warn "no decryption key set — run 'k' (menu) or pass a passphrase; results may be empty"
  fi
  printf '%s%s%s\n' "$C_META" "$(print_tshark_command 1 0 "$@")" "$C_RESET" >&2
  "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" "${DEC[@]}" "$@" | tr -d '\r'
}

# Quiet query helpers used by the report generator.  These deliberately do not
# emit teaching lines because the corresponding command is printed beside each
# report result by report_command().
tq()  { "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" "$@" 2>/dev/null | tr -d '\r'; }
tqd() { "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" "${DEC[@]}" "$@" 2>/dev/null | tr -d '\r'; }

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
  # Deliberately NO tshark pass here. Building ALL_BSSIDS costs a full read of the
  # capture, and only clients/keys/handshakes/map/mapall/report actually need it —
  # so it is built on first use instead (need_all_bssids). Startup is now O(1).
  ALL_BSSIDS=()
  ALL_BSSIDS_LOADED=0
  TGT_AKMS=""
  TGT_AKMS_LOADED=0
  # The keyring lives next to the pcap and persists between runs.
  KEYRING="${PCAP}.keys"
  rebuild_dec
  [ -s "$KEYRING" ] && note "loaded $(grep -c . "$KEYRING") key(s) from $KEYRING"
}

# need_all_bssids: build the every-BSSID-in-the-capture index, once, on demand.
#   WHY lazy: it is a full pass over the file. Only the commands that must tell an
#   AP apart from a station need it (clients, keys, handshakes, map, mapall, report);
#   crypto/bands/hardware/hosts/topology/probes/pmkid never touch it, and used to pay
#   for it anyway on every startup.
#   WHY the caller must be the PARENT shell: `paint` reads ALL_BSSIDS, and both sides
#   of `cmd | paint` run in subshells — a load performed inside either one is invisible
#   to the other and to the cache. So menu()/main() call this BEFORE building the pipe.
need_all_bssids() {
  [ "$ALL_BSSIDS_LOADED" = 1 ] && return 0
  [ -n "$PCAP" ] || return 0
  note "indexing capture (one pass to list all BSSIDs)..."
  mapfile -t ALL_BSSIDS < <(
    "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" -Y 'wlan.fc.type_subtype==8' -T fields -e wlan.bssid 2>/dev/null |
      tr -d '\r' | drop_group | sort -u | grep .
  )
  ALL_BSSIDS_LOADED=1
  note "capture has ${#ALL_BSSIDS[@]} beaconing BSSIDs"
}

# ssid_exists NAME: true if NAME beacons anywhere in the capture — and it STOPS
#   READING as soon as the first matching beacon is seen.
#   HOW the early exit works: `grep -m1` closes the pipe after one line, tshark takes
#   SIGPIPE and dies mid-file instead of decoding the remaining packets. `-l` makes
#   tshark line-flush so that first line (and therefore the SIGPIPE) arrives at the
#   first match rather than when a 4 KB output buffer fills. Measured on a 4 MB
#   capture: 0.687s full pass -> 0.104s. The saving grows with capture size.
ssid_exists() {
  local n
  # Stage 1: beacons — the normal case, and usually an early hit.
  n="$("$TSHARK" "${TSHARK_QUIET[@]}" -l -r "$PCAP" -Y "wlan.fc.type_subtype==8 && wlan.ssid==\"$1\"" \
    -T fields -e wlan.bssid 2>/dev/null | tr -d '\r' | grep -m1 . )"
  [ -n "$n" ] && return 0
  # Stage 2: a hidden AP beacons with a zero-length SSID, so the name only ever
  # appears in probe responses (5) and association requests (0). Without this a
  # perfectly valid hidden target would look like a typo. Also early-exit.
  n="$("$TSHARK" "${TSHARK_QUIET[@]}" -l -r "$PCAP" \
    -Y "(wlan.fc.type_subtype==5 || wlan.fc.type_subtype==0) && wlan.ssid==\"$1\"" \
    -T fields -e wlan.bssid 2>/dev/null | tr -d '\r' | grep -m1 . )"
  [ -n "$n" ]
}

# pick_ssid: list the SSIDs in the capture (with how many BSSIDs each spans) and
#            let the user choose the target. This is the "single network" scope:
#            you must see the names before you can focus on one.
# resolve_hidden BSSID: recover a hidden AP's SSID from the frames that DO carry it —
#   probe responses (subtype 5) and association requests (subtype 0) referencing that
#   BSSID. Returns the most-seen name, or empty if the SSID was never disclosed.
resolve_hidden() {
  local b="$1"
  "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" \
    -Y "wlan.bssid==$b && (wlan.fc.type_subtype==5 || wlan.fc.type_subtype==0) && wlan.ssid != \"\"" \
    -T fields -e wlan.ssid 2>/dev/null | tr -d '\r' | dessid 1 |
    grep -v '<MISSING>' | grep . | sort | uniq -c | sort -rn | sed 's/^ *[0-9]* *//' | head -1
}

pick_ssid() {
  section "networks in this capture"
  # Build a numbered list of unique, non-empty SSIDs.
  mapfile -t names < <(
    "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" -Y 'wlan.fc.type_subtype==8' -T fields -e wlan.ssid 2>/dev/null |
      tr -d '\r' | dessid 1 | sort | uniq -c | sort -rn | sed 's/^ *//' |
      grep -v '^[0-9]* *$' | grep -v '<MISSING>' # named nets; hidden ones handled below
  )
  # Hidden APs beacon with a zero-length SSID; list them too (with any recovered
  # name) so a hidden target can still be selected — it scopes by BSSID afterward.
  mapfile -t hidden < <(
    "$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" -Y 'wlan.fc.type_subtype==8 && (wlan.ssid=="" || wlan.ssid=="<MISSING>")' \
      -T fields -e wlan.bssid 2>/dev/null | tr -d '\r' | sort -u | grep .
  )
  local i=1 line b nm
  local -a hnames=()
  for line in "${names[@]}"; do
    printf '  %2d) %s\n' "$i" "$line"
    i=$((i + 1))
  done
  for b in "${hidden[@]}"; do
    nm="$(resolve_hidden "$b")"
    hnames+=("$nm")
    if [ -n "$nm" ]; then
      printf '  %2d) %s %s(hidden, %s)%s\n' "$i" "$nm" "$C_DIM" "$b" "$C_RESET"
    else printf '  %2d) %s<hidden>%s  %s\n' "$i" "$C_DIM" "$C_RESET" "$b"; fi
    i=$((i + 1))
  done
  printf 'select target SSID number (or type a name): '
  read -r choice || die "no input"
  local nn="${#names[@]}" nh="${#hidden[@]}"
  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$((nn + nh))" ]; then
    if [ "$choice" -le "$nn" ]; then
      SSID="$(printf '%s\n' "${names[$((choice - 1))]}" | sed 's/^[0-9]* *//')" # strip count
      load_target_bssids
    else
      local hb="${hidden[$((choice - nn - 1))]}"
      SSID="${hnames[$((choice - nn - 1))]:-$hb}"
      TGT_BSSIDS=("$hb") # hidden: beacons carry no name, scope by BSSID
      note "hidden network: scoping by BSSID $hb"
    fi
  else
    SSID="$choice"
    load_target_bssids
  fi
  [ -n "$SSID" ] || die "no SSID selected"
  note "target SSID: $SSID  (${#TGT_BSSIDS[@]} BSSIDs)"
}

# load_target_bssids: cache the BSSIDs that advertise the chosen SSID.
load_target_bssids() {
  # ONE pass, two answers. The BSSID list and the AKM suite list come from exactly
  # the same beacons, so fetching both here makes every later "is this SAE?" test
  # free — pmkid, export22000, set_key and handshakes all used to pay for their own
  # full pass just to ask that question.
  # drop_group: a BSSID is a real AP's unicast address by definition. Some captures
  # (replayed, malformed radiotap, or certain injection tools) report a beacon's
  # BSSID as ff:ff:ff:ff:ff:ff, and accepting that scopes every later filter to the
  # broadcast address — which matches nothing useful while looking like a success.
  local _raw
  _raw="$("$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" -Y "$(beacons_of_target)" -T fields -E aggregator=, \
    -e wlan.bssid -e wlan.rsn.akms.type 2>/dev/null | tr -d '\r')"
  mapfile -t TGT_BSSIDS < <(printf '%s\n' "$_raw" | cut -f1 | drop_group | sort -u | grep .)
  TGT_AKMS="$(printf '%s\n' "$_raw" | cut -f2 | tr ',' '\n' | tr -d ' ' | grep -E '^[0-9]+$' | sort -un)"
  TGT_AKMS_LOADED=1

  # A hidden AP's beacons carry a zero-length SSID, so the filter above matches
  # nothing and every scoped command would silently return an empty result. The
  # name still appears in probe responses (5), association (0) and reassociation (2)
  # requests — scope by the BSSIDs seen there, and take the AKMs from the same
  # frames. Costs an extra pass ONLY when stage 1 came back empty.
  if [ "${#TGT_BSSIDS[@]}" -eq 0 ] && [ -n "$SSID" ]; then
    _raw="$("$TSHARK" "${TSHARK_QUIET[@]}" -r "$PCAP" \
      -Y "(wlan.fc.type_subtype==5 || wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"" \
      -T fields -E aggregator=, -e wlan.bssid -e wlan.rsn.akms.type 2>/dev/null | tr -d '\r')"
    mapfile -t TGT_BSSIDS < <(printf '%s\n' "$_raw" | cut -f1 | drop_group | sort -u | grep .)
    TGT_AKMS="$(printf '%s\n' "$_raw" | cut -f2 | tr ',' '\n' | tr -d ' ' | grep -E '^[0-9]+$' | sort -un)"
    [ "${#TGT_BSSIDS[@]}" -gt 0 ] &&
      note "no usable beacon BSSID for \"$SSID\" (hidden AP, or beacons carry a group address) — scoped by ${#TGT_BSSIDS[@]} BSSID(s) from probe/assoc frames"
  fi
}

# set_key: ask for the WPA passphrase, store it in the keyring, and rebuild DEC.
#   The wpa-pwd entry lets tshark derive the PMK and every client PTK on its own.
#   The PMK depends on passphrase AND SSID, which is why the SSID is chosen first.
set_key() {
  [ -n "$SSID" ] || {
    note "choose an SSID first (needed to derive the key)"
    return
  }
  printf 'WPA passphrase for "%s" (blank = skip): ' "$SSID"
  read -r PASS || PASS=""
  if [ -n "$PASS" ]; then
    kr_add wpa-pwd "$PASS:$SSID"
    rebuild_dec
    note "decryption enabled (wpa-pwd added to keyring)"
    sae_passphrase_warning
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
  [ -n "$PASS" ] && [ -n "$SSID" ] || {
    note "need passphrase+SSID for PSK"
    return
  }
  local pmk
  pmk="$(pmk_hex)"
  [ -n "$pmk" ] && {
    kr_add wpa-psk "$pmk"
    note "PSK/PMK: $pmk"
  }
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
  [ -n "$g" ] || {
    note "no GTKs recoverable (need a decryptable handshake)"
    return
  }
  local gtk
  while read -r gtk; do
    [ -n "$gtk" ] || continue
    kr_add tk "$gtk"
    note "GTK -> $gtk"
  done <<<"$g"
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
  [ -n "$rows" ] || {
    note "no GTKs recoverable — add the passphrase/PMK or a TK first (k/harvest/addkey)"
    return
  }
  local sa gtk
  while IFS=$'\t' read -r sa gtk; do
    [ -n "$gtk" ] || continue
    kr_add tk "$gtk"
    note "GTK  from $sa  ->  $gtk"
  done <<<"$rows"
  rebuild_dec
  local ngtk
  ngtk="$(printf '%s\n' "$rows" | awk -F'\t' '{print $2}' | sort -u | grep -c .)"
  note "scraped $ngtk unique GTK(s); keyring now holds $(grep -c . "$KEYRING") key(s)"
}

# harvest: do all three (PSK, PTK, GTK), then reload DEC so everything after
#   this point decrypts with the full keyring.
harvest() {
  [ -n "$PASS" ] || {
    note "set a passphrase first ('k') — needed to derive PSK/PTK"
    return
  }
  section "harvesting keys for $SSID"
  derive_psk
  rebuild_dec # PSK usable now, so GTK extraction can decrypt msg3
  harvest_ptk
  harvest_gtk
  rebuild_dec
  keyring
}

# keyring: show the current key store.
keyring() {
  section "🗝️  keyring: $(hlink "file://$KEYRING" "${KEYRING:-<none>}")"
  if [ -n "$KEYRING" ] && [ -s "$KEYRING" ]; then
    local _t _v
    while IFS=$'\t' read -r _t _v; do
      [ -n "$_t" ] || continue
      printf '  %s%-8s%s %s\n' "$C_MAG" "$_t" "$C_RESET" "$_v"
      printf '           %s%s%s\n' "$C_DIM" "$(key_type_label "$_t")" "$C_RESET"
    done < "$KEYRING"
    printf '%stotal keys:%s %s\n' "$C_B" "$C_RESET" "$(grep -c . "$KEYRING")"
  else
    echo "  (empty — set a passphrase 'k' or run harvest 'h')"
  fi
}

# key_type_label TYPE: what a keyring type actually IS, in words. A column of
#   "wpa-pwd / wpa-psk / tk" tells a reader nothing about which secret they are
#   holding or what it decrypts; these labels are the difference between a key
#   inventory and a list of strings.
key_type_label() {
  case "${1%%$'\r'}" in
    wpa-pwd) printf 'WPA passphrase + SSID (tshark derives the PMK via PBKDF2 — WPA2-PSK only)' ;;
    wpa-psk) printf 'PMK / PSK, 256-bit — the pairwise master key for this SSID' ;;
    tk)      printf 'PTK-TK, the per-session pairwise temporal key (decrypts one client)' ;;
    gtk)     printf 'GTK, the group temporal key (decrypts broadcast/multicast)' ;;
    wep)     printf 'WEP key (legacy, 40/104/128-bit)' ;;
    msk)     printf 'MSK from 802.1X/EAP (Enterprise)' ;;
    *)       printf 'unrecognized key type' ;;
  esac
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
  if [ -z "$type" ] || [ -z "$val" ]; then # interactive prompt
    printf 'key type (wpa-pwd|wpa-psk|tk|wep|msk): '
    read -r type || return
    printf 'value: '
    read -r val || return
  fi
  case "$type" in
  tk) is_hex "$val" && [ "${#val}" -eq 32 ] || {
    note "tk must be 32 hex chars (128-bit)"
    return
  } ;;
  wpa-psk) is_hex "$val" && [ "${#val}" -eq 64 ] || {
    note "wpa-psk must be 64 hex chars (256-bit)"
    return
  } ;;
  wep | msk) is_hex "$val" || {
    note "$type expects hex"
    return
  } ;;
  wpa-pwd) : ;; # passphrase[:ssid], anything goes
  *)
    note "unknown key type '$type' (use wpa-pwd|wpa-psk|tk|wep|msk)"
    return
    ;;
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
  [ -z "$f" ] && {
    printf 'key file to import: '
    read -e -r f || return
  }
  [ -f "$f" ] || {
    note "no such file: $f"
    return
  }
  local added=0 type val line
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"                                                      # strip CR
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" # trim
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac # comment
    type=""
    val=""
    if [[ "$line" =~ ^\"?(wpa-pwd|wpa-psk|tk|wep|msk)\"?[[:space:],]+\"?(.+)$ ]]; then
      type="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]%\"}" # explicit type,value
    elif is_hex "$line" && [ "${#line}" -eq 32 ]; then
      type=tk
      val="$line"
    elif is_hex "$line" && [ "${#line}" -eq 64 ]; then
      type=wpa-psk
      val="$line"
    else
      note "skip (unrecognized): $line"
      continue
    fi
    kr_add "$type" "$val"
    added=$((added + 1))
  done <"$f"
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
    -e radiotap.channel.freq |
    sort -u |
    awk 'BEGIN{FS=OFS="\t"}
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
#         24  SAE-GDH                25  FT-SAE-GDH        (WPA3 R3 group-dependent hash)
#         12  802.1X Suite-B-384     13  FT-802.1X-SHA384 14-17 FILS
#         18  OWE                    19  FT-PSK-SHA384    20  PSK-SHA384
#        When no RSN AKM is present we fall back to the WPA1 vendor IE, then the
#        Privacy capability bit to tell WEP (1) from truly open (0).

# classify_akm: pure verdict engine — reads the set of AKM suite numbers (one per
#   line on stdin) plus two flags, privacy-bit-seen ($1) and wpa1-IE-seen ($2), and
#   prints "class<TAB>verdict". class ∈ strong|trans|ent|weak|open picks the colour.
#   No tshark, no globals — so the classification is unit-testable on its own.
# ---- WPA3 / RSN number -> name decoding -------------------------------------
# tshark reports AKM and cipher suites as bare selector numbers. Printing "8" or
# "9" tells you nothing; "SAE" and "GCMP-256" tell you the whole story. Both
# decoders are stdin filters (one number per line) so selftest can exercise them
# with no pcap. Unknown numbers pass through labelled rather than silently blank.
# Tables: IEEE 802.11-2020 Table 9-151 (AKM) and Table 9-149 (cipher suites),
# plus AKM 24/25 (SAE group-dependent hash) from the WPA3 R3 / 802.11-2024 update.
akm_names() {
  awk -v tbl="1:802.1X-EAP 2:PSK 3:FT-802.1X 4:FT-PSK 5:802.1X-SHA256 6:PSK-SHA256 7:TDLS-TPK 8:SAE 9:FT-SAE 10:APPeerKey 11:802.1X-SuiteB-SHA256 12:802.1X-SuiteB-192-SHA384 13:FT-802.1X-SHA384 14:FILS-SHA256 15:FILS-SHA384 16:FT-FILS-SHA256 17:FT-FILS-SHA384 18:OWE 19:FT-PSK-SHA384 20:PSK-SHA384 24:SAE-GDH 25:FT-SAE-GDH" '
    BEGIN{ n=split(tbl,a," "); for(i=1;i<=n;i++){ split(a[i],kv,":"); N[kv[1]+0]=kv[2] } }
    { gsub(/[^0-9]/,""); if($0=="") next; t=$0+0; print (t in N) ? N[t] : ("AKM-" t) }'
}

cipher_names() {
  awk -v tbl="0:use-group 1:WEP-40 2:TKIP 4:CCMP-128 5:WEP-104 6:BIP-CMAC-128 7:no-group-traffic 8:GCMP-128 9:GCMP-256 10:CCMP-256 11:BIP-GMAC-128 12:BIP-GMAC-256 13:BIP-CMAC-256" '
    BEGIN{ n=split(tbl,a," "); for(i=1;i<=n;i++){ split(a[i],kv,":"); N[kv[1]+0]=kv[2] } }
    { gsub(/[^0-9]/,""); if($0=="") next; t=$0+0; print (t in N) ? N[t] : ("cipher-" t) }'
}

# rsn_decode_row: rewrite a  BSSID / privacy / gcs / pcs / akms / mfpc / mfpr  TSV
#   in place so the cipher and AKM columns read as names. Comma-separated lists are
#   preserved element-for-element, and PMF becomes yes/no instead of 1/0 — a report
#   table full of bare selector numbers is evidence nobody can check.
rsn_decode_row() {
  awk -F'\t' -v OFS='\t' -v atbl="1:802.1X-EAP 2:PSK 3:FT-802.1X 4:FT-PSK 5:802.1X-SHA256 6:PSK-SHA256 7:TDLS-TPK 8:SAE 9:FT-SAE 10:APPeerKey 11:802.1X-SuiteB-SHA256 12:802.1X-SuiteB-192-SHA384 13:FT-802.1X-SHA384 14:FILS-SHA256 15:FILS-SHA384 16:FT-FILS-SHA256 17:FT-FILS-SHA384 18:OWE 19:FT-PSK-SHA384 20:PSK-SHA384 24:SAE-GDH 25:FT-SAE-GDH" -v ctbl="0:use-group 1:WEP-40 2:TKIP 4:CCMP-128 5:WEP-104 6:BIP-CMAC-128 7:no-group-traffic 8:GCMP-128 9:GCMP-256 10:CCMP-256 11:BIP-GMAC-128 12:BIP-GMAC-256 13:BIP-CMAC-256" '
    BEGIN{ n=split(atbl,x," "); for(i=1;i<=n;i++){ split(x[i],kv,":"); A[kv[1]+0]=kv[2] }
           n=split(ctbl,y," "); for(i=1;i<=n;i++){ split(y[i],kv,":"); C[kv[1]+0]=kv[2] } }
    function dec(v,T,pfx,   m,parts,i,o,t) {
      if (v=="") return ""
      m=split(v,parts,",")
      for(i=1;i<=m;i++){ t=parts[i]; gsub(/[^0-9]/,"",t); if(t=="") continue
        o = o (o?",":"") (((t+0) in T) ? T[t+0] : pfx t) }
      return o }
    # tshark renders a boolean field as "True"/"False", NOT as 1/0, so a test for
    # "1" alone reported every PMF-required BSS as "no" — the exact opposite of the
    # truth, and disagreeing with the verdict line printed underneath it.
    function yn(v) { if (v=="") return ""
                     return (v ~ /(^|,)[[:space:]]*([1]|[Tt][Rr][Uu][Ee])[[:space:]]*($|,)/) ? "yes" : "no" }
    { $3=dec($3,C,"cipher-"); $4=dec($4,C,"cipher-"); $5=dec($5,A,"AKM-")
      $6=yn($6); $7=yn($7); print }'
}

classify_akm() {
  awk -v priv="${1:-}" -v wpa1="${2:-}" '
    { t=$1+0
      if      (t==8||t==9||t==24||t==25)            sae=1   # 24/25 = SAE group-dependent hash (WPA3 R3)
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

# target_akms: the set of AKM suite numbers the target advertises, one per line,
#   cached for the session (one pass, reused by crypto/pmkid/set_key/export22000).
target_akms() {
  # Normally already filled in by load_target_bssids from the same beacons, so this
  # is a cache read. The pass below is only a safety net for a caller that set SSID
  # without going through load_target_bssids.
  if [ "$TGT_AKMS_LOADED" != 1 ]; then
    TGT_AKMS="$(tq -Y "$(beacons_of_target)" -T fields -e wlan.rsn.akms.type |
      tr ',' '\n' | tr -d ' ' | grep -E '^[0-9]+$' | sort -un)"
    TGT_AKMS_LOADED=1
  fi
  printf '%s\n' "$TGT_AKMS"
}

# target_is_sae / target_has_psk: which key-establishment the target actually offers.
target_is_sae()  { target_akms | grep -qxE '8|9|24|25'; }
target_has_psk() { target_akms | grep -qxE '2|6|19|20'; }

# sae_passphrase_warning: the single most expensive misunderstanding in WPA3 triage.
#   tshark's `wpa-pwd` key turns a passphrase into a PMK with PBKDF2(passphrase,SSID)
#   — that is the WPA2-PSK derivation and ONLY that. Under WPA3-SAE the PMK is an
#   output of the SAE elliptic-curve exchange; it is not a function of the passphrase
#   alone and no amount of correct password gets you the PMK. So on an SAE-only BSS
#   the tool would happily say "decryption enabled" and then decrypt nothing, which
#   reads as a broken capture rather than a protocol boundary. Say so out loud.
sae_passphrase_warning() {
  [ -n "$SSID" ] || return 0
  target_is_sae || return 0
  if target_has_psk; then
    warn "WPA2/WPA3 transition BSS: this passphrase only decrypts clients that joined with WPA2-PSK."
    warn "SAE clients need harvested key material instead — 'h' harvest, or 'a' addkey with a PTK-TK/GTK."
  else
    warn "⚠ $SSID is WPA3-SAE only: a passphrase CANNOT decrypt it."
    warn "  wpa-pwd means PBKDF2(passphrase,SSID) = the WPA2 PMK. SAE derives its PMK from the"
    warn "  elliptic-curve exchange, so the password alone is not enough — even when it is correct."
    warn "  Use 'h' harvest / 'g' scrapegtk / 'a' addkey to load a PTK-TK or GTK directly."
  fi
}

# sae_summary: the WPA3 SAE authentication exchange — invisible to EAPOL msgnr.
#   SAE runs inside 802.11 Authentication frames (algorithm 3) BEFORE the 4-way:
#     message type 1 = Commit, 2 = Confirm; one of each in BOTH directions = complete.
#   Status codes worth seeing: 0 success, 76 anti-clogging token required (the AP is
#   rate-limiting / under load), 77 unsupported finite cyclic group (client and AP
#   disagree on the ECC group — a real-world WPA3 interop failure).
sae_summary() {
  local mt="wlan.fixed.sae_message_type"
  tshark_has_field "$mt" || mt="wlan.fixed.auth_seq"
  ts -Y "wlan.fixed.auth.alg==3 && $(bssid_filter)" -T fields \
    -e wlan.sa -e wlan.da -e wlan.bssid -e "$mt" -e wlan.fixed.status_code |
    awk -F'\t' -v OFS='\t' '
      $1!="" {
        k=$1 SUBSEP $2 SUBSEP $3
        if(!(k in seen)){ seen[k]=1; ord[++m]=k }
        if($4==1) commit[k]++; else if($4==2) confirm[k]++
        if($5!="" && $5!="0") st[k]=st[k] (st[k]?",":"") $5
      }
      END{ for(i=1;i<=m;i++){ k=ord[i]; split(k,q,SUBSEP)
             print q[1],q[2],q[3],commit[k]+0,confirm[k]+0,(st[k]==""?"0 (success)":st[k]) } }' |
    sort
}

crypto() {
  section "🔐 encryption for $SSID"
  # ONE pass answers every question below. This used to issue a separate full read
  # of the capture per question (AKMs, ciphers, privacy bit, WPA1 vendor IE, mfpc,
  # mfpr, H2E, transition-disable) — eight scans of the same beacons. Optional
  # fields are appended only when this tshark knows them: naming a field tshark
  # does not have makes it reject the ENTIRE -e list and print nothing at all.
  local -a xf=()
  local has_h2e=0 has_td=0
  tshark_has_field wlan.rsnx.sae_hash_to_element && { xf+=(-e wlan.rsnx.sae_hash_to_element); has_h2e=1; }
  tshark_has_field wlan.transition_disable_bitmap && { xf+=(-e wlan.transition_disable_bitmap); has_td=1; }
  local rsn
  rsn="$(ts -Y "$(beacons_of_target)" -T fields -E aggregator=, \
    -e wlan.bssid -e wlan.rsn.gcs.type -e wlan.rsn.pcs.type -e wlan.rsn.akms.type \
    -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr \
    -e wlan.fixed.capabilities.privacy -e wlan.wfa.ie.wpa.version "${xf[@]}" | sort -u)"

  # Per-BSSID RSN detail, with the selector numbers spelled out. Group/pairwise
  # ciphers matter for WPA3: Enterprise-192 mandates GCMP-256, so a "WPA3" AP
  # advertising CCMP-128 is not running Suite-B at all.
  # Project into the column order rsn_decode_row expects (BSSID, privacy, gcs, pcs,
  # akms, mfpc, mfpr) — it decodes by POSITION, so the order is part of the contract.
  # Dedupe AFTER projecting, not before: $rsn is deduped across all ten collected
  # fields, so two beacons that differ only in a column this table does not show
  # (the WPA1 vendor IE, RSNXE, the transition-disable bitmap) both survive and then
  # render as the same row — the same BSSID printed twice for no visible reason.
  printf '%s\n' "$rsn" | awk -F'\t' -v OFS='\t' '{print $1,$7,$2,$3,$4,$5,$6}' |
    grep '[^[:space:]]' | LC_ALL=C sort -u |
    rsn_decode_row |
    tcol $'BSSID\tPrivacy\tGroup cipher\tPairwise cipher\tAKM suites\tPMF capable\tPMF required'

  # Derive every verdict input from the single pass above — no more tshark here.
  local akms priv wpa1
  akms="$(printf '%s\n' "$rsn" | cut -f4 | tr ',' '\n' | tr -d ' ' | grep -E '^[0-9]+$' | sort -un)"
  priv="$(printf '%s\n' "$rsn" | cut -f7 | tr ',' '\n' | tr -d ' ' | grep -m1 -ixE '1|true')"
  wpa1="$(printf '%s\n' "$rsn" | cut -f8 | tr -d ' ' | grep -m1 .)"
  # Seed the session-wide AKM cache so pmkid/export22000/set_key need no pass at all.
  TGT_AKMS="$akms"; TGT_AKMS_LOADED=1

  local cls txt
  IFS=$'\t' read -r cls txt < <(printf '%s\n' "$akms" | classify_akm "$priv" "$wpa1")
  local col
  case "$cls" in
  strong | ent) col="$C_GOOD" ;;      # WPA3 / Enterprise: current practice
  trans | weak) col="$C_WARN" ;;      # transition or WPA2-PSK: dated, not broken
  open) col="$C_BAD" ;;               # open / WEP / WPA1: actually unprotected
  *) col="$C_B" ;;
  esac
  printf '\n%s🔒 verdict:%s %s%s%s\n' "$C_B" "$C_RESET" "$col$C_B" "$txt" "$C_RESET"

  local akm_txt cipher_txt
  akm_txt="$(printf '%s\n' "$akms" | akm_names | paste -sd, - | sed 's/,/, /g')"
  cipher_txt="$(printf '%s\n' "$rsn" | cut -f2,3 | tr '\t,' '\n\n' | tr -d ' ' |
    grep -E '^[0-9]+$' | sort -un | cipher_names | paste -sd, - | sed 's/,/, /g')"
  kv "AKM suites" "${akm_txt:-—}"
  kv "ciphers"    "${cipher_txt:-—}"

  # PMF / 802.11w. WPA3-Personal REQUIRES management frame protection; a BSS that
  # claims SAE but leaves mfpr clear is still deauth-attackable, which is exactly
  # the misconfiguration this tool exists to surface.
  local mfpc mfpr pmf
  mfpc="$(printf '%s\n' "$rsn" | cut -f5 | tr ',' '\n' | tr -d ' ' | grep -m1 -ixE '1|true')"
  mfpr="$(printf '%s\n' "$rsn" | cut -f6 | tr ',' '\n' | tr -d ' ' | grep -m1 -ixE '1|true')"
  if [ -n "$mfpr" ];   then pmf="${C_GRN}required${C_RESET}"
  elif [ -n "$mfpc" ]; then pmf="${C_YEL}capable, not required${C_RESET}"
  else                      pmf="${C_RED}absent — deauth/disassoc spoofing works${C_RESET}"; fi
  kv "PMF (11w)" "$pmf"

  # WPA3 R3 extras: hash-to-element (closes the SAE dictionary side-channel in the
  # original hunting-and-pecking loop), and the transition-disable bitmap (the AP
  # telling clients to stop accepting the WPA2 fallback).
  if [ "$has_h2e" = 1 ]; then
    local c=9
    printf '%s\n' "$rsn" | cut -f$c | grep -qiE '^(1|true)' && kv "SAE H2E" "advertised (hash-to-element)"
  fi
  if [ "$has_td" = 1 ]; then
    local c=$((9 + has_h2e))
    printf '%s\n' "$rsn" | cut -f$c | grep -q '[^[:space:]]' &&
      kv "transition" "disable bitmap present (WPA2 fallback being withdrawn)"
  fi

  if target_is_sae && [ -z "$mfpr" ]; then
    warn "SAE advertised but PMF is not required — that combination is out of spec for WPA3-Personal."
  fi
  sae_passphrase_warning
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
  # gw_ident MUST be initialised: it is only assigned when a DHCP router option was
  # seen, and `set -u` aborts on the `[ -n "$gw_ident" ]` test below otherwise — so
  # `hardware` died outright on every capture without DHCP evidence.
  local gw gw_ident=''
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

# show_cmd DECRYPT ARGS...: print the teaching line for a tshark pass WITHOUT
#   running it. Lets fingerprint() launch its independent passes concurrently and
#   still show each command next to its own result, in a deterministic order.
show_cmd() {
  local d="$1"; shift
  printf '%s%s%s\n' "$C_META" "$(print_tshark_command "$d" 0 "$@")" "$C_RESET" >&2
}

# wifi_generation: map the capability elements in an association request to the
#   marketing generation, because "does this client do HE?" is the question people
#   actually ask. HE (802.11ax) => Wi-Fi 6 (6E when it associated on 6 GHz), VHT
#   (11ac) => Wi-Fi 5, HT (11n) => Wi-Fi 4, none => legacy 11a/b/g. Wireshark 4.2
#   exposes no EHT capability field, so Wi-Fi 7 is not distinguishable here and we
#   deliberately do not guess it.
#   Input TSV: sa, sa_resolved, ht, vht, he, freq
wifi_generation() {
  awk -F'\t' -v OFS='\t' '
    $1!="" {
      sa=$1; if(!(sa in seen)){seen[sa]=1; ord[++n]=sa}
      if($2!="") vendor[sa]=$2
      if($3!="") ht[sa]=1
      if($4!="") vht[sa]=1
      if($5!="") he[sa]=1
      if($6!="") f[sa]=$6+0
    }
    END{
      for(i=1;i<=n;i++){ sa=ord[i]; g="legacy 11a/b/g"
        if(sa in he)       g = (f[sa]>=5925) ? "Wi-Fi 6E (11ax, 6 GHz)" : "Wi-Fi 6 (11ax)"
        else if(sa in vht) g = "Wi-Fi 5 (11ac)"
        else if(sa in ht)  g = "Wi-Fi 4 (11n)"
        v = vendor[sa]
        if (v=="" || tolower(v)==tolower(sa)) v="—"    # sa_resolved echoes the MAC when unknown
        # U/L bit (bit 1 of the first octet) set = locally administered = a randomized
        # privacy MAC, not burned-in hardware. For unicast that is second hex digit
        # 2/6/a/e. This is why the vendor column is empty for most modern phones —
        # and knowing WHICH stations randomize is itself the finding, since a
        # randomized MAC cannot be tracked across sessions but a real OUI can.
        print sa, v, (tolower(substr(sa,2,1)) ~ /^[26ae]$/ ? "randomized" : "hardware"), g,
              ((sa in ht)?"yes":"—"), ((sa in vht)?"yes":"—"), ((sa in he)?"yes":"—")
      }
    }'
}

# ttl_os_hint: initial-TTL is a coarse but genuinely useful OS discriminator, and
#   it costs nothing once the traffic is decrypted. Stacks ship distinct defaults:
#   64 (Linux/Android/macOS/iOS/*BSD), 128 (Windows), 255 (network gear/printers).
#   We report the OBSERVED ttl and the nearest default above it, and label it a hint
#   — a router in the path decrements it, so this is evidence, not proof.
ttl_os_hint() {
  awk -F'\t' -v OFS='\t' '
    $1!="" && $2!="" {
      k=$1; t=$2+0
      if(!(k in seen)){seen[k]=1; ord[++n]=k}
      if(!(k in lo) || t>hi[k]) hi[k]=t
      cnt[k]++
    }
    END{
      for(i=1;i<=n;i++){ k=ord[i]; t=hi[k]
        if(t<=64)       {init=64;  os="Linux / Android / macOS / iOS / BSD"}
        else if(t<=128) {init=128; os="Windows"}
        else            {init=255; os="network device / printer / embedded"}
        print k, t, init, os, cnt[k]
      }
    }'
}

# fingerprint: identify the DEVICES, not just the addresses. Two halves:
#   (1) works with no keys at all — the 802.11 capability profile a client leaks in
#       its association request (vendor OUI, Wi-Fi generation, country code);
#   (2) needs decryption — DHCP option-55 signature, TLS SNI + JA3/JA4, DNS-SD
#       service and model strings, TTL, and service banners.
#   Every pass here is independent, so they run concurrently and the command for
#   each is printed beside its own result afterwards.
fingerprint() {
  section "🔎 device fingerprinting for $SSID"
  ws_size_jobs
  local D; D="$(mktemp -d)"
  _progress_start 7 "fingerprinting"
  # shellcheck disable=SC2064
  trap "rm -rf '$D'" RETURN

  local assoc_filter="(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\""
  local -a a_args=(-Y "$assoc_filter" -T fields -E aggregator=,
    -e wlan.sa -e wlan.sa_resolved -e wlan.ht.capabilities -e wlan.vht.capabilities
    -e wlan.ext_tag.he_mac_caps -e radiotap.channel.freq)
  local -a c_args=(-Y "$assoc_filter && wlan.country_info.code" -T fields -E occurrence=f
    -e wlan.sa -e wlan.country_info.code)
  local -a d_args=(-Y 'dhcp' -T fields -E aggregator=, -E occurrence=a
    -e dhcp.hw.mac_addr -e dhcp.ip.your -e dhcp.option.hostname
    -e dhcp.option.vendor_class_id -e dhcp.option.request_list_item)
  # JA3/JA4 are not in every Wireshark build. Naming a field this tshark does not
  # have makes it reject the whole -e list and emit NOTHING, so the section would
  # look empty rather than degraded. Build the field list and its header together.
  local tls_hdr=$'Source IP\tSNI (server name)'
  local -a t_args=(-Y 'tls.handshake.type==1' -T fields -E occurrence=f
    -e ip.src -e tls.handshake.extensions_server_name)
  if tshark_has_field tls.handshake.ja3; then t_args+=(-e tls.handshake.ja3); tls_hdr+=$'\tJA3'; fi
  if tshark_has_field tls.handshake.ja4; then t_args+=(-e tls.handshake.ja4); tls_hdr+=$'\tJA4'; fi
  local -a s_args=(-Y 'dns.ptr.domain_name || dns.txt' -T fields -E aggregator=,
    -e ip.src -e dns.ptr.domain_name -e dns.txt)
  local -a l_args=(-Y 'ip' -T fields -e ip.src -e ip.ttl)
  local -a b_args=(-Y 'http.user_agent || http.server || ssh.protocol' -T fields -E occurrence=f
    -e ip.src -e http.user_agent -e http.server -e ssh.protocol)

  _jobgate
  { tq "${a_args[@]}" | wifi_generation; } > "$D/assoc" &
  _jobgate
  { tq "${c_args[@]}" | sort -u; } > "$D/country" &
  _jobgate
  { tqd "${d_args[@]}" 2>/dev/null | sort -u; } > "$D/dhcp" &
  _jobgate
  { tqd "${t_args[@]}" 2>/dev/null | sort -u; } > "$D/tls" &
  _jobgate
  { tqd "${s_args[@]}" 2>/dev/null | sort -u; } > "$D/sd" &
  _jobgate
  { tqd "${l_args[@]}" 2>/dev/null | ttl_os_hint; } > "$D/ttl" &
  _jobgate
  { tqd "${b_args[@]}" 2>/dev/null | sort -u; } > "$D/banner" &
  _wait_progress
  _progress_done "fingerprint passes complete"

  subsection "802.11 client capability profile  (no decryption needed)"
  show_cmd 0 "${a_args[@]}"
  tcol $'Station\tVendor (OUI)\tMAC type\tGeneration\tHT (11n)\tVHT (11ac)\tHE (11ax)' < "$D/assoc"

  subsection "regulatory domain advertised by clients"
  show_cmd 0 "${c_args[@]}"
  tcol $'Station\tCountry code' < "$D/country"

  # Option 55 is the ordered list of options a client asks for. That order is a
  # stable per-OS signature (the classic fingerbank/p0f DHCP fingerprint), so it
  # separates Android from iOS from Windows even when the hostname is generic.
  subsection "DHCP identity + option-55 parameter-request signature"
  show_cmd 1 "${d_args[@]}"
  tcol $'Client MAC\tAssigned IP\tHostname\tVendor class (60)\tParameter request list (55)' < "$D/dhcp"

  # SNI says which service the device phones home to; JA3/JA4 hash the TLS
  # ClientHello, which is a per-stack signature that survives an encrypted payload.
  subsection "TLS ClientHello identity (SNI + JA3/JA4)"
  show_cmd 1 "${t_args[@]}"
  tcol "$tls_hdr" < "$D/tls"

  # DNS-SD advertises what a device IS: _airplay._tcp, _googlecast._tcp,
  # _printer._tcp, and TXT records that usually carry an explicit model= string.
  subsection "DNS-SD / mDNS advertised services and model strings"
  show_cmd 1 "${s_args[@]}"
  tcol $'Source IP\tService (PTR)\tTXT record' < "$D/sd"

  subsection "OS hint from observed IP TTL"
  show_cmd 1 "${l_args[@]}"
  tcol $'Source IP\tMax TTL seen\tLikely initial TTL\tLikely stack\tPackets' < "$D/ttl"

  subsection "service banners (HTTP / SSH)"
  show_cmd 1 "${b_args[@]}"
  tcol $'Source IP\tHTTP User-Agent\tHTTP Server\tSSH protocol' < "$D/banner"
}

# pmkid: list RSN PMKID evidence.  PMKIDs are commonly carried in association RSN
#   information, so requiring EAPOL here silently misses valid client-less data.
#   Zero-valued PMKIDs are filtered out.
pmkid() {
  section "🪪 PMKIDs (offline-crackable, client-less)"
  # The client-less PMKID attack recovers a WPA2 passphrase because the PMKID is
  # HMAC over a PMK that IS PBKDF2(passphrase,SSID). Under SAE the PMK comes from
  # the ECC exchange, so an SAE PMKID is not a password oracle — it is just an
  # identifier. Flag it, or the hashcat run below is wasted effort.
  if target_is_sae && ! target_has_psk; then
    warn "target is WPA3-SAE only: any PMKID below is NOT offline-crackable (the PMK is not derived from the passphrase)"
  elif target_is_sae; then
    warn "transition-mode BSS: only PMKIDs from WPA2-PSK associations are crackable; SAE ones are not"
  fi
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
# _hc22000_build OUT: write hashcat-22000 lines to OUT and echo the method used.
#   Quiet, and deliberately incapable of aborting the caller: report() calls this, and
#   the old inline `need "$XXD"` would have called die() and killed a report that was
#   otherwise fine just because xxd was missing.
#   hcxpcapngtool handles PMKID (WPA*01) *and* EAPOL (WPA*02). Without it we can still
#   build PMKID lines by hand; EAPOL lines need the MIC/nonce packing hcxpcapngtool
#   does, so we say so rather than emitting a half-file that looks complete.
_hc22000_build() {
  local out="$1"
  : > "$out" 2>/dev/null || return 1
  local have_hcx=0
  if command -v hcxpcapngtool >/dev/null 2>&1; then
    have_hcx=1
    hcxpcapngtool -o "$out" "$PCAP" >/dev/null 2>&1
    if [ -s "$out" ]; then printf 'hcxpcapngtool (PMKID + EAPOL)'; return 0; fi
    # hcxpcapngtool declining is NOT a reason to give up. It is strict: out-of-
    # sequence timestamps, a deauth flood, or handshake messages it cannot pair all
    # make it write nothing. Observed on a real merge that holds 964 perfectly good
    # non-zero PMKIDs — it refused every one, and returning here meant the report
    # claimed "no PMKID in the capture" while sitting on 1492 PMKID rows.
    # So fall through and package the PMKIDs ourselves.
  fi
  command -v "$XXD" >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  local ehex; ehex="$(printf '%s' "$SSID" | "$XXD" -p -c 999999 | tr -d '\r\n')"
  tq -Y "(wlan.pmkid.akms || wlan.rsn.ie.pmkid) && $(bssid_filter)" -T fields \
     -e wlan.bssid -e wlan.staa -e wlan.rsn.ie.pmkid \
    | awk -F'\t' -v e="$ehex" '$3!="" && $3 !~ /^0*$/ {ap=$1;sta=$2;gsub(/:/,"",ap);gsub(/:/,"",sta);
        printf "WPA*01*%s*%s*%s*%s***\n",$3,ap,sta,e}' | LC_ALL=C sort -u > "$out"
  if [ -s "$out" ]; then
    if [ "$have_hcx" = 1 ]; then printf 'built-in PMKID packing (hcxpcapngtool declined this capture)'
    else printf 'built-in PMKID only (install hcxpcapngtool to package EAPOL/WPA*02 too)'; fi
    return 0
  fi
  rm -f "$out"; return 1
}

# hc22000_kind: label each hashcat line by what it actually is, so a reader knows
#   which are client-less (PMKID) and which came from a 4-way.
hc22000_kind() {
  awk -F'*' '/^WPA\*/{ k=($2=="01")?"PMKID (client-less)":(($2=="02")?"EAPOL 4-way":"WPA*" $2)
                       printf "%s\t%s\t%s\n", k, toupper($4), toupper($5) }'
}

export22000() {
  local out="${1:-${PCAP%.*}.hc22000}"
  # hashcat -m 22000 recovers a PASSPHRASE. That only means anything where the PMK
  # is PBKDF2(passphrase,SSID) — i.e. WPA2-PSK. On an SAE-only BSS the export may
  # still produce lines, and cracking them cannot succeed.
  if target_is_sae && ! target_has_psk; then
    warn "⚠ $SSID is WPA3-SAE only — hashcat -m 22000 cannot recover an SAE passphrase from this."
    warn "  SAE is not offline-crackable this way; capture/derive a PTK-TK or GTK instead ('h' harvest)."
  fi
  local how
  if how="$(_hc22000_build "$out")"; then
    ok "wrote $(hlink "file://$out" "$out")  ($(grep -c . "$out") line(s) via $how)"
  else
    note "nothing to export — no PMKID or EAPOL material this build can package"
    command -v hcxpcapngtool >/dev/null 2>&1 || note "  (hcxpcapngtool is not installed; it would also package EAPOL handshakes)"
  fi
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
  local hs
  hs="$(handshake_summary)"
  if [ -n "$hs" ]; then
    printf '%s\n' "$hs" | awk -F'\t' '{printf "%-18s @ %-18s  msgs:%s  crackable:%s\n",$1,$2,$3,$4}'
    printf '   rows: %s\n' "$(printf '%s\n' "$hs" | grep -c .)"
  else
    printf '  (none observed)\n'
  fi

  # WPA3: the 4-way above is only half the story. SAE authenticates first, in
  # Authentication frames, and a capture can hold a complete SAE with no EAPOL at
  # all (or EAPOL that will never be crackable because the PMK came from SAE).
  section "🔑 SAE (WPA3) authentication exchange"
  # Only look if SAE is actually possible here. SAE authenticates TO this BSS, so if
  # the target advertises no SAE AKM there can be no SAE frames for it — and the AKM
  # list is already cached from load_target_bssids, making this test free. Skipping
  # saves a full pass on every WPA2-only network. If the AKM list is empty we do not
  # know (hidden AP, no beacons captured), so we look anyway rather than assume.
  local sae=''
  if target_is_sae || [ -z "$(target_akms)" ]; then
    sae="$(sae_summary)"
  else
    printf '  %s(skipped — target advertises no SAE AKM, so no SAE frames can exist for it)%s\n' "$C_DIM" "$C_RESET"
  fi
  if [ -n "$sae" ]; then
    printf '%s\n' "$sae" |
      tcol $'Source\tDestination\tBSSID\tCommit\tConfirm\tStatus'
    note "a completed SAE needs Commit and Confirm in BOTH directions; status 76 = anti-clogging token, 77 = unsupported group"
    warn "SAE-derived PMKs are not recoverable from the passphrase — the EAPOL rows above are not crackable on an SAE-only BSS"
  elif target_is_sae; then
    printf '  (none observed)\n'
    warn "the target advertises SAE but no SAE auth frames were captured — the association happened before this capture started"
  fi
}

# delkey VALUE|all: remove key(s) from the keyring by matching value (or wipe all).
delkey() {
  local v="${1:-}"
  [ -n "$KEYRING" ] && [ -s "$KEYRING" ] || {
    note "keyring empty"
    return
  }
  [ -z "$v" ] && {
    keyring
    printf 'value to remove (or "all"): '
    read -e -r v || return
  }
  if [ "$v" = all ]; then
    : >"$KEYRING"
    rebuild_dec
    ok "cleared keyring"
    return
  fi
  grep -vF "$v" "$KEYRING" >"$KEYRING.tmp" 2>/dev/null && mv "$KEYRING.tmp" "$KEYRING"
  rebuild_dec
  ok "removed keys matching '$v' — $(grep -c . "$KEYRING" 2>/dev/null || echo 0) left"
}

# clearkey: wipe the whole keyring.
clearkey() {
  [ -n "$KEYRING" ] && : >"$KEYRING"
  rebuild_dec
  ok "keyring cleared"
}

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
  [ "$all" = 1 ] || [ -n "$SSID" ] || {
    note "select an SSID first (s), or use mapall"
    return
  }
  local out="${1:-${SSID:-network}.drawio}" wd
  wd="$(mktemp -d)"
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
    ts -Y "eapol && $(bssid_filter)" -T fields -e wlan.sa -e wlan.da -e wlan.bssid 2>/dev/null |
      awk -v aps="${ALL_BSSIDS[*]}" 'BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
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
  local GEN_PY
  read -r -d '' GEN_PY <<'PY'
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
  [ "${#ALL_BSSIDS[@]}" -gt 0 ] || {
    note "no beaconing BSSIDs in this capture"
    return
  }
  local out="${1:-network.drawio}"
  # Widen the BSSID scope to the entire capture for the duration of the draw, then
  # restore whatever single-SSID target the session had.
  local _ssid="$SSID"
  local -a _tgt=()
  [ "${#TGT_BSSIDS[@]}" -gt 0 ] && _tgt=("${TGT_BSSIDS[@]}")
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

# oui_field_name: the per-BSSID vendor field, chosen from what THIS tshark knows.
#   WHY this exists: `wlan.bssid.oui_resolved` is not a field in Wireshark 4.2
#   (only eth.*.oui_resolved is). Naming it made tshark reject the whole -e list
#   with "Some fields aren't valid" and exit WITHOUT OUTPUT — and because the
#   report's beacon pass asked for it, that pass returned nothing at all. The
#   downstream effect was silent and severe: no identity/band/channel/RSSI table,
#   no RSN table, and an AKM list that parsed as empty, so an encrypted network was
#   reported as "open (no encryption)". One invalid field name, wrong verdict.
#   Falling back to wlan.bssid_resolved keeps the column count stable (the report's
#   awk is positional) and still carries the vendor name tshark resolved.
oui_field_name() {
  if tshark_has_field wlan.bssid.oui_resolved; then printf 'wlan.bssid.oui_resolved'
  else printf 'wlan.bssid_resolved'; fi
}

# md_table HEADER_TSV: turn tab-separated rows into a clean GitHub/Obsidian table.
# Empty cells are rendered as an em dash and an empty result is stated explicitly.
# A blank line is emitted before AND after the block: Obsidian only renders a table
# that is surrounded by blank lines, so this keeps every table (and the <details>
# that follows) from collapsing into raw "|" text.
md_table() {
  local header="$1" data
  data="$(cat)"
  echo
  if ! printf '%s\n' "$data" | grep -q '[^[:space:]]'; then
    echo "_No matching evidence observed._"
    echo
    return
  fi
  printf '%s\n' "$data" | awk -F'\t' -v H="$header" '
    function clean(v){gsub(/\|/,"\\|",v);gsub(/\r|\n/," ",v);return v==""?"—":v}
    BEGIN{n=split(H,h,"\t");printf "|";for(i=1;i<=n;i++)printf " %s |",h[i];print "";
          printf "|";for(i=1;i<=n;i++)printf " --- |";print ""}
    {printf "|";for(i=1;i<=n;i++)printf " %s |",clean($i);print ""}'
  echo
}

# report_command DECRYPT PIPELINE ARGS...: print the command that produced the
# adjacent report block.  PIPELINE is documentary (e.g. "LC_ALL=C sort -u").
# Key values are redacted by default; WIFISCOPE_REPORT_SECRETS=1 opts in.
# md_details_open LABEL / md_details_close: Obsidian is stricter than GitHub about an
#   HTML block that wraps fenced code. It wants the tags on their OWN lines with a
#   blank line between the tag and the markdown inside. Written inline as
#   "<details><summary>x</summary>" with the fence butted straight against
#   "</details>", the fence leaks out of the HTML block and every following section
#   renders as one run-on blob. These helpers are the only place that shape is decided.
md_details_open() { printf '<details>\n<summary>%s</summary>\n\n' "$1"; }
md_details_close() { printf '\n</details>\n\n'; }

report_command() {
  local decrypt="$1" pipeline="$2" redact=1 rendered; shift 2
  [ "${WIFISCOPE_REPORT_SECRETS:-1}" = 1 ] && redact=0
  rendered="$(print_tshark_command "$decrypt" "$redact" "$@")"
  md_details_open 'Reproduce with TShark'
  echo '```bash'
  if [ -n "$pipeline" ]; then
    printf '%s\n' "$rendered" | sed '1s/^\$ //' | sed '$s/$/ \\/'
    printf '  | %s\n' "$pipeline"
  else
    printf '%s\n' "$rendered" | sed '1s/^\$ //'
  fi
  echo '```'
  md_details_close
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
  local out="${1:-${SSID:-report}_analysis.md}" mapout="${1:-${SSID:-report}_analysis.md}"
  mapout="${mapout%.md}.drawio"
  local generated row_limit secrets_label decrypt_label
  # Dynamically scoped so report_command -> print_tshark_command renders the key set
  # as a single "${KEYS[@]}" placeholder; unset everywhere else (interactive teaching
  # output keeps showing the real per-key records).
  local REPORT_KEYSET_TOKEN='"${KEYS[@]}"'
  generated="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date)"
  row_limit="${WIFISCOPE_REPORT_ROW_LIMIT:-500}"
  secrets_label="redacted"; [ "${WIFISCOPE_REPORT_SECRETS:-1}" = 1 ] && secrets_label="included"
  decrypt_label="no"; [ "${#DEC[@]}" -gt 0 ] && decrypt_label="yes"

  # Collect each evidence family once.  Every INDEPENDENT tshark pass is launched
  # concurrently to a temp file; on a multi-core box this turns ~20 sequential
  # full-capture scans into min(passes,cores) waves. The queries are unchanged, so
  # the assembled report is byte-identical to the sequential version — only the
  # cheap AWK/bash post-processing runs after the wait.
  local report_secrets has_gps=0 has_tk=0 D
  ws_size_jobs
  report_secrets="${WIFISCOPE_REPORT_SECRETS:-1}"
  tshark_has_field ppi_gps.lat      && has_gps=1   # warm the -G fields cache once,
  tshark_has_field wlan.analysis.tk && has_tk=1    # so the parallel jobs don't re-run it
  local sae_mt='wlan.fixed.sae_message_type'       # WPA3: absent on older tshark, so
  tshark_has_field "$sae_mt" || sae_mt='wlan.fixed.auth_seq'   # fall back to auth seq
  local oui_field; oui_field="$(oui_field_name)"    # invalid here = empty beacon pass
  local -a he_f=()                                  # HE caps: absent on older tshark
  tshark_has_field wlan.ext_tag.he_mac_caps && he_f=(-e wlan.ext_tag.he_mac_caps)
  local -a ja_f=()                                  # JA3/JA4: absent on older tshark
  local tls_hdr=$'Source IP\tSNI (server name)'
  tshark_has_field tls.handshake.ja3 && { ja_f+=(-e tls.handshake.ja3); tls_hdr+=$'\tJA3'; }
  tshark_has_field tls.handshake.ja4 && { ja_f+=(-e tls.handshake.ja4); tls_hdr+=$'\tJA4'; }
  local assoc_f="(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\""
  D="$(mktemp -d)"
  # 29 gated passes, minus the two that only run when their fields exist. A test
  # asserts this constant still matches the number of _jobgate calls in report().
  local _pg_total=29
  [ "$has_gps" = 1 ] || _pg_total=$((_pg_total - 1))
  [ "$has_tk"  = 1 ] || _pg_total=$((_pg_total - 1))
  _progress_start "$_pg_total" "collecting evidence"

  _jobgate
  { tq -T fields -E occurrence=f -e frame.number -e frame.time_epoch -e frame.time -e frame.cap_len -e frame.len \
      | awk -F'\t' 'NR==1{first=$2;firstt=$3} {n++;last=$2;lastt=$3;cap+=$4;wire+=$5;if($4<$5)tr++}
          END{if(n)printf "%d\t%s\t%s\t%.3f\t%d\t%d\t%d",n,firstt,lastt,last-first,cap,wire,tr+0}'; } > "$D/frame_stats" &
  _jobgate
  { tq -Y "wlan.fc.retry==1 && $(bssid_filter)" -T fields -e frame.number | grep -c .; } > "$D/retry" &
  _jobgate
  { tq -Y "$(beacons_of_target)" -T fields -E aggregator='|' \
      -e frame.time -e wlan.bssid -e wlan.bssid_resolved -e wlan.ssid \
      -e wlan.ds.current_channel -e wlan.ht.info.primarychannel \
      -e radiotap.channel.freq -e radiotap.dbm_antsignal \
      -e wlan.fixed.capabilities.privacy -e wlan.rsn.gcs.type -e wlan.rsn.pcs.type \
      -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr \
      -e "$oui_field" -e wlan.wfa.ie.wpa.version; } > "$D/bcn" &
  _jobgate
  { tq -Y "$(bssid_filter) && (wps.manufacturer || wps.model_name || wps.model_number || wps.device_name || wps.serial_number || wps.os_version)" \
      -T fields -E occurrence=f -e frame.number -e wlan.bssid -e wps.manufacturer \
      -e wps.model_name -e wps.model_number -e wps.device_name -e wps.serial_number \
      -e wps.os_version | sort -u; } > "$D/wps" &
  _jobgate
  [ "$has_gps" = 1 ] && { tq -Y "ppi_gps.lat && ppi_gps.lon && $(beacons_of_target)" -T fields -E occurrence=f \
      -e frame.time -e wlan.bssid -e ppi_gps.lat -e ppi_gps.lon -e ppi_gps.alt \
      -e ppi_gps.eph -e ppi.80211-common.dbm.antsignal | head -n "$row_limit"; } > "$D/gps" &
  _jobgate
  { tq -Y "eapol && $(bssid_filter)" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid \
      -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
      -e wlan_rsna_eapol.keydes.key_info; } > "$D/eapol" &
  _jobgate
  { tq -Y "$(bssid_filter) && (wlan.pmkid.akms || wlan.rsn.ie.pmkid)" \
      -T fields -E occurrence=f -e frame.number -e frame.time -e wlan.fc.type_subtype \
      -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.pmkid.akms -e wlan.rsn.ie.pmkid \
    | awk -F'\t' '$7!="" || ($8!="" && $8 !~ /^0*$/)' | sort -u; } > "$D/pmkid" &
  _jobgate
  { tqd -Y "$(bssid_filter) && (dhcp || arp || ip || ipv6)" -T fields -e frame.number | grep -c .; } > "$D/deccount" &
  _jobgate
  { tqd -Y "$(bssid_filter) && (dhcp || arp || (icmpv6 && icmpv6.opt.linkaddr) || nbns || mdns || llmnr || dns.qry.name || dns.resp.name || http.user_agent || http.server || ssh.protocol)" \
      -T fields -E occurrence=f \
      -e frame.number -e _ws.col.protocol \
      -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname -e dhcp.option.vendor_class_id \
      -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
      -e ipv6.src -e icmpv6.opt.linkaddr -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address \
      -e ip.src -e ip.dst -e nbns.name -e dns.resp.name -e dns.qry.name -e dns.a -e dns.aaaa \
      -e http.user_agent -e http.server -e ssh.protocol; } > "$D/l3" &
  _jobgate
  { tq -Y "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"" -T fields -E occurrence=f -e wlan.sa -e wlan.bssid; } > "$D/st_assoc" &
  _jobgate
  { tq -Y "wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)" -T fields -E occurrence=f -e wlan.sa -e wlan.bssid; } > "$D/st_up" &
  _jobgate
  { tq -Y "wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)" -T fields -E occurrence=f -e wlan.da -e wlan.bssid; } > "$D/st_down" &
  _jobgate
  { tq -Y "$(bssid_filter) && wlan.fc.type_subtype in {0,1,2,3,11}" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.fc.type_subtype -e wlan.sa -e wlan.da \
      -e wlan.bssid -e wlan.fixed.status_code -e wlan.fixed.aid; } > "$D/assoc" &
  _jobgate
  { tq -Y "$(bssid_filter) && wlan.fc.type_subtype in {10,12}" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.fc.type_subtype -e wlan.sa -e wlan.da \
      -e wlan.bssid -e wlan.fixed.reason_code -e radiotap.dbm_antsignal; } > "$D/action" &
  _jobgate
  { tq -Y 'wlan.fc.tods==1 && wlan.fc.fromds==1' -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.ta -e wlan.ra -e wlan.sa -e wlan.da | head -n "$row_limit"; } > "$D/wds" &
  _jobgate
  { tq -Y 'wlan.fc.type_subtype==4 && wlan.ssid!=""' -T fields -E occurrence=f \
      -e wlan.sa -e wlan.ssid | dessid 2 | sort -u; } > "$D/probe" &
  _jobgate
  [ "$has_tk" = 1 ] && { tqd -Y "$(bssid_filter) && (wlan.analysis.kck || wlan.analysis.kek || wlan.analysis.tk)" \
      -T fields -E occurrence=f -e frame.number -e frame.time -e wlan.bssid -e wlan.staa \
      -e wlan_rsna_eapol.keydes.msgnr -e eapol.keydes.replay_counter \
      -e wlan.analysis.pmk -e wlan.analysis.kck -e wlan.analysis.kek -e wlan.analysis.tk \
      | awk -F'\t' -v OFS='\t' -v show="$report_secrets" '{if(!show)for(i=7;i<=10;i++)if($i!="")$i="REDACTED";print}' | sort -u; } > "$D/keyanalysis" &
  _jobgate
  { tqd -Y "$(bssid_filter) && eapol && wlan_rsna_eapol.keydes.msgnr==3 && (wlan.rsn.ie.gtk_kde.gtk || wlan.rsn.ie.igtk.kde.igtk || wlan.rsn.ie.bigtk_kde.bigtk)" \
      -T fields -E occurrence=f -e frame.number -e frame.time -e wlan.sa -e wlan.da \
      -e wlan.bssid -e eapol.keydes.replay_counter -e wlan.rsn.ie.gtk_kde.key_id \
      -e wlan.rsn.ie.gtk_kde.tx -e wlan.rsn.ie.gtk_kde.gtk \
      -e wlan.rsn.ie.igtk.kde.keyid -e wlan.rsn.ie.igtk.kde.ipn -e wlan.rsn.ie.igtk.kde.igtk \
      -e wlan.rsn.ie.bigtk_kde.key_id -e wlan.rsn.ie.bigtk_kde.bipn -e wlan.rsn.ie.bigtk_kde.bigtk \
    | awk -F'\t' -v OFS='\t' -v show="$report_secrets" '{if(!show){if($9!="")$9="REDACTED";if($12!="")$12="REDACTED";if($15!="")$15="REDACTED"}print}' | sort -u; } > "$D/gtk" &
  _jobgate
  { tq -Y "wlan.fixed.auth.alg==3 && $(bssid_filter)" -T fields -E occurrence=f \
      -e frame.number -e frame.time -e wlan.sa -e wlan.da -e wlan.bssid \
      -e "$sae_mt" -e wlan.fixed.status_code | sort -u; } > "$D/sae" &
  _jobgate
  # Aggregate INSIDE the pass. These four passes used to write one line per PACKET
  # to a temp file and, for two of them, then slurp that file into a shell variable -
  # which on a busy 255 MB capture is hundreds of MB of text pushed through bash.
  # Folding the summarise step into the pipeline keeps every temp file proportional to
  # the number of DEVICES instead of the number of frames.
  { tq -Y "$assoc_f" -T fields -E aggregator=, -e wlan.sa -e wlan.sa_resolved \
      -e wlan.ht.capabilities -e wlan.vht.capabilities "${he_f[@]}" -e radiotap.channel.freq |
      wifi_generation; } > "$D/fpcap" &
  _jobgate
  { tq -Y "$assoc_f && wlan.country_info.code" -T fields -E occurrence=f \
      -e wlan.sa -e wlan.country_info.code | sort -u; } > "$D/fpcountry" &
  _jobgate
  { tqd -Y "$(bssid_filter) && dhcp" -T fields -E aggregator=, -E occurrence=a \
      -e dhcp.hw.mac_addr -e dhcp.ip.your -e dhcp.option.hostname \
      -e dhcp.option.vendor_class_id -e dhcp.option.request_list_item | sort -u; } > "$D/fpdhcp" &
  _jobgate
  { tqd -Y "$(bssid_filter) && tls.handshake.type==1" -T fields -E occurrence=f \
      -e ip.src -e tls.handshake.extensions_server_name "${ja_f[@]}" | sort -u; } > "$D/fptls" &
  _jobgate
  { tqd -Y "$(bssid_filter) && (dns.ptr.domain_name || dns.txt)" -T fields -E aggregator=, \
      -e ip.src -e dns.ptr.domain_name -e dns.txt | sort -u; } > "$D/fpsd" &
  _jobgate
  { tqd -Y "$(bssid_filter) && ip" -T fields -e ip.src -e ip.ttl | ttl_os_hint; } > "$D/fpttl" &
  # Frame counts per MAC inside the target BSS — "times seen" for the selector list.
  _jobgate
  { tq -Y "$(bssid_filter)" -T fields -e wlan.sa -e wlan.da |
      awk -F'\t' -v OFS='\t' '{for(i=1;i<=2;i++) if($i!="") c[tolower($i)]++}
                              END{for(m in c) print m, c[m]}'; } > "$D/macseen" &
  # Every directed probe request in the capture, with the SSID sought and a count.
  _jobgate
  # Probes aimed at THIS network only: a probe request naming our SSID, or one
  # directed at one of our BSSIDs. Unscoped, this listed every probing device in the
  # capture - 731 of them on a busy merge - which buried the section it belongs to and
  # answered a question nobody asked. The whole-capture view still exists in section 8.
  { tq -Y "wlan.fc.type_subtype==4 && (wlan.ssid==\"$SSID\" || $(bssid_filter))" \
      -T fields -e wlan.sa -e wlan.ssid | dessid 2 |
      awk -F'\t' -v OFS='\t' '$1!="" { m=tolower($1); c[m]++
                                 if($2!="" && !seen[m SUBSEP $2]++) s[m]=s[m] (s[m]?", ":"") $2 }
                              END{for(m in c) print m, c[m], s[m]}'; } > "$D/probe_all" &
  _jobgate
  { tq -q -z io,phs; } > "$D/phs_plain" &
  _jobgate
  { tqd -Y "$(bssid_filter)" -q -z io,phs -z endpoints,ip -z conv,tcp -z conv,udp; } > "$D/l3stats" &
  _wait_progress
  _progress_done "evidence collected ($_pg_total passes)"
  _progress_phase "assembling tables and diagram…"

  # ---- assemble from the completed passes (cheap AWK/bash only, no more tshark) ----
  local frame_stats capture_bytes capture_hash truncated_count retry_count phs_plain l3stats
  frame_stats="$(cat "$D/frame_stats")"
  capture_bytes="$(wc -c < "$PCAP" | tr -d ' ')"; capture_hash="$(sha256_file)"
  truncated_count="$(printf '%s' "$frame_stats" | awk -F'\t' '{print $7+0}')"
  retry_count="$(cat "$D/retry")"
  phs_plain="$(cat "$D/phs_plain")"; l3stats="$(cat "$D/l3stats")"

  local beacon_rows security_rows wps_rows oui_rows gps_rows verdict _bcn _akms _priv _wpa1
  local sae_rows fp_cap_rows fp_country_rows fp_dhcp_rows fp_tls_rows fp_sd_rows fp_ttl_rows
  sae_rows="$(cat "$D/sae" 2>/dev/null)"
  fp_cap_rows="$(cat "$D/fpcap" 2>/dev/null)"
  fp_country_rows="$(cat "$D/fpcountry" 2>/dev/null)"
  fp_dhcp_rows="$(cat "$D/fpdhcp" 2>/dev/null)"
  fp_tls_rows="$(cat "$D/fptls" 2>/dev/null)"
  fp_sd_rows="$(cat "$D/fpsd" 2>/dev/null)"
  fp_ttl_rows="$(cat "$D/fpttl" 2>/dev/null)"
  _bcn="$(cat "$D/bcn")"
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
  wps_rows="$(cat "$D/wps")"
  oui_rows="$(printf '%s\n' "$_bcn" \
    | awk -F'\t' -v OFS='\t' '{for(i=1;i<=NF;i++){k=index($i,"|");if(k)$i=substr($i,1,k-1)} print $2,$3,$15}' | sort -u)"
  gps_rows="$([ -f "$D/gps" ] && cat "$D/gps")"
  _akms="$(printf '%s\n' "$_bcn" | cut -f12 | tr '|,' '\n\n' | tr -d ' ' | grep -E '^[0-9]+$' | sort -un)"
  # tshark renders the privacy bit as "True"/"False", so the old `grep 1` never
  # matched it — a WEP network (privacy set, no RSN) was reported as "open".
  _priv="$(printf '%s\n' "$_bcn" | cut -f9  | tr '|,' '\n\n' | tr -d ' ' | sort -u | grep -m1 -ixE '1|true')"
  _wpa1="$(printf '%s\n' "$_bcn" | awk -F'\t' '$16!=""{print $2; exit}')"
  local _cls
  IFS=$'\t' read -r _cls verdict < <(printf '%s\n' "$_akms" | classify_akm "$_priv" "$_wpa1")
  # Summary facts, all derived from passes that have already completed.
  local _mfpc _mfpr pmf_label pmf_glyph sec_glyph sae_count fp_client_count fp_random_count
  _mfpc="$(printf '%s\n' "$_bcn" | cut -f13 | tr '|,' '\n\n' | tr -d ' ' | sort -u | grep -m1 -ixE '1|true')"
  _mfpr="$(printf '%s\n' "$_bcn" | cut -f14 | tr '|,' '\n\n' | tr -d ' ' | sort -u | grep -m1 -ixE '1|true')"
  if   [ -n "$_mfpr" ]; then pmf_label='required';              pmf_glyph='✅'
  elif [ -n "$_mfpc" ]; then pmf_label='capable, not required';  pmf_glyph='⚠️'
  else                       pmf_label='absent — deauth/disassoc spoofing works'; pmf_glyph='❌'; fi
  # WPA2-PSK is dated, not broken: it earns a caution, not a failure. Only an
  # actually-unprotected link (open / WEP / WPA1) gets the hard mark.
  case "$_cls" in
    strong|ent)  sec_glyph='✅' ;;
    trans|weak)  sec_glyph='⚠️' ;;
    *)           sec_glyph='❌' ;;
  esac
  sae_count="$(printf '%s\n' "$sae_rows" | grep -c '[^[:space:]]')"
  fp_client_count="$(printf '%s\n' "$fp_cap_rows" | grep -c '[^[:space:]]')"
  fp_random_count="$(printf '%s\n' "$fp_cap_rows" | grep -c 'randomized')"

  local eapol_rows hs_rows pmkid_rows pmkid_count m3_count _eapol
  _eapol="$(cat "$D/eapol")"
  eapol_rows="$(printf '%s\n' "$_eapol" | grep . | _collapse 3,4,5,6,7,8 8 | head -n "$row_limit")"
  hs_rows="$(printf '%s\n' "$_eapol" | awk -F'\t' -v OFS='\t' '$1!=""{print $3,$4,$5,$6}' | _hs_mask)"
  pmkid_rows="$(cat "$D/pmkid")"
  pmkid_count="$(printf '%s\n' "$pmkid_rows" | grep -c '[^[:space:]]')"
  m3_count="$(printf '%s\n' "$_eapol" | awk -F'\t' '$6=="3"{n++}END{print n+0}')"

  local decrypt_count dhcp_rows arp_rows nd_rows names_rows dns_rows software_rows _l3
  decrypt_count="$(cat "$D/deccount")"
  _l3="$(cat "$D/l3")"
  # Collapse repeated observations (a router re-emits the same UPnP banner, a host
  # re-ARPs the same pair, a device repeats the same mDNS name hundreds of times):
  # dedupe on the meaningful columns, keep the first frame, append a Copies count,
  # then cap at row_limit. Turns ~350 identical rows into one.
  dhcp_rows="$(printf '%s\n' "$_l3"     | awk -F'\t' -v OFS='\t' 'tolower($2)~/dhcp|bootp/{print $1,$3,$4,$5,$6,$7,$8,$9}'    | grep . | _collapse 2,3,4,5,6,7,8 8 | head -n "$row_limit")"
  arp_rows="$(printf '%s\n' "$_l3"      | awk -F'\t' -v OFS='\t' 'tolower($2)~/arp/{print $1,$10,$11,$12,$13,$14}'            | grep . | _collapse 2,3,4,5,6 6   | head -n "$row_limit")"
  nd_rows="$(printf '%s\n' "$_l3"       | awk -F'\t' -v OFS='\t' '$16!=""{print $1,$15,$16,$17,$18}'                          | grep . | _collapse 2,3,4,5 5     | head -n "$row_limit")"
  names_rows="$(printf '%s\n' "$_l3"    | awk -F'\t' -v OFS='\t' '$8!=""||tolower($2)~/nbns|mdns|llmnr/{print $1,$19,$8,$21,$22,$23}' | grep . | _collapse 2,3,4,5,6 6 | head -n "$row_limit")"
  dns_rows="$(printf '%s\n' "$_l3"      | awk -F'\t' -v OFS='\t' '$23!=""||$22!=""{print $1,$19,$20,$23,$22,$24,$25}'         | grep . | _collapse 2,3,4,5,6,7 7 | head -n "$row_limit")"
  software_rows="$(printf '%s\n' "$_l3" | awk -F'\t' -v OFS='\t' '$26!=""||$27!=""||$28!=""{print $1,$19,$20,$26,$27,$28}'    | grep . | _collapse 2,3,4,5,6 6   | head -n "$row_limit")"

  local station_rows assoc_rows action_rows wds_rows probe_rows
  station_rows="$({
      awk -F'\t' 'BEGIN{OFS="\t"}$1&&$2{print tolower($1),tolower($2),"association"}' "$D/st_assoc"
      printf '%s\n' "$_eapol" | awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" 'BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}$1!=""{sa=tolower($3);da=tolower($4);b=tolower($5);s=(sa in AP)?da:sa;if(s&&b)print s,b,"EAPOL"}'
      awk -F'\t' 'BEGIN{OFS="\t"}$1&&$2{print tolower($1),tolower($2),"uplink data"}' "$D/st_up"
      awk -F'\t' 'BEGIN{OFS="\t"}$1&&$2{print tolower($1),tolower($2),"downlink data"}' "$D/st_down"
    } | awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" '
         BEGIN{n=split(aps,a," ");for(i=1;i<=n;i++)AP[tolower(a[i])]=1}
         {c=tolower($1); if(c=="" || c in AP || tolower(substr(c,2,1)) ~ /[13579bdf]/)next;
          k=c SUBSEP tolower($2); if(!seen[k SUBSEP $3]++){ev[k]=ev[k] (ev[k]?", ":"") $3}}
         END{for(k in ev){split(k,p,SUBSEP);print p[1],p[2],ev[k]}}' | sort)"
  assoc_rows="$(grep . "$D/assoc" | _collapse 3,4,5,6,7,8 8 | head -n "$row_limit")"
  action_rows="$(grep . "$D/action" | _collapse 3,4,5,6,7 8 | head -n "$row_limit")"
  wds_rows="$(cat "$D/wds")"
  probe_rows="$(cat "$D/probe")"

  local keyring_rows key_analysis_rows gtk_rows gtk_count
  # Key inventory carries a "what it is" column: a bare  tk / wpa-psk / wpa-pwd
  # column does not tell the reader which secret they are holding or what it opens.
  keyring_rows=""
  local _kt _kv
  if [ -s "$KEYRING" ]; then
    if [ "$report_secrets" = 1 ]; then
      while IFS=$'\t' read -r _kt _kv; do
        [ -n "$_kt" ] || continue
        keyring_rows+="${keyring_rows:+$'\n'}${_kt}"$'\t'"$(key_type_label "$_kt")"$'\t'"\`${_kv}\`"
      done < <(LC_ALL=C sort -u "$KEYRING")
    else
      while IFS=$'\t' read -r _kt _kv; do
        [ -n "$_kt" ] || continue
        keyring_rows+="${keyring_rows:+$'\n'}${_kt}"$'\t'"$(key_type_label "$_kt")"$'\t'"${_kv}"
      done < <(awk -F'\t' 'BEGIN{OFS="\t"}$1!=""{n[$1]++}END{for(k in n)print k,n[k]" stored value(s) — REDACTED"}' "$KEYRING" | LC_ALL=C sort)
    fi
  fi
  local keyring_count=0
  [ -s "$KEYRING" ] && keyring_count="$(grep -c . "$KEYRING")"
  key_analysis_rows="$([ -f "$D/keyanalysis" ] && cat "$D/keyanalysis")"
  gtk_rows="$(cat "$D/gtk")"
  gtk_count="$(printf '%s\n' "$gtk_rows" | grep -c '[^[:space:]]')"
  # Mission-report selector inputs: read them here, while $D still exists.
  local macseen_rows probe_all_rows
  macseen_rows="$(cat "$D/macseen" 2>/dev/null)"
  probe_all_rows="$(cat "$D/probe_all" 2>/dev/null)"
  rm -rf "$D"

  local gateway gateway_mac handshake_good station_count wds_count
  gateway="$(printf '%s\n' "$dhcp_rows" | awk -F'\t' '$6!=""{print $6;exit}')"
  gateway_mac="$(printf '%s\n' "$arp_rows" | awk -F'\t' -v g="$gateway" '$3==g{print $4;exit}')"
  handshake_good="$(printf '%s\n' "$hs_rows" | awk -F'\t' '$4=="YES"{n++}END{print n+0}')"
  station_count="$(printf '%s\n' "$station_rows" | grep -c '[^[:space:]]')"
  wds_count="$(printf '%s\n' "$wds_rows" | grep -c '[^[:space:]]')"

  # ---- mission-report facts (all from passes already completed) --------------
  local op_author op_name op_date
  op_author="${WIFISCOPE_AUTHOR:-${SUDO_USER:-${USER:-unknown}}}"
  op_name="${WIFISCOPE_OPNAME:-${SSID:-UNNAMED}}"
  op_date="${generated%%T*}"

  # Make / model / firmware from the WPS identity rows (frame,bssid,mfr,model,
  # model#,device,serial,os_version). First non-empty wins; WPS is the only place
  # most APs state their own identity.
  local ap_make ap_model ap_modelnum ap_device ap_serial ap_fw
  ap_make="$(printf '%s\n'   "$wps_rows" | awk -F'\t' '$3!=""{print $3;exit}')"
  ap_model="$(printf '%s\n'  "$wps_rows" | awk -F'\t' '$4!=""{print $4;exit}')"
  ap_modelnum="$(printf '%s\n' "$wps_rows" | awk -F'\t' '$5!=""{print $5;exit}')"
  ap_device="$(printf '%s\n' "$wps_rows" | awk -F'\t' '$6!=""{print $6;exit}')"
  ap_serial="$(printf '%s\n' "$wps_rows" | awk -F'\t' '$7!=""{print $7;exit}')"
  ap_fw="$(printf '%s\n'     "$wps_rows" | awk -F'\t' '$8!=""{print $8;exit}')"
  # Firmware also leaks from the router's own HTTP Server banner once decrypted.
  # ...and it also leaks from the router's own HTTP Server banner (column 27 of the
  # decrypted L3 pass) once decryption is working.
  [ -z "$ap_fw" ] && ap_fw="$(printf '%s\n' "$_l3" | awk -F'\t' '$27!=""{print $27;exit}')"

  # Per-band BSSIDs, channels and frequencies come from beacon_rows:
  #   1 bssid  2 ssid  3 vendor  4 band  5 channel  6 freq  7 avg  8 min  9 max  10 samples
  local mac24 mac5 mac6 ch_list freq_list rssi_best rssi_best_bssid
  mac24="$(printf '%s\n' "$beacon_rows" | awk -F'\t' '$4=="2.4 GHz"{print $1}' | paste -sd, - | sed 's/,/, /g')"
  mac5="$(printf '%s\n'  "$beacon_rows" | awk -F'\t' '$4=="5 GHz"{print $1}'   | paste -sd, - | sed 's/,/, /g')"
  mac6="$(printf '%s\n'  "$beacon_rows" | awk -F'\t' '$4=="6 GHz"{print $1}'   | paste -sd, - | sed 's/,/, /g')"
  ch_list="$(printf '%s\n' "$beacon_rows" | awk -F'\t' '$5!=""{print $5}' | sort -un | paste -sd, - | sed 's/,/, /g')"
  freq_list="$(printf '%s\n' "$beacon_rows" | awk -F'\t' '$6!=""{print $6}' | sort -un | paste -sd, - | sed 's/,/, /g')"
  rssi_best="$(printf '%s\n' "$beacon_rows" | awk -F'\t' '$9!=""{if(b==""||$9+0>b+0){b=$9;m=$1}}END{print b}')"
  rssi_best_bssid="$(printf '%s\n' "$beacon_rows" | awk -F'\t' '$9!=""{if(b==""||$9+0>b+0){b=$9;m=$1}}END{print m}')"

  # Estimated location: the collector position recorded on the strongest beacon.
  # This is where the RADIO was heard best, which is the standard field estimate —
  # it is NOT a survey fix on the AP, and the report says so where it prints it.
  # Keep lat/lon/alt as separate values: building a map URL out of a formatted
  # string means re-parsing your own output, and that breaks the first time the
  # format changes.
  local est_lat est_lon est_alt est_loc=''
  IFS=$'\t' read -r est_lat est_lon est_alt < <(printf '%s\n' "$gps_rows" | awk -F'\t' -v OFS='\t' '
      $3!="" && $4!="" { r=($7==""?-999:$7+0); if(b==""||r>b){b=r;la=$3;lo=$4;al=$5} }
      END{ if(la!="") print la, lo, al }')
  if [ -n "${est_lat:-}" ]; then
    est_loc="$est_lat, $est_lon${est_alt:+ (alt $est_alt m)}"
  fi

  # Selector lists. Associated = a station with association/EAPOL/data evidence on a
  # target BSSID (station_rows); times-seen counts every frame it sent or received.
  local assoc_selectors probe_selectors wired_selectors
  assoc_selectors="$(printf '%s\n' "$station_rows" |
    awk -F'\t' '$1!=""{print tolower($1)}' | sort -u |
    awk -v caps="$(printf '%s\n' "$fp_cap_rows" | awk -F'\t' -v OFS='|' '{print tolower($1),$2,$3,$4}' | paste -sd';' -)" \
        -v counts="$(printf '%s\n' "$macseen_rows" | awk -F'\t' '$1!=""{printf "%s|%s;", $1, $2}')" '
      BEGIN{ n=split(caps,A,";"); for(i=1;i<=n;i++){ if(A[i]=="")continue; split(A[i],f,"|"); V[f[1]]=f[2]; T[f[1]]=f[3]; G[f[1]]=f[4] }
             n=split(counts,B,";"); for(i=1;i<=n;i++){ if(B[i]=="")continue; split(B[i],f,"|"); C[f[1]]=f[2] } }
      { m=$0
        v=(V[m]==""||V[m]=="—") ? "OUI not resolved" : V[m]
        t=(T[m]=="") ? ((tolower(substr(m,2,1)) ~ /^[26ae]$/) ? "randomized" : "hardware") : T[m]
        g=(G[m]=="") ? "" : ", " G[m]
        printf "- **%s**: %s, %s MAC%s, seen in %d frame(s)\n", m, v, t, g, C[m]+0 }')"

  # $probe_all_rows is already  mac<TAB>count<TAB>ssid-set  from the pass above.
  # Emit a TABLE sorted busiest-first, not a bullet per station: on a real capture this
  # is ~70 rows that are identical apart from the address, and as bullets it buried
  # every section around it. Sorting by probe count puts the station that sent 54 at
  # the top, where the one that sent 2 is noise.
  probe_selectors="$(printf '%s\n' "$probe_all_rows" | awk -F'\t' -v OFS='\t' -v aps="${ALL_BSSIDS[*]}" '
      BEGIN{ n=split(aps,a," "); for(i=1;i<=n;i++) AP[tolower(a[i])]=1 }
      $1!="" && !($1 in AP) {
        print $1, ((tolower(substr($1,2,1)) ~ /^[26ae]$/) ? "randomized" : "hardware"),
              $2+0, ($3==""?"—":$3) }' |
    LC_ALL=C sort -t"$(printf '\t')" -k3,3nr -k1,1)"

  # Wired = a MAC that owns an IP in the decrypted L2 traffic but is neither an AP,
  # nor a wireless station of this BSS, nor the default gateway. Seeing a device's
  # IP without ever seeing it associate is the evidence that it is on cable.
  wired_selectors="$(printf '%s\n' "$_l3" | awk -F'\t' -v OFS='\t' '
      { if($12!="" && $11!="") print tolower($12), $11
        if($3!=""  && $5!="")  print tolower($3),  $5
        if($16!="" && $15!="") print tolower($16), $15 }' | sort -u |
    awk -F'\t' -v aps="${ALL_BSSIDS[*]}" \
        -v sta="$(printf '%s\n' "$station_rows" | awk -F'\t' '{print tolower($1)}' | paste -sd' ' -)" \
        -v gwm="$(printf '%s' "$gateway_mac" | tr 'A-Z' 'a-z')" -v gwi="$gateway" '
      BEGIN{ n=split(aps,a," "); for(i=1;i<=n;i++) AP[tolower(a[i])]=1
             n=split(sta,b," "); for(i=1;i<=n;i++) ST[tolower(b[i])]=1 }
      $1!="" && $2!="" {
        m=$1; if(m in AP || m in ST || m==gwm) next
        if(tolower(substr(m,2,1)) ~ /[13579bdf]/) next          # group-addressed
        if(!(seen[m]++)) printf "- **%s**: %s — no association or handshake seen, so wired (or on another BSS)\n", m, $2 }' | sort)"

  # Hashcat export, produced by the same button that produces the report - the whole
  # point of the handshake evidence is the file you can actually crack, so writing the
  # report without it left a manual step that is easy to forget.
  local hcout hc_how hc_lines hc_body hc_kinds
  hcout="${out%.md}.hc22000"
  hc_how=''; hc_lines=0; hc_body=''; hc_kinds=''
  if hc_how="$(_hc22000_build "$hcout")"; then
    hc_lines="$(grep -c . "$hcout" 2>/dev/null || echo 0)"
    # Count by KIND only. Aggregating on kind+AP+STA produced a row per station and
    # flattened the tabs into one cell, so md_table rendered a two-column table with
    # everything crammed in column one and "—" in column two.
    # Build the two columns by hand: blanking $1 and printing with OFS re-joins the
    # remaining fields, which splits a label like "PMKID (client-less)" across columns.
    hc_kinds="$(hc22000_kind < "$hcout" | cut -f1 | LC_ALL=C sort | uniq -c |
                  awk '{ n=$1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0); print n "\t" $0 }')"
    if [ "$report_secrets" = 1 ]; then hc_body="$(cat "$hcout")"; fi
  else
    hc_how=''
  fi
  _progress_phase "wrote $(basename "$hcout") (${hc_lines} hash line(s))"

  # Dynamic scope: the report is always plain Markdown, independent of terminal UX.
  local C_RESET= C_B= C_DIM= C_RED= C_GRN= C_YEL= C_BLU= C_MAG= C_CYN= C_ORG= UX_LINKS=0
  {
    echo '---'
    printf "author: '%s'\n" "${op_author//\'/\'\'}"
    printf "date: '%s'\n" "$op_date"
    printf "title: '%s Mission Report'\n" "${op_name//\'/\'\'}"
    printf "ssid: '%s'\n" "${SSID//\'/\'\'}"
    printf "pcap: '%s'\n" "${PCAP//\'/\'\'}"
    printf "generated_utc: '%s'\n" "$generated"
    printf "tool_version: '%s'\n" "$VERSION"
    printf "decryption_enabled: '%s'\n" "$decrypt_label"
    printf "secret_values: '%s'\n" "$secrets_label"
    printf "row_limit_per_event_table: %s\n" "$row_limit"
    printf "diagram: '%s'\n" "${mapout##*/}"
    echo 'tags: [wiboc, wifi, pcap, autopsy]'
    echo '---'
    echo
    echo "# $op_name Mission Report"
    echo
    echo "> Evidence scope: packet observations from \`$PCAP\`. **Observed** means a field/frame is present; **inferred** means a role is derived from multiple observations; **not observed** is not proof of absence."
    echo
    echo "Matching diagram: [${mapout##*/}](${mapout##*/})"
    echo
    # A 12-section evidence dump is unnavigable without an index. GitHub and
    # Obsidian both derive heading anchors the same way (lowercase, spaces and
    # dots to hyphens), so one list of links works in either renderer.
    echo '## Contents'
    echo
    echo '**Mission report** — [Survey Imagery](#survey-imagery) · [Targets](#targets) · [Router Info](#router-info) · [Handshakes](#handshakes) · [Selectors of Interest](#selectors-of-interest) · [Actions Taken](#actions-taken) · [Notes](#notes)'
    echo
    echo '**Detailed evidence**'
    echo
    echo '| # | Section | What it answers |'
    echo '| --- | --- | --- |'
    echo '| 1 | [Capture overview and integrity](#1-capture-overview-and-integrity) | Is this capture whole and untampered? |'
    echo '| 2 | [Router identity, band, channel, signal](#2-router-identity-band-channel-frequency-and-signal) | Which radios, where, how strong? |'
    echo '| 3 | [Encryption, ciphers, PMF, hardware](#3-encryption-ciphers-pmf-and-hardware-identity) | What protects it, and what is the AP? |'
    echo '| 4 | [GPS collection evidence](#4-gps-collection-evidence) | Where was the collector? |'
    echo '| 5 | [EAPOL handshake, PMKID, SAE](#5-eapol-handshake-and-pmkid-evidence) | Is there crackable/derivable key context? |'
    echo '| 6 | [Decryption validation and key inventory](#6-decryption-validation-and-key-inventory) | Which keys do we hold, and do they work? |'
    echo '| 7 | [DHCP, subnet, gateway, ARP, IPv6, names](#7-dhcp-subnet-gateway-arp-ipv6-and-names) | What is the network layout? |'
    echo '| 8 | [Station, management-action, topology](#8-wireless-station-management-action-and-topology-evidence) | Who was on it and how do the APs link? |'
    echo '| 9 | [Device fingerprinting](#9-device-fingerprinting) | What kind of devices are these? |'
    echo '| 10 | [Decrypted DNS and software evidence](#10-decrypted-dns-and-software-evidence) | What were they talking to? |'
    echo '| 11 | [Capture-quality checks](#11-capture-quality-checks) | How much should we trust the above? |'
    echo '| 12 | [Limitations, gaps, and questions](#12-limitations-gaps-and-questions) | What this capture cannot tell us. |'
    echo
    md_details_open 'Paste once: table helpers + key set used by the commands below'
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
    if [ "${WIFISCOPE_REPORT_SECRETS:-1}" = 1 ] && [ "${#DEC[@]}" -gt 0 ]; then
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
    md_details_close
    # ---- MISSION REPORT: the answers first, evidence tables afterwards -------
    # Everything here is a summary of the numbered sections below; each block names
    # the tshark command that produced it so a reader can re-derive any single line.
    echo '# Survey Imagery'
    echo
    if [ -n "$est_loc" ]; then
      echo "Collector track recorded in this capture. Strongest-signal collection point: \`$est_loc\`."
      echo
      echo "- Map: [OpenStreetMap](https://www.openstreetmap.org/?mlat=${est_lat}&mlon=${est_lon}#map=18/${est_lat}/${est_lon})"
      echo "- Full GPS track: [section 4](#4-gps-collection-evidence)"
    else
      echo '_No GPS metadata in this capture (no PPI-GPS header). Attach survey photos, a site sketch, or a heat-map export here._'
    fi
    echo
    echo "- Network diagram: [${mapout##*/}](${mapout##*/})"
    echo

    echo '# Targets'
    echo
    echo '## Router Info'
    echo
    printf -- '- **Make:** %s\n'              "${ap_make:-_not advertised (no WPS identity)_}"
    printf -- '- **Model:** %s\n'             "${ap_model:-_not advertised_}"
    printf -- '- **Model number:** %s\n'      "${ap_modelnum:-_not advertised_}"
    printf -- '- **Device name:** %s\n'       "${ap_device:-_not advertised_}"
    printf -- '- **Serial:** %s\n'            "${ap_serial:-_not advertised_}"
    printf -- '- **Firmware:** %s\n'          "${ap_fw:-_not observed (no WPS OS version, no HTTP Server banner)_}"
    printf -- '- **2.4GHz MAC:** %s\n'        "${mac24:-_none beaconing on 2.4 GHz_}"
    printf -- '- **5GHz MAC:** %s\n'          "${mac5:-_none beaconing on 5 GHz_}"
    printf -- '- **6GHz MAC:** %s\n'          "${mac6:-_none beaconing on 6 GHz_}"
    printf -- '- **Channels:** %s\n'          "${ch_list:-_not advertised_}"
    printf -- '- **Frequencies:** %s MHz\n'   "${freq_list:-—}"
    printf -- '- **SSID:** %s\n'              "$SSID"
    printf -- '- **Encryption:** %s %s — PMF %s %s\n' "$sec_glyph" "$verdict" "$pmf_glyph" "$pmf_label"
    printf -- '- **Estimated Location:** %s\n' "${est_loc:-_no GPS in capture_}"
    printf -- '- **Strongest RSSI:** %s\n'    "$([ -n "$rssi_best" ] && printf '%s dBm (on %s)' "$rssi_best" "$rssi_best_bssid" || printf '_no radiotap signal data_')"
    echo
    echo '> [!note] Estimated Location is the **collector** position recorded on the strongest beacon, not a survey fix on the AP. Make/model/firmware come from what the AP advertises about itself; an AP with an empty WPS IE states nothing, which is why those lines can be blank on a perfectly healthy capture.'
    echo
    md_details_open 'How this was derived with TShark'
    echo '```bash'
    echo '# Identity (make / model / firmware) — WPS is where an AP names itself:'
    echo "tshark -r '${PCAP##*/}' -Y '$(bssid_filter) && (wps.manufacturer || wps.model_name || wps.os_version)' \\"
    echo "  -T fields -e wlan.bssid -e wps.manufacturer -e wps.model_name -e wps.model_number \\"
    echo "  -e wps.device_name -e wps.serial_number -e wps.os_version"
    echo
    echo '# Per-band MAC, channel, frequency and RSSI (band is derived from frequency):'
    echo "tshark -r '${PCAP##*/}' -Y '$(beacons_of_target)' \\"
    echo "  -T fields -e wlan.bssid -e wlan.ds.current_channel -e wlan.ht.info.primarychannel \\"
    echo "  -e radiotap.channel.freq -e radiotap.dbm_antsignal"
    echo
    echo '# Encryption and PMF:'
    echo "tshark -r '${PCAP##*/}' -Y '$(beacons_of_target)' \\"
    echo "  -T fields -e wlan.rsn.akms.type -e wlan.rsn.gcs.type -e wlan.rsn.pcs.type \\"
    echo "  -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr -e wlan.fixed.capabilities.privacy"
    echo
    echo '# Collector position per beacon (needs a PPI-GPS capture):'
    echo "tshark -r '${PCAP##*/}' -Y 'ppi_gps.lat && ppi_gps.lon && $(beacons_of_target)' \\"
    echo "  -T fields -e ppi_gps.lat -e ppi_gps.lon -e ppi_gps.alt -e ppi.80211-common.dbm.antsignal"
    echo '```'
    md_details_close

    # Key material lives here as well as in section 6 on purpose: section 6 is the
    # validation record, this is the operational recipe - everything needed to decrypt
    # this capture again in six months, next to the router it belongs to.
    echo '### Key Material — how to decrypt this capture later'
    if [ "$keyring_count" -gt 0 ]; then
      printf '%s\n' "$keyring_rows" | md_table $'Key type\tWhat it is\tValue'   # emits its own blank line
    else
      echo
      echo '_Keyring is empty — nothing stored for this capture yet. Run `harvest` to derive the PSK/PTK-TK, or `addkey` to import material from another tool._'
      echo
    fi
    # Keys Wireshark derived from the handshakes themselves (PMK / KCK / KEK / TK),
    # and the group keys carried in message 3. These are per-session, so they are the
    # ones that matter when the passphrase alone will not do — notably under SAE.
    local _derived
    _derived="$({
      printf '%s\n' "$key_analysis_rows" | awk -F'\t' -v OFS='\t' \
        '$10!=""{print "PTK-TK", $3, $4, $10} $7!=""{print "PMK", $3, $4, $7}'
      printf '%s\n' "$gtk_rows" | awk -F'\t' -v OFS='\t' \
        '$9!=""{print "GTK", $5, "(group)", $9} $12!=""{print "IGTK", $5, "(group)", $12} $15!=""{print "BIGTK", $5, "(group)", $15}'
    } | grep '[^[:space:]]' | LC_ALL=C sort -u)"
    if [ -n "$_derived" ]; then
      echo '**Derived from the handshakes in this capture:**'
      printf '%s\n' "$_derived" | md_table $'Key\tBSSID\tStation\tValue'
    fi
    if [ "${#DEC[@]}" -gt 0 ] && [ "$report_secrets" = 1 ]; then
      echo 'Paste this to decrypt the capture again with exactly the keys used here:'
      echo
      echo '```bash'
      printf 'tshark -r %s \\\n' "${PCAP##*/}"
      local _i=0
      while [ "$_i" -lt "${#DEC[@]}" ]; do
        printf '  %s %s \\\n' "${DEC[$_i]}" "$(shell_quote_human "${DEC[$((_i + 1))]}")"
        _i=$((_i + 2))
      done
      printf '  -Y %s\n' "'(dhcp || arp || ip || ipv6)'"
      echo '```'
      echo
      printf '_Or keep the same `type<TAB>value` lines in `%s`; they are reapplied on every run._\n' "${KEYRING##*/}"
      echo
    elif [ "${#DEC[@]}" -gt 0 ]; then
      printf '_%s decryption key(s) are loaded but withheld here. The values are in `%s`._\n' "${#DEC[@]}" "${KEYRING##*/}"
      echo
    fi
    echo '> [!tip] `wpa-pwd` is a passphrase and only works for WPA2-PSK. A `tk` decrypts exactly one client session and a `gtk` decrypts broadcast/multicast — those are what you need on an SAE (WPA3) network, where the passphrase cannot produce the PMK. Section 6 records which of these Wireshark actually accepted.'
    echo

    echo '### Handshakes'
    echo
    printf -- '- **Recoverable 4-way contexts:** %s of %s station/BSSID pair(s) (M1+M2 or M2+M3 observed)\n' \
      "$handshake_good" "$(printf '%s\n' "$hs_rows" | grep -c '[^[:space:]]')"
    printf -- '- **PMKID rows:** %s\n' "$pmkid_count"
    printf -- '- **SAE (WPA3) auth frames:** %s\n' "$sae_count"
    printf -- '- **Keys held:** %s\n' "$([ "$keyring_count" -gt 0 ] && printf '%s (see §6)' "$keyring_count" || printf 'none')"
    if [ -n "$hc_how" ]; then
      printf -- '- **hashcat-22000 export:** `%s` — %s line(s) via %s\n' "${hcout##*/}" "$hc_lines" "$hc_how"
      [ -n "$hc_kinds" ] && printf '%s\n' "$hc_kinds" | awk -F'\t' '{printf "    - %s x %s\n", $1, $2}'
      printf -- '- **Crack with:** `hashcat -m 22000 %s wordlist.txt`\n' "${hcout##*/}"
    else
      printf -- '- **hashcat-22000 export:** _nothing exportable from this capture_\n'
    fi
    echo
    printf '%s\n' "$hs_rows" | md_table $'Station\tBSSID\tMessages 1–4\tPTK/offline-check context usable'
    if [ "$sae_count" -gt 0 ]; then
      echo '> [!important] SAE frames are present. An SAE PMK comes from the elliptic-curve exchange, not from `PBKDF2(passphrase, SSID)` — so for SAE sessions the passphrase cannot decrypt and the 4-way above is not offline-crackable. Harvested PTK-TK / GTK material is required.'
      echo
    fi
    md_details_open 'How this was derived with TShark'
    echo '```bash'
    echo '# 4-way messages per station (msgnr 1..4), folded into a per-station mask:'
    echo "tshark -r '${PCAP##*/}' -Y 'eapol && $(bssid_filter)' \\"
    echo "  -T fields -e wlan.sa -e wlan.da -e wlan.bssid -e wlan_rsna_eapol.keydes.msgnr"
    echo
    echo '# Client-less PMKID (carried in association RSN as well as EAPOL):'
    echo "tshark -r '${PCAP##*/}' -Y '$(bssid_filter) && (wlan.pmkid.akms || wlan.rsn.ie.pmkid)' \\"
    echo "  -T fields -e wlan.sa -e wlan.bssid -e wlan.rsn.ie.pmkid"
    echo
    echo '# WPA3 SAE lives in Authentication frames, algorithm 3 (1=Commit, 2=Confirm):'
    echo "tshark -r '${PCAP##*/}' -Y 'wlan.fixed.auth.alg==3 && $(bssid_filter)' \\"
    echo "  -T fields -e wlan.sa -e wlan.da -e $sae_mt -e wlan.fixed.status_code"
    echo '```'
    md_details_close

    echo '## Selectors of Interest'
    echo
    echo '### Associated MACs'
    echo
    if [ -n "$assoc_selectors" ]; then
      local _an; _an="$(printf '%s\n' "$assoc_selectors" | grep -c '^- ')"
      printf '%s\n' "$assoc_selectors" | head -n "$row_limit"
      [ "$_an" -gt "$row_limit" ] && {
        echo
        printf '_Showing the first %s of %s associated station(s); raise the report row limit to list them all._\n' "$row_limit" "$_an"
      }
    else
      echo '_None observed._'
    fi
    echo
    echo '_"Randomized" means the U/L bit is set (a locally administered address): the device is rotating its MAC and cannot be correlated to another session. "Hardware" means a real OUI, which can._'
    echo
    md_details_open 'How this was derived with TShark'
    echo '```bash'
    echo '# Association evidence (a station that asked to join this SSID):'
    echo "tshark -r '${PCAP##*/}' -Y '(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2) && wlan.ssid==\"$SSID\"' \\"
    echo "  -T fields -e wlan.sa -e wlan.sa_resolved -e wlan.bssid"
    echo
    echo '# Data-frame evidence, uplink then downlink (a station actually using the BSS):'
    echo "tshark -r '${PCAP##*/}' -Y 'wlan.fc.type==2 && wlan.fc.tods==1 && wlan.fc.fromds==0 && $(bssid_filter)' -T fields -e wlan.sa -e wlan.bssid"
    echo "tshark -r '${PCAP##*/}' -Y 'wlan.fc.type==2 && wlan.fc.tods==0 && wlan.fc.fromds==1 && $(bssid_filter)' -T fields -e wlan.da -e wlan.bssid"
    echo
    echo '# Times seen = every frame to or from the MAC inside the target BSS:'
    echo "tshark -r '${PCAP##*/}' -Y '$(bssid_filter)' -T fields -e wlan.sa -e wlan.da"
    echo '```'
    md_details_close

    echo '### Wired MACs'
    echo
    if [ -n "$wired_selectors" ]; then printf '%s\n' "$wired_selectors"; else echo '_None observed (needs working decryption to see L2/L3 at all)._'; fi
    echo
    echo '_A MAC that owns an IP in the decrypted traffic but never associated and never handshaked is reached over cable — or sits on a BSS this capture did not cover. The default gateway is excluded; it is reported separately in the executive summary._'
    echo
    md_details_open 'How this was derived with TShark'
    echo '```bash'
    echo '# MAC<->IP ownership from ARP, from the DHCP lease, and from IPv6 ND:'
    echo "tshark -r '${PCAP##*/}' \"\${KEYS[@]}\" -Y '$(bssid_filter) && (arp || dhcp || (icmpv6 && icmpv6.opt.linkaddr))' \\"
    echo "  -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 -e dhcp.hw.mac_addr -e dhcp.ip.your \\"
    echo "  -e icmpv6.opt.linkaddr -e ipv6.src"
    echo '# ...then subtract every BSSID, every associated station, and the gateway.'
    echo '```'
    md_details_close

    echo '### Probing MACs'
    echo
    if [ -n "$probe_selectors" ]; then
      local _pn _prand _phw _pmax
      _pn="$(printf '%s\n' "$probe_selectors" | grep -c '[^[:space:]]')"
      _prand="$(printf '%s\n' "$probe_selectors" | awk -F'\t' '$2=="randomized"' | grep -c .)"
      _phw=$((_pn - _prand))
      _pmax="$(printf '%s\n' "$probe_selectors" | awk -F'\t' 'NR==1{print $3" probes from "$1}')"
      printf '**%s station(s)** probed for this network — %s randomized, %s with a real OUI. Busiest: %s.\n' \
        "$_pn" "$_prand" "$_phw" "$_pmax"
      printf '%s\n' "$probe_selectors" | head -n "$row_limit" |
        md_table $'Station\tMAC type\tProbes\tSSID sought'
      [ "$_pn" -gt "$row_limit" ] &&
        printf '_Showing the %s busiest of %s probing station(s); raise the report row limit to list them all._\n' "$row_limit" "$_pn"
    else
      echo '_None observed — no station probed for this SSID or addressed one of its BSSIDs._'
    fi
    echo
    echo '_These are stations hunting for **this** network specifically: a probe request naming the SSID, or one directed at one of its BSSIDs. A device that probes for a network it is not currently connected to has been on it before, and that is broadcast in the clear with no association required. For every probing device in the capture regardless of target, see section 8._'
    echo
    md_details_open 'How this was derived with TShark'
    echo '```bash'
    echo '# Probe requests (subtype 4) that name THIS SSID or target one of its BSSIDs:'
    echo "tshark -r '${PCAP##*/}' \\"
    echo "  -Y 'wlan.fc.type_subtype==4 && (wlan.ssid==\"$SSID\" || $(bssid_filter))' \\"
    echo "  -T fields -e wlan.sa -e wlan.ssid"
    echo '# wlan.ssid is hex under -T fields; it is decoded to text and'
    echo '# counted per station.'
    echo '```'
    md_details_close

    echo '# Actions Taken'
    echo
    echo '_Operator log — what was done, when, and under what authority._'
    echo
    printf -- '- %s — capture `%s` (%s bytes, SHA-256 `%s`) analysed\n' \
      "$generated" "${PCAP##*/}" "$capture_bytes" "$capture_hash"
    printf -- '- Decryption: %s%s\n' "$decrypt_label" \
      "$([ "$keyring_count" -gt 0 ] && printf ' (%s key(s) in %s)' "$keyring_count" "${KEYRING##*/}" || printf '')"
    echo
    echo '# Notes'
    echo
    echo '_Free-form notes. Everything from here on is generated from the capture._'
    echo
    echo '# Detailed evidence'
    echo
    echo 'Each section below states the observation and the exact command that produced it.'
    echo
    echo '## Executive summary'
    echo
    printf '| Item | Result | Confidence |\n| --- | --- | --- |\n'
    printf '| Target | %s (%d beaconing BSSID(s)) | Observed |\n' "$SSID" "${#TGT_BSSIDS[@]}"
    printf '| Security | %s | Observed RSN/privacy fields; verdict is interpretation, not observation |\n' "$verdict"
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
    echo '```text'; printf '%s\n' "$phs_plain"; echo '```'
    report_command 0 '' -q -z io,phs

    echo; echo '## 2. Router identity, band, channel, frequency, and signal'
    echo
    printf '%s\n' "$beacon_rows" | md_table $'BSSID\tSSID\tResolved BSSID\tBand\tAdvertised channel\tCapture frequency MHz\tAvg beacon RSSI dBm\tMin RSSI\tMax RSSI\tRSSI samples'
    echo
    echo '_Advertised DS/HT channel is AP evidence. Radiotap frequency is collector metadata and can vary during channel hopping._'
    report_command 0 'table_rows  # then group by BSSID; RSSI min/avg/max computed per BSSID' \
      -Y "$(beacons_of_target)" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e frame.time -e wlan.bssid -e wlan.bssid_resolved -e wlan.ssid \
      -e wlan.ds.current_channel -e wlan.ht.info.primarychannel \
      -e radiotap.channel.freq -e radiotap.dbm_antsignal

    echo; echo '## 3. Encryption, ciphers, PMF, and hardware identity'
    echo
    echo "**Interpreted verdict:** $verdict"
    echo
    printf '%s\n' "$security_rows" | rsn_decode_row |
      md_table $'BSSID\tPrivacy bit\tGroup cipher\tPairwise cipher\tAKM suites\tPMF capable\tPMF required'
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
      -e wlan.bssid -e wlan.bssid_resolved -e "$oui_field"

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

    echo; echo '### hashcat-22000 export'
    echo
    if [ -n "$hc_how" ]; then
      printf 'Written alongside this report as [`%s`](%s) — %s line(s), via %s.\n' \
        "${hcout##*/}" "${hcout##*/}" "$hc_lines" "$hc_how"
      echo
      printf '%s\n' "$hc_kinds" | md_table $'Count\tKind'
      if [ -n "$hc_body" ]; then
        echo '```'
        printf '%s\n' "$hc_body"
        echo '```'
        echo
      else
        echo '_Hash lines withheld (`WIFISCOPE_REPORT_SECRETS=0`); the file itself still contains them._'
        echo
      fi
      echo '```bash'
      printf 'hashcat -m 22000 %s wordlist.txt\n' "${hcout##*/}"
      echo '```'
      echo
      echo '> [!note] `WPA*01` lines are PMKID and need no client; `WPA*02` lines come from a 4-way handshake. Both recover the **passphrase**, so they are only meaningful where the PMK is `PBKDF2(passphrase, SSID)` — i.e. WPA2-PSK, not SAE.'
    else
      if command -v hcxpcapngtool >/dev/null 2>&1; then
        echo '_No exportable hash material: `hcxpcapngtool` declined this capture, and no non-zero PMKID could be packaged either._'
      else
        echo '_No exportable hash material: no non-zero PMKID in the capture, and `hcxpcapngtool` (which also packages EAPOL handshakes as `WPA*02`) is not installed._'
      fi
    fi

    echo; echo '### SAE (WPA3) authentication exchange'
    printf '%s\n' "$sae_rows" | md_table $'Frame\tTime\tSource\tDestination\tBSSID\tSAE message (1=Commit, 2=Confirm)\tStatus code'
    echo
    echo '_SAE precedes the 4-way handshake and lives in Authentication frames (algorithm 3). A complete exchange shows Commit and Confirm in both directions. Status 76 = anti-clogging token required, 77 = unsupported finite cyclic group._'
    if [ -n "$sae_rows" ]; then
      echo
      echo '> [!important] This BSS authenticates with SAE. The SAE PMK is an output of the elliptic-curve exchange, not `PBKDF2(passphrase, SSID)`. A correct passphrase therefore cannot decrypt SAE sessions and the EAPOL/PMKID evidence above is not offline-crackable for them — decryption requires harvested PTK-TK / GTK material.'
    fi
    report_command 0 'table_unique' -Y "wlan.fixed.auth.alg==3 && $(bssid_filter)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e frame.time \
      -e wlan.sa -e wlan.da -e wlan.bssid -e "$sae_mt" -e wlan.fixed.status_code

    echo; echo '## 6. Decryption validation and key inventory'
    echo
    printf '| Check | Result |\n| --- | --- |\n| Decryption options loaded | %s |\n| Target DHCP/ARP/IP/IPv6 frames decoded | %s |\n| Secret values in this report | %s |\n' \
      "$decrypt_label" "$decrypt_count" "$secrets_label"
    echo
    report_command 1 'wc -l' -Y "$(bssid_filter) && (dhcp || arp || ip || ipv6)"
    echo; echo '### Stored keyring inventory'
    printf '%s\n' "$keyring_rows" | md_table $'Key type\tWhat it is\tValue'
    echo
    if [ "$report_secrets" = 1 ]; then
      echo "> [!warning] This report includes full key material (passphrase, PMK, PTK, GTK). Re-run with key redaction enabled before sharing it outside a controlled artifact."
    else
      echo "> [!note] Key material is redacted in this report. Counts are shown instead of values; re-run with redaction disabled to include them."
    fi
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
    printf '%s\n' "$dhcp_rows" | md_table $'Frame\tClient MAC\tRequested IP\tOffered IP\tSubnet mask\tRouter\tHostname\tVendor class\tCopies'
    report_command 1 'table_unique' -Y "$(bssid_filter) && dhcp" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e frame.number -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address -e dhcp.ip.your \
      -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.hostname -e dhcp.option.vendor_class_id
    echo; echo '### ARP IPv4 mapping'
    printf '%s\n' "$arp_rows" | md_table $'Frame\tOpcode\tSource IPv4\tSource MAC\tDestination IPv4\tDestination MAC\tCopies'
    report_command 1 'table_unique' -Y "$(bssid_filter) && arp" -T fields -E separator=/t -E occurrence=f -E header=y \
      -e frame.number -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac
    echo; echo '### IPv6 neighbor mapping'
    printf '%s\n' "$nd_rows" | md_table $'Frame\tIPv6 source\tLink-layer MAC\tNS target\tNA target\tCopies'
    report_command 1 'table_unique' -Y "$(bssid_filter) && icmpv6 && icmpv6.opt.linkaddr" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ipv6.src \
      -e icmpv6.opt.linkaddr -e icmpv6.nd.ns.target_address -e icmpv6.nd.na.target_address
    echo; echo '### Hostname and service-name evidence'
    printf '%s\n' "$names_rows" | md_table $'Frame\tSource IP\tDHCP hostname\tNBNS name\tmDNS response name\tDNS/LLMNR query\tCopies'
    report_command 1 'table_unique' -Y "$(bssid_filter) && (dhcp.option.hostname || nbns || mdns || llmnr)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ip.src \
      -e dhcp.option.hostname -e nbns.name -e dns.resp.name -e dns.qry.name

    echo; echo '## 8. Wireless station, management-action, and topology evidence'
    echo; echo '### Station inventory with evidence source'
    printf '%s\n' "$station_rows" | md_table $'Station\tBSSID\tEvidence source(s)'
    echo '_The four result sets below are unioned, then group-addressed MACs and known AP BSSIDs are removed._'
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

    echo; echo '## 9. Device fingerprinting'
    echo
    echo 'Who and what the clients are, separated by what the evidence requires. The 802.11 capability profile needs no keys at all; everything after it needs decryption.'
    echo; echo '### 802.11 client capability profile (no decryption required)'
    printf '%s\n' "$fp_cap_rows" | md_table $'Station\tVendor (OUI)\tMAC type\tGeneration\tHT (11n)\tVHT (11ac)\tHE (11ax)'
    echo
    echo '_Generation is read from the capability elements in the association request: HE (802.11ax) = Wi-Fi 6, and Wi-Fi 6E when it associated above 5925 MHz; VHT = Wi-Fi 5; HT = Wi-Fi 4. Wireshark 4.2 exposes no EHT capability field, so Wi-Fi 7 is not claimed here. "MAC type" reads the U/L bit: a randomized (locally administered) address cannot be correlated across sessions, a hardware OUI can._'
    report_command 0 'table_unique' -Y "$assoc_f" -T fields -E separator=/t -E header=y -E aggregator=, \
      -e wlan.sa -e wlan.sa_resolved -e wlan.ht.capabilities -e wlan.vht.capabilities "${he_f[@]}" -e radiotap.channel.freq

    echo; echo '### Regulatory domain advertised by clients'
    printf '%s\n' "$fp_country_rows" | md_table $'Station\tCountry code'
    report_command 0 'table_unique' -Y "$assoc_f && wlan.country_info.code" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e wlan.sa -e wlan.country_info.code

    echo; echo '### DHCP identity and option-55 parameter-request signature'
    printf '%s\n' "$fp_dhcp_rows" | md_table $'Client MAC\tAssigned IP\tHostname\tVendor class (60)\tParameter request list (55)'
    echo
    echo '_DHCP option 55 is the ordered list of options a client asks for, and that order is a stable per-OS signature (the basis of the classic p0f/fingerbank DHCP fingerprint). It separates Android from iOS from Windows even when the hostname is generic or absent._'
    report_command 1 'table_unique' -Y "$(bssid_filter) && dhcp" -T fields -E separator=/t -E header=y \
      -E aggregator=, -E occurrence=a -e dhcp.hw.mac_addr -e dhcp.ip.your -e dhcp.option.hostname \
      -e dhcp.option.vendor_class_id -e dhcp.option.request_list_item

    echo; echo '### TLS ClientHello identity (SNI, JA3, JA4)'
    printf '%s\n' "$fp_tls_rows" | md_table "$tls_hdr"
    echo
    echo '_SNI names the service the device phones home to; JA3/JA4 hash the ClientHello itself, which is a per-TLS-stack signature that survives an otherwise encrypted payload._'
    report_command 1 'table_unique' -Y "$(bssid_filter) && tls.handshake.type==1" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e ip.src \
      -e tls.handshake.extensions_server_name "${ja_f[@]}"

    echo; echo '### DNS-SD / mDNS advertised services and model strings'
    printf '%s\n' "$fp_sd_rows" | md_table $'Source IP\tService (PTR)\tTXT record'
    echo
    echo '_DNS-SD advertises what a device **is**: `_airplay._tcp`, `_googlecast._tcp`, `_printer._tcp`, and TXT records that frequently carry an explicit `model=` string._'
    report_command 1 'table_unique' -Y "$(bssid_filter) && (dns.ptr.domain_name || dns.txt)" \
      -T fields -E separator=/t -E header=y -E aggregator=, -e ip.src -e dns.ptr.domain_name -e dns.txt

    echo; echo '### OS hint from observed IP TTL'
    printf '%s\n' "$fp_ttl_rows" | md_table $'Source IP\tMax TTL seen\tLikely initial TTL\tLikely stack\tPackets'
    echo
    echo '> [!note] TTL is a hint, not proof. Stacks ship distinct initial values (64 for Linux/Android/macOS/iOS/BSD, 128 for Windows, 255 for network gear and printers), but any router in the path decrements it, so a lower observed value does not by itself change the verdict.'
    report_command 1 'table_rows  # then the max TTL per source is taken' \
      -Y "$(bssid_filter) && ip" -T fields -E separator=/t -E header=y -e ip.src -e ip.ttl

    echo; echo '## 10. Decrypted DNS and software evidence'
    echo; echo '### DNS/mDNS/LLMNR names and answers'
    printf '%s\n' "$dns_rows" | md_table $'Frame\tSource IP\tDestination IP\tQuery\tResponse name\tA\tAAAA\tCopies'
    report_command 1 "sort -u | head -n $row_limit | table_rows" -Y "$(bssid_filter) && (dns.qry.name || dns.resp.name)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ip.src -e ip.dst \
      -e dns.qry.name -e dns.resp.name -e dns.a -e dns.aaaa
    echo; echo '### HTTP and SSH version strings'
    printf '%s\n' "$software_rows" | md_table $'Frame\tSource IP\tDestination IP\tHTTP User-Agent\tHTTP Server\tSSH protocol\tCopies'
    report_command 1 'table_unique' -Y "$(bssid_filter) && (http.user_agent || http.server || ssh.protocol)" \
      -T fields -E separator=/t -E occurrence=f -E header=y -e frame.number -e ip.src -e ip.dst \
      -e http.user_agent -e http.server -e ssh.protocol
    # One decrypt pass emits all four statistics tables (tshark accepts repeated
    # -z), instead of re-dissecting the whole capture four times.
    echo; echo '### Decrypted L3 statistics (protocol hierarchy, IP endpoints, TCP/UDP conversations)'
    if printf '%s' "$l3stats" | grep -q '[^[:space:]]'; then
      echo '```text'; printf '%s\n' "$l3stats"; echo '```'
      report_command 1 '' -Y "$(bssid_filter)" -q -z io,phs -z endpoints,ip -z conv,tcp -z conv,udp
    else
      echo '_No matching evidence observed (decryption produced no L3 traffic for this target)._'
    fi

    echo; echo '## 11. Capture-quality checks'
    printf '| Check | Count | Interpretation |\n| --- | ---: | --- |\n'
    printf '| Truncated frames | %s | cap_len < frame.len |\n' "$truncated_count"
    printf '| Target retry frames | %s | Retries may reflect RF loss/contention; not unique traffic |\n' "$retry_count"
    echo
    report_command 0 'wc -l' -Y 'frame.cap_len < frame.len'
    report_command 0 'wc -l' -Y "$(bssid_filter) && wlan.fc.retry==1"

    echo; echo '## 12. Limitations, gaps, and questions'
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
  check_akm() { # <akms space-sep> <priv> <wpa1> <want-substr>
    local a="$1" p="$2" w="$3" want="$4" out
    out="$(printf '%s\n' $a | classify_akm "$p" "$w" | cut -f2)"
    if [[ "$out" == *"$want"* ]]; then
      ok "akm{$a}${p:+ priv}${w:+ wpa1} -> $out"
    else
      note "FAIL akm{$a}: got '$out', want '*$want*'"
      fail=1
    fi
  }
  check_akm "2" "" "" "WPA2-Personal (PSK)"
  check_akm "2 8" "" "" "transition"
  check_akm "8" "" "" "WPA3-Personal (SAE)"
  check_akm "1" "" "" "Enterprise (802.1X/EAP)" # regression: was "open/WEP?"
  check_akm "5 1" "" "" "Enterprise (802.1X/EAP)"
  check_akm "12" "" "" "Suite-B"
  check_akm "18" "" "" "OWE"
  check_akm "6" "" "" "WPA2-Personal (PSK)"
  check_akm "" "1" "" "WEP"
  check_akm "" "" "yes" "WPA1"
  check_akm "" "" "" "open"
  # WPA3 R3 group-dependent-hash SAE — a real AKM that used to fall through to
  # "open (no encryption)", the most dangerous possible mislabel.
  check_akm "24" "" "" "WPA3-Personal (SAE)"
  check_akm "25" "" "" "WPA3-Personal (SAE)"
  check_akm "2 24" "" "" "transition"

  # ---- RSN selector decoding -------------------------------------------------
  check_str() { # <label> <got> <want>
    if [ "$2" = "$3" ]; then ok "$1"; else
      note "FAIL $1: got '$2', want '$3'"
      fail=1
    fi
  }
  check_str "akm_names decodes SAE/PSK/OWE/Suite-B and labels unknowns" \
    "$(printf '8\n2\n18\n12\n24\n99\n' | akm_names | paste -sd, -)" \
    "SAE,PSK,OWE,802.1X-SuiteB-192-SHA384,SAE-GDH,AKM-99"
  check_str "cipher_names decodes CCMP/GCMP/TKIP and labels unknowns" \
    "$(printf '4\n8\n9\n10\n2\n99\n' | cipher_names | paste -sd, -)" \
    "CCMP-128,GCMP-128,GCMP-256,CCMP-256,TKIP,cipher-99"
  check_str "rsn_decode_row rewrites ciphers/AKMs in place and maps PMF to yes/no" \
    "$(printf 'aa:bb:cc:00:11:22\t1\t9\t9\t8,2\t1\t0\n' | rsn_decode_row | tr '\t' '|')" \
    "aa:bb:cc:00:11:22|1|GCMP-256|GCMP-256|SAE,PSK|yes|no"
  check_str "rsn_decode_row reads tshark's True/False booleans, not just 1/0" \
    "$(printf 'aa:bb:cc:00:11:22\tTrue\t4\t4\t8\tTrue\tFalse\n' | rsn_decode_row | tr '\t' '|')" \
    "aa:bb:cc:00:11:22|True|CCMP-128|CCMP-128|SAE|yes|no"
  check_str "rsn_decode_row leaves blank RSN columns blank (open network)" \
    "$(printf 'aa:bb:cc:00:11:22\t\t\t\t\t\t\n' | rsn_decode_row | tr '\t' '|')" \
    "aa:bb:cc:00:11:22||||||"

  # wifi_generation: capability elements -> marketing generation, plus randomized-MAC
  # detection. Pure logic, so assert it directly.
  check_str "wifi_generation reads HE/VHT/HT and flags randomized MACs" \
    "$(printf '00:11:22:00:00:01\tAcme_x\t0x1\t0x2\t\t5180\n7a:3d:76:c3:25:3f\t\t0x1\t\t\t2437\nfc:31:5d:5b:98:5e\tApple_y\t0x1\t0x2\t0x3\t5955\naa:bb:cc:00:00:09\t\t\t\t\t2437\n' |
        wifi_generation | awk -F'\t' '{print $1,$2,$3,$4}' | paste -sd';' -)" \
    "00:11:22:00:00:01 Acme_x hardware Wi-Fi 5 (11ac);7a:3d:76:c3:25:3f — randomized Wi-Fi 4 (11n);fc:31:5d:5b:98:5e Apple_y hardware Wi-Fi 6E (11ax, 6 GHz);aa:bb:cc:00:00:09 — randomized legacy 11a/b/g"
  check_str "ttl_os_hint maps observed TTL to a likely stack" \
    "$(printf '10.0.0.5\t64\n10.0.0.5\t64\n10.0.0.9\t128\n10.0.0.1\t255\n' |
        ttl_os_hint | awk -F'\t' '{print $1"="$3}' | paste -sd, -)" \
    "10.0.0.5=64,10.0.0.9=128,10.0.0.1=255"

  got="$(printf 'de:ad:be:ef:00:01\nff:ff:ff:ff:ff:ff\n01:00:5e:00:00:fb\n33:33:00:00:00:01\naa:bb:cc:dd:ee:00\n' |
    drop_group | tr '\n' ',')"
  exp="de:ad:be:ef:00:01,aa:bb:cc:dd:ee:00,"
  [ "$got" = "$exp" ] && ok "drop_group keeps only unicast" || {
    note "FAIL drop_group: $got"
    fail=1
  }

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
    local kn
    kn="$([ -s "${KEYRING:-/dev/null}" ] && grep -c . "$KEYRING" || echo 0)"
    cat <<EOF

  ${C_B}wifiscope${C_RESET}  pcap:${C_CYN}${PCAP##*/}${C_RESET}  target:${C_B}${SSID:-<none>}${C_RESET} ${C_DIM}(${#TGT_BSSIDS[@]} bssid)${C_RESET}  decrypt:$([ ${#DEC[@]} -gt 0 ] && printf "%son%s" "$C_GRN" "$C_RESET" || printf "%soff%s" "$C_DIM" "$C_RESET")  keys:${C_MAG}${kn}${C_RESET}
  ${C_DIM}──────────────────────────────────────────────────────────${C_RESET}
   ${C_CYN}ANALYZE${C_RESET}  1 recon   2 bands   3 crypto   4 hardware
            5 clients 6 keys    7 topology 8 hosts
            9 probes  0 handshakes  f fingerprint
   ${C_CYN}CRACK${C_RESET}    p pmkid   x export22000  ${C_DIM}(hashcat -m 22000)${C_RESET}
   ${C_CYN}KEYS${C_RESET}     k passphrase  h harvest  g scrapegtk  j keymaterial
            a addkey  i import  K show  d delkey  c clearkey
   ${C_CYN}SESSION${C_RESET}  s select-ssid  m map  M mapall  r report  q quit
  ${C_DIM}──────────────────────────────────────────────────────────${C_RESET}
EOF
    # `|| break` exits cleanly on end-of-input instead of spinning on empty reads.
    printf "${C_B}wifiscope›${C_RESET} "
    read -r c || break
    case "$c" in
      1|recon)      recon | paint ;;
      2|bands)      bands | paint ;;
      3|crypto)     crypto | paint ;;
      4|hardware)   hardware | paint ;;
      5|clients)    need_all_bssids; clients | paint ;;
      6|keys)       need_all_bssids; keys | paint ;;
      7|topology)   topology | paint ;;
      8|hosts)      hosts | paint ;;
      9|probes)     probes | paint ;;
      0|handshakes) need_all_bssids; handshakes | paint ;;
      f|fingerprint) fingerprint | paint ;;
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
      m|map)        printf 'drawio file [%s.drawio]: ' "${SSID:-net}"; read -e -r f; need_all_bssids; map "${f:-}" ;;
      M|mapall)     printf 'drawio file [network.drawio]: '; read -e -r f; need_all_bssids; mapall "${f:-}" ;;
      r)            printf 'report file [%s_analysis.md]: ' "${SSID:-report}"; read -e -r f; need_all_bssids; report "${f:-}" ;;
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
                          printf '       wifiscope.sh <pcap> [ssid] [passphrase]   # menu, no startup prompts\n'
                          printf 'commands: recon bands crypto hardware clients keys topology hosts\n'
                          printf '          probes handshakes fingerprint pmkid export22000 map mapall report\n'
                          printf '          harvest scrapegtk keymaterial keyring addkey import delkey clearkey\n'
                          printf '          selftest version   (run with no args for the interactive menu)\n'; return ;;
    selftest)             selftest; return ;;
  esac

  need "$TSHARK"

  # One-shot forms that take their own args (not ssid/passphrase):
  case "${1:-}" in
  addkey)
    shift
    [ -n "${1:-}" ] || die "usage: wifiscope.sh addkey <pcap> <type> <value>"
    load_pcap "$1"
    addkey "${2:-}" "${3:-}"
    return
    ;;
  import)
    shift
    [ -n "${1:-}" ] || die "usage: wifiscope.sh import <pcap> <keyfile>"
    load_pcap "$1"
    import "${2:-}"
    return
    ;;
  delkey)
    shift
    [ -n "${1:-}" ] || die "usage: wifiscope.sh delkey <pcap> <value|all>"
    load_pcap "$1"
    delkey "${2:-}"
    return
    ;;
  clearkey)
    shift
    [ -n "${1:-}" ] || die "usage: wifiscope.sh clearkey <pcap>"
    load_pcap "$1"
    clearkey
    return
    ;;
  esac

  # One-shot form:  wifiscope.sh <command> <pcap> [ssid] [passphrase]
  case "${1:-}" in
    recon|bands|crypto|hardware|clients|keys|topology|hosts|report|harvest|scrapegtk|keymaterial|keyring|pmkid|probes|handshakes|fingerprint|export22000|map|mapall)
      local cmd="$1"; shift
      [ -n "${1:-}" ] || die "usage: wifiscope.sh $cmd <pcap> [ssid] [passphrase]"
      load_pcap "$1"
      # mapall has no SSID/passphrase operands: arg 2 is an optional output path.
      if [ "$cmd" = mapall ]; then SSID=""; need_all_bssids; mapall "${2:-}"; return; fi
      SSID="${2:-}"
      [ -n "$SSID" ] && load_target_bssids
      # Only these need the whole-capture BSSID index; load it in the PARENT shell so
      # both `cmd` and `paint` (each a subshell of the pipe below) can see it.
      case "$cmd" in clients|keys|handshakes|map|report) need_all_bssids ;; esac
      if [ -n "${3:-}" ] && [ -n "$SSID" ]; then
        PASS="$3"; kr_add wpa-pwd "$PASS:$SSID"; rebuild_dec
      fi
      # bands/crypto/etc need an SSID; nudge if it's missing (recon/mapall don't).
      [ -z "$SSID" ] && [ "$cmd" != recon ] && [ "$cmd" != mapall ] && warn "no SSID given — pass one as arg 2 for scoped results"
      # Paint the read-only display commands; run the rest (report/harvest/…) direct.
      # mapall takes no SSID, so its arg-2 (if any) is the output .drawio filename.
      case " recon bands crypto hardware clients keys topology hosts pmkid probes handshakes fingerprint keymaterial " in
        *" $cmd "*) "$cmd" | paint ;;
        *) "$cmd" ;;
      esac
      return
      ;;
  esac

  # Interactive form:  wifiscope.sh [pcap] [ssid] [passphrase]
  if [ -n "${1:-}" ]; then
    load_pcap "$1"
  else
    # `read -e` turns on readline, giving filename TAB-completion + line editing.
    printf 'pcap file: '
    read -e -r p
    load_pcap "$p"
  fi

  # ---- FAST PATH:  wifiscope.sh <pcap> <SSID> [passphrase] ------------------
  # Naming the target up front makes both startup prompts redundant, so skip them.
  # What this saves: pick_ssid renders a picker you have already answered, and to do
  # that it reads the WHOLE capture twice (once for beacon SSIDs, once for hidden-AP
  # BSSIDs) plus one more full pass per hidden AP inside resolve_hidden. Naming the
  # SSID replaces all of that with one early-exit probe that stops at the first
  # matching beacon. Startup drops from 4+ full passes and 2 prompts to 1 partial
  # pass and 1 full pass (load_target_bssids, kept full so mesh/multi-AP targets
  # still resolve EVERY BSSID — scoping to one AP would quietly narrow every
  # downstream command).
  # Note these args used to be accepted and then silently ignored on this path.
  if [ -n "${2:-}" ]; then
    SSID="$2"
    if ssid_exists "$SSID"; then
      load_target_bssids
      note "target SSID: $SSID  (${#TGT_BSSIDS[@]} BSSIDs)"
    else
      warn "SSID \"$SSID\" is not in this capture — falling back to the picker"
      SSID=""
      pick_ssid
    fi
    # Passphrase as arg 3 replaces the set_key prompt. Blank/absent = leave
    # decryption off; the menu's `k` still adds one later.
    if [ -n "${3:-}" ] && [ -n "$SSID" ]; then
      PASS="$3"
      if kr_add wpa-pwd "$PASS:$SSID"; then
        rebuild_dec
        note "decryption enabled (wpa-pwd added to keyring)"
        sae_passphrase_warning
      fi
    fi
  else
    pick_ssid
    set_key
  fi
  menu
}

main "$@"
