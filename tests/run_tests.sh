#!/usr/bin/env bash
# run_tests.sh — end-to-end regression tests for wifiscope.
#
# Builds a synthetic capture with scapy (tests/make_fixture.py), then runs
# wifiscope one-shot commands against it and asserts on the output. Also runs the
# built-in pure-logic selftest. Exits non-zero on any failure.
#
#   ./tests/run_tests.sh
#
# Requires: tshark, python3 + scapy. If scapy is missing the pcap-based tests are
# skipped (the selftest still runs) and the script still passes.
set -uo pipefail
cd "$(dirname "$0")/.."
WS=./wifiscope.sh
# The report test re-exports TSHARK into a subshell. Under `set -u` an unset TSHARK
# killed that subshell before the report was ever written, so its six assertions all
# failed on a missing file rather than on anything about the report. Default it here,
# the same way wifiscope.sh itself does.
TSHARK="${TSHARK:-tshark}"
PASS=0 FAIL=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PCAP="$TMP/sample.pcap"

ok()   { printf '  \033[32m✔\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m✘ %s\033[0m\n' "$1"; FAIL=$((FAIL+1)); }
# assert_has <description> <needle> <<< "$haystack"
assert_has() { local d="$1" n="$2" h; h="$(cat)"; case "$h" in *"$n"*) ok "$d";; *) bad "$d — missing: $n";; esac; }
assert_lacks() { local d="$1" n="$2" h; h="$(cat)"; case "$h" in *"$n"*) bad "$d — unexpectedly found: $n";; *) ok "$d";; esac; }

echo "== selftest =="
if NO_COLOR=1 "$WS" selftest >/dev/null 2>&1; then ok "built-in selftest passes"; else bad "built-in selftest FAILED"; fi

echo "== fixture =="
PYTHON_REAL="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYTHON_REAL" ] || ! "$PYTHON_REAL" -c 'import scapy' 2>/dev/null; then
  printf '  \033[33m· scapy not installed — skipping pcap-based tests\033[0m\n'
  echo; echo "passed=$PASS failed=$FAIL"; [ "$FAIL" -eq 0 ]; exit
fi
"$PYTHON_REAL" tests/make_fixture.py "$PCAP" >/dev/null 2>&1 && ok "built synthetic capture" || { bad "fixture build failed"; exit 1; }

run() { NO_COLOR=1 "$WS" "$@" 2>/dev/null; }   # stdout only (data); stderr = teaching lines

echo "== recon =="
recon="$(run recon "$PCAP")"
assert_has "recon lists MainNet" MainNet <<<"$recon"
assert_has "recon lists Guest"   Guest   <<<"$recon"
assert_has "recon lists Modern3" Modern3 <<<"$recon"
assert_has "recon lists CorpNet" CorpNet <<<"$recon"

echo "== crypto verdicts =="
assert_has "MainNet -> WPA2-Personal (PSK)"       "WPA2-Personal (PSK)"     <<<"$(run crypto "$PCAP" MainNet)"
assert_has "Modern3 -> WPA3-Personal (SAE)"       "WPA3-Personal (SAE)"     <<<"$(run crypto "$PCAP" Modern3)"
assert_has "CorpNet -> Enterprise (not open/WEP)" "Enterprise (802.1X/EAP)" <<<"$(run crypto "$PCAP" CorpNet)"

echo "== bands (2.4 + 5GHz) =="
bands="$(run bands "$PCAP" MainNet)"
assert_has "MainNet has a 2.4GHz ch6 radio" "ch6"  <<<"$bands"
assert_has "MainNet has a 5GHz ch36 radio"  "ch36" <<<"$bands"
assert_has "5GHz band labelled"             "5GHz" <<<"$bands"

echo "== station discovery =="
assert_has "client found (assoc+data+eapol)" "aa:bb:cc:00:00:01" <<<"$(run clients "$PCAP" MainNet)"

echo "== handshakes =="
assert_has "client handshake is crackable" "crackable:YES" <<<"$(run handshakes "$PCAP" MainNet)"
assert_has "M1-only station is listed" "aa:bb:cc:00:00:02" <<<"$(run handshakes "$PCAP" MainNet)"
assert_has "M1-only station is not called crackable" "msgs:1···  crackable:no" <<<"$(run handshakes "$PCAP" MainNet)"
assert_has "PTK count excludes M1-only station" "recoverable PTK contexts: 1" <<<"$(run keys "$PCAP" MainNet)"

echo "== topology (backhaul) =="
assert_has "WDS backhaul link seen" "00:11:22:cc:dd:10" <<<"$(run topology "$PCAP" MainNet)"

echo "== mapall (whole-capture drawio) =="
printf '#!/usr/bin/env bash\nprintf called > %q\nexit 97\n' "$TMP/nonreport-python-called" > "$TMP/python3-forbidden"
chmod +x "$TMP/python3-forbidden"
PYTHON3="$TMP/python3-forbidden" run mapall "$PCAP" "$TMP/net.drawio" >/dev/null 2>&1
if "$PYTHON_REAL" -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('$TMP/net.drawio')" 2>/dev/null; then ok "mapall produced well-formed drawio"; else bad "mapall drawio malformed"; fi
assert_has "public map identifies Bash/AWK generator" "Bash/AWK" <<<"$(cat "$TMP/net.drawio")"
assert_has "map draws MainNet SSID on a unit" "MainNet" <<<"$(cat "$TMP/net.drawio")"
assert_has "map draws a WDS backhaul edge"    "WDS backhaul" <<<"$(cat "$TMP/net.drawio")"

echo "== Bash/OpenSSL key derivation =="
if command -v openssl >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1 && openssl kdf -help >/dev/null 2>&1; then
  PYTHON3="$TMP/python3-forbidden" run harvest "$PCAP" MainNet fixturepass >/dev/null 2>&1
  assert_has "harvest produced a wpa-psk entry" $'wpa-psk\t' <<<"$(cat "$PCAP.keys")"
  assert_has "harvest produced a PTK-TK entry" $'tk\t' <<<"$(cat "$PCAP.keys")"
else
  printf '  \033[33m· OpenSSL 3.x/xxd unavailable — skipping harvest regression\033[0m\n'
fi
if [ ! -e "$TMP/nonreport-python-called" ]; then ok "map/harvest did not invoke python3"; else bad "a non-report command invoked python3"; fi

# Regression: every display command must survive a capture with no DHCP/no keys.
# `hardware` used to abort with "gw_ident: unbound variable" in exactly that case.
# Concurrency guard. report/fingerprint fan out one full-capture tshark pass per
# evidence family; launching them all at once exhausted a VM's RAM on a 255 MB
# capture and wedged the box. Every backgrounded pass must sit behind _jobgate, and
# no pass may write one line per packet to a temp file. Structural, so it cannot
# flake, and it fails the moment someone adds an ungated pass.
echo "== every backgrounded tshark pass is concurrency-gated =="
# Look back past comments and blank lines: a gate separated from its launch by a
# comment block is still correct, since only executable lines run.
_ungated="$(awk '
  /^[[:space:]]*(#|$)/ { next }
  /^[[:space:]]*(\{ tq|\[ "\$has_(gps|tk)" = 1 \] && \{ tq)/ {
    if (prev !~ /^[[:space:]]*_jobgate$/) print NR": "substr($0,1,60)
  }
  { prev = $0 }' "$WS")"
if [ -z "$_ungated" ]; then ok "all backgrounded tshark passes are behind _jobgate"
else bad "ungated tshark pass(es): $(printf '%s' "$_ungated" | head -3 | tr '\n' ' ')"; fi
grep -q '^_jobgate() {' "$WS" && ok "_jobgate helper is defined" || bad "_jobgate helper missing"
grep -q 'WS_JOBS="${WIFISCOPE_JOBS:-0}"' "$WS" && ok "WIFISCOPE_JOBS override is honored" || bad "WIFISCOPE_JOBS override missing"
# Assert the four passes that used to emit one row per packet now summarise inside
# the pipeline. A launch group can span several lines (backslash continuations, a
# trailing pipe, or a multi-line awk program in quotes), so look back from the
# redirect rather than trying to rejoin the group into one line.
for _p in fpcap:wifi_generation fpttl:ttl_os_hint macseen:awk probe_all:awk; do
  _f="${_p%%:*}"; _agg="${_p##*:}"
  if grep -B7 -F "> \"\$D/$_f\" &" "$WS" | grep -qF "$_agg"; then
    ok "$_f aggregates in-pass (bounded by devices, not packets)"
  else bad "$_f is not aggregated in-pass - temp file would grow with packet count"; fi
done

# The progress bar's denominator is a literal, so it silently goes wrong the moment
# someone adds or removes a pass. Assert it still matches the real gate count, and
# that progress stays terminal-only so reports and pipes cannot be polluted.
echo "== progress indicator is consistent and terminal-only =="
_rpt_gates="$(awk '/^report\(\) \{/,/^\}$/' "$WS" | grep -c '^  _jobgate$')"
_rpt_total="$(grep -m1 -oE 'local _pg_total=[0-9]+' "$WS" | grep -oE '[0-9]+')"
if [ "$_rpt_gates" = "$_rpt_total" ]; then ok "report progress total ($_rpt_total) matches its $_rpt_gates gated passes"
else bad "report progress total is $_rpt_total but there are $_rpt_gates gated passes"; fi
_fp_gates="$(awk '/^fingerprint\(\) \{/,/^\}$/' "$WS" | grep -c '^  _jobgate$')"
_fp_total="$(awk '/^fingerprint\(\) \{/,/^\}$/' "$WS" | grep -m1 -oE '_progress_start [0-9]+' | grep -oE '[0-9]+')"
if [ "$_fp_gates" = "$_fp_total" ]; then ok "fingerprint progress total ($_fp_total) matches its $_fp_gates gated passes"
else bad "fingerprint progress total is $_fp_total but there are $_fp_gates gated passes"; fi
grep -q 'PG_ON=0' "$WS" && grep -q '\[ -t 2 \]' "$WS" && ok "progress is gated on stderr being a terminal" || bad "progress is not tty-gated"
grep -q 'WIFISCOPE_NO_PROGRESS' "$WS" && ok "WIFISCOPE_NO_PROGRESS opt-out exists" || bad "no progress opt-out"
# Progress must never reach the report or a redirected stderr. Run in a scratch dir
# with an ABSOLUTE script path, and assert the run actually produced a report -
# otherwise a failed invocation makes the leak checks pass vacuously.
_wsabs="$PWD/wifiscope.sh"
_pgdir="$TMP/pgcheck"; mkdir -p "$_pgdir"
_perr="$_pgdir/stderr.txt"
( cd "$_pgdir" && NO_COLOR=1 TSHARK="$TSHARK" "$_wsabs" report "$PCAP" MainNet >/dev/null 2>"$_perr" )
_pgmd="$_pgdir/wifiscope_MainNet.md"
if [ -s "$_pgmd" ]; then
  ok "progress leak check actually produced a report to inspect"
  if grep -qE '━|leave it running|passes complete' "$_perr"; then bad "progress leaked into redirected stderr"
  else ok "no progress output when stderr is not a terminal"; fi
  if grep -qE '━|leave it running' "$_pgmd"; then bad "progress leaked into the report"
  else ok "no progress output in the report file"; fi
else
  bad "progress leak check could not generate a report ($_pgmd missing)"
fi

echo "== all display commands survive a no-decryption capture =="
for _c in recon bands crypto hardware clients keys topology hosts probes handshakes fingerprint pmkid; do
  _out="$(NO_COLOR=1 TSHARK="$TSHARK" "$WS" "$_c" "$PCAP" MainNet 2>&1)"
  case "$_out" in
    *"unbound variable"*|*"syntax error"*|*"command not found"*)
      bad "$_c aborted: $(printf '%s' "$_out" | grep -m1 -E 'unbound variable|syntax error|command not found')" ;;
    *) ok "$_c ran clean" ;;
  esac
done

echo "== report + evidence-qualified map =="
printf 'tk\t00112233445566778899aabbccddeeff\n' > "$PCAP.keys"
ROOT="$(pwd)"
printf '#!/usr/bin/env bash\nprintf called > %q\nexec %q "$@"\n' "$TMP/report-python-called" "$PYTHON_REAL" > "$TMP/report-python3"
chmod +x "$TMP/report-python3"
(cd "$TMP" && NO_COLOR=1 TSHARK="$TSHARK" PYTHON3="$TMP/report-python3" "$ROOT/wifiscope.sh" report "$PCAP" MainNet >/dev/null 2>&1)
REPORT="$TMP/wifiscope_MainNet.md"; RMAP="$TMP/wifiscope_MainNet.drawio"
if [ -e "$TMP/report-python-called" ]; then ok "python3 was confined to report generation"; else bad "report did not invoke its report-only python3"; fi
assert_has "report has Obsidian frontmatter" "title: 'MainNet Mission Report'" <<<"$(cat "$REPORT")"
assert_has "report frontmatter carries author and date" "author: '" <<<"$(cat "$REPORT")"
assert_has "mission report answers Router Info first" "- **2.4GHz MAC:**" <<<"$(cat "$REPORT")"
assert_has "mission report lists associated-MAC selectors" "### Associated MACs" <<<"$(cat "$REPORT")"
assert_has "mission report has operator sections" "# Actions Taken" <<<"$(cat "$REPORT")"
assert_has "mission report precedes the detail half" "# Detailed evidence" <<<"$(cat "$REPORT")"
assert_has "report has clean Markdown tables" "| BSSID | SSID | Resolved BSSID |" <<<"$(cat "$REPORT")"
assert_has "report includes reproduction commands" "<summary>Reproduce with TShark</summary>" <<<"$(cat "$REPORT")"
# Keys are INCLUDED by default (an autopsy of your own lab capture is useless
# without them); redaction is opt-in via WIFISCOPE_REPORT_SECRETS=0. Assert both
# directions — the old test asserted only redaction and, because it never ran, it
# silently disagreed with the shipped default.
assert_has "report includes stored key material by default" "00112233445566778899aabbccddeeff" <<<"$(cat "$REPORT")"
assert_has "report shows the real key in the reproduction command" 'uat:80211_keys:"tk","00112233445566778899aabbccddeeff"' <<<"$(cat "$REPORT")"
# Run in its own directory: the one-shot form treats arg 3 as the PASSPHRASE, so a
# filename there would be added to the keyring instead of naming the output.
mkdir -p "$TMP/red"
(cd "$TMP/red" && NO_COLOR=1 TSHARK="$TSHARK" WIFISCOPE_REPORT_SECRETS=0 PYTHON3="$TMP/report-python3" \
  "$ROOT/wifiscope.sh" report "$PCAP" MainNet >/dev/null 2>&1)
REDACTED="$TMP/red/wifiscope_MainNet.md"
assert_has "WIFISCOPE_REPORT_SECRETS=0 redacts the keyring inventory" 'stored value(s) — REDACTED' <<<"$(cat "$REDACTED")"
assert_has "WIFISCOPE_REPORT_SECRETS=0 templates the reproduction key set" 'uat:80211_keys:"wpa-pwd","<passphrase>:<SSID>"' <<<"$(cat "$REDACTED")"
assert_lacks "WIFISCOPE_REPORT_SECRETS=0 does not leak the stored TK" "00112233445566778899aabbccddeeff" <<<"$(cat "$REDACTED")"
assert_has "unproven AP is a root candidate" "ROOT CANDIDATE" <<<"$(cat "$RMAP")"
assert_lacks "map never invents an ISP/WAN" "Internet / ISP" <<<"$(cat "$RMAP")"
assert_lacks "map never claims an unproved gateway" "ROOT / GATEWAY" <<<"$(cat "$RMAP")"

# Obsidian is stricter than GitHub about HTML blocks wrapping fenced code: the tags
# need their own lines with blank lines around the markdown inside, or the fence leaks
# out and every following section renders as one run-on blob.
echo "== report markdown is Obsidian-safe =="
assert_lacks "no inline <details><summary> on one line" "<details><summary>" <<<"$(cat "$REPORT")"
_dopen="$(grep -c '^<details>$' "$REPORT")"; _dclose="$(grep -c '^</details>$' "$REPORT")"
[ "$_dopen" = "$_dclose" ] && [ "$_dopen" -gt 0 ] \
  && ok "details tags are balanced and on their own lines ($_dopen pairs)" \
  || bad "details tags unbalanced: $_dopen open vs $_dclose close"
awk '/^```/{n++} END{exit (n%2)}' "$REPORT" \
  && ok "code fences are balanced" || bad "code fences are unbalanced"
# A blank line must separate a fence close from </details>, else Obsidian mis-nests.
if grep -B1 '^</details>$' "$REPORT" | grep -q '^```$'; then
  bad "a fence close butts directly against </details>"
else ok "every </details> is preceded by a blank line"; fi
assert_lacks "no empty '-' list items" $'\n-\n' <<<"$(cat "$REPORT")"

echo "== handshake hashes are exported by the report =="
assert_has "report has a hashcat-22000 section" "### hashcat-22000 export" <<<"$(cat "$REPORT")"
assert_has "mission block reports the hashcat export" "**hashcat-22000 export:**" <<<"$(cat "$REPORT")"
grep -q '^_hc22000_build() {' "$WS" && ok "_hc22000_build helper exists" || bad "_hc22000_build missing"
# It must never abort its caller the way the old inline `need "$XXD"` could.
awk '/^_hc22000_build\(\) \{/,/^\}$/' "$WS" | grep -q 'need ' \
  && bad "_hc22000_build can still die() via need" \
  || ok "_hc22000_build cannot abort the report"

echo "== decrypt recipe sits with the router info AND stays in section 6 =="
assert_has "Key Material block next to Router Info" "### Key Material" <<<"$(cat "$REPORT")"
assert_has "section 6 key inventory still present" "### Stored keyring inventory" <<<"$(cat "$REPORT")"
assert_has "recipe names the keyring file" "reapplies them on every run" <<<"$(cat "$REPORT")"

echo "== probing MACs are scoped to the selected target =="
assert_has "probing section explains the scoping" "hunting for **this** network" <<<"$(cat "$REPORT")"
awk '/> "\$D\/probe_all" &/{found=1} /wlan.fc.type_subtype==4/{if(!seen){seen=1}} END{}' "$WS" >/dev/null
if grep -B6 '> "\$D/probe_all" &' "$WS" | grep -q 'wlan.ssid==' ; then
  ok "probe_all pass filters on the selected SSID/BSSID"
else bad "probe_all pass is still capture-wide"; fi


echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
