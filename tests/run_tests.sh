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

echo "== report + evidence-qualified map =="
printf 'tk\t00112233445566778899aabbccddeeff\n' > "$PCAP.keys"
ROOT="$(pwd)"
printf '#!/usr/bin/env bash\nprintf called > %q\nexec %q "$@"\n' "$TMP/report-python-called" "$PYTHON_REAL" > "$TMP/report-python3"
chmod +x "$TMP/report-python3"
(cd "$TMP" && NO_COLOR=1 TSHARK="$TSHARK" PYTHON3="$TMP/report-python3" "$ROOT/wifiscope.sh" report "$PCAP" MainNet >/dev/null 2>&1)
REPORT="$TMP/wifiscope_MainNet.md"; RMAP="$TMP/wifiscope_MainNet.drawio"
if [ -e "$TMP/report-python-called" ]; then ok "python3 was confined to report generation"; else bad "report did not invoke its report-only python3"; fi
assert_has "report has Obsidian frontmatter" "title: 'WiFiScope autopsy — MainNet'" <<<"$(cat "$REPORT")"
assert_has "report has clean Markdown tables" "| BSSID | SSID | Resolved BSSID |" <<<"$(cat "$REPORT")"
assert_has "report includes reproduction commands" "<summary>Reproduce with TShark</summary>" <<<"$(cat "$REPORT")"
assert_has "report redacts key values" 'uat:80211_keys:"tk","REDACTED"' <<<"$(cat "$REPORT")"
assert_lacks "report does not leak stored TK" "00112233445566778899aabbccddeeff" <<<"$(cat "$REPORT")"
assert_has "unproven AP is a root candidate" "ROOT CANDIDATE" <<<"$(cat "$RMAP")"
assert_lacks "map never invents an ISP/WAN" "Internet / ISP" <<<"$(cat "$RMAP")"
assert_lacks "map never claims an unproved gateway" "ROOT / GATEWAY" <<<"$(cat "$RMAP")"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
