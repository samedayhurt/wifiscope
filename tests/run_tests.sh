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

echo "== selftest =="
if NO_COLOR=1 "$WS" selftest >/dev/null 2>&1; then ok "built-in selftest passes"; else bad "built-in selftest FAILED"; fi

echo "== fixture =="
if ! python3 -c 'import scapy' 2>/dev/null; then
  printf '  \033[33m· scapy not installed — skipping pcap-based tests\033[0m\n'
  echo; echo "passed=$PASS failed=$FAIL"; [ "$FAIL" -eq 0 ]; exit
fi
python3 tests/make_fixture.py "$PCAP" >/dev/null 2>&1 && ok "built synthetic capture" || { bad "fixture build failed"; exit 1; }

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

echo "== topology (backhaul) =="
assert_has "WDS backhaul link seen" "00:11:22:cc:dd:10" <<<"$(run topology "$PCAP" MainNet)"

echo "== mapall (whole-capture drawio) =="
run mapall "$PCAP" "$TMP/net.drawio" >/dev/null 2>&1
if python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('$TMP/net.drawio')" 2>/dev/null; then ok "mapall produced well-formed drawio"; else bad "mapall drawio malformed"; fi
assert_has "map draws MainNet SSID on a unit" "MainNet" <<<"$(cat "$TMP/net.drawio")"
assert_has "map draws a WDS backhaul edge"    "WDS backhaul" <<<"$(cat "$TMP/net.drawio")"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
