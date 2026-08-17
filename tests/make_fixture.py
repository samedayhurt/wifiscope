#!/usr/bin/env python3
# make_fixture.py — build a small synthetic monitor-mode 802.11 capture that
# exercises wifiscope's cleartext-management analysis end to end (no decryption
# needed). Written with scapy; run:  python3 make_fixture.py out.pcap
#
# What it contains:
#   * a 2-unit mesh "MainNet": root (2.4 ch6 + guest SSID, 5GHz ch36) and a
#     satellite (2.4 ch11), joined by a 4-address WDS backhaul link
#   * a WPA3-SAE net "Modern3" and a WPA2-Enterprise net "CorpNet"
#   * a hidden AP (blank-SSID beacon) whose name "SecretNet" leaks in a probe resp
#   * one client: association request + a full 4-way EAPOL handshake + ToDS data
#   * one M1-only station, proving that a handshake start is not a recovered PTK
#
# MACs are laid out so ukey()/near() cluster each physical unit correctly:
#   root radios share octets 3-5 = 22:aa:bb, satellite = 22:cc:dd.
import sys, struct
from scapy.all import (RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt,
                       Dot11AssoReq, Dot11EltRSN, AKMSuite, RSNCipherSuite,
                       LLC, SNAP, EAPOL, wrpcap)

out = sys.argv[1] if len(sys.argv) > 1 else 'sample.pcap'
pkts = []

def rtap(freq):
    # RadioTap with just the Channel field so radiotap.channel.freq is populated.
    return RadioTap(present='Channel', ChannelFrequency=freq, ChannelFlags=0)

def rsn(akms):
    return Dot11EltRSN(group_cipher_suite=RSNCipherSuite(cipher=4),
                       pairwise_cipher_suites=[RSNCipherSuite(cipher=4)],
                       akm_suites=[AKMSuite(suite=a) for a in akms],
                       mfp_capable=1)

def beacon(bssid, ssid, freq, ch, akms=(2,), hidden=False, guest=None):
    d = RadioTap()/Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                         addr2=bssid, addr3=bssid)
    d /= Dot11Beacon(cap='ESS+privacy')
    d /= Dot11Elt(ID='SSID', info=b'' if hidden else ssid.encode())
    d /= Dot11Elt(ID='DSset', info=bytes([ch]))
    if akms:
        d /= rsn(list(akms))
    return rtap(freq).__class__(bytes(d))  # normalise

def frame(freq, dot11, payload=None):
    p = rtap(freq)/dot11
    if payload is not None:
        p = p/payload
    return p

# --- root unit: MainNet 2.4 (ch6), Guest 2.4 (ch6), MainNet 5GHz (ch36) --------
ROOT_24, ROOT_G, ROOT_5 = '00:11:22:aa:bb:00', '00:11:22:aa:bb:01', '00:11:22:aa:bb:02'
SAT_24 = '00:11:22:cc:dd:00'
for _ in range(3):
    pkts.append(frame(2437, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ROOT_24, addr3=ROOT_24)
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'MainNet')
                      /Dot11Elt(ID='DSset', info=bytes([6]))/rsn([2])))
    pkts.append(frame(2437, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ROOT_G, addr3=ROOT_G)
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'Guest')
                      /Dot11Elt(ID='DSset', info=bytes([6]))/rsn([2])))
    pkts.append(frame(5180, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ROOT_5, addr3=ROOT_5)
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'MainNet')
                      /Dot11Elt(ID='DSset', info=bytes([36]))/rsn([2])))
    pkts.append(frame(2462, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=SAT_24, addr3=SAT_24)
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'MainNet')
                      /Dot11Elt(ID='DSset', info=bytes([11]))/rsn([2])))

# --- other nets: WPA3-SAE and WPA2-Enterprise ---------------------------------
for _ in range(2):
    pkts.append(frame(2412, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='00:11:22:99:88:00', addr3='00:11:22:99:88:00')
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'Modern3')
                      /Dot11Elt(ID='DSset', info=bytes([1]))/rsn([8])))
    pkts.append(frame(2417, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='00:11:22:77:66:00', addr3='00:11:22:77:66:00')
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'CorpNet')
                      /Dot11Elt(ID='DSset', info=bytes([2]))/rsn([1])))

# --- hidden AP: blank-SSID beacon + a probe response that leaks the name --------
HID = '00:11:22:ee:ff:00'
for _ in range(2):
    pkts.append(frame(2412, Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=HID, addr3=HID)
                      /Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'')
                      /Dot11Elt(ID='DSset', info=bytes([1]))/rsn([2])))
pkts.append(frame(2412, Dot11(type=0, subtype=5, addr1='aa:bb:cc:00:00:09', addr2=HID, addr3=HID)
                  /Dot11ProbeResp(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'SecretNet')
                  /Dot11Elt(ID='DSset', info=bytes([1]))/rsn([2])))

# --- client on root MainNet: assoc req, 4-way handshake, ToDS data -------------
CLI = 'aa:bb:cc:00:00:01'
pkts.append(frame(2437, Dot11(type=0, subtype=0, addr1=ROOT_24, addr2=CLI, addr3=ROOT_24)
                  /Dot11AssoReq(cap='ESS+privacy')/Dot11Elt(ID='SSID', info=b'MainNet')
                  /Dot11Elt(ID='DSset', info=bytes([6]))))

def eapol_key(src, dst, bssid, key_info, nonce, to_ds):
    # Hand-build an 802.1X EAPOL-Key body so tshark derives keydes.msgnr from the
    # Key Information bits. Layout per IEEE 802.11 EAPOL-Key.
    body  = bytes([2])                       # descriptor type = RSN
    body += struct.pack('>H', key_info)      # key information
    body += struct.pack('>H', 16)            # key length
    body += b'\x00'*8                        # replay counter
    body += nonce                            # key nonce (32)
    body += b'\x00'*16                       # key IV
    body += b'\x00'*8                        # key RSC
    body += b'\x00'*8                        # key ID
    body += b'\x00'*16                       # key MIC
    body += struct.pack('>H', 0)             # key data length
    fc = Dot11(type=2, subtype=0, FCfield=('to-DS' if to_ds else 'from-DS'),
               addr1=dst, addr2=src, addr3=bssid)
    return frame(2437, fc, LLC()/SNAP(code=0x888e)/EAPOL(version=2, type=3)/body)

AN = bytes(range(32))                        # ANonce
SN = bytes(range(32, 64))                    # SNonce
KI = {1: 0x008a, 2: 0x010a, 3: 0x13ca, 4: 0x030a}  # msg1..4 key-info (m3 has enc-data bit)
pkts.append(eapol_key(ROOT_24, CLI, ROOT_24, KI[1], AN, to_ds=False))   # AP->STA
pkts.append(eapol_key(CLI, ROOT_24, ROOT_24, KI[2], SN, to_ds=True))    # STA->AP
pkts.append(eapol_key(ROOT_24, CLI, ROOT_24, KI[3], AN, to_ds=False))   # AP->STA
pkts.append(eapol_key(CLI, ROOT_24, ROOT_24, KI[4], b'\x00'*32, to_ds=True))  # STA->AP

# A second station only receives M1. It is a valid station observation, but must
# never increment the "recoverable PTK context" count.
CLI_M1 = 'aa:bb:cc:00:00:02'
pkts.append(eapol_key(ROOT_24, CLI_M1, ROOT_24, KI[1], AN, to_ds=False))

# ToDS data uplink (client transmits to AP) — extra station-discovery evidence.
pkts.append(frame(2437, Dot11(type=2, subtype=0, FCfield='to-DS',
                  addr1=ROOT_24, addr2=CLI, addr3='ff:ff:ff:ff:ff:ff')/LLC()/SNAP(code=0x0806)/(b'\x00'*28)))

# --- WDS 4-address backhaul: satellite backhaul radio <-> root backhaul radio ---
ROOT_BH, SAT_BH = '00:11:22:aa:bb:10', '00:11:22:cc:dd:10'
for _ in range(3):
    d = Dot11(type=2, subtype=0, FCfield='to-DS+from-DS',
              addr1=ROOT_BH, addr2=SAT_BH, addr3='00:11:22:aa:bb:00', addr4=SAT_BH)
    pkts.append(frame(5180, d, LLC()/SNAP(code=0x0800)/(b'\x00'*20)))

wrpcap(out, pkts)
print('wrote %s (%d frames)' % (out, len(pkts)))
