"""
test_arp.py - Generates harmless test ARP traffic so the detector can be demonstrated.
Run ONLY on your own network, as Administrator, while monitoring is active.
It uses an unused IP address on purpose, so it does not disturb any real device.
"""
import time
from scapy.all import ARP, Ether, sendp, get_if_list, conf

# ---- EDIT THESE TWO LINES ----
# Pick an IP on your Wi-Fi subnet that NO device is using (e.g. if your laptop is 192.168.1.5, use 192.168.1.250).
# Do NOT use your router's IP, that would really poison other devices.
FAKE_IP = "10.143.52.250"
# Leave as None to use your default interface, or paste the name Scapy shows for your Wi-Fi adapter.
IFACE = None
# ------------------------------

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"

iface = IFACE or conf.iface
print(f"Using interface: {iface}")

def arp_reply(mac):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac, psrc=FAKE_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=FAKE_IP
    )

# Test 1: ARP poisoning pattern - the same IP claimed by two different MAC addresses
print("Test 1: sending conflicting ARP replies (IP-to-MAC mismatch)...")
for _ in range(3):
    sendp(arp_reply(MAC_A), iface=iface, verbose=False)
    time.sleep(0.5)
    sendp(arp_reply(MAC_B), iface=iface, verbose=False)
    time.sleep(0.5)

# Test 2: ARP flood - a large burst of ARP packets in a short time
print("Test 2: sending an ARP flood (200 packets)...")
for i in range(200):
    sendp(arp_reply(MAC_A), iface=iface, verbose=False)
    time.sleep(0.01)

print("Done. Wait a few seconds, then check the dashboard (it refreshes every 10 seconds).")