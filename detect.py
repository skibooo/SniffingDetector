from database import log_alert
from scapy.all import ARP, DNS, DNSQR, IP, IPv6
from collections import defaultdict
import time

# ---------------- Settings ----------------
ARP_THRESHOLD = 20          # more than this many ARP packets from one device...
TIME_WINDOW = 5             # ...within this many seconds counts as flooding
DNS_REVERSE_THRESHOLD = 5   # this many reverse DNS lookups...
DNS_WINDOW = 30             # ...within this many seconds counts as suspicious
ALERT_COOLDOWN = 30         # seconds before the same alert can be logged again

# ---------------- Memory of what the detector has seen ----------------
ip_mac_table = {}                    # trusted IP -> MAC pairs (learned on first sight)
arp_tracker = defaultdict(list)      # timestamps of ARP packets per MAC address
dns_tracker = defaultdict(list)      # timestamps of reverse DNS queries per source IP
last_alert = {}                      # when each alert was last logged


def should_alert(key):
    """Returns True only if this same alert has not been logged in the last ALERT_COOLDOWN seconds."""
    now = time.time()
    last = last_alert.get(key)
    if last is not None and now - last < ALERT_COOLDOWN:
        return False
    last_alert[key] = now
    return True


def detect_arp(packet):
    """
    Detects ARP attacks using two rules:
    1. ARP poisoning: an IP address that was already seen with one MAC address
       is now claimed by a DIFFERENT MAC address.
    2. ARP flooding: one device sends too many ARP packets in a short time.
    """
    if not packet.haslayer(ARP):
        return False

    arp = packet[ARP]
    ip = arp.psrc
    mac = arp.hwsrc.lower()
    now = time.time()
    alerted = False

    # ---- Rule 1: IP-to-MAC mismatch (ARP poisoning) ----
    if ip and ip != "0.0.0.0":
        known_mac = ip_mac_table.get(ip)
        if known_mac is None:
            ip_mac_table[ip] = mac          # first time we see this IP: remember it
        elif known_mac != mac:              # same IP, different MAC: someone is lying
            if should_alert(("poison", ip, mac)):
                details = (
                    f"ARP poisoning suspected. IP {ip} was registered to MAC {known_mac}, "
                    f"but MAC {mac} is now claiming it."
                )
                recommendation = (
                    "Enable Dynamic ARP Inspection (DAI) on your network. "
                    "Use static ARP entries for the gateway and consider enabling WPA3 and a VPN."
                )
                log_alert(
                    ip_address=ip,
                    mac_address=mac,
                    attack_type="ARP Poisoning",
                    details=details,
                    recommendation=recommendation
                )
                print(f"[ALERT] ARP Poisoning: {ip} changed from {known_mac} to {mac}")
                alerted = True

    # ---- Rule 2: ARP flooding ----
    arp_tracker[mac] = [t for t in arp_tracker[mac] if now - t < TIME_WINDOW]
    arp_tracker[mac].append(now)
    count = len(arp_tracker[mac])

    if count > ARP_THRESHOLD:
        if should_alert(("flood", mac)):
            details = (
                f"ARP flooding detected from MAC {mac} (IP {ip}). "
                f"{count} ARP packets in {TIME_WINDOW} seconds."
            )
            recommendation = (
                "This may indicate MAC flooding or network reconnaissance. "
                "Block the device and enforce WPA3 encryption."
            )
            log_alert(
                ip_address=ip,
                mac_address=mac,
                attack_type="ARP Flooding",
                details=details,
                recommendation=recommendation
            )
            print(f"[ALERT] ARP Flooding from {ip} ({mac})")
            alerted = True

    return alerted


def detect_dns(packet):
    """
    Detects suspicious DNS reverse lookups, characteristic of sniffing tools
    resolving captured IP addresses into hostnames.
    Only DNS QUERIES are counted (not the server's replies), and the counter
    only covers the last DNS_WINDOW seconds.
    """
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return False

    # qr = 0 means a query, qr = 1 means a reply. Replies are ignored.
    if packet[DNS].qr != 0:
        return False

    query = packet[DNSQR].qname.decode(errors="ignore")

    # Reverse DNS lookups end in .in-addr.arpa or .ip6.arpa
    if not (query.endswith(".in-addr.arpa.") or query.endswith(".ip6.arpa.")):
        return False

    # Find who sent the query (works for IPv4 and IPv6)
    if packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
    elif packet.haslayer(IP):
        src_ip = packet[IP].src
    else:
        src_ip = "Unknown"

    now = time.time()
    dns_tracker[src_ip] = [t for t in dns_tracker[src_ip] if now - t < DNS_WINDOW]
    dns_tracker[src_ip].append(now)
    count = len(dns_tracker[src_ip])

    if count >= DNS_REVERSE_THRESHOLD:
        if should_alert(("dns", src_ip)):
            details = (
                f"Excessive reverse DNS lookups from {src_ip}. "
                f"{count} reverse lookups in {DNS_WINDOW} seconds. "
                f"Last query: {query}"
            )
            recommendation = (
                "Reverse DNS lookups are a common indicator of active packet sniffing. "
                "Investigate this device immediately. Enable WPA3 and consider VPN usage."
            )
            log_alert(
                ip_address=src_ip,
                mac_address="N/A",
                attack_type="Suspicious DNS Activity",
                details=details,
                recommendation=recommendation
            )
            print(f"[ALERT] Suspicious DNS reverse lookups from {src_ip}")
            dns_tracker[src_ip] = []
            return True

    return False


def detect_promiscuous(packet):
    """
    Heuristic check for promiscuous-mode behaviour: a normal ARP reply is
    addressed to one specific device. A reply addressed to the broadcast MAC
    (ff:ff:ff:ff:ff:ff) is abnormal and is typical of crafted traffic or
    a device handling frames not meant for it.
    """
    if packet.haslayer(ARP):
        arp = packet[ARP]
        mac = arp.hwsrc.lower()

        if arp.op == 2 and arp.hwdst.lower() == "ff:ff:ff:ff:ff:ff":
            if should_alert(("promisc", arp.psrc, mac)):
                details = (
                    f"Device {arp.psrc} ({mac}) may be operating "
                    f"in promiscuous mode. Sent an ARP reply addressed to the "
                    f"broadcast MAC, which a normal host does not do."
                )
                recommendation = (
                    "A device in promiscuous mode can capture all network traffic. "
                    "Investigate this device. Enable WPA3 and use encrypted protocols."
                )
                log_alert(
                    ip_address=arp.psrc,
                    mac_address=mac,
                    attack_type="Promiscuous Mode Detected",
                    details=details,
                    recommendation=recommendation
                )
                print(f"[ALERT] Possible promiscuous mode: {arp.psrc} ({mac})")
                return True

    return False


def analyse_packet(packet):
    """
    Master function - runs all detection checks
    on every captured packet.
    """
    detect_arp(packet)
    detect_dns(packet)
    detect_promiscuous(packet)