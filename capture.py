from scapy.all import sniff, get_if_list, conf, ARP, DNS, TCP, UDP
from detect import analyse_packet
import threading
import time

# Global state
monitoring = False
monitor_thread = None
stop_event = None          # each capture session gets its own stop signal

# Live network activity counters
stats_lock = threading.Lock()
stats = {
    "total": 0,
    "arp": 0,
    "dns": 0,
    "tcp": 0,
    "udp": 0,
    "other": 0,
    "started_at": 0,
}


def reset_stats():
    """
    Resets all activity counters. Called each time monitoring starts.
    """
    with stats_lock:
        stats.update(total=0, arp=0, dns=0, tcp=0, udp=0, other=0,
                     started_at=time.time())


def record_packet(packet):
    """
    Counts the packet by protocol type for the Network Activity panel.
    """
    if packet.haslayer(ARP):
        key = "arp"
    elif packet.haslayer(DNS):
        key = "dns"
    elif packet.haslayer(TCP):
        key = "tcp"
    elif packet.haslayer(UDP):
        key = "udp"
    else:
        key = "other"

    with stats_lock:
        stats["total"] += 1
        stats[key] += 1


def get_stats():
    """
    Returns the current activity counters, packets per second and uptime.
    """
    with stats_lock:
        data = dict(stats)

    if monitoring and data["started_at"]:
        uptime = int(time.time() - data["started_at"])
    else:
        uptime = 0

    data["uptime_seconds"] = uptime
    data["packets_per_second"] = round(data["total"] / uptime, 1) if uptime > 0 else 0
    data["monitoring"] = monitoring
    del data["started_at"]
    return data


def get_interfaces():
    """
    Returns a list of available network interfaces
    on the machine.
    """
    return get_if_list()


def get_default_interface():
    """
    Returns the default network interface
    Scapy has selected for this machine.
    """
    return conf.iface


def handle_packet(packet, session_stop):
    """
    Called for every captured packet: counts it, then runs the detection rules.
    Packets arriving after this session was stopped are ignored.
    """
    if session_stop.is_set():
        return
    record_packet(packet)
    try:
        analyse_packet(packet)
    except Exception as e:
        print(f"[ERROR] Detection error: {e}")


def start_capture(interface, session_stop):
    """
    Starts capturing packets on the specified
    interface. Runs in a background thread so
    the Flask dashboard stays responsive.
    """
    global monitoring

    if not interface:
        interface = get_default_interface()

    print(f"[INFO] Starting packet capture on interface: {interface}")

    try:
        sniff(
            iface=interface,
            prn=lambda p: handle_packet(p, session_stop),
            store=False,
            stop_filter=lambda p: session_stop.is_set()
        )
    except Exception as e:
        print(f"[ERROR] Capture error: {e}")
        if stop_event is session_stop:
            monitoring = False


def stop_capture():
    """
    Stops the packet capture for the current session.
    """
    global monitoring
    monitoring = False
    if stop_event is not None:
        stop_event.set()
    print("[INFO] Packet capture stopped.")


def start_capture_thread(interface=None):
    """
    Launches the packet capture in a
    separate background thread so Flask
    can run simultaneously.
    """
    global monitor_thread, monitoring, stop_event

    if monitoring:
        print("[INFO] Capture already running.")
        return

    reset_stats()
    stop_event = threading.Event()
    monitoring = True

    monitor_thread = threading.Thread(
        target=start_capture,
        args=(interface, stop_event),
        daemon=True
    )
    monitor_thread.start()
    print("[INFO] Capture thread started.")


def is_monitoring():
    """
    Returns current monitoring status.
    """
    return monitoring