import scapy.all as scapy

def sniff_packets(interface, filter, count, timeout, store):
    """
    Sniff packets on the specified interface.

    Args:
        interface (str): The interface to sniff on (e.g. eth0, wlan0, etc.).
        filter (str): The filter to apply to the captured packets (e.g. "tcp", "udp", etc.).
        count (int): The number of packets to capture.
        timeout (int): The timeout in seconds.
        store (bool): Whether to store the captured packets in memory or not.

    Returns:
        A list of captured packets.
    """
    print(f"Sniffing on interface {interface} with filter {filter}...")
    packets = scapy.sniff(iface=interface, filter=filter, count=count, timeout=timeout, store=store)
    print(f"Captured {len(packets)} packets.")
    return packets

def print_packet_info(packet):
    """
    Print information about a captured packet.

    Args:
        packet (scapy.packet): The captured packet.
    """
    try:
        print("Packet Information:")
        print(f"  Source IP: {packet[scapy.IP].src}")
        print(f"  Destination IP: {packet[scapy.IP].dst}")
        if packet.haslayer(scapy.TCP):
            print(f"  Source Port: {packet[scapy.TCP].sport}")
            print(f"  Destination Port: {packet[scapy.TCP].dport}")
        print(f"  Packet Length: {len(packet)}")
        print("")
    except AttributeError:
        print("Error: Unable to parse packet.")

def main():
    interface = "eth0"  # Set the interface to sniff on (e.g. eth0, wlan0, etc.)
    filter = "tcp"  # Set the filter to capture only TCP packets
    count = 100  # Set the number of packets to capture
    timeout = 10  # Set the timeout in seconds
    store = False  # Set whether to store the captured packets in memory or not

    packets = sniff_packets(interface, filter, count, timeout, store)

    for packet in packets:
        print_packet_info(packet)

if __name__ == "__main__":
    main()