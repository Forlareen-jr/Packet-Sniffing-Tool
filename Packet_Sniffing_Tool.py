from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Display relevant information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        
        # Check for TCP or UDP and display payload if available
        if TCP in packet:
            print(f"TCP Payload: {bytes(packet[TCP].payload)}")
        elif UDP in packet:
            print(f"UDP Payload: {bytes(packet[UDP].payload)}")
        elif Raw in packet:
            print(f"Raw Payload: {bytes(packet[Raw].load)}")
        
        print("-" * 50)

def start_sniffer(interface='Wi-Fi'):  # Replace 'Wi-Fi' with your actual interface name
    print("Starting packet sniffer...")
    # Start sniffing packets
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Print available network interfaces
    print("Available network interfaces:")
    print(get_if_list())
    
    # Specify the network interface
    network_interface = 'Wi-Fi'  # Update this to your actual interface name
    start_sniffer(network_interface)
