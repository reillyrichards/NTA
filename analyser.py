from scapy.all import sniff, IP, TCP, UDP
#sniff -> scapy's function that captures packets from an interface
#IP -> IP layer of a packet (source ip, dst ip)
# TCP/UDP -> Transport layer (contains source/dst port)

from detector import ThreatDetector
from logger import log_info
from config import INTERFACE

detector = ThreatDetector()

def process_packet(packet):
    """
    Scapy calls this automatically for every captured packet. 
    Used to extract source IP and destination port and pass them along.
    """


    #haslayer(IP) checks if packet contains an IP header
    #If it does not contain one, no point in processing since we can't attribute
    #traffic to anyone
    if not packet.haslayer(IP):
        return
    
    #packet[IP].src gives us source IP address as a string
    src_ip = packet[IP].src
    
    dst_port = None

    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    if dst_port is None:
        return

    #Detector only needs IP and port
    detector.analyse_packet(src_ip,dst_port) 

def start_capture():
    """
    Starts packet capture loop, runs forever until Ctrl + C is pressed, it is supposed to run continuously
    """
    log_info(f"Starting packet capture on interface: {INTERFACE}")
    log_info(f"Press Ctrl + C to stop.")

    sniff(
        iface = INTERFACE, #Which NI to listen on
        prn=process_packet,
        store = False,
        filter = "tcp or udp"
    )

if __name__ == "__main__":
    start_capture()