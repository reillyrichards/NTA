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