from scapy.all import sniff, IP, TCP, UDP
#sniff -> scapy's function that captures packets from an interface
#IP -> IP layer of a packet (source ip, dst ip)
# TCP/UDP -> Transport layer (contains source/dst port)

from detector import ThreatDetector
from logger import log_info
from config import INTERFACE