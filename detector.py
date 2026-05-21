import time
from collections import defaultdict
from config import (
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    HIGH_TRAFFIC_THRESHOLD, HIGH_TRAFFIC_WINDOW,
    SUSPICIOUS_PORTS
)
from logger import logAlert

class Threatdetector:
    def __init__(self):
        """
        Tracks the ports each IP has touched, structure: {ip: [(port, timestamp)]}
        Tracks SSH connection attempts per IP, structure: {ip:[timestamp, ...]}
        Tracks total packet count per IP, structure: {ip: [timestamp, ...]}

        """
        self.port_activity = defaultdict(list)
        self.ssh_attempts = defaultdict(list)
        self.packet_counts = defaultdict(list)

    def _clean_old_events(self, event_list, window):
        """Removes old events longer than the window"""
        cutoff = time.time() - window
        return [e for e in event_list if e[-1] >= cutoff]
        #e-1 assumes timestamp is always last element in tuple
    