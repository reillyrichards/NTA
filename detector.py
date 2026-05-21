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

    def check_port_scan(self, src_ip, dst_port):
        """Detect if IP is scanning multiple ports"""
        now = time.time()

        #Add port hit
        self.port_activity[src_ip].append((dst_port, now))
        
        #Remove old events outside window
        self.port_activity[src_ip] = self._clean_old_events(
            self.port_activity[src_ip], PORT_SCAN_WINDOW)
        
        #Count unique ports hit in window
        unique_ports = set(p for p, t in self.port_activity[src_ip])

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            logAlert(
                "PORT SCAN", 
                src_ip,
                f"{len(unique_ports)} unique ports hit in {PORT_SCAN_WINDOW}s - ports: {sorted(unique_ports)}"
            )
    
    def check_brute_force(self, src_ip, dst_port):
        """
        Detects SSH brute force attempts
        """
        if dst_port != 22:
            return
        
        now = time.time()
        
