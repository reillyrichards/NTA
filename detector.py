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
    """
    Plain function can't remember anything between calls. Class stores data in self and keeps it
    as long as program runs
    """
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
        """
        Detect if IP is scanning multiple ports
        Logic: 
        1. Record IP just hit port, with a timestamp
        2. Throw away any records older than PORT_SCAN_WINDOW seconds
        3. Count how many unique ports this IP has hit in this window
        4. If it's >= threshold, ping an alert
        """
        now = time.time()

        #Add port hit
        self.port_activity[src_ip].append((dst_port, now))
        
        #Remove old events outside window
        self.port_activity[src_ip] = self._clean_old_events(
            self.port_activity[src_ip], PORT_SCAN_WINDOW)
        
        #Count unique ports hit in window, it is a set because they deduplicate automatically
        unique_ports = set(port for port, timestamp in self.port_activity[src_ip])

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            logAlert(
                "PORT SCAN", 
                src_ip,
                f"{len(unique_ports)} unique ports hit in {PORT_SCAN_WINDOW}s - ports: {sorted(unique_ports)}"
            )
    
    def check_brute_force(self, src_ip, dst_port):
        """
        Detects SSH brute force attempts
        Logic same as port scan
        """
        #Ignore anything not targeting SSH
        if dst_port != 22:
            return
        
        now = time.time()
        
        self.ssh_attempts[src_ip].append((now,))

        self.ssh_attempts[src_ip] = self._clean_old_events(
            self.ssh_attempts[src_ip], BRUTE_FORCE_WINDOW)
        
        if len(self.ssh_attempts[src_ip] >= BRUTE_FORCE_THRESHOLD):
            logAlert(
                "SSH BRUTE FORCE",
                src_ip,
                f"{len(self.self.ssh_attempts[src_ip])} SSH attempts "
                f"in {BRUTE_FORCE_WINDOW}s"
            )
    def check_high_traffic(self, src_ip):
        """
        Detects unsually high packet volume from a single IP
        """
        now = time.time()
        self.packet_counts[src_ip].append((now,))

        self.packet_counts[src_ip] = self._clean_old_events(
            self.packet_counts[src_ip], HIGH_TRAFFIC_WINDOW)
    
        if len(self.packets_count[src_ip] >= HIGH_TRAFFIC_THRESHOLD):
            logAlert(
                "HIGH TRAFFIC VOLUME",
                src_ip,
                f"{len(self.packet_counts[src_ip])} packets "
                f"in {HIGH_TRAFFIC_WINDOW}s "
            )
    