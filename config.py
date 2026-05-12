#Acts as a settings file that helps make the detector more or less sensitive

PORT_SCAN_THRESHOLD = 10 #N of unique ports = suspicious
PORT_SCAN_WINDOW = 5 # N of seconds we look back

BRUTE_FORCE_THRESHOLD = 5 #N of unique attempts = suspicious
BRUTE_FORCE_WINDOW = 10

#DoS (Denial of Service attack detection)
HIGH_TRAFFIC_THRESHOLD = 100 #nPackets from 1 IP = suspicious
HIGH_TRAFFIC_WINDOW = 5 

SUSPICIOUS_PORTS = [4444, 1337, 31337, 6666, 9999]
# 4444  → default Metasploit reverse shell listener port
# 1337  → historically used by early hacking tools ("leet")
# 31337 → same origin as 1337, common in older malware
# 6666  → used by some RATs (Remote Access Trojans)
# 9999  → common backdoor/RAT port

INTERFACE = "lo" #Change to "eth0" after local testing
LOG_FILE = "logs/alerts.log"