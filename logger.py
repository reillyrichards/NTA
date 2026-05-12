#File handles all outputs, prints to terminal and log file.
#Isolated incase HOW we want to change logged, only this file would need changing.

import logging
import os
from config import LOG_FILE

os.makedirs("logs", exist_ok=True) #exist_ok = true so won't crash if folder already exists

#Setting up global logging behaviour
#   level=INFO means log everything rated INFO or higher
#   (INFO → WARNING → ERROR → CRITICAL, in order of severity)
# 2 Handlers used to write to a file AND print to terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
#Creates a named logger, if needed can add more later
logger = logging.getLogger("ThreatAnalyser")


def logAlert(threat_type, src_ip, detail):
    """
    Formatted as pipe separated so that parsing it later if needed will be easier.
    """
    message = f"ALERT | TYPE: {threat_type} | SOURCE IP: {src_ip} | DETAIL: {detail}"
    logger.warning(message)

def log_info(message):
    """
    Log general status messages, INFO appears in the log but aren't flagged as threats
    """
    logger.info(message)


