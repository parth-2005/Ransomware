"""
Smart Signature Sentinel: Hybrid Ransomware Detection
=======================================================
This version uses a HYBRID approach to avoid false positives:

1. Binary Files (.db, .dat): Check Magic Header integrity
   - Valid edit: Header preserved → SAFE
   - Ransomware: Header destroyed → KILL

2. Text Files (.txt): Check entropy of first 64 bytes
   - Valid edit: Low entropy (~4.5) → SAFE
   - Ransomware: High entropy (>7.5) → KILL

3. Emergency: Burst detection (5+ events/second)
"""

import os
import math
import time
import logging
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import deque, Counter

# Configuration
MONITOR_DIR = "./test_vault"
LOG_FILE = "sentinel_entropy.log"

# Magic Header Configuration
MAGIC_HEADER = b'CORP_DB_FORMAT_V1'  # 17 bytes
HEADER_CHECK_SIZE = len(MAGIC_HEADER)

# Binary file extensions (use header check)
BINARY_EXTENSIONS = {".db", ".dat"}

# Text file extensions (use entropy check)
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml"}

# Entropy threshold for text files
TEXT_ENTROPY_THRESHOLD = 7.5  # Normal text ~4.5, encrypted ~7.9

# Ransomware extension triggers (instant kill)
RANSOMWARE_EXTENSIONS = {".locked", ".encrypted", ".crypted", ".ransom", ".locky"}

# Honeytoken files (instant kill)
HONEYTOKEN_FILES = {
    "config_sys_backup.dat",
    "wallet_seed.dat",
    "credentials_backup.dat",
    "recovery_key.dat"
}

# Burst Detection Settings
BURST_THRESHOLD = 5
BURST_WINDOW = 1.0

# Setup Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)


def calculate_entropy(data):
    """Calculate Shannon entropy of bytes."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class MitigationModule:
    """Handles process termination when threats are detected."""
    
    @staticmethod
    def emergency_lockdown(reason):
        """
        KILL SWITCH: Terminates ALL Python processes except this Sentinel.
        """
        logging.critical(f"!!! EMERGENCY LOCKDOWN !!! Reason: {reason}")
        print(f"\n{'='*60}")
        print(f"[!!!] LOCKDOWN INITIATED")
        print(f"[!!!] Reason: {reason}")
        print(f"{'='*60}")
        
        killed_count = 0
        my_pid = os.getpid()

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_name = proc.info.get('name', '').lower()
                    if 'python' not in proc_name:
                        continue
                    if proc.info['pid'] == my_pid:
                        continue
                    
                    cmdline = proc.info.get('cmdline', [])
                    script_name = cmdline[1] if cmdline and len(cmdline) > 1 else "unknown"
                    
                    logging.warning(f"KILLING: {script_name} (PID: {proc.info['pid']})")
                    print(f"[KILL] Terminating: {script_name} (PID: {proc.info['pid']})")
                    
                    proc.kill()
                    killed_count += 1
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, IndexError):
                    continue
        except Exception as e:
            logging.error(f"Lockdown error: {e}")

        print(f"\n[+] Lockdown Complete. Neutralized {killed_count} processes.")
        logging.critical(f"Lockdown complete. Terminated {killed_count} processes.")
        return killed_count


class SmartSignatureSentinel(FileSystemEventHandler):
    """
    Hybrid Ransomware Detector with Magic Byte + Entropy Checks
    
    This solves the False Positive problem:
    - Valid edits preserve headers and keep low entropy
    - Ransomware destroys headers and spikes entropy
    """
    
    def __init__(self):
        self.event_times = deque(maxlen=20)
        self.lockdown_triggered = False
        self.event_count = 0
    
    def _trigger_lockdown(self, reason):
        """Trigger emergency lockdown (only once)."""
        if not self.lockdown_triggered:
            self.lockdown_triggered = True
            MitigationModule.emergency_lockdown(reason)
    
    def _check_burst(self):
        """Check if there's a burst of events."""
        now = time.time()
        self.event_times.append(now)
        cutoff = now - BURST_WINDOW
        recent_count = sum(1 for t in self.event_times if t > cutoff)
        return recent_count >= BURST_THRESHOLD
    
    def _check_extension(self, file_path):
        """Check if file has a ransomware extension."""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in RANSOMWARE_EXTENSIONS
    
    def _check_honeytoken(self, file_path):
        """Check if the file is a honeytoken."""
        filename = os.path.basename(file_path)
        return filename in HONEYTOKEN_FILES
    
    def _check_header_integrity(self, file_path):
        """
        Check if binary file has valid magic header.
        Returns: (is_valid, actual_header)
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(HEADER_CHECK_SIZE)
            return header == MAGIC_HEADER, header
        except:
            return True, b""  # Can't read = assume safe
    
    def _check_text_entropy(self, file_path):
        """
        Check entropy of first 64 bytes of text file.
        Returns: (is_suspicious, entropy_value)
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read(64)  # Only read first 64 bytes!
            entropy = calculate_entropy(data)
            return entropy > TEXT_ENTROPY_THRESHOLD, entropy
        except:
            return False, 0.0  # Can't read = assume safe
    
    def _get_file_type(self, file_path):
        """Determine file type based on extension."""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        if ext in BINARY_EXTENSIONS:
            return "binary"
        elif ext in TEXT_EXTENSIONS:
            return "text"
        return "unknown"
    
    def _analyze_event(self, file_path, event_type):
        """Analyze a file event using hybrid detection."""
        if self.lockdown_triggered:
            return
        
        # Ignore log file
        if LOG_FILE in file_path:
            return
        
        self.event_count += 1
        filename = os.path.basename(file_path)
        _, ext = os.path.splitext(file_path)
        
        # === CHECK 1: Ransomware Extension (INSTANT KILL) ===
        if self._check_extension(file_path):
            logging.critical(f"RANSOMWARE EXTENSION: {file_path}")
            self._trigger_lockdown(f"Ransomware extension detected: {ext}")
            return
        
        # === CHECK 2: Honeytoken Access (INSTANT KILL) ===
        if self._check_honeytoken(file_path):
            logging.critical(f"HONEYTOKEN TRIGGERED: {filename}")
            self._trigger_lockdown(f"Honeytoken modified: {filename}")
            return
        
        # === CHECK 3: Burst Detection ===
        if self._check_burst():
            logging.critical(f"BURST ATTACK: {BURST_THRESHOLD}+ events in {BURST_WINDOW}s")
            self._trigger_lockdown(f"Burst attack detected")
            return
        
        # === CHECK 4: Smart Signature Check ===
        file_type = self._get_file_type(file_path)
        
        if file_type == "binary":
            # Check Magic Header integrity
            is_valid, actual_header = self._check_header_integrity(file_path)
            if not is_valid:
                header_preview = actual_header[:8] if actual_header else b"<empty>"
                logging.critical(f"HEADER CORRUPTION: {filename} - Expected '{MAGIC_HEADER.decode()}', got '{header_preview}'")
                self._trigger_lockdown(f"Magic header destroyed in {filename}")
                return
            else:
                logging.debug(f"[SAFE] {filename} - Header intact")
        
        elif file_type == "text":
            # Check entropy of first 64 bytes
            is_suspicious, entropy = self._check_text_entropy(file_path)
            if is_suspicious:
                logging.critical(f"HIGH ENTROPY: {filename} - Entropy: {entropy:.2f} (threshold: {TEXT_ENTROPY_THRESHOLD})")
                self._trigger_lockdown(f"Text file encrypted: {filename} (entropy: {entropy:.2f})")
                return
            else:
                logging.debug(f"[SAFE] {filename} - Entropy: {entropy:.2f}")
        
        # Log activity periodically
        if self.event_count % 20 == 0:
            logging.info(f"Activity: {self.event_count} events processed")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._analyze_event(event.src_path, "MODIFY")

    def on_moved(self, event):
        if event.is_directory:
            return
        self._analyze_event(event.src_path, "MOVE_FROM")
        self._analyze_event(event.dest_path, "MOVE_TO")

    def on_created(self, event):
        if event.is_directory:
            return
        self._analyze_event(event.src_path, "CREATE")


def main():
    print("=" * 60)
    print("   SMART SIGNATURE SENTINEL: Hybrid Ransomware Guard")
    print("=" * 60)
    print(f"[*] Monitoring: {MONITOR_DIR}")
    print(f"[*] Magic Header: {MAGIC_HEADER.decode()}")
    print("-" * 60)
    print("[*] Detection Methods:")
    print(f"    Binary (.db, .dat): Magic Header check")
    print(f"    Text (.txt):        Entropy check (threshold: {TEXT_ENTROPY_THRESHOLD})")
    print(f"    Extensions:         {RANSOMWARE_EXTENSIONS}")
    print(f"    Honeytokens:        {len(HONEYTOKEN_FILES)} trap files")
    print(f"    Burst:              {BURST_THRESHOLD} events in {BURST_WINDOW}s")
    print("-" * 60)
    
    if not os.path.exists(MONITOR_DIR):
        print(f"[!] WARNING: {MONITOR_DIR} does not exist!")
        print("[!] Run setup_vault.py first.")
        return
    
    event_handler = SmartSignatureSentinel()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    
    print("[*] Sentinel ACTIVE. Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
