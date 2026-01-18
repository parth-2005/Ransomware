"""
Zero-Latency Sentinel: Ransomware Guard
========================================
This version uses METADATA-ONLY detection - NO file I/O in the event loop.
Detection is based purely on:
1. File extensions (.locked, .encrypted)
2. Honeytoken filename matching
3. Burst event detection (5+ events/second)

This is 100x faster than entropy-based detection.
"""

import os
import time
import logging
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import deque

# Configuration
MONITOR_DIR = "./test_vault"
LOG_FILE = "sentinel_entropy.log"

# Honeytoken Configuration (Instant Kill Triggers)
HONEYTOKEN_FILES = {
    "config_sys_backup.dat",
    "wallet_seed.dat",
    "credentials_backup.dat",
    "recovery_key.dat"
}

# Ransomware Extension Triggers
RANSOMWARE_EXTENSIONS = {".locked", ".encrypted", ".crypted", ".ransom", ".locky"}

# Burst Detection Settings
BURST_THRESHOLD = 5   # Number of events
BURST_WINDOW = 1.0    # Within this many seconds

# Setup Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)


class MitigationModule:
    """Handles process termination when threats are detected."""
    
    @staticmethod
    def emergency_lockdown(reason):
        """
        KILL SWITCH: Terminates ALL Python processes except this Sentinel.
        
        This is the "nuclear option" - we don't try to be polite or identify
        specific processes. If it's running Python and it's not us, it dies.
        """
        logging.critical(f"!!! EMERGENCY LOCKDOWN !!! Reason: {reason}")
        print(f"\n{'='*60}")
        print(f"[!!!] LOCKDOWN INITIATED")
        print(f"[!!!] Reason: {reason}")
        print(f"{'='*60}")
        
        killed_count = 0
        my_pid = os.getpid()  # Don't kill ourselves!

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # Check if it's a Python process
                    proc_name = proc.info.get('name', '').lower()
                    if 'python' not in proc_name:
                        continue
                    
                    # Don't commit suicide
                    if proc.info['pid'] == my_pid:
                        continue
                    
                    # Kill it!
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


class ZeroLatencySentinel(FileSystemEventHandler):
    """
    Zero-Latency Ransomware Detector
    
    CRITICAL: This handler does NO file I/O. All detection is metadata-based.
    """
    
    def __init__(self):
        self.event_times = deque(maxlen=20)  # Track timestamps
        self.lockdown_triggered = False
        self.event_count = 0
    
    def _trigger_lockdown(self, reason):
        """Trigger emergency lockdown (only once)."""
        if not self.lockdown_triggered:
            self.lockdown_triggered = True
            MitigationModule.emergency_lockdown(reason)
    
    def _check_burst(self):
        """Check if there's a burst of events (5+ in 1 second)."""
        now = time.time()
        self.event_times.append(now)
        
        # Count events within the time window
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
    
    def _analyze_event(self, file_path, event_type):
        """Analyze a file event using metadata only - NO FILE I/O!"""
        if self.lockdown_triggered:
            return
        
        # Ignore log file
        if LOG_FILE in file_path:
            return
        
        self.event_count += 1
        filename = os.path.basename(file_path)
        
        # === CHECK 1: Honeytoken Access (INSTANT KILL) ===
        if self._check_honeytoken(file_path):
            logging.critical(f"HONEYTOKEN TRIGGERED: {filename}")
            self._trigger_lockdown(f"Honeytoken accessed: {filename}")
            return
        
        # === CHECK 2: Ransomware Extension (INSTANT KILL) ===
        if self._check_extension(file_path):
            logging.critical(f"RANSOMWARE EXTENSION DETECTED: {file_path}")
            self._trigger_lockdown(f"Ransomware extension: {os.path.splitext(file_path)[1]}")
            return
        
        # === CHECK 3: Burst Detection ===
        if self._check_burst():
            logging.critical(f"BURST ATTACK: {BURST_THRESHOLD}+ events in {BURST_WINDOW}s")
            self._trigger_lockdown(f"Burst attack: {BURST_THRESHOLD}+ rapid file events")
            return
        
        # Log normal activity (minimal)
        if self.event_count % 10 == 0:  # Only log every 10th event to reduce noise
            logging.info(f"[{event_type}] {filename} (Event #{self.event_count})")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._analyze_event(event.src_path, "MODIFY")

    def on_moved(self, event):
        if event.is_directory:
            return
        # Check BOTH source and destination paths
        self._analyze_event(event.src_path, "MOVE_FROM")
        self._analyze_event(event.dest_path, "MOVE_TO")

    def on_created(self, event):
        if event.is_directory:
            return
        self._analyze_event(event.src_path, "CREATE")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._analyze_event(event.src_path, "DELETE")


def main():
    print("=" * 60)
    print("   ZERO-LATENCY SENTINEL: Ransomware Guard")
    print("=" * 60)
    print(f"[*] Monitoring: {MONITOR_DIR}")
    print(f"[*] Detection Mode: METADATA-ONLY (Zero I/O)")
    print(f"[*] Honeytokens: {', '.join(HONEYTOKEN_FILES)}")
    print(f"[*] Burst Threshold: {BURST_THRESHOLD} events in {BURST_WINDOW}s")
    print("-" * 60)
    
    if not os.path.exists(MONITOR_DIR):
        print(f"[!] WARNING: {MONITOR_DIR} does not exist!")
        print("[!] Run setup_vault.py first.")
        return
    
    event_handler = ZeroLatencySentinel()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    
    print("[*] Sentinel ACTIVE. Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(0.1)  # Fast polling
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
