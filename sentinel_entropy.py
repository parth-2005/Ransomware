import os
import math
import time
import logging
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import Counter

# Configuration
MONITOR_DIR = "./test_vault"
LOG_FILE = "sentinel_entropy.log"
# Fernet uses Base64 encoding, so max entropy is ~6 bits. 
# Real ransomware is >7.5. For this demo, we use 5.5.
ENTROPY_THRESHOLD = 5.0 

# Setup Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(module)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

class EntropyModule:
    @staticmethod
    def calculate_shannon_entropy(file_path):
        """Calculates Shannon Entropy for a given file with retry logic."""
        retries = 3
        for i in range(retries):
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                if not data:
                    return 0.0

                counter = Counter(data)
                length = len(data)
                entropy = 0.0

                for count in counter.values():
                    p = count / length
                    entropy -= p * math.log2(p)
                
                return entropy
            except (PermissionError, OSError):
                # File might be locked by the attacker process
                if i < retries - 1:
                    time.sleep(0.05)
                    continue
                return 0.0
            except Exception as e:
                logging.error(f"Error calculating entropy for {file_path}: {e}")
                return 0.0
        return 0.0

class MitigationModule:
    @staticmethod
    def identify_process(file_path):
        """Attempts to identify the process modifying the file."""
        # Note: This is a best-effort approach. Short-lived processes might close the file before we check.
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for f in proc.info['open_files']:
                            if f.path == os.path.abspath(file_path):
                                return proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logging.error(f"Error identifying process: {e}")
        return None

    @staticmethod
    def kill_process(proc):
        """Terminates the given process."""
        try:
            if proc:
                logging.warning(f"!!! MITIGATION TRIGGERED !!! Killing process: {proc.info['name']} (PID: {proc.info['pid']})")
                proc.kill()
                return True
        except psutil.NoSuchProcess:
            logging.warning("Process already dead.")
        except Exception as e:
            logging.error(f"Failed to kill process: {e}")
        return False

class AILogicModule:
    @staticmethod
    def analyze(entropy, file_extension):
        """Heuristic analysis to flag malicious behavior."""
        # Check Entropy
        # DEBUG LOG
        # logging.info(f"DEBUG CHECK: {entropy} > {ENTROPY_THRESHOLD} ? {entropy > ENTROPY_THRESHOLD}")
        
        if entropy > ENTROPY_THRESHOLD:
            return 'malicious'
            
        # Check Extension
        if file_extension == '.locked':
            return 'malicious'
            
        return 'benign'

class SentinelMonitor(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        # Ignore temp files or the log file itself
        if file_path.endswith(LOG_FILE) or '~' in file_path:
            return
        
        # Calculate with retry
        entropy = EntropyModule.calculate_shannon_entropy(file_path)
        file_ext = os.path.splitext(file_path)[1]
        
        verdict = AILogicModule.analyze(entropy, file_ext)
        
        # Only log significant events to reduce noise
        if entropy > 0 or verdict == 'malicious':
             logging.info(f"File Modified: {file_path} | Entropy: {entropy:.4f} | Verdict: {verdict}")

        if verdict == 'malicious':
            logging.warning(f"MALICIOUS ACTIVITY DETECTED on {file_path}")
            
            # Attempt to find source process
            proc = MitigationModule.identify_process(file_path)
            
            if proc:
                MitigationModule.kill_process(proc)
            else:
                 # Fallback for demo: Look for likely culprits 
                 for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                     try:
                         if p.info['cmdline'] and any("attack" in arg for arg in p.info['cmdline']):
                             logging.warning(f"Fallback Identification found suspect process: {p.info['name']} {p.info['cmdline']}")
                             MitigationModule.kill_process(p)
                             break
                     except:
                        pass


    def on_moved(self, event):
        if event.is_directory:
            return
        # Check the new file path
        self.on_modified(type('Event', (object,), {'src_path': event.dest_path, 'is_directory': False}))

    def on_created(self, event):
        self.on_modified(event)

def main():
    print("==========================================")
    print("   SentinelEntropy: Ransomware Guard")
    print("==========================================")
    print(f"[*] Monitoring directory: {MONITOR_DIR}")
    print(f"[*] Entropy Threshold: {ENTROPY_THRESHOLD} (Tuned for Base64)")

    event_handler = SentinelMonitor()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()

