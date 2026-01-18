import os
import math
import time
import logging
import psutil
import numpy as np
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import Counter, deque
from sklearn.ensemble import IsolationForest

# Configuration
MONITOR_DIR = "./test_vault"
LOG_FILE = "sentinel_entropy.log"
CANARY_FILE = "config_sys_backup.dat"  # Honeytoken triggers immediate lockdown

# Burst Detection Settings
BURST_THRESHOLD = 5   # Number of events
BURST_WINDOW = 1.0    # Within this many seconds

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


class AnomalyDetector:
    """ML-based anomaly detection using Isolation Forest."""
    
    def __init__(self, training_dir):
        self.model = IsolationForest(
            contamination=0.1,  # Expect ~10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.is_trained = False
        self._train(training_dir)
    
    def _train(self, directory):
        """Train on benign files using (file_size, entropy) features."""
        features = []
        logging.info(f"[ML] Training Isolation Forest on files in {directory}...")
        
        try:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    path = os.path.join(root, filename)
                    try:
                        if os.path.isfile(path):
                            size = os.path.getsize(path)
                            entropy = EntropyModule.calculate_shannon_entropy(path)
                            features.append([size, entropy])
                    except Exception as e:
                        logging.warning(f"[ML] Skipped {path}: {e}")
            
            if len(features) >= 2:
                self.model.fit(np.array(features))
                self.is_trained = True
                logging.info(f"[ML] Training complete. Learned from {len(features)} benign files.")
            else:
                logging.warning("[ML] Not enough files to train. Using fallback entropy threshold.")
                self.is_trained = False
        except Exception as e:
            logging.error(f"[ML] Training failed: {e}")
            self.is_trained = False
    
    def predict(self, file_path):
        """Returns 'malicious' if anomaly detected, 'benign' otherwise."""
        try:
            size = os.path.getsize(file_path)
            entropy = EntropyModule.calculate_shannon_entropy(file_path)
            
            if self.is_trained:
                prediction = self.model.predict([[size, entropy]])
                # Isolation Forest: -1 = anomaly, 1 = normal
                verdict = 'malicious' if prediction[0] == -1 else 'benign'
                logging.debug(f"[ML] Prediction for {file_path}: size={size}, entropy={entropy:.4f}, verdict={verdict}")
                return verdict
            else:
                # Fallback to entropy threshold if ML not trained
                return 'malicious' if entropy > 5.0 else 'benign'
        except Exception as e:
            logging.error(f"[ML] Prediction error for {file_path}: {e}")
            return 'benign'


class MitigationModule:
    @staticmethod
    def identify_process(file_path):
        """Attempts to identify the process modifying the file."""
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

    @staticmethod
    def emergency_lockdown(reason):
        """Kill all suspicious attack processes immediately."""
        logging.critical(f"!!! EMERGENCY LOCKDOWN !!! Reason: {reason}")
        killed = 0
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if p.info['cmdline'] and any("attack" in arg.lower() for arg in p.info['cmdline']):
                    logging.warning(f"Terminating suspicious process: {p.info['name']} (PID: {p.info['pid']})")
                    p.kill()
                    killed += 1
            except:
                pass
        logging.critical(f"Lockdown complete. Terminated {killed} suspicious processes.")
        return killed


class SentinelMonitor(FileSystemEventHandler):
    def __init__(self, anomaly_detector):
        self.anomaly_detector = anomaly_detector
        self.event_times = deque(maxlen=10)  # Track timestamps of last 10 events
        self.lockdown_triggered = False
    
    def _check_burst(self):
        """Check if there's a burst of events (5+ in 1 second)."""
        now = time.time()
        self.event_times.append(now)
        
        if len(self.event_times) >= BURST_THRESHOLD:
            # Count events within the time window
            recent = [t for t in self.event_times if now - t <= BURST_WINDOW]
            if len(recent) >= BURST_THRESHOLD:
                return True
        return False
    
    def _check_honeytoken(self, file_path):
        """Check if the modified file is a honeytoken (canary)."""
        filename = os.path.basename(file_path)
        # Check for main canary file
        if filename == CANARY_FILE:
            return True
        # Check for honeypot folder files
        if "backup_images" in file_path:
            return True
        return False

    def on_modified(self, event):
        if event.is_directory or self.lockdown_triggered:
            return

        file_path = event.src_path
        
        # Ignore temp files or the log file itself
        if file_path.endswith(LOG_FILE) or '~' in file_path:
            return
        
        # === CHECK 1: Honeytoken Detection (Instant Kill) ===
        if self._check_honeytoken(file_path):
            logging.critical(f"!!! HONEYTOKEN TRIGGERED !!! File: {file_path}")
            self.lockdown_triggered = True
            MitigationModule.emergency_lockdown(f"Honeytoken accessed: {file_path}")
            return
        
        # === CHECK 2: Burst Detection (5+ events in 1 second) ===
        if self._check_burst():
            logging.critical(f"!!! BURST ATTACK DETECTED !!! {BURST_THRESHOLD}+ events in {BURST_WINDOW}s")
            self.lockdown_triggered = True
            MitigationModule.emergency_lockdown(f"Burst attack: {BURST_THRESHOLD}+ events in {BURST_WINDOW}s")
            return
        
        # === CHECK 3: ML-Based Anomaly Detection ===
        entropy = EntropyModule.calculate_shannon_entropy(file_path)
        file_ext = os.path.splitext(file_path)[1]
        
        # Check for known ransomware extension
        if file_ext == '.locked':
            logging.warning(f"RANSOMWARE EXTENSION DETECTED on {file_path}")
            self.lockdown_triggered = True
            MitigationModule.emergency_lockdown(f"Ransomware extension: {file_path}")
            return
        
        # Use ML model for prediction
        verdict = self.anomaly_detector.predict(file_path)
        
        # Only log significant events to reduce noise
        if entropy > 0 or verdict == 'malicious':
            logging.info(f"File Modified: {file_path} | Entropy: {entropy:.4f} | ML Verdict: {verdict}")

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
    print("=" * 60)
    print("   SentinelEntropy: ML-Powered Ransomware Guard")
    print("=" * 60)
    print(f"[*] Monitoring directory: {MONITOR_DIR}")
    print(f"[*] Honeytoken file: {CANARY_FILE}")
    print(f"[*] Burst detection: {BURST_THRESHOLD} events in {BURST_WINDOW}s")
    print("[*] Detection: Isolation Forest ML + Entropy Analysis")
    print("-" * 60)
    
    # Initialize ML model by training on current benign files
    print("[*] Training ML model on existing files...")
    anomaly_detector = AnomalyDetector(MONITOR_DIR)
    
    event_handler = SentinelMonitor(anomaly_detector)
    observer = Observer()
    # Enable recursive monitoring to catch honeypot folder access
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    
    print("[*] Sentinel ACTIVE. Press Ctrl+C to stop.")
    print("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
