import os
import time

VAULT_DIR = "./test_vault"

def attack_sprinter():
    print("[*] Starting ATTACK: The Sprinter (Rapid Renamer)")
    
    if not os.path.exists(VAULT_DIR):
        print(f"[!] Error: {VAULT_DIR} not found. Run setup_vault.py first.")
        return

    files = [f for f in os.listdir(VAULT_DIR) if os.path.isfile(os.path.join(VAULT_DIR, f))]
    
    start_time = time.time()
    for filename in files:
        if filename.endswith(".locked"):
            continue
            
        old_path = os.path.join(VAULT_DIR, filename)
        new_path = os.path.join(VAULT_DIR, filename + ".locked")
        
        try:
            os.rename(old_path, new_path)
            print(f"    [!] Renamed: {filename} -> {filename}.locked")
        except Exception as e:
            print(f"    [x] Failed to rename {filename}: {e}")
            
    end_time = time.time()
    print(f"[*] Attack complete. Renamed {len(files)} files in {end_time - start_time:.4f} seconds.")

if __name__ == "__main__":
    attack_sprinter()
