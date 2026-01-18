import os
import shutil
import random

VAULT_DIR = "./test_vault"

def setup_vault():
    # Clean up existing vault
    if os.path.exists(VAULT_DIR):
        shutil.rmtree(VAULT_DIR)
    os.makedirs(VAULT_DIR)
    
    # Create Honeypot directory
    honey_dir = os.path.join(VAULT_DIR, "backup_images")
    os.makedirs(honey_dir)

    print(f"[*] Created {VAULT_DIR}")
    print("[*] Generating HEAVY files (this simulates real user data)...")

    # 1. Create the Honeytoken (Trap) - DO NOT encrypt this quickly!
    with open(os.path.join(VAULT_DIR, "config_sys_backup.dat"), "wb") as f:
        f.write(os.urandom(1024))  # 1KB random data
    print("    [+] Created Honeytoken: config_sys_backup.dat")
    
    # 2. Create Honeytokens in subfolder
    honeypot_files = ["wallet_seed.dat", "credentials_backup.dat", "recovery_key.dat"]
    for filename in honeypot_files:
        with open(os.path.join(honey_dir, filename), "wb") as f:
            f.write(os.urandom(1024))
        print(f"    [+] Created Honeypot: backup_images/{filename}")

    # 3. Create "Heavy" Dummy Files (5MB each)
    # Larger files = Slower encryption = Better chance for Sentinel to catch it
    print("\n[*] Creating heavy database files (5MB each)...")
    dummy_data = b"A" * (1024 * 1024 * 5)  # 5MB block of 'A's
    
    for i in range(1, 21):  # 20 heavy files = 100MB total
        filename = f"heavy_data_{i:02d}.db"
        path = os.path.join(VAULT_DIR, filename)
        with open(path, "wb") as f:
            f.write(dummy_data)
        print(f"    [+] Created 5MB file: {filename}")
    
    # 4. Create some small text files (mixed environment)
    print("\n[*] Creating small text files...")
    for i in range(1, 11):
        filename = f"notes_{i:02d}.txt"
        path = os.path.join(VAULT_DIR, filename)
        with open(path, "w") as f:
            f.write("Important business data\n" * 100)
        print(f"    [+] Created text file: {filename}")
    
    print("\n" + "=" * 50)
    print("[*] Vault setup complete. Ready for battle.")
    print(f"    - 20 Heavy files (5MB each = 100MB total)")
    print(f"    - 10 Small text files")
    print(f"    - 4 Honeytokens (traps)")
    print("=" * 50)

if __name__ == "__main__":
    setup_vault()
