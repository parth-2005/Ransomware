"""
Setup Vault: Creates a realistic test environment with Magic Byte Headers
==========================================================================
Binary files (.db) have a custom header that ransomware will destroy.
This allows the Sentinel to distinguish between:
- Valid edits (header preserved)
- Ransomware (header overwritten with garbage)
"""

import os
import shutil

VAULT_DIR = "./test_vault"

# Magic Header for binary files (16 bytes)
# Real apps would preserve this header. Ransomware destroys it.
MAGIC_HEADER = b'CORP_DB_FORMAT_V1'  # Exactly 17 bytes

def setup_vault():
    # Clean up existing vault
    if os.path.exists(VAULT_DIR):
        shutil.rmtree(VAULT_DIR)
    os.makedirs(VAULT_DIR)
    
    # Create Honeypot directory
    honey_dir = os.path.join(VAULT_DIR, "backup_images")
    os.makedirs(honey_dir)

    print("=" * 60)
    print("   VAULT SETUP: Creating Protected Environment")
    print("=" * 60)
    print(f"[*] Magic Header: {MAGIC_HEADER.decode()}")
    print(f"[*] Directory: {VAULT_DIR}")
    print("-" * 60)

    # 1. Create the Honeytoken (Trap) - with magic header
    honeytoken_path = os.path.join(VAULT_DIR, "config_sys_backup.dat")
    with open(honeytoken_path, "wb") as f:
        f.write(MAGIC_HEADER)
        f.write(os.urandom(1024))
    print("[TRAP] Created Honeytoken: config_sys_backup.dat")
    
    # 2. Create Honeytokens in subfolder - with magic header
    honeypot_files = ["wallet_seed.dat", "credentials_backup.dat", "recovery_key.dat"]
    for filename in honeypot_files:
        path = os.path.join(honey_dir, filename)
        with open(path, "wb") as f:
            f.write(MAGIC_HEADER)
            f.write(os.urandom(1024))
        print(f"[TRAP] Created Honeypot: backup_images/{filename}")

    # 3. Create "Heavy" Database Files (5MB each) - WITH MAGIC HEADER
    print("\n[*] Creating heavy database files with Magic Headers...")
    dummy_data = b"A" * (1024 * 1024 * 5)  # 5MB block of 'A's
    
    for i in range(1, 21):  # 20 heavy files = 100MB total
        filename = f"heavy_data_{i:02d}.db"
        path = os.path.join(VAULT_DIR, filename)
        with open(path, "wb") as f:
            f.write(MAGIC_HEADER)  # Write header FIRST
            f.write(dummy_data)    # Then write data
        print(f"    [+] Created 5MB file: {filename} (Header: {MAGIC_HEADER[:8].decode()}...)")
    
    # 4. Create small TEXT files (NO magic header - will use entropy detection)
    print("\n[*] Creating plain text files (no header)...")
    for i in range(1, 11):
        filename = f"notes_{i:02d}.txt"
        path = os.path.join(VAULT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            # Low entropy text content
            f.write("Important business notes.\n" * 100)
            f.write(f"Document #{i} - Quarterly Report\n")
            f.write("Budget analysis and forecasting data.\n" * 50)
        print(f"    [+] Created text file: {filename}")
    
    print("\n" + "=" * 60)
    print("[*] VAULT SETUP COMPLETE")
    print("-" * 60)
    print(f"    Binary Files (.db): 20 files with Magic Header")
    print(f"    Text Files (.txt):  10 files (plain)")
    print(f"    Honeytokens:        4 trap files")
    print(f"    Total Size:         ~100MB")
    print("=" * 60)
    print("\n[!] DETECTION LOGIC:")
    print("    - Binary files: Header must be 'CORP_DB_FORMAT_V1'")
    print("    - Text files:   Entropy must be < 7.5")
    print("    - Ransomware destroys headers and spikes entropy!")

if __name__ == "__main__":
    setup_vault()
