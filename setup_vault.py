import os
import random
import shutil

VAULT_DIR = "./test_vault"

def create_honeytokens():
    """Create honeytoken (canary) files that trigger alerts when accessed."""
    print("[*] Creating honeytokens...")
    
    # Honeytoken 1: Hidden canary file with fake binary data (looks like encrypted credentials)
    canary_path = os.path.join(VAULT_DIR, "config_sys_backup.dat")
    with open(canary_path, "wb") as f:
        # Random bytes to look like encrypted/important data
        f.write(os.urandom(1024))
    print("    [+] Created honeytoken: config_sys_backup.dat (canary file)")
    
    # Honeytoken 2: Honeypot subfolder with bait files
    honeypot_dir = os.path.join(VAULT_DIR, "backup_images")
    os.makedirs(honeypot_dir, exist_ok=True)
    
    honeypot_files = [
        ("image_backup_001.dat", 512),
        ("credentials_backup.dat", 256),
        ("wallet_seed.dat", 128),
    ]
    
    for filename, size in honeypot_files:
        path = os.path.join(honeypot_dir, filename)
        with open(path, "wb") as f:
            f.write(os.urandom(size))
        print(f"    [+] Created honeypot: backup_images/{filename}")
    
    print("[*] Honeytokens created successfully.")

def setup_vault():
    # Clean up existing vault
    if os.path.exists(VAULT_DIR):
        shutil.rmtree(VAULT_DIR)
    os.makedirs(VAULT_DIR)
    print(f"[*] Created {VAULT_DIR}")

    # Dummy content
    content_samples = [
        "The quick brown fox jumps over the lazy dog.",
        "To be or not to be, that is the question.",
        "In the middle of the journey of our life I found myself within a dark woods.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Ransomware simulation test file. Do not panic.",
        "Tyger Tyger, burning bright, In the forests of the night,"
    ]

    # Create 20 dummy files
    for i in range(1, 21):
        filename = f"file_{i:02d}.txt"
        path = os.path.join(VAULT_DIR, filename)
        with open(path, "w") as f:
            # Repeat content to give it some size
            f.write("\n".join([random.choice(content_samples) for _ in range(50)]))
        print(f"    [+] Created {filename}")
    
    print("[*] Vault setup complete with 20 files.")
    
    # Add honeytokens
    create_honeytokens()
    
    print("=" * 50)
    print("[*] VAULT READY: 20 text files + honeytokens deployed")

if __name__ == "__main__":
    setup_vault()
