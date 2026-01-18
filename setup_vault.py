import os
import random
import shutil

VAULT_DIR = "./test_vault"

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

if __name__ == "__main__":
    setup_vault()
