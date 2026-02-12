"""
Cleanup Test Environment
=========================
Decrypts files and restores the test environment to original state.
"""

import os
import sys
import shutil
from pathlib import Path
from cryptography.fernet import Fernet

# Add parent's dynamic_path_config to path
sys.path.insert(0, str(Path(__file__).parent.parent / "dynamic_path_config"))
from path_config import get_test_folder

TEST_FOLDER = str(get_test_folder())  # Dynamically determined test folder


def decrypt_files():
    """Decrypt all .locked files using saved key"""
    
    key_file = os.path.join(TEST_FOLDER, ".decryption_key.secret")
    
    if not os.path.exists(key_file):
        print("⚠️  No decryption key found!")
        print("Files cannot be automatically decrypted.")
        print("Recommendation: Delete test folder and run setup_test_environment.py again")
        return False
    
    # Load decryption key
    with open(key_file, 'rb') as f:
        encryption_key = f.read()
    
    cipher = Fernet(encryption_key)
    print(f"✓ Loaded decryption key")
    
    # Find all .locked files
    decrypted_count = 0
    for root, dirs, files in os.walk(TEST_FOLDER):
        for filename in files:
            if filename.endswith('.locked'):
                locked_path = os.path.join(root, filename)
                original_path = locked_path[:-7]  # Remove .locked extension
                
                try:
                    # Read encrypted file
                    with open(locked_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # Decrypt
                    decrypted_data = cipher.decrypt(encrypted_data)
                    
                    # Write original file back
                    with open(original_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    # Remove .locked file
                    os.remove(locked_path)
                    
                    print(f"  ✓ Decrypted: {os.path.basename(original_path)}")
                    decrypted_count += 1
                    
                except Exception as e:
                    print(f"  ✗ Error decrypting {filename}: {e}")
    
    # Remove decryption key
    os.remove(key_file)
    
    # Remove ransom note
    ransom_note = os.path.join(TEST_FOLDER, "⚠️_RANSOM_NOTE_⚠️.txt")
    if os.path.exists(ransom_note):
        os.remove(ransom_note)
        print("✓ Removed ransom note")
    
    print(f"\n✅ Decrypted {decrypted_count} files")
    return True


def full_cleanup():
    """Completely remove test folder"""
    
    if not os.path.exists(TEST_FOLDER):
        print(f"⚠️  Test folder doesn't exist: {TEST_FOLDER}")
        return
    
    print(f"⚠️  This will DELETE the entire test folder: {TEST_FOLDER}")
    response = input("Confirm deletion? (yes/no): ").strip().lower()
    
    if response == 'yes':
        shutil.rmtree(TEST_FOLDER)
        print(f"✅ Deleted test folder completely")
    else:
        print("❌ Deletion cancelled")


def main():
    print("="*60)
    print("🔄 CLEANUP TEST ENVIRONMENT")
    print("="*60)
    
    if not os.path.exists(TEST_FOLDER):
        print(f"❌ Test folder not found: {TEST_FOLDER}")
        print("Nothing to clean up.")
        return
    
    print("Choose cleanup option:")
    print("1. Decrypt files (restore to original state)")
    print("2. Delete entire test folder")
    print("3. Cancel")
    
    choice = input("\nEnter choice (1/2/3): ").strip()
    
    if choice == '1':
        print("\n--- Decrypting Files ---")
        decrypt_files()
        print("\n✅ Test environment restored!")
        
    elif choice == '2':
        print("\n--- Full Deletion ---")
        full_cleanup()
        
    else:
        print("❌ Cleanup cancelled")


if __name__ == "__main__":
    main()
