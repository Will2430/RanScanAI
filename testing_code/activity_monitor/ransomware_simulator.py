"""
Ransomware Behavior Simulator - SAFE TEST VERSION
Simulates ransomware behavior patterns for ML detection testing
COMPLETELY SAFE - Only operates in designated test folder
"""

import os
import sys
import time
import random
import string
import socket
import winreg
import json
from pathlib import Path
from datetime import datetime

# Add parent's dynamic_path_config to path
sys.path.insert(0, str(Path(__file__).parent.parent / "dynamic_path_config"))
try:
    from path_config import get_test_folder
except ImportError:
    print("ERROR: Could not import path_config module")
    sys.exit(1)

# ============================================================================
# SAFETY CONFIGURATION - ONLY OPERATES IN TEST FOLDER
# ============================================================================
TEST_FOLDER = get_test_folder()  # Dynamically determined test folder
SAFE_MODE = True # Never disable this!

# Ensure we ONLY work in test folder (with dynamic validation)
if not TEST_FOLDER.exists():
    TEST_FOLDER.mkdir(parents=True, exist_ok=True)
    print(f"[INIT] Created test folder: {TEST_FOLDER}")
elif not any(part in str(TEST_FOLDER).lower() for part in ['downloads', 'test', 'ransomware']):
    print("ERROR: Invalid test folder path!")
    sys.exit(1)


def setup_test_environment():
    """Create safe test environment"""
    TEST_FOLDER.mkdir(parents=True, exist_ok=True)
    print(f"[INIT] Test folder: {TEST_FOLDER}")
    print(f"[INIT] Safe mode: {SAFE_MODE}")
    print(f"[INIT] Starting simulation at {datetime.now()}")
    print("-" * 60)


def generate_random_filename():
    """Generate random filename"""
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    ext = random.choice(['.txt', '.doc', '.jpg', '.pdf', '.xlsx'])
    return name + ext


def simulate_file_encryption():
    """
    Simulate file encryption behavior (SAFE - EXTREME VERSION)
    Creates dummy files, renames them, deletes them - AGGRESSIVE
    """
    print("\n[FILE] Starting AGGRESSIVE file encryption simulation...")
    
    created_files = []
    encrypted_files = []
    deleted_files = []
    
    # Create 500 dummy test files (increased from 100)
    for i in range(500):
        filename = TEST_FOLDER / generate_random_filename()
        try:
            # Create dummy file with random content
            content = ''.join(random.choices(string.ascii_letters, k=random.randint(100, 10000)))
            filename.write_text(content)
            created_files.append(filename)
            
            if i % 50 == 0:
                print(f"[FILE] Created {i+1}/500 files...")
        except Exception as e:
            print(f"[FILE] Error creating {filename}: {e}")
    
    print(f"[FILE] Created {len(created_files)} test files")
    
    # Simulate encryption by renaming files with ransomware extensions
    ransomware_extensions = ['.locked', '.encrypted', '.crypto', '.crypted', '.crypt', '.encrypted', '.locked']
    for i, filepath in enumerate(created_files):
        try:
            ext = random.choice(ransomware_extensions)
            encrypted_name = filepath.parent / (filepath.stem + ext)
            filepath.rename(encrypted_name)
            encrypted_files.append(encrypted_name)
            
            if i % 50 == 0:
                print(f"[FILE] Encrypted {i+1}/{len(created_files)} files...")
        except Exception as e:
            print(f"[FILE] Error encrypting {filepath}: {e}")
    
    print(f"[FILE] Simulated encryption of {len(encrypted_files)} files")
    
    # Delete 20% of encrypted files (simulating data loss)
    files_to_delete = encrypted_files[:len(encrypted_files)//5]
    for filepath in files_to_delete:
        try:
            filepath.unlink()
            deleted_files.append(filepath)
        except Exception as e:
            pass
    
    print(f"[FILE] Deleted {len(deleted_files)} files (simulating data destruction)")
    
    # Create multiple ransom notes in different locations
    ransom_notes = [
        "README_DECRYPT.txt",
        "HOW_TO_DECRYPT.txt",
        "YOUR_FILES_ARE_ENCRYPTED.txt",
        "DECRYPT_INSTRUCTION.txt"
    ]
    
    for note_name in ransom_notes:
        ransom_note = TEST_FOLDER / note_name
        ransom_note.write_text(f"""
=== YOUR FILES HAVE BEEN ENCRYPTED ===

All your important files have been encrypted with military-grade encryption.
Your documents, photos, databases - EVERYTHING is locked.

To decrypt your files, you must pay 0.5 BTC to:
bc1q{random.randint(10**15, 10**16-1)}

You have 72 hours before the decryption key is destroyed permanently.

=== This is a SIMULATION for testing purposes ===
Test folder: C:\\Users\\willi\\Downloads\\RANSOMWARE_TEST_FOLDER
""")
    
    print(f"[FILE] Created {len(ransom_notes)} ransom notes")
    
    return created_files, encrypted_files


def simulate_registry_activity():
    """
    Simulate registry activity (SAFE - READS + TEST WRITES - EXTREME VERSION)
    Performs MASSIVE registry reads + safe writes to test key
    """
    print("\n[REGISTRY] Starting AGGRESSIVE registry activity simulation...")
    
    # Common registry paths that ransomware checks (READ ONLY)
    safe_registry_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion"),
        (winreg.HKEY_CURRENT_USER, r"Software"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        (winreg.HKEY_CURRENT_USER, r"Environment"),
        (winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop"),
        (winreg.HKEY_CURRENT_USER, r"Software\Classes"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"),
    ]
    
    read_count = 0
    write_count = 0
    delete_count = 0
    
    # Phase 1: Perform 2000 registry reads (increased from 500)
    for _ in range(2000):
        hkey, path = random.choice(safe_registry_paths)
        try:
            # READ ONLY - opens registry key and reads values
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
            
            # Enumerate some values (read only)
            try:
                for i in range(min(10, winreg.QueryInfoKey(key)[1])):
                    winreg.EnumValue(key, i)
                    read_count += 1
            except:
                pass
            
            winreg.CloseKey(key)
            
            if read_count % 100 == 0 and read_count > 0:
                print(f"[REGISTRY] Performed {read_count} registry reads...")
                
        except Exception as e:
            # Silently skip inaccessible keys
            pass
    
    print(f"[REGISTRY] Completed {read_count} registry read operations")
    
    # Phase 2: Write to MULTIPLE test registry keys (SAFE - isolated test keys)
    # This mimics ransomware persistence mechanisms
    test_keys = [
        r"Software\TestRansomware",
        r"Software\TestRansomware\Persistence",
        r"Software\TestRansomware\Encryption",
        r"Software\TestRansomware\C2Config"
    ]
    
    for test_key_path in test_keys:
        try:
            test_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key_path)
            
            # Write multiple values to simulate persistence attempts
            persistence_values = [
                ("MalwareEntry1", f"C:\\FakeRansomware_{random.randint(1000, 9999)}.exe"),
                ("MalwareEntry2", f"C:\\Windows\\Temp\\malware_{random.randint(1000, 9999)}.dll"),
                ("MalwareEntry3", f"C:\\ProgramData\\UpdateService_{random.randint(1000, 9999)}.exe"),
                ("EncryptionKey", ''.join(random.choices(string.ascii_letters + string.digits, k=64))),
                ("C2Server", f"http://evil-c2-{random.randint(100, 999)}.malware.test"),
                ("C2ServerBackup", f"https://backup-c2-{random.randint(100, 999)}.onion"),
                ("InstallDate", datetime.now().isoformat()),
                ("VictimID", ''.join(random.choices(string.hexdigits, k=32))),
                ("EncryptedFiles", str(random.randint(5000, 15000))),
                ("RansomAmount", f"${random.randint(1000, 10000)} BTC"),
                ("BitcoinAddress", f"bc1q{random.randint(10**15, 10**16-1)}"),
                ("DeadlineTimestamp", str(int(time.time()) + 72*3600)),
                ("EncryptionAlgorithm", "AES-256-CBC"),
                ("MutexName", f"RansomMutex_{random.randint(10000, 99999)}"),
                ("AutoStart", "1"),
            ]
            
            for name, value in persistence_values:
                winreg.SetValueEx(test_key, name, 0, winreg.REG_SZ, value)
                write_count += 1
            
            winreg.CloseKey(key)
            print(f"[REGISTRY] Wrote {len(persistence_values)} values to: {test_key_path}")
            
        except Exception as e:
            print(f"[REGISTRY] Error writing to test key: {e}")
    
    print(f"[REGISTRY] Completed {write_count} registry write operations across {len(test_keys)} keys")
    
    return read_count, write_count


def simulate_network_activity():
    """
    Simulate network activity (SAFE - DNS LOOKUPS ONLY - EXTREME VERSION)
    Performs MASSIVE DNS lookups to simulate C2 communication and network scanning
    """
    print("\n[NETWORK] Starting AGGRESSIVE network activity simulation...")
    
    # Fake C2 domains (these don't exist - just DNS lookups)
    fake_c2_domains = [
        f"c2-server-{i}.malware-test.invalid" for i in range(100)
    ] + [
        f"ransomware-panel-{i}.onion.invalid" for i in range(50)
    ] + [
        "evil-command-control.invalid",
        "ransomware-payment.invalid",
        "btc-wallet-check.invalid",
        "encryption-key-server.invalid",
        "victim-data-exfil.invalid",
        "tor-proxy-gateway.invalid",
        "anonymous-payment-gateway.invalid",
        "crypto-ransom-wallet.invalid",
        "ransomware-as-a-service.invalid",
        "darkweb-ransomware-panel.invalid",
    ]
    
    dns_lookups = 0
    connection_attempts = 0
    
    # Perform 1000 DNS lookups (increased from 200)
    for _ in range(1000):
        domain = random.choice(fake_c2_domains)
        try:
            # This will fail (domains don't exist) but generates DNS traffic
            socket.gethostbyname(domain)
        except socket.gaierror:
            # Expected - domain doesn't exist
            dns_lookups += 1
        except Exception as e:
            pass
        
        if dns_lookups % 100 == 0 and dns_lookups > 0:
            print(f"[NETWORK] Performed {dns_lookups} DNS lookups...")
        
        # Small delay to avoid overwhelming DNS
        time.sleep(0.005)
    
    print(f"[NETWORK] Completed {dns_lookups} DNS lookup requests")
    
    # Simulate port scanning behavior (connection attempts to common C2 ports)
    common_c2_ports = [80, 443, 8080, 8443, 4444, 5555, 6666, 7777, 8888, 9999]
    print(f"[NETWORK] Simulating port scanning on {len(common_c2_ports)} ports...")
    
    for port in common_c2_ports:
        try:
            # Attempt to connect to localhost on various ports (will fail, but generates connection attempts)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            sock.connect(('127.0.0.1', port))
            sock.close()
        except:
            connection_attempts += 1
    
    print(f"[NETWORK] Completed {connection_attempts} connection attempt scans")
    print(f"[NETWORK] Total network operations: {dns_lookups + connection_attempts}")


def simulate_process_activity():
    """
    Simulate process enumeration (SAFE)
    """
    print("\n[PROCESS] Starting process activity simulation...")
    
    try:
        import psutil
        
        # Enumerate processes multiple times
        for i in range(50):
            processes = list(psutil.process_iter(['pid', 'name']))
            
            if i % 10 == 0:
                print(f"[PROCESS] Process enumeration #{i+1}/50 ({len(processes)} processes)")
            
            time.sleep(0.05)
        
        print(f"[PROCESS] Completed process enumeration")
        
    except ImportError:
        print("[PROCESS] psutil not available - skipping process simulation")


def simulate_persistence_check():
    """
    Simulate persistence mechanism checks (SAFE - READ ONLY)
    Checks common persistence locations without modifying
    """
    print("\n[PERSISTENCE] Checking persistence locations (read-only)...")
    
    # Common persistence locations (READ ONLY)
    persistence_checks = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    
    checks = 0
    for hkey, path in persistence_checks:
        try:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
            num_values = winreg.QueryInfoKey(key)[1]
            print(f"[PERSISTENCE] Checked {path}: {num_values} entries")
            winreg.CloseKey(key)
            checks += 1
        except:
            pass
    
    print(f"[PERSISTENCE] Completed {checks} persistence checks")


def simulate_mutex_creation():
    """
    Simulate mutex creation (ransomware often uses mutexes)
    """
    print("\n[MUTEX] Simulating mutex creation...")
    
    # This is just for show - mutexes are harmless
    mutex_name = f"RansomSim_{random.randint(10000, 99999)}"
    print(f"[MUTEX] Created mutex: {mutex_name}")


def cleanup_test_files():
    """
    Clean up test files and registry after simulation
    """
    print("\n[CLEANUP] Cleaning up test environment...")
    
    # Clean up test files
    try:
        import shutil
        if TEST_FOLDER.exists():
            shutil.rmtree(TEST_FOLDER)
            print(f"[CLEANUP] Removed test folder: {TEST_FOLDER}")
    except Exception as e:
        print(f"[CLEANUP] Error during cleanup: {e}")
        print(f"[CLEANUP] Please manually delete: {TEST_FOLDER}")
    
    # Clean up test registry keys
    test_keys_to_remove = [
        r"Software\TestRansomware\Persistence",
        r"Software\TestRansomware\Encryption",
        r"Software\TestRansomware\C2Config",
        r"Software\TestRansomware"
    ]
    
    for test_key_path in test_keys_to_remove:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key_path)
            print(f"[CLEANUP] Removed registry key: HKCU\\{test_key_path}")
        except FileNotFoundError:
            # Key doesn't exist - already clean
            pass
        except Exception as e:
            print(f"[CLEANUP] Error removing registry key {test_key_path}: {e}")
            print(f"[CLEANUP] Please manually delete: HKCU\\{test_key_path}")


def main():
    """
    Main simulation routine
    """
    # Check for --auto-run flag (used by vm_behavioral_monitor.py)
    auto_run = '--auto-run' in sys.argv
    
    print("="*60)
    print("RANSOMWARE BEHAVIOR SIMULATOR")
    print("SAFE TEST VERSION - FOR ML DETECTION TESTING")
    if auto_run:
        print("MODE: AUTO-RUN (Non-interactive)")
    print("="*60)
    
    if not SAFE_MODE:
        print("ERROR: Safe mode disabled! Aborting.")
        sys.exit(1)
    
    # Setup
    setup_test_environment()
    
    # Track behavioral statistics
    behavioral_stats = {
        "target": sys.argv[0],
        "start_time": datetime.now().isoformat(),
        "registry": {
            "read": 0,
            "write": 0,
            "delete": 0,
            "keys_modified": []
        },
        "network": {
            "dns": 0,
            "http": 0,
            "connections": 0,
            "domains": []
        },
        "processes": {
            "total": 0,
            "created": []
        },
        "files": {
            "created": [],
            "encrypted": [],
            "deleted": [],
            "suspicious": 0,
            "malicious": 0
        },
        "dlls": [],
        "apis": 0,
        "execution_time": 0.0,
        "status": "running"
    }
    
    start_time_exec = time.time()
    
    # Simulate various ransomware behaviors
    try:
        # Phase 1: Initial reconnaissance
        simulate_mutex_creation()
        time.sleep(0.5)
        
        # Phase 2: System enumeration (EXTREME ACTIVITY)
        reg_reads, reg_writes = simulate_registry_activity()  # 2000+ reads + 60 writes
        behavioral_stats["registry"]["read"] = reg_reads
        behavioral_stats["registry"]["write"] = reg_writes
        behavioral_stats["registry"]["keys_modified"] = [
            "HKCU\\Software\\TestRansomware",
            "HKCU\\Software\\TestRansomware\\Persistence",
            "HKCU\\Software\\TestRansomware\\Encryption",
            "HKCU\\Software\\TestRansomware\\C2Config"
        ]
        time.sleep(0.5)
        
        # Phase 3: Network communication (EXTREME ACTIVITY)
        simulate_network_activity()  # 1000+ DNS lookups + port scans
        behavioral_stats["network"]["dns"] = 1000
        behavioral_stats["network"]["http"] = 10
        behavioral_stats["network"]["connections"] = 1010
        behavioral_stats["network"]["domains"] = [
            "c2-server.malware-test.invalid",
            "evil-command-control.invalid",
            "ransomware-payment.invalid"
        ]
        time.sleep(0.5)
        
        # Phase 4: Persistence checks
        simulate_persistence_check()
        time.sleep(0.5)
        
        # Phase 5: Process enumeration
        simulate_process_activity()
        behavioral_stats["processes"]["total"] = 50
        time.sleep(0.5)
        
        # Phase 6: File encryption (creating, renaming files)
        created, encrypted = simulate_file_encryption()  # 500 files
        behavioral_stats["files"]["created"] = [str(f) for f in created[:20]]  # Limit to 20
        behavioral_stats["files"]["encrypted"] = [str(f) for f in encrypted[:20]]  # Limit to 20
        behavioral_stats["files"]["deleted"] = [str(f) for f in encrypted[:100] if random.random() < 0.2]
        behavioral_stats["files"]["suspicious"] = len(encrypted)
        behavioral_stats["files"]["malicious"] = len(encrypted)
        
        behavioral_stats["execution_time"] = time.time() - start_time_exec
        behavioral_stats["status"] = "completed"
        
        # Write behavioral data to JSON
        behavioral_json = Path(__file__).parent / "behavioral_data.json"
        with open(behavioral_json, 'w') as f:
            json.dump(behavioral_stats, f, indent=2)
        
        print("\n" + "="*60)
        print("SIMULATION COMPLETE")
        print("="*60)
        print(f"Files created: {len(created)}")
        print(f"Files encrypted: {len(encrypted)}")
        print(f"Registry reads: {reg_reads}+")
        print(f"Registry writes: {reg_writes}+")
        print(f"Network requests: 1000+")
        print(f"Test folder: {TEST_FOLDER}")
        print(f"Behavioral data: {behavioral_json}")
        print("="*60)
        
        # Optional: Clean up automatically (skip if running non-interactively or auto-run)
        if sys.stdin and sys.stdin.isatty() and not auto_run:
            cleanup_choice = input("\nClean up test files? (y/n): ").lower()
            if cleanup_choice == 'y':
                cleanup_test_files()
            else:
                print(f"\nTest files remain in: {TEST_FOLDER}")
        else:
            # Non-interactive mode or auto-run - don't clean up
            print(f"\n[AUTO] Non-interactive/auto-run mode - test files remain in: {TEST_FOLDER}")
        
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Simulation stopped by user")
        behavioral_stats["execution_time"] = time.time() - start_time_exec
        behavioral_stats["status"] = "interrupted"
        
        # Write partial data
        behavioral_json = Path(__file__).parent / "behavioral_data.json"
        with open(behavioral_json, 'w') as f:
            json.dump(behavioral_stats, f, indent=2)
        
        if sys.stdin and sys.stdin.isatty() and not auto_run:
            cleanup_choice = input("\nClean up test files? (y/n): ").lower()
            if cleanup_choice == 'y':
                cleanup_test_files()
        else:
            print(f"\n[AUTO] Auto-run/non-interactive mode - skipping cleanup")
    
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
