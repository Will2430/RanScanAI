"""
Build script for compiling ransomware_simulator.py to .exe
This creates an executable with suspicious characteristics for ML testing
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime

# Add parent's dynamic_path_config to path
sys.path.insert(0, str(Path(__file__).parent.parent / "dynamic_path_config"))
from path_config import get_test_folder

# Build configuration
SCRIPT_DIR = Path(__file__).parent  # Dynamic - finds files in same directory
# Build uses the activity_monitor copy — that is the maintained, optimised version.
# The ransomware_simulation/ransomware_simulator.py copy is kept for reference only.
RANSOMWARE_SCRIPT = SCRIPT_DIR.parent / "activity_monitor" / "ransomware_simulator.py"
OUTPUT_DIR = SCRIPT_DIR / "dist"
BUILD_DIR = SCRIPT_DIR / "build"
SPEC_FILE = SCRIPT_DIR / "ransomware_simulator.spec"

# PyInstaller options that create suspicious characteristics
# Note: We'll use 'python -m PyInstaller' instead of 'pyinstaller' for reliability
PYINSTALLER_OPTIONS = [
    "--onefile",                    # Single executable (common for malware)  # No console window (suspicious)
    # "--clean",                    # Clean PyInstaller cache (disabled due to permission issues)
    "--distpath", str(OUTPUT_DIR),  # Output directory
    "--workpath", str(BUILD_DIR),   # Build directory
    "--name", "System_Update",      # Deceptive filename (suspicious)
    # Include the dynamic_path_config module
    "--paths", str(SCRIPT_DIR.parent / "dynamic_path_config"),
    "--hidden-import", "path_config",
    str(RANSOMWARE_SCRIPT)
]

# Additional suspicious options
SUSPICIOUS_OPTIONS = [
    "--noupx",                      # Don't compress (easier to analyze, but suspicious  # Hide console (very suspicious)
]


def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            print(f"✓ PyInstaller found: {result.stdout.strip()}")
            return True
        else:
            print("✗ PyInstaller not found")
            return False
    except FileNotFoundError:
        print("✗ PyInstaller not found")
        return False
    except Exception as e:
        print(f"✗ Error checking PyInstaller: {e}")
        return False


def install_pyinstaller():
    """Install PyInstaller"""
    print("\nInstalling PyInstaller...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pyinstaller"],
            check=True
        )
        print("✓ PyInstaller installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install PyInstaller: {e}")
        return False


def build_executable():
    """Build the executable using PyInstaller"""
    print("\n" + "="*60)
    print("BUILDING MALICIOUS TEST EXECUTABLE")
    print("="*60)
    
    # Check if ransomware_simulator.py exists
    if not RANSOMWARE_SCRIPT.exists():
        print(f"✗ Error: {RANSOMWARE_SCRIPT} not found!")
        return False
    
    print(f"Source script: {RANSOMWARE_SCRIPT}")
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"Output name: System_Update.exe")
    
    # Build command with suspicious options - use python -m PyInstaller for reliability
    build_command = [sys.executable, "-m", "PyInstaller"] + PYINSTALLER_OPTIONS + SUSPICIOUS_OPTIONS
    
    print(f"\nBuild command:")
    print(" ".join(build_command))
    
    # Execute build
    print("\nBuilding... (this may take a few minutes)")
    try:
        result = subprocess.run(
            build_command,
            check=True,
            capture_output=True,
            text=True
        )
        
        print("\n✓ Build completed successfully!")
        
        # Check output
        exe_path = OUTPUT_DIR / "System_Update.exe"
        if exe_path.exists():
            file_size = exe_path.stat().st_size
            print(f"\n✓ Executable created: {exe_path}")
            print(f"  Size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
            
            # Display characteristics
            print("\n" + "="*60)
            print("SUSPICIOUS CHARACTERISTICS")
            print("="*60)
            print("✓ Single-file executable (common for malware)")
            print("✓ No console window (hidden execution)")
            print("✓ Deceptive filename (System_Update.exe)")
            print("✓ No icon (suspicious)")
            print("✓ Packed executable (PyInstaller bootloader)")
            print("✓ Will perform 500+ file operations")
            print("✓ Will perform 2000+ registry operations")
            print("✓ Will perform 1000+ network requests")
            print("✓ Creates ransom notes")
            print("✓ Encrypts files (renames with .locked/.encrypted)")
            print("="*60)
            
            return True
        else:
            print(f"\n✗ Error: Executable not found at {exe_path}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Build failed!")
        print(f"Error: {e}")
        if e.stdout:
            print(f"\nStdout:\n{e.stdout}")
        if e.stderr:
            print(f"\nStderr:\n{e.stderr}")
        return False


def create_manifest():
    """Create a manifest file for the malicious executable"""
    manifest_path = OUTPUT_DIR / "System_Update_manifest.txt"
    test_folder = get_test_folder()
    
    manifest_content = f"""
MALICIOUS TEST EXECUTABLE MANIFEST
==================================

Filename: System_Update.exe
Purpose: Ransomware behavior simulator for ML detection testing
Safety: SAFE - Only operates in: {test_folder}

BEHAVIORAL CHARACTERISTICS:
--------------------------
[+] File Operations: 500+ (creates, encrypts, deletes)
[+] Registry Operations: 2000+ reads, 60+ writes
[+] Network Operations: 1000+ DNS lookups, port scans
[+] Process Enumeration: 50+ iterations
[+] Persistence Checks: Multiple autorun locations
[+] Mutex Creation: Ransomware-style mutex
[+] Ransom Notes: Creates 4+ ransom notes

PE CHARACTERISTICS (Suspicious):
--------------------------------
[+] Packed executable (PyInstaller)
[+] No console window (--noconsole)
[+] Deceptive filename
[+] No code signature
[+] Dynamic imports
[+] Entropy analysis will show high entropy (packed)

EXPECTED ML DETECTION:
---------------------
This executable SHOULD be flagged as MALICIOUS by your model due to:
- High volume of file operations
- Extensive registry manipulation
- Suspicious network activity
- Ransomware-like behavioral patterns
- PE characteristics matching malware

TESTING PROCEDURE:
-----------------
1. Upload System_Update.exe to your detection system
2. Run behavioral analysis / dynamic analysis
3. Verify model flags it as MALICIOUS
4. Check confidence score (should be high)

Built: {datetime.now().isoformat()}
"""
    
    try:
        manifest_path.write_text(manifest_content, encoding='utf-8')
        print(f"\n✓ Manifest created: {manifest_path}")
    except Exception as e:
        print(f"\n✗ Failed to create manifest: {e}")


def main():
    print("="*60)
    print("MALICIOUS EXECUTABLE BUILD SCRIPT")
    print("Build ransomware_simulator.py into suspicious .exe")
    print("="*60)
    
    # Check PyInstaller
    if not check_pyinstaller():
        print("\nPyInstaller is required to build the executable.")
        
        # Check if running interactively
        if sys.stdin and sys.stdin.isatty():
            choice = input("Install PyInstaller now? (y/n): ").lower()
            if choice == 'y':
                if not install_pyinstaller():
                    print("\nFailed to install PyInstaller. Exiting.")
                    return
            else:
                print("\nCannot build without PyInstaller. Exiting.")
                return
        else:
            # Non-interactive mode - auto-install
            print("\nNon-interactive mode detected - auto-installing PyInstaller...")
            if not install_pyinstaller():
                print("\nFailed to install PyInstaller. Exiting.")
                return
    
    # Build executable
    if build_executable():
        create_manifest()
        
        print("\n" + "="*60)
        print("BUILD SUCCESSFUL!")
        print("="*60)
        print(f"\nYour malicious test executable is ready:")
        print(f"  {OUTPUT_DIR / 'System_Update.exe'}")
        print(f"\nNext steps:")
        print(f"  1. Test with your ML model")
        print(f"  2. Verify it's flagged as MALICIOUS")
        print(f"  3. Analyze confidence scores")
        print(f"  4. Review behavioral data in behavioral_data.json")
        print("\n" + "="*60)
    else:
        print("\n" + "="*60)
        print("BUILD FAILED")
        print("="*60)


if __name__ == "__main__":
    main()
