"""
Setup Test Environment for Ransomware Simulation
=================================================
Creates isolated test folder with sample files for safe testing.
"""

import os
import sys
import random
from pathlib import Path

# Add parent's dynamic_path_config to path
sys.path.insert(0, str(Path(__file__).parent.parent / "dynamic_path_config"))
from path_config import get_test_folder

TEST_FOLDER = str(get_test_folder())  # Dynamically determined test folder


def create_test_folder():
    """Create isolated test folder"""
    if os.path.exists(TEST_FOLDER):
        print(f"⚠️  Test folder already exists: {TEST_FOLDER}")
        response = input("Delete and recreate? (yes/no): ").strip().lower()
        if response == 'yes':
            import shutil
            shutil.rmtree(TEST_FOLDER)
            print("✓ Deleted existing test folder")
        else:
            print("❌ Setup cancelled")
            return False
    
    os.makedirs(TEST_FOLDER, exist_ok=True)
    print(f"✓ Created test folder: {TEST_FOLDER}")
    return True


def create_sample_files():
    """Create dummy files for encryption testing"""
    
    sample_files = [
        ("document1.txt", "This is a sample text document for testing.\n" * 10),
        ("document2.txt", "Important business data would go here.\n" * 10),
        ("report.txt", "Quarterly financial report - CONFIDENTIAL\n" * 10),
        ("notes.txt", "Meeting notes and project planning.\n" * 10),
        ("data.txt", "Database backup simulation file.\n" * 10),
    ]
    
    # Create subdirectory
    subfolder = os.path.join(TEST_FOLDER, "documents")
    os.makedirs(subfolder, exist_ok=True)
    
    created_count = 0
    
    # Create files in main folder
    for filename, content in sample_files[:3]:
        filepath = os.path.join(TEST_FOLDER, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        created_count += 1
    
    # Create files in subfolder
    for filename, content in sample_files[3:]:
        filepath = os.path.join(subfolder, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        created_count += 1
    
    print(f"✓ Created {created_count} sample files")
    return created_count


def create_readme():
    """Create README explaining the test environment"""
    
    readme_content = """
RANSOMWARE TEST ENVIRONMENT
===========================

This folder contains SAFE TEST FILES for ransomware simulation.

Files in this folder:
- Sample .txt files (dummy data, no real content)
- Will be encrypted by ransomware_simulator.py
- Can be restored by cleanup_test.py

⚠️  IMPORTANT SAFETY NOTES:
- This folder is ISOLATED from your real files
- Only files in THIS folder will be affected
- Your real Downloads folder is SAFE
- The simulator has multiple safety checks

Usage:
1. Run ransomware_simulator.py to encrypt these files
2. Package as EXE: pyinstaller --onefile ransomware_simulator.py
3. Test the .exe for PE feature extraction
4. Run cleanup_test.py to restore original files

Created: 2026-02-09
"""
    
    readme_path = os.path.join(TEST_FOLDER, "README.txt")
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"✓ Created README: {readme_path}")


def main():
    print("="*60)
    print("🔧 SETTING UP TEST ENVIRONMENT")
    print("="*60)
    
    # Create folder structure
    if not create_test_folder():
        return
    
    # Create sample files
    create_sample_files()
    
    # Create README
    create_readme()
    
    print("\n" + "="*60)
    print("✅ TEST ENVIRONMENT READY")
    print("="*60)
    print(f"Location: {TEST_FOLDER}")
    print("\nNext steps:")
    print("1. Review the files in the test folder")
    print("2. Run: python ransomware_simulator.py")
    print("3. Package as EXE: pyinstaller --onefile ransomware_simulator.py")
    print("4. Test the .exe for PE features")
    print("5. Cleanup: python cleanup_test.py")
    print("="*60)


if __name__ == "__main__":
    main()
