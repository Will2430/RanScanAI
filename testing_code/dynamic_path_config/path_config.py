"""
Dynamic Path Configuration for Ransomware Testing
==================================================
Provides a centralized, reusable way to reference the ransomware test folder
across multiple files without hardcoding paths.

Usage in other files:
    from path_config import get_test_folder
    
    TEST_FOLDER = get_test_folder()
"""

import os
from pathlib import Path


def get_project_root():
    """
    Dynamically find the project root directory.
    Searches upward from this file's location until it finds the workspace root.
    """
    current_file = Path(__file__).resolve()
    current_dir = current_file.parent
    
    # Look for indicators of project root (must have multiple indicators)
    # This ensures we find the actual workspace root, not a subdirectory
    project_indicators = ['config.py', 'README.md', 'models', 'Dataset', 'migration_package']
    
    # Search up to 5 levels up
    for _ in range(5):
        # Check if this directory contains MULTIPLE project indicators (stronger validation)
        matches = sum(1 for indicator in project_indicators if (current_dir / indicator).exists())
        if matches >= 3:  # At least 3 indicators = likely the root
            return current_dir
        
        # Move up one directory
        parent = current_dir.parent
        if parent == current_dir:  # Reached filesystem root
            break
        current_dir = parent
    
    # Fallback: return the parent of Testing_Code folder
    return Path(__file__).resolve().parent.parent.parent


def get_user_downloads_folder():
    """
    Get the current user's Downloads folder dynamically.
    Works across different Windows user accounts.
    """
    # Try multiple methods to find Downloads folder
    
    # Method 1: Use USERPROFILE environment variable
    user_profile = os.environ.get('USERPROFILE')
    if user_profile:
        downloads = Path(user_profile) / 'Downloads'
        if downloads.exists():
            return downloads
    
    # Method 2: Use HOMEDRIVE + HOMEPATH
    home_drive = os.environ.get('HOMEDRIVE', 'C:')
    home_path = os.environ.get('HOMEPATH', '')
    if home_path:
        downloads = Path(home_drive + home_path) / 'Downloads'
        if downloads.exists():
            return downloads
    
    # Method 3: Try common Windows patterns
    username = os.environ.get('USERNAME')
    if username:
        downloads = Path(f'C:/Users/{username}/Downloads')
        if downloads.exists():
            return downloads
    
    # Fallback: Use temp directory
    return Path(os.environ.get('TEMP', 'C:/Temp'))


def get_test_folder(prefer_downloads=True):
    """
    Get the ransomware test folder path dynamically.
    
    Args:
        prefer_downloads (bool): If True, uses Downloads folder. 
                                 If False, uses project directory.
    
    Returns:
        Path: Absolute path to the test folder
    
    Examples:
        >>> test_folder = get_test_folder()
        >>> print(test_folder)
        C:\\Users\\CurrentUser\\Downloads\\RANSOMWARE_TEST_FOLDER
        
        >>> test_folder = get_test_folder(prefer_downloads=False)
        >>> print(test_folder)
        C:\\Users\\User\\OneDrive\\Test\\K\\Testing_Code\\Ransomware_Simulation\\test_data
    """
    if prefer_downloads:
        # Use Downloads folder (isolated from project)
        downloads = get_user_downloads_folder()
        test_folder = downloads / 'RANSOMWARE_TEST_FOLDER'
    else:
        # Use project directory
        project_root = get_project_root()
        test_folder = project_root / 'Testing_Code' / 'Ransomware_Simulation' / 'test_data'
    
    return test_folder


def get_test_folder_str(prefer_downloads=True):
    """
    Get the ransomware test folder path as a string.
    Convenience function for legacy code.
    
    Returns:
        str: Absolute path to the test folder as string
    """
    return str(get_test_folder(prefer_downloads=prefer_downloads))


# Quick test/validation
if __name__ == '__main__':
    print("=" * 70)
    print("Path Configuration Test")
    print("=" * 70)
    
    print(f"\n📁 Current file location:")
    print(f"   {Path(__file__).resolve()}")
    
    print(f"\n📁 Project root detected:")
    print(f"   {get_project_root()}")
    
    print(f"\n📁 User Downloads folder:")
    print(f"   {get_user_downloads_folder()}")
    
    print(f"\n📁 Test folder (Downloads mode):")
    print(f"   {get_test_folder(prefer_downloads=True)}")
    
    print(f"\n📁 Test folder (Project mode):")
    print(f"   {get_test_folder(prefer_downloads=False)}")
    
    print("\n" + "=" * 70)
    print("✓ Path configuration is working correctly!")
    print("=" * 70)
    
    print("\n💡 Usage in your code:")
    print("   from path_config import get_test_folder")
    print("   TEST_FOLDER = get_test_folder()")
    print("=" * 70)
