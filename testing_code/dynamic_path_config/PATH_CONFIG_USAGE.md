# Path Configuration Usage Guide

## Overview
The `path_config.py` module provides a **dynamic, reusable way** to reference the ransomware test folder across all files without hardcoding paths.

## Quick Start

### Basic Usage (Recommended)
```python
from path_config import get_test_folder

# Get test folder as Path object
TEST_FOLDER = get_test_folder()

# Use it
print(f"Test folder: {TEST_FOLDER}")
TEST_FOLDER.mkdir(parents=True, exist_ok=True)
```

### As String (For Legacy Code)
```python
from path_config import get_test_folder_str

# Get test folder as string
TEST_FOLDER = get_test_folder_str()

# Use it
import os
os.makedirs(TEST_FOLDER, exist_ok=True)
```

### Choose Location Mode
```python
from path_config import get_test_folder

# Use Downloads folder (default, isolated from project)
TEST_FOLDER = get_test_folder(prefer_downloads=True)
# Result: C:\Users\CurrentUser\Downloads\RANSOMWARE_TEST_FOLDER

# Use project directory (keeps test data with code)
TEST_FOLDER = get_test_folder(prefer_downloads=False)
# Result: C:\Users\User\OneDrive\Test\K\Testing_Code\Ransomware_Simulation\test_data
```

## Migration Pattern

### Before (Hardcoded):
```python
import os
from pathlib import Path

TEST_FOLDER = Path(r"C:\Users\willi\Downloads\RANSOMWARE_TEST_FOLDER")
```

### After (Dynamic):
```python
import os
from pathlib import Path
from path_config import get_test_folder

TEST_FOLDER = get_test_folder()
```

## Updated Files
The following files have been updated to use dynamic paths:
- ✅ `ransomware_simulator.py`
- ✅ `cleanup_test.py`
- ✅ `setup_test_environment.py`
- ⚠️ `build_malicious_exe.py` (doesn't reference test folder directly)

## Benefits

1. **User-Independent**: Works for any Windows user without modification
2. **No Hardcoding**: Automatically detects correct paths
3. **Portable**: Code works on different machines
4. **Centralized**: Change location preference in one place
5. **Safe**: Maintains security validation

## Testing the Configuration

Run the path_config module directly to verify paths:
```bash
python path_config.py
```

This will display:
- Current file location
- Detected project root
- User Downloads folder
- Test folder paths (both modes)

## How It Works

1. **Project Root Detection**: Searches upward for indicators like `config.py`, `README.md`, `models/`
2. **User Downloads**: Uses environment variables (`USERPROFILE`, `USERNAME`) to find Downloads
3. **Dynamic Selection**: Chooses between Downloads or project directory based on preference
4. **Path Object**: Returns `pathlib.Path` object for modern Python code
5. **Fallback**: Graceful degradation if paths cannot be detected

## Advanced Usage

### Custom Validation
```python
from path_config import get_test_folder

TEST_FOLDER = get_test_folder()

# Add your own validation
if not TEST_FOLDER.exists():
    TEST_FOLDER.mkdir(parents=True, exist_ok=True)
    print(f"Created: {TEST_FOLDER}")

# Verify it's in a safe location
safe_locations = ['downloads', 'test', 'ransomware']
if not any(part in str(TEST_FOLDER).lower() for part in safe_locations):
    raise ValueError("Test folder must be in a safe location!")
```

### Accessing Other Project Paths
```python
from path_config import get_project_root

# Get project root
project_root = get_project_root()

# Access other folders relative to project root
models_dir = project_root / 'models'
dataset_dir = project_root / 'Dataset'
config_file = project_root / 'config.py'
```

## Support

The `path_config.py` module is self-contained and has no external dependencies beyond Python's standard library (`os`, `pathlib`).

Works with:
- ✅ Python 3.6+
- ✅ Windows (all versions)
- ✅ Any user account
- ✅ Any project location
