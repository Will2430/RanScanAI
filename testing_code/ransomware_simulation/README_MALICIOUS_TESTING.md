# Malicious Executable Generation & Detection Testing

**Purpose**: Generate a Windows executable with malicious behavioral patterns to prove your ML model can detect ransomware.

## 🔥 What This Does

Creates a **SAFE but SUSPICIOUS** Windows executable that:
- ✅ Performs 500+ file operations (create, encrypt, delete)
- ✅ Executes 2000+ registry operations (reads + writes)
- ✅ Generates 1000+ network requests (DNS lookups, port scans)
- ✅ Creates ransomware-style ransom notes
- ✅ Has suspicious PE characteristics (packed, no console, deceptive name)
- ✅ **ONLY operates in safe test folder** - 100% safe for testing

## 📋 Quick Start

### Option 1: One-Command Full Test
```powershell
python test_malicious_detection.py
```
This runs the entire pipeline: simulator → build → analyze → test with model

### Option 2: Step-by-Step

#### Step 1: Generate Behavioral Data (Optional)
```powershell
python ransomware_simulator.py
```
- Creates `behavioral_data.json` with malicious patterns
- Only operates in `C:\Users\willi\Downloads\RANSOMWARE_TEST_FOLDER`
- Generates 500 files, 2000+ registry ops, 1000+ network requests

#### Step 2: Build the Executable
```powershell
python build_malicious_exe.py
```
- Compiles `ransomware_simulator.py` to `dist/System_Update.exe`
- Uses PyInstaller with suspicious flags (--noconsole, --onefile)
- Creates executable with malware-like characteristics

#### Step 3: Analyze PE Headers (Optional)
```powershell
python manipulate_pe_headers.py
```
- Reads PE structure of compiled executable
- Calculates entropy (should be HIGH for packed files)
- Displays sections, characteristics, etc.

#### Step 4: Test with Your Model
```powershell
python test_exe_features.py
```
- Extracts PE features from executable
- Loads behavioral data
- Tests with your ML model at `http://127.0.0.1:8001`
- Verifies detection as MALICIOUS

## 🎯 Expected Results

### The executable should be flagged as MALICIOUS because:

**File Activity:**
- 500 files created
- 500 files renamed with ransomware extensions (.locked, .encrypted, .crypto)
- 100+ files deleted
- 4 ransom notes created

**Registry Activity:**
- 2000+ registry reads across system locations
- 60+ registry writes to persistence locations
- 4 registry keys created under `HKCU\Software\TestRansomware`
- Fake encryption keys, C2 servers, bitcoin addresses written

**Network Activity:**
- 1000+ DNS lookups to suspicious domains
- Port scanning on common C2 ports (4444, 5555, 6666, etc.)
- Connection attempts to fake C2 servers

**PE Characteristics:**
- Packed executable (PyInstaller bootloader)
- No console window (--noconsole flag)
- Deceptive filename (System_Update.exe)
- High entropy (7.0+) from PyInstaller packing
- Dynamic imports

## 📂 Files Created

```
Testing_Code/
├── ransomware_simulator.py           # Enhanced simulator with aggressive behaviors
├── build_malicious_exe.py            # Build script for creating .exe
├── manipulate_pe_headers.py          # PE analysis tool
├── test_malicious_detection.py       # Complete test suite
├── test_exe_features.py              # Feature extraction test (auto-generated)
├── behavioral_data.json              # Generated behavioral patterns
└── dist/
    └── System_Update.exe             # Your malicious test executable
```

## 🔧 Requirements

### Required:
- Python 3.x
- PyInstaller: `pip install pyinstaller`

### Optional (for PE analysis):
- pefile: `pip install pefile`
- requests: `pip install requests` (for model testing)

### For Model Testing:
- Your model service running at `http://127.0.0.1:8001`
- Start with: `python migration_package/model_service.py`

## ⚠️ Safety Notes

**This is 100% SAFE for testing:**
- ✅ Only operates in designated test folder
- ✅ No real encryption (just file renaming)
- ✅ No real malware installation
- ✅ DNS lookups to non-existent domains
- ✅ Registry writes only to test keys
- ✅ All actions reversible

**Clean up:**
```powershell
# Delete test folder
Remove-Item -Recurse -Force "C:\Users\willi\Downloads\RANSOMWARE_TEST_FOLDER"

# Delete registry keys
reg delete "HKCU\Software\TestRansomware" /f
```

## 🧪 Testing Your Model

### Manual Test:
```python
import requests

# Upload executable to model
with open('dist/System_Update.exe', 'rb') as f:
    response = requests.post(
        'http://127.0.0.1:8001/analyze',
        files={'file': f}
    )

result = response.json()
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']}")
```

### Expected Detection:
- **Prediction**: `malicious` or `1`
- **Confidence**: `> 0.8` (80%+)
- **Features used**: PE features + behavioral features

## 📊 Matching Dataset Features

Your sample had these PE characteristics:
```
Machine: Intel 386 (0x014c)
Characteristics: IMAGE_SUBSYSTEM_WINDOWS_GUI
DLL Characteristics: DYNAMIC_BASE, GUARD_CF, NX_COMPAT, TERMINAL_SERVER_AWARE
```

The compiled executable will have similar:
- ✅ PE32 format for Intel 386
- ✅ Windows GUI subsystem (no console)
- ✅ Packed/compressed (high entropy)
- ✅ Suspicious sections
- ✅ Dynamic imports

## 🎓 What This Proves

By creating and detecting this executable, you demonstrate:
1. ✅ Your model can detect malicious PE files
2. ✅ Behavioral features improve detection
3. ✅ The system works end-to-end (extraction → prediction)
4. ✅ You have a working detection pipeline

## 🚀 Next Steps

1. **Run the test**: `python test_malicious_detection.py`
2. **Verify detection**: Confirm model flags as malicious
3. **Check confidence**: Should be high (80%+)
4. **Document results**: Use for your presentation/report
5. **Test with real samples**: Try with actual dataset files

## 📝 Notes

- The executable is **safe for Windows Defender** - it's not real malware
- **Antivirus may flag it** due to PyInstaller (known false positive)
- **Behavioral analysis** happens when you RUN the exe (optional)
- **Static analysis** works on the compiled .exe file alone
- **Best results** come from combining PE features + behavioral data

## ❓ Troubleshooting

**Build fails:**
- Install PyInstaller: `pip install pyinstaller`
- Update Python: Ensure Python 3.8+

**Model doesn't detect:**
- Check feature extraction (verify features match dataset)
- Review behavioral data (ensure it's loaded)
- Adjust detection threshold
- Retrain model with more aggressive samples

**High entropy warning:**
- This is EXPECTED for PyInstaller executables
- High entropy (7.0+) is a GOOD indicator for detection
- Real ransomware is often packed/encrypted too

---

**Created**: February 10, 2026  
**Version**: 1.0  
**Purpose**: ML Model Validation Testing
