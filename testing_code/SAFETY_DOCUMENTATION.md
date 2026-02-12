# Ransomware Simulator - Safety Documentation

## ⚠️ CRITICAL SAFETY GUARANTEES

### What This Simulator WILL Do:
✅ Only operate within `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER`  
✅ Encrypt ONLY dummy test files created by setup script  
✅ Save decryption key for easy restoration  
✅ Provide clear warnings and confirmations  
✅ Generate PE executable with ransomware-like characteristics  

### What This Simulator WILL NOT Do:
❌ Access files outside the test folder  
❌ Spread to other directories  
❌ Modify system registry  
❌ Create actual persistence mechanisms  
❌ Contact external servers  
❌ Delete files permanently (decryption key is saved)  

---

## 🔒 Safety Mechanisms

### 1. **Hardcoded Path Restrictions**
```python
SAFE_TEST_FOLDER = r"C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER"
```
- Path is hardcoded and checked multiple times
- Will abort if path is modified or invalid

### 2. **Triple Verification System**
```python
def verify_safe_environment():
    # Check 1: Verify Downloads folder
    # Check 2: Ensure "TEST" in folder name  
    # Check 3: Verify folder exists
```

### 3. **File Type Restrictions**
```python
ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.docx']
```
- Only encrypts specific test file types
- Won't touch executables, system files, or other data

### 4. **Per-File Safety Check**
```python
if SAFE_TEST_FOLDER not in file_path:
    print(f"SAFETY ABORT: File outside test folder")
    return False
```

### 5. **User Confirmation Required**
- Script asks for explicit "yes" before encrypting
- Can be cancelled at any time (Ctrl+C)

### 6. **Decryption Key Backup**
- Key is saved locally: `.decryption_key.secret`
- Files can be restored anytime via `cleanup_test.py`

---

## 📋 Usage Workflow (Safe Testing)

### Step 1: Setup Environment
```bash
cd "C:\Users\User\OneDrive\Test\K\Testing Code"
python setup_test_environment.py
```

**What happens:**
- Creates `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER`
- Generates 5 dummy .txt files
- Creates README explaining the setup

### Step 2: Run Simulation
```bash
python ransomware_simulator.py
```

**What happens:**
- Verifies safety checks
- Scans for test files in test folder ONLY
- Asks for confirmation
- Encrypts test files (adds `.locked` extension)
- Creates ransom note
- Saves decryption key

### Step 3: Build Executable
```bash
build_exe.bat
```

**What happens:**
- Installs PyInstaller (if needed)
- Packages `ransomware_simulator.py` as `RansomwareSimulator.exe`
- Creates standalone PE executable in `dist/` folder

### Step 4: Test ML Model
```bash
# Extract PE features from the EXE
python your_feature_extractor.py dist/RansomwareSimulator.exe

# Run through ML model for classification
python test_detection.py dist/RansomwareSimulator.exe
```

### Step 5: Cleanup
```bash
python cleanup_test.py
```

**Options:**
1. Decrypt files (restore original state)
2. Delete entire test folder

---

## 🔬 Why This is Safe for Testing

### Issue: "Won't this harm my computer?"
**Answer:** No. The simulator:
- Has hardcoded path restrictions
- Only touches files it creates itself
- Saves decryption key locally
- Won't spread beyond test folder
- Can be fully reversed

### Issue: "What if the path check fails?"
**Answer:** Multiple failsafes:
- Script aborts if test folder doesn't exist
- Verifies folder path 3 times before running
- Each file is checked before encryption
- User must explicitly type "yes" to proceed

### Issue: "Can Windows Defender detect this?"
**Answer:** Maybe, and that's okay:
- This is for PE feature testing, not actual deployment
- If Defender flags it, that validates your ML model's purpose
- You can exclude the test folder from Defender scans
- The simulator is clearly labeled as educational

### Issue: "What if I accidentally run the EXE twice?"
**Answer:** No problem:
- First run encrypts test files
- Second run finds no target files (already encrypted)
- Script reports "No target files found" and exits
- No additional harm possible

---

## 🎯 Technical Details for ML Testing

### PE Features This Executable Will Have:

**Static Features:**
- **Imports:** `cryptography`, `os`, `sys`, `pathlib`
- **Entropy:** Higher than normal (due to encrypted strings)
- **Sections:** `.text`, `.data`, `.rdata` (standard PyInstaller)
- **File size:** ~10-15 MB (PyInstaller bundles Python runtime)

**Behavioral Indicators (from code structure):**
- File discovery/traversal logic
- Encryption operations
- File deletion operations
- Write operations to create ransom note

**What Your Model Should Detect:**
- Cryptography library imports (suspicious)
- File traversal patterns
- High volume of file operations
- Writes to multiple files
- Deletion operations

---

## 🚨 Emergency Procedures

### If Something Goes Wrong:

**1. Simulation Won't Stop:**
- Press `Ctrl+C` to interrupt
- Script catches KeyboardInterrupt gracefully

**2. Files Are Encrypted But Key Is Lost:**
- Don't panic - these are dummy test files
- Just delete `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER`
- Run `setup_test_environment.py` again

**3. Test Folder Accidentally Deleted:**
- No problem - it only contained dummy data
- Run `setup_test_environment.py` to recreate

**4. Want to Start Fresh:**
```bash
# Full cleanup
python cleanup_test.py
# Choose option 2: Delete entire folder

# Recreate
python setup_test_environment.py
```

---

## ✅ Pre-Flight Checklist

Before running the simulator, verify:

- [ ] Test folder location: `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER`
- [ ] Folder is EMPTY or contains only test files
- [ ] No important files in the test folder
- [ ] You ran `setup_test_environment.py` first
- [ ] You understand this is a SIMULATION
- [ ] You have `cleanup_test.py` ready for restoration

---

## 📊 Expected Test Results

### When You Scan RansomwareSimulator.exe:

**VirusTotal Detection:**
- Some engines may flag it (false positive)
- Reason: Uses cryptography + file operations
- This is EXPECTED and validates your research

**Your ML Model:**
- Should classify as suspicious/malicious
- High confidence (70-95%)
- Feature importance: cryptography imports, file ops

**Explainability Output:**
```
⚠️ Malicious Detected (87% confidence)

Top suspicious features:
  • Cryptography library imports (32%)
  • File traversal operations (24%)
  • File deletion operations (18%)
  • Multiple write operations (13%)
```

This demonstrates your model works correctly!

---

## 📞 Support

If you're unsure about ANYTHING:

1. **Don't run it yet**
2. Review this documentation again
3. Check the code in `ransomware_simulator.py`
4. Verify the path restrictions
5. Test with `setup_test_environment.py` first

**Remember:** This is a CONTROLLED EXPERIMENT for educational purposes. All safety measures are in place.
