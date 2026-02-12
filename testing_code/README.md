# Ransomware Simulator Testing Suite

## 🎯 Purpose

Generate a **safe, controlled** ransomware-like executable for testing your ML malware detection model.

**What this solves:**
- ✅ No need to download/execute real malware
- ✅ Safe testing environment (isolated folder)
- ✅ Generate PE executables with ransomware characteristics
- ✅ Test feature extraction and ML classification
- ✅ Demonstrate explainability on suspicious files

---

## 📦 What's Included

| File | Purpose |
|------|---------|
| `setup_test_environment.py` | Creates isolated test folder with dummy files |
| `ransomware_simulator.py` | Main simulator - encrypts test files |
| `build_exe.bat` | Packages simulator as standalone .exe |
| `test_ml_model.py` | Analyzes the .exe and tests ML model |
| `cleanup_test.py` | Decrypts files or deletes test folder |
| `SAFETY_DOCUMENTATION.md` | Detailed safety analysis |
| `QUICKSTART.md` | 30-second setup guide |
| `requirements.txt` | Python dependencies |

---

## 🚀 Quick Start (5 Minutes)

### 1️⃣ Install Dependencies
```bash
cd "C:\Users\User\OneDrive\Test\K\Testing Code"
pip install -r requirements.txt
```

### 2️⃣ Setup Test Environment
```bash
python setup_test_environment.py
```
✅ Creates: `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER`  
✅ Generates: 5 dummy .txt files for encryption

### 3️⃣ Run Simulation
```bash
python ransomware_simulator.py
```
- Type `yes` to confirm
- Encrypts test files
- Creates ransom note
- Saves decryption key

### 4️⃣ Build EXE
```bash
build_exe.bat
```
✅ Output: `dist\RansomwareSimulator.exe` (~10-15 MB)

### 5️⃣ Test ML Model
```bash
python test_ml_model.py
```
- Extracts PE features
- Analyzes suspicious indicators
- Classifies with ML model

### 6️⃣ Cleanup
```bash
python cleanup_test.py
```
- Option 1: Decrypt files (restore)
- Option 2: Delete entire folder

---

## 🔒 Safety Guarantees

### ✅ What Makes This Safe:

| Safety Feature | How It Works |
|----------------|--------------|
| **Isolated Path** | Hardcoded to `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER` only |
| **Triple Verification** | Checks path validity 3 times before running |
| **No Real Files** | Only encrypts dummy files it creates itself |
| **Decryption Key** | Always saved for easy restoration |
| **User Confirmation** | Must type "yes" explicitly |
| **File Type Restriction** | Only touches .txt, .pdf, .docx test files |
| **Per-File Check** | Verifies each file is in test folder before encryption |

### ❌ What It Will Never Do:

- ❌ Access files outside test folder
- ❌ Spread to other directories
- ❌ Modify system registry
- ❌ Create actual persistence
- ❌ Contact external servers
- ❌ Delete files permanently (key is saved)

📖 **Read [SAFETY_DOCUMENTATION.md](SAFETY_DOCUMENTATION.md) for complete safety analysis**

---

## 🎓 Educational Value

### What Your ML Model Can Learn:

**1. Static Features (from .exe):**
- PE headers structure
- Import table (cryptography, file operations)
- Section characteristics
- High entropy (encryption code)

**2. Behavioral Indicators (from code logic):**
- File discovery/traversal
- Encryption operations
- File deletion
- Ransom note creation

**3. Explainability Demonstration:**
```
⚠️ Malicious Detected (87% confidence)

Top suspicious features:
  • Cryptography library imports (32%)
  • File traversal operations (24%)
  • File deletion operations (18%)
  • Multiple write operations (13%)
```

---

## 📊 Expected Test Results

### When You Test the .exe:

| Test | Expected Result |
|------|----------------|
| **PE Analysis** | Valid PE structure, cryptography imports detected |
| **Entropy** | High (>7.0) due to Python runtime + crypto |
| **VirusTotal** | 2-5 engines may flag (false positive) |
| **Your ML Model** | Should classify as malicious (70-95% confidence) |
| **Feature Importance** | Crypto + file ops should rank highest |

### This Proves Your Model Works:

✅ Detects ransomware-like characteristics  
✅ Explains WHY file is flagged (transparency)  
✅ Works on unfamiliar samples (generalization)  
✅ Differentiates from benign files

---

## 🔄 Testing Workflow

```
┌─────────────────────────────────────────────────────────┐
│ 1. Setup Test Environment                               │
│    → Creates isolated folder with dummy files           │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Run Simulator                                        │
│    → Encrypts test files, creates ransom note          │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Package as EXE                                       │
│    → PyInstaller builds standalone executable           │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Extract PE Features                                  │
│    → Static analysis: headers, imports, sections        │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 5. ML Model Classification                              │
│    → Predict: Malicious (87% confidence)               │
│    → Explain: Crypto imports + file ops detected        │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 6. Validate Results                                     │
│    → Compare with VirusTotal consensus                  │
│    → Document for FYP presentation                      │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 7. Cleanup                                              │
│    → Decrypt files or delete folder                     │
└─────────────────────────────────────────────────────────┘
```

---

## 🐛 Troubleshooting

### Error: "ModuleNotFoundError: No module named 'cryptography'"
```bash
pip install cryptography
```

### Error: "Test folder does not exist"
```bash
python setup_test_environment.py
```

### Error: "PyInstaller not found"
```bash
pip install pyinstaller
```

### Want to start completely fresh?
```bash
python cleanup_test.py  # Choose option 2
python setup_test_environment.py
```

### Windows Defender blocks the .exe
This is expected (validates your approach):
1. The simulator uses cryptography + file operations
2. Defender may flag as potentially unwanted
3. **Solution:** Exclude test folder from Defender scans:
   - Windows Security → Virus & threat protection
   - Exclusions → Add folder
   - Add: `C:\Users\User\Downloads\RANSOMWARE_TEST_FOLDER`

---

## 📝 Files Generated

After running the full workflow:

```
C:\Users\User\Downloads\
└── RANSOMWARE_TEST_FOLDER\
    ├── document1.txt.locked       ← Encrypted test file
    ├── document2.txt.locked       ← Encrypted test file
    ├── report.txt.locked          ← Encrypted test file
    ├── ⚠️_RANSOM_NOTE_⚠️.txt      ← Ransom note
    ├── .decryption_key.secret     ← Saved decryption key
    ├── README.txt                 ← Folder explanation
    └── documents\
        ├── notes.txt.locked       ← Encrypted test file
        └── data.txt.locked        ← Encrypted test file

Testing Code\
└── dist\
    └── RansomwareSimulator.exe   ← PE executable for testing
```

---

## 🎯 For Your FYP Presentation

### Demo Flow:

1. **Show the simulator code** - Explain ransomware behavior
2. **Run setup** - Create test environment
3. **Run simulation** - Encrypt test files, show ransom note
4. **Build EXE** - Package as executable
5. **Extract features** - Show PE analysis
6. **ML classification** - Demonstrate detection
7. **Explainability** - Show feature importance
8. **Cleanup** - Decrypt files (prove it's reversible)

### Key Talking Points:

✅ "This demonstrates our model detects ransomware-like behavior"  
✅ "We extract both static and behavioral features"  
✅ "Explainability shows WHY the file is flagged"  
✅ "Safe testing without downloading real malware"  
✅ "Model generalizes to unfamiliar samples"

---

## 📞 Need Help?

1. **Read safety docs first:** [SAFETY_DOCUMENTATION.md](SAFETY_DOCUMENTATION.md)
2. **Quick start:** [QUICKSTART.md](QUICKSTART.md)
3. **Check code:** Review `ransomware_simulator.py` source
4. **Still stuck?** Double-check path restrictions and safety checks

---

## ⚖️ Legal & Ethical Notice

**Educational Use Only:**
- This tool is for academic research and testing
- Simulates ransomware behavior in controlled environment
- Must not be used maliciously
- Must not be distributed without context
- Must not be used against systems you don't own

**You are responsible for:**
- Using this ethically and legally
- Not modifying safety restrictions
- Keeping it within your test environment
- Properly documenting its educational purpose

---

## 🏆 Success Criteria

You'll know this worked when:

✅ EXE is generated without errors  
✅ PE structure is valid and analyzable  
✅ ML model classifies as malicious (high confidence)  
✅ Feature importance highlights crypto + file ops  
✅ You can explain WHY it was flagged  
✅ Files can be decrypted successfully  

**This proves your malware detection system works! 🎉**
