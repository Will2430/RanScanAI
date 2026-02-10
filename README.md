# 🛡️ RanScanAI - Privacy-First Malware Detection System

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![ML Accuracy](https://img.shields.io/badge/accuracy-99.3%25-success.svg)](docs/model.md)

**RanScanAI** is a privacy-preserving malware detection system designed for SMEs. It performs **local-first scanning** using a hybrid AI model (99.3% accurate) and optionally enriches threats with VirusTotal intelligence - without uploading benign files to the cloud.

![SecureGuard Architecture](https://via.placeholder.com/800x400?text=SecureGuard+Architecture)

## ✨ Key Features

- 🔒 **100% Local Scanning** - No data leaves your machine unless YOU choose
- ⚡ **Instant Results** - <100ms detection time  
- 🤖 **Hybrid AI Analysis** - Static + Dynamic + Network features
- 🌐 **Browser Integration** - Right-click to scan downloads
- 🔍 **VirusTotal Enrichment** - Get malware family names for confirmed threats
- 💾 **Lightweight** - 3MB model, runs on old hardware

## 🏗️ Project Structure

```
SecureGuard/
│
├── browser-extension/       # Chrome/Firefox browser extension
│   ├── manifest.json        # Extension configuration
│   ├── background.js        # Service worker for scanning
│   ├── popup.html/js/css    # Extension UI
│   └── README.md            # Extension documentation
│
├── Iteration_1/             # Backend API & ML model
│   ├── backend/             # FastAPI server
│   │   ├── main.py          # REST API endpoints
│   │   ├── ml_model.py      # ML model wrapper
│   │   ├── vt_integration.py # VirusTotal enrichment
│   │   └── requirements.txt # Python dependencies
│   └── README_SECUREGUARD.md # Full documentation
│
├── Iteration_2/             # Advanced features
│   ├── feature_extractor.py # Extract file features
│   ├── adaptive_learning/   # Model retraining pipeline
│   └── TESTING_STRATEGY.md  # Testing documentation
│
├── native-host/             # Native messaging for quarantine
│   ├── secureguard_host.py  # Python native host
│   ├── install_host.ps1     # Windows installer
│   └── README.md            # Setup instructions
│
├── malware_detector_zenodo_v1.pkl  # Trained ML model (99.3% accuracy)
├── zenodo_model_metadata.json      # Model metadata
└── README.md                        # This file
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (tested on 3.9, 3.10, 3.11, 3.14)
- **Chrome/Edge/Firefox** browser
- **Windows/macOS/Linux**

### 1. Install Backend

```bash
# Navigate to backend directory
cd Iteration_1/backend

# Install dependencies
pip install -r requirements.txt

# Start the backend server
python main.py
```

Backend will run on `http://localhost:8000`

### 2. Install Browser Extension

#### Chrome / Edge:
1. Open `chrome://extensions/` (or `edge://extensions/`)
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select `browser-extension/` folder
5. Extension appears with shield icon ✓

#### Firefox:
1. Go to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json` from `browser-extension/`
4. Extension loads ✓

### 3. Start Scanning!

- **Method 1:** Right-click any file → "Scan with SecureGuard"
- **Method 2:** Click extension icon → "Scan File" button  
- **Method 3:** Downloads auto-scan automatically

## 📊 ML Model Details

| Metric | Value |
|--------|-------|
| **Algorithm** | Random Forest Classifier |
| **Features** | 72 hybrid features (static + dynamic + network) |
| **Training Data** | Zenodo ransomware dataset |
| **Accuracy** | 99.33% |
| **Model Size** | 3.12 MB |
| **Scan Time** | <100ms |

## 🔒 Privacy & Security

### What We Do:
- ✅ All scanning happens **locally** on your machine
- ✅ Only confirmed threats optionally sent to VirusTotal
- ✅ No telemetry, no tracking, no cloud storage
- ✅ You control all data

### What We DON'T Do:
- ❌ Upload benign files to any server
- ❌ Collect personal information
- ❌ Track your browsing history
- ❌ Send data to third parties

## 📖 Documentation

- **Quick Start Guide:** [`Iteration_1/QUICKSTART.md`](Iteration_1/QUICKSTART.md)
- **Full Documentation:** [`Iteration_1/README_SECUREGUARD.md`](Iteration_1/README_SECUREGUARD.md)
- **Architecture:** [`Iteration_1/ARCHITECTURE.md`](Iteration_1/ARCHITECTURE.md)
- **Browser Extension:** [`browser-extension/README.md`](browser-extension/README.md)
- **Native Host Setup:** [`native-host/README.md`](native-host/README.md)
- **Testing Strategy:** [`Iteration_2/TESTING_STRATEGY.md`](Iteration_2/TESTING_STRATEGY.md)

## 🛠️ Technology Stack

**Backend:**
- FastAPI (Python web framework)
- scikit-learn (ML model)
- pandas, numpy (data processing)
- VirusTotal API (threat intelligence)

**Frontend:**
- Vanilla JavaScript (no frameworks!)
- Chrome Extension Manifest V3
- Modern CSS (Flexbox/Grid)

**ML Pipeline:**
- joblib (model persistence)
- Random Forest (classification)
- Feature engineering pipeline

## 🧪 Testing

```bash
# Test backend health
curl http://localhost:8000/health

# Run system check
python Iteration_1/system_check.py

# Test scan
python Iteration_1/test_scan.py
```

## 📈 Performance

| Metric | Value |
|--------|-------|
| Backend Startup | ~3 seconds |
| File Scan Time | 50-100ms |
| Extension RAM | ~10 MB |
| Backend RAM | ~200 MB |
| Model Load Time | ~6 seconds |

## 🤝 Contributing

This is a Final Year Project (FYP) for educational purposes. 

## 📜 License

This project is for educational use as part of a Final Year Project (2025-2026).

## 🎓 Academic Context

**Project:** Privacy-First Malware Detection for SMEs  
**Institution:** [Your Institution]  
**Year:** 2025-2026  
**Type:** Final Year Project (FYP)

## 📞 Support

For issues or questions:
1. Check the documentation in respective README files
2. Review backend logs: `Iteration_1/backend/main.py` output
3. Test backend health: `http://localhost:8000/health`

## 🎉 Acknowledgments

- **Zenodo** for the ransomware dataset
- **VirusTotal** for threat intelligence API
- **scikit-learn** for ML framework
- **FastAPI** for modern Python web framework

---

**Made with ❤️ for a safer internet**

*SecureGuard v1.0.0 - Privacy-First Malware Detection*
