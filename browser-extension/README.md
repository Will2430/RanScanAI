# 🛡️ SecureGuard Browser Extension

**Privacy-First Malware Scanner - Right in Your Browser**

---

## 📦 What's This?

A Chrome/Firefox extension that lets you scan files for malware **locally** - no cloud upload required!

---

## ⚡ Quick Install

### Chrome / Edge

1. Open browser
2. Go to `chrome://extensions/` (or `edge://extensions/`)
3. Enable **"Developer mode"** (toggle in top-right)
4. Click **"Load unpacked"**
5. Select this folder (`browser-extension/`)
6. Extension appears with shield icon ✓

### Firefox

1. Go to `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on"**
3. Select `manifest.json` from this folder
4. Extension loads ✓

---

## 🎯 How to Use

### Method 1: Right-Click Menu
1. Download a file (or right-click any link)
2. Right-click → **"Scan with SecureGuard"**
3. File scans automatically
4. Notification shows result

### Method 2: Extension Popup
1. Click extension icon (shield)
2. Click **"Scan File"** button
3. Select file from your computer
4. View result in popup

### Method 3: Auto-Monitor Downloads
- Extension automatically scans downloaded files
- Shows notification for each scan
- View history in popup dashboard

---

## 📊 Features

### Dashboard
- ✅ Total scans counter
- ✅ Threats detected counter
- ✅ Clean files counter
- ✅ Recent scan history (last 5)
- ✅ Backend status indicator

### Scan Results
- ✅ Instant notification (benign vs malicious)
- ✅ Confidence score (0-100%)
- ✅ Timestamp
- ✅ VirusTotal enrichment (for threats)
- ✅ Scan time display

### Privacy
- 🔒 All scans happen locally
- 🔒 No automatic uploads to cloud
- 🔒 You control VirusTotal enrichment
- 🔒 History stored locally in browser

---

## 🔧 Configuration

### Enable/Disable VirusTotal

Edit `background.js`:
```javascript
// Line ~80
enable_vt: true  // Change to false to disable
```

### Change Backend URL

Edit `background.js`:
```javascript
// Line 3
const API_BASE = 'http://localhost:8000';  // Change port if needed
```

### Adjust Auto-Quarantine Threshold

Edit `background.js`:
```javascript
// Line ~95
if (result.confidence > 0.8) {  // Change threshold (0.0-1.0)
  chrome.downloads.cancel(downloadId);
}
```

---

## 📁 File Structure

```
browser-extension/
│
├── manifest.json          # Extension configuration
│   └── Defines: name, version, permissions, icons
│
├── popup.html             # Dashboard UI
│   └── Shows: stats, history, scan button
│
├── popup.js               # Frontend logic
│   └── Handles: UI updates, file selection, history display
│
├── background.js          # Service worker
│   └── Handles: context menu, file scanning, API calls
│
├── styles.css             # UI styling
│   └── Modern responsive design with animations
│
└── icons/                 # Extension icons
    ├── icon16.png         # Toolbar icon
    ├── icon32.png         # Extension management
    ├── icon48.png         # Extension details
    ├── icon128.png        # Chrome Web Store
    └── ICON_INSTRUCTIONS.txt
```

---

## 🎨 Screenshots

### Extension Popup Dashboard
```
┌────────────────────────────────────┐
│  🛡️ SecureGuard     🟢 Backend Online│
├────────────────────────────────────┤
│  ┌──────┐  ┌──────┐  ┌──────┐    │
│  │  42  │  │   3  │  │  39  │    │
│  │Total │  │Threat│  │Clean │    │
│  └──────┘  └──────┘  └──────┘    │
├────────────────────────────────────┤
│  [Scan File] [History]            │
├────────────────────────────────────┤
│  Recent Scans:                     │
│  ✓ document.pdf - Clean (95%)     │
│  ⚠ malware.exe - Malicious (98%)  │
│  ✓ image.jpg - Clean (92%)        │
└────────────────────────────────────┘
```

### Notification
```
╔═══════════════════════════════════╗
║  SecureGuard                      ║
║  ✓ File Clean                     ║
║                                   ║
║  document.pdf appears safe        ║
║  (95.3% confidence)               ║
╚═══════════════════════════════════╝
```

---

## 🚨 Permissions Explained

From `manifest.json`:

| Permission | Why Needed |
|------------|------------|
| `contextMenus` | Right-click "Scan with SecureGuard" |
| `storage` | Save scan history locally |
| `notifications` | Show scan result popups |
| `http://localhost:8000/*` | Connect to backend service |

**We do NOT request:**
- ❌ `<all_urls>` - We don't track your browsing
- ❌ `tabs` - We don't access your tabs
- ❌ `cookies` - We don't use cookies
- ❌ `webRequest` - We don't monitor network

---

## 🔒 Privacy & Security

### What We Collect
- ✅ Scan results (stored locally in browser)
- ✅ File names (not content)
- ✅ Timestamps

### What We DON'T Collect
- ❌ File content
- ❌ Browsing history
- ❌ Personal information
- ❌ Usage telemetry

### Data Storage
- 📍 **Local only** (Chrome storage)
- 📍 **No cloud sync**
- 📍 **No server logs**
- 📍 **You control deletion** (Clear History button)

---

## 🛠️ Development

### Testing Changes

After modifying files:
1. Go to `chrome://extensions/`
2. Click reload icon on SecureGuard card
3. Test the changes

### Debugging

1. Right-click extension icon → **"Inspect popup"**
2. View Console for popup.js logs
3. Go to `chrome://extensions/` → **"Inspect views: service worker"**
4. View Console for background.js logs

### Common Issues

**Extension not loading:**
- Check manifest.json for syntax errors
- Ensure all files exist
- Check browser console for errors

**"Backend Offline" status:**
- Ensure backend is running: `python backend/main.py`
- Check `http://localhost:8000/health` in browser
- Verify port 8000 is not blocked

**Scans failing:**
- Check backend terminal for errors
- Ensure model file exists
- View browser console for network errors

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Extension Size** | ~50 KB |
| **RAM Usage** | ~10 MB |
| **CPU Usage** | <1% |
| **Scan Time** | 50-100ms |
| **Popup Load** | <50ms |

---

## 🚀 Future Features

- [ ] Real-time file monitoring
- [ ] Scheduled scans
- [ ] Custom scan rules
- [ ] Detailed threat reports
- [ ] Cloud sync (encrypted)
- [ ] Mobile companion app
- [ ] Team collaboration

---

## 🎓 For Developers

### Key Functions

**background.js:**
- `handleFileScan()` - Initiates scan process
- `scanDownloadedFile()` - Scans completed downloads
- `showNotification()` - Displays results

**popup.js:**
- `loadScanHistory()` - Fetches scan history
- `displayRecentScans()` - Renders scan list
- `scanSelectedFile()` - Handles manual uploads

### API Communication

```javascript
// Scan request
const response = await fetch('http://localhost:8000/scan-upload', {
  method: 'POST',
  body: formData
});

const result = await response.json();
// {is_malicious: false, confidence: 0.95, ...}
```

### Storage Schema

```javascript
{
  scanHistory: [
    {
      timestamp: "2026-01-11T10:30:00.000Z",
      filename: "document.pdf",
      is_malicious: false,
      confidence: 0.953,
      scan_time_ms: 47.2
    },
    // ... more scans
  ]
}
```

---

## 📞 Support

### Getting Help

1. **Check backend status:** `http://localhost:8000/health`
2. **View logs:** Browser Console (F12)
3. **Run tests:** `python demo_secureguard.py`
4. **Read docs:** `../README_SECUREGUARD.md`

### Reporting Issues

When reporting issues, include:
- Browser version (Chrome/Firefox)
- Backend status (online/offline)
- Error message from console
- Steps to reproduce

---

## 🎉 Credits

**Project:** SecureGuard - Privacy-First Malware Detection  
**Version:** 1.0.0  
**License:** Educational Use  
**FYP:** Final Year Project 2025-2026

**Built with:**
- Vanilla JavaScript (no frameworks!)
- Chrome Extension Manifest V3
- Modern CSS (Flexbox/Grid)
- REST API integration

---

## ✅ Installation Checklist

Before using:
- [ ] Backend running (`start_backend.bat`)
- [ ] Extension installed in browser
- [ ] Backend status shows green dot
- [ ] Test scan completed successfully

---

**🚀 Ready to scan? Click the shield icon and start protecting your files!**

---

**For full documentation, see: [../README_SECUREGUARD.md](../README_SECUREGUARD.md)**
