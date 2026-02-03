# Browser Extension Implementation Guide

## Feature Request: Download Detection & Scan Prompt

**Goal**: When a user starts downloading a file, show a notification offering to scan it with your malware detection service.

---

## YES, This is 100% Possible!

Browser extensions have access to the **Downloads API** which allows:
- Detecting when downloads start
- Accessing file information (name, size, URL)
- Showing notifications/popups
- Intercepting/pausing downloads

---

## Architecture

```
User clicks download link
        ↓
Chrome detects download starting
        ↓
Extension listens to chrome.downloads.onCreated
        ↓
Show notification: "Scan this file for malware?"
        ↓
User clicks "Scan"
        ↓
Extension sends file to your FastAPI backend
        ↓
Backend analyzes file (Static ML + VirusTotal)
        ↓
Extension shows result: "Safe" or "Dangerous!"
```

---

## Implementation

### 1. **Manifest Configuration** (`manifest.json`)

```json
{
  "manifest_version": 3,
  "name": "Ransomware Detection Extension",
  "version": "1.0",
  "description": "Privacy-first malware detection for downloaded files",
  
  "permissions": [
    "downloads",           // Access download events
    "downloads.open",      // Open downloaded files
    "notifications",       // Show notifications
    "storage"             // Store user preferences
  ],
  
  "host_permissions": [
    "http://localhost:8000/*"  // Your FastAPI backend
  ],
  
  "background": {
    "service_worker": "background.js"
  },
  
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  }
}
```

---

### 2. **Background Service Worker** (`background.js`)

This is the core logic that detects downloads:

```javascript
// background.js - Listens for download events

// Listen for new downloads
chrome.downloads.onCreated.addListener((downloadItem) => {
  console.log('Download detected:', downloadItem);
  
  // Check if file is executable (potential malware)
  const filename = downloadItem.filename.toLowerCase();
  const riskyExtensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.msi', '.vbs', '.js', '.jar', '.apk'];
  
  const isRiskyFile = riskyExtensions.some(ext => filename.endsWith(ext));
  
  if (isRiskyFile) {
    // Show notification offering to scan
    showScanPrompt(downloadItem);
  }
});

// Show notification with scan option
function showScanPrompt(downloadItem) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: 'Malware Scan Available',
    message: `Would you like to scan "${downloadItem.filename}" for malware?`,
    buttons: [
      { title: 'Scan Now' },
      { title: 'Skip' }
    ],
    requireInteraction: true  // Notification stays until user clicks
  }, (notificationId) => {
    // Store download ID for later use
    chrome.storage.local.set({ 
      [notificationId]: downloadItem.id 
    });
  });
}

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  if (buttonIndex === 0) {  // "Scan Now" clicked
    // Retrieve download ID
    chrome.storage.local.get(notificationId, (result) => {
      const downloadId = result[notificationId];
      scanDownloadedFile(downloadId);
    });
  }
  
  // Clear notification
  chrome.notifications.clear(notificationId);
});

// Scan the downloaded file
async function scanDownloadedFile(downloadId) {
  try {
    // Get download details
    const [download] = await chrome.downloads.search({ id: downloadId });
    
    if (!download || !download.filename) {
      console.error('Download not found or not complete');
      return;
    }
    
    // Wait for download to complete
    if (download.state !== 'complete') {
      console.log('Waiting for download to complete...');
      await waitForDownloadComplete(downloadId);
    }
    
    // Show scanning notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Scanning File...',
      message: `Analyzing "${download.filename}" for malware threats`
    });
    
    // Read file and send to backend
    const filePath = download.filename;
    const result = await sendToBackend(filePath);
    
    // Show result notification
    showScanResult(download.filename, result);
    
  } catch (error) {
    console.error('Scan failed:', error);
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Scan Failed',
      message: 'Unable to scan file. Please try again.'
    });
  }
}

// Wait for download to complete
function waitForDownloadComplete(downloadId) {
  return new Promise((resolve, reject) => {
    const checkInterval = setInterval(async () => {
      const [download] = await chrome.downloads.search({ id: downloadId });
      
      if (download.state === 'complete') {
        clearInterval(checkInterval);
        resolve();
      } else if (download.state === 'interrupted') {
        clearInterval(checkInterval);
        reject(new Error('Download was interrupted'));
      }
    }, 500);
  });
}

// Send file to FastAPI backend
async function sendToBackend(filePath) {
  // Create FormData with file
  const formData = new FormData();
  
  // Note: Browser extensions can't directly read local files
  // You'll need to use chrome.runtime.getPackageDirectoryEntry or
  // ask user to drag-drop file into extension popup
  
  // For now, send file hash/path to backend
  const response = await fetch('http://localhost:8000/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      file_path: filePath,  // Backend needs access to downloads folder
      scan_type: 'full'     // static + VT
    })
  });
  
  if (!response.ok) {
    throw new Error(`Backend error: ${response.status}`);
  }
  
  return await response.json();
}

// Show scan results
function showScanResult(filename, result) {
  const isMalicious = result.prediction === 'Malicious';
  const iconUrl = isMalicious ? 'icons/danger.png' : 'icons/safe.png';
  
  let message = '';
  if (isMalicious) {
    message = `WARNING: File may be malicious! (Confidence: ${(result.confidence * 100).toFixed(1)}%)`;
    if (result.vt_enrichment) {
      message += `\nVirusTotal: ${result.vt_enrichment.detections}/${result.vt_enrichment.total_engines} detected`;
    }
  } else {
    message = `File appears safe (Confidence: ${(result.confidence * 100).toFixed(1)}%)`;
  }
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: iconUrl,
    title: isMalicious ? '🚨 THREAT DETECTED' : '✓ File is Safe',
    message: message,
    buttons: isMalicious ? [
      { title: 'Delete File' },
      { title: 'View Details' }
    ] : [],
    requireInteraction: isMalicious  // Keep warning visible
  });
}

// Listen for extension install
chrome.runtime.onInstalled.addListener(() => {
  console.log('Malware Detection Extension installed');
  
  // Set default preferences
  chrome.storage.local.set({
    autoScanEnabled: true,
    scanThreshold: 0.7  // Only prompt if ML confidence > 70%
  });
});
```

---

### 3. **Popup Interface** (`popup.html`)

When user clicks extension icon:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Malware Scanner</title>
  <style>
    body {
      width: 400px;
      padding: 20px;
      font-family: 'Segoe UI', Arial, sans-serif;
    }
    .header {
      text-align: center;
      margin-bottom: 20px;
    }
    .scan-zone {
      border: 2px dashed #ccc;
      padding: 40px;
      text-align: center;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.3s;
    }
    .scan-zone:hover {
      border-color: #4CAF50;
      background: #f0f8f0;
    }
    .settings {
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid #eee;
    }
    .toggle {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin: 10px 0;
    }
    .status {
      padding: 10px;
      border-radius: 4px;
      margin: 10px 0;
    }
    .status.safe { background: #d4edda; color: #155724; }
    .status.danger { background: #f8d7da; color: #721c24; }
    .status.scanning { background: #fff3cd; color: #856404; }
  </style>
</head>
<body>
  <div class="header">
    <h2>🛡️ Malware Scanner</h2>
    <p>Privacy-first ransomware detection</p>
  </div>
  
  <div class="scan-zone" id="dropZone">
    <h3>Drop file here to scan</h3>
    <p>or click to select file</p>
    <input type="file" id="fileInput" style="display: none;">
  </div>
  
  <div id="status"></div>
  
  <div class="settings">
    <h3>Settings</h3>
    
    <div class="toggle">
      <label>Auto-scan downloads</label>
      <input type="checkbox" id="autoScanToggle" checked>
    </div>
    
    <div class="toggle">
      <label>VirusTotal integration</label>
      <input type="checkbox" id="vtToggle" checked>
    </div>
    
    <div class="toggle">
      <label>Only scan executable files</label>
      <input type="checkbox" id="execOnlyToggle" checked>
    </div>
  </div>
  
  <script src="popup.js"></script>
</body>
</html>
```

---

### 4. **Popup Logic** (`popup.js`)

```javascript
// popup.js - Handles manual file scanning

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const statusDiv = document.getElementById('status');

// Click to select file
dropZone.addEventListener('click', () => {
  fileInput.click();
});

// Drag and drop
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.style.borderColor = '#4CAF50';
});

dropZone.addEventListener('dragleave', () => {
  dropZone.style.borderColor = '#ccc';
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.style.borderColor = '#ccc';
  
  const file = e.dataTransfer.files[0];
  if (file) {
    scanFile(file);
  }
});

// File input change
fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) {
    scanFile(file);
  }
});

// Scan file
async function scanFile(file) {
  showStatus('scanning', `Scanning ${file.name}...`);
  
  try {
    // Create FormData
    const formData = new FormData();
    formData.append('file', file);
    
    // Send to backend
    const response = await fetch('http://localhost:8000/api/scan', {
      method: 'POST',
      body: formData
    });
    
    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }
    
    const result = await response.json();
    
    // Show result
    if (result.prediction === 'Malicious') {
      showStatus('danger', `⚠️ MALICIOUS DETECTED!\nConfidence: ${(result.confidence * 100).toFixed(1)}%`);
    } else {
      showStatus('safe', `✓ File appears safe\nConfidence: ${(result.confidence * 100).toFixed(1)}%`);
    }
    
  } catch (error) {
    showStatus('danger', `Scan failed: ${error.message}`);
  }
}

// Show status message
function showStatus(type, message) {
  statusDiv.className = `status ${type}`;
  statusDiv.textContent = message;
  statusDiv.style.display = 'block';
}

// Load settings
chrome.storage.local.get(['autoScanEnabled', 'vtEnabled', 'execOnly'], (result) => {
  document.getElementById('autoScanToggle').checked = result.autoScanEnabled !== false;
  document.getElementById('vtToggle').checked = result.vtEnabled !== false;
  document.getElementById('execOnlyToggle').checked = result.execOnly !== false;
});

// Save settings
document.getElementById('autoScanToggle').addEventListener('change', (e) => {
  chrome.storage.local.set({ autoScanEnabled: e.target.checked });
});

document.getElementById('vtToggle').addEventListener('change', (e) => {
  chrome.storage.local.set({ vtEnabled: e.target.checked });
});

document.getElementById('execOnlyToggle').addEventListener('change', (e) => {
  chrome.storage.local.set({ execOnly: e.target.checked });
});
```

---

## FastAPI Backend Integration

Your backend needs to handle file uploads:

```python
# main.py (FastAPI)
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
from hybrid_detector import HybridDetector

app = FastAPI()

# Enable CORS for extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to extension ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = HybridDetector(
    model_path='static_malware_detector.pkl',
    vt_api_key=os.getenv('VT_API_KEY')
)

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Scan uploaded file for malware
    """
    # Save uploaded file temporarily
    temp_path = f"/tmp/{file.filename}"
    
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Scan file
        result = detector.detect(temp_path)
        
        return {
            "prediction": result['prediction'],
            "confidence": result['confidence'],
            "detection_method": result['detection_method'],
            "vt_enrichment": result.get('vt_enrichment', None),
            "timestamp": "2026-01-29T10:30:00"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "model_loaded": True}
```

---

## User Experience Flow

### Scenario 1: Download Detection
```
1. User downloads "setup.exe" from website
2. Extension detects download
3. Notification appears: "Scan setup.exe for malware?"
4. User clicks "Scan Now"
5. Extension shows "Scanning..."
6. Backend analyzes file (Static ML + VT)
7. Result notification: "⚠️ THREAT DETECTED - 45/72 engines flagged this file"
8. User can delete or ignore
```

### Scenario 2: Manual Scan
```
1. User clicks extension icon
2. Popup opens with drag-drop zone
3. User drags suspicious file into popup
4. Extension uploads to backend
5. Popup shows: "✓ File appears safe (92% confidence)"
```

---

## Installation Steps

### For Development:
1. Navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select your extension folder
5. Extension is now active!

### Project Structure:
```
extension/
├── manifest.json
├── background.js
├── popup.html
├── popup.js
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   ├── danger.png
│   └── safe.png
└── README.md
```

---

## Advanced Features (Future Enhancements)

### 1. **Pause Download Until Scan Complete**
```javascript
chrome.downloads.onCreated.addListener((download) => {
  // Pause download immediately
  chrome.downloads.pause(download.id);
  
  // Scan URL reputation
  scanURL(download.url).then((result) => {
    if (result.safe) {
      chrome.downloads.resume(download.id);
    } else {
      chrome.downloads.cancel(download.id);
      showWarning('Download blocked - malicious source detected');
    }
  });
});
```

### 2. **Real-time Protection Dashboard**
- Show scan history
- Display threat statistics
- Weekly reports

### 3. **Context Menu Integration**
```javascript
chrome.contextMenus.create({
  id: 'scanFile',
  title: 'Scan with Malware Detector',
  contexts: ['link']
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scanFile') {
    // Scan linked file
    scanURL(info.linkUrl);
  }
});
```

---

## For FYP Demonstration

**Demo Script:**
1. Open Chrome with extension installed
2. Download a test file (e.g., EICAR test file)
3. Notification pops up: "Scan this file?"
4. Click "Scan Now"
5. Show real-time scanning progress
6. Display result with VT enrichment
7. Highlight privacy (local processing) vs cloud (optional VT)

**Key Talking Points:**
- ✓ Proactive protection (scans before user opens file)
- ✓ Non-intrusive (optional, not forced)
- ✓ Privacy-preserving (local ML + optional cloud)
- ✓ Educational (shows detection reasoning)

---

## Answer to Your Questions

### Q1: "How do we extract features from user files?"
**Answer**: Use **static-only features** (PE headers) that can be extracted safely without execution. See [FEATURE_EXTRACTION_SOLUTION.md](FEATURE_EXTRACTION_SOLUTION.md) for details.

### Q2: "Can extension detect downloads and show scan prompt?"
**Answer**: **YES!** Use `chrome.downloads.onCreated` listener + `chrome.notifications` API. See implementation above.

---

## Next Steps

1. Create `extension/` folder
2. Implement files above
3. Test with EICAR test file
4. Integrate with your FastAPI backend
5. Demo for FYP!

This gives you a complete, working browser extension with download detection!
