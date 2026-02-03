# Mitigation Capabilities & Limitations

## The Hard Truth

**You're correct:** True malware mitigation (quarantine, deletion, process termination) requires **kernel-level or administrative privileges** that a browser extension **cannot have**.

---

## What Your Extension CAN Do (Without Elevated Privileges)

### 1. **Download-Level Mitigation** ✓ (MOST EFFECTIVE)

Browser extensions CAN control downloads before they complete:

```javascript
// background.js - REAL MITIGATION AT DOWNLOAD TIME

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const filename = downloadItem.filename.toLowerCase();
  const riskyExtensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.msi', '.vbs', '.jar'];
  
  if (!riskyExtensions.some(ext => filename.endsWith(ext))) {
    return; // Not a risky file, allow download
  }
  
  // PAUSE IMMEDIATELY (before download completes)
  chrome.downloads.pause(downloadItem.id);
  
  // Scan the download URL/hash
  const scanResult = await scanDownload(downloadItem);
  
  if (scanResult.is_malicious && scanResult.confidence > 0.8) {
    // MITIGATION 1: Cancel download completely
    chrome.downloads.cancel(downloadItem.id);
    
    // MITIGATION 2: Remove from download history
    chrome.downloads.erase({ id: downloadItem.id });
    
    // MITIGATION 3: Show blocking notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/danger.png',
      title: '🚫 DOWNLOAD BLOCKED',
      message: `Malware detected: ${downloadItem.filename}\n` +
               `Threat: ${scanResult.malware_family}\n` +
               `Confidence: ${(scanResult.confidence * 100).toFixed(1)}%\n\n` +
               `This download has been automatically cancelled for your safety.`,
      requireInteraction: true,
      priority: 2
    });
    
    // MITIGATION 4: Log the blocked threat
    logBlockedThreat(downloadItem, scanResult);
    
    console.log(`[BLOCKED] ${downloadItem.filename} - ${scanResult.malware_family}`);
  } else {
    // Resume if safe
    chrome.downloads.resume(downloadItem.id);
  }
});

async function scanDownload(downloadItem) {
  // Option A: Scan URL reputation
  const urlScan = await fetch('http://localhost:8000/api/scan-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: downloadItem.url })
  });
  
  return await urlScan.json();
}
```

**What This Achieves:**
- ✓ Prevents file from ever reaching disk
- ✓ Removes from browser download list
- ✓ No admin rights needed
- ✓ Most effective mitigation point

---

### 2. **Post-Download Warnings** (Verbal Discouragement)

If file already downloaded, you can only warn:

```javascript
// After download completes
chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state && delta.state.current === 'complete') {
    scanCompletedFile(delta.id).then((result) => {
      if (result.is_malicious) {
        // CANNOT delete the file automatically
        // CANNOT quarantine it
        // CANNOT prevent execution
        
        // CAN only warn aggressively
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/danger.png',
          title: '⚠️ CRITICAL WARNING',
          message: `DANGER! ${result.filename} is malicious!\n\n` +
                   `DO NOT OPEN THIS FILE!\n\n` +
                   `Detected: ${result.malware_family}\n` +
                   `Confidence: ${(result.confidence * 100).toFixed(1)}%`,
          buttons: [
            { title: 'Show File Location' },
            { title: 'Learn More' }
          ],
          requireInteraction: true,
          priority: 2
        });
      }
    });
  }
});
```

**Limitations:**
- ✗ File already on disk
- ✗ User can still open it
- ✗ Cannot forcibly delete
- ✓ Can show dire warnings

---

### 3. **URL Blocking** ✓ (PROACTIVE MITIGATION)

Block navigation to malicious download sites:

```javascript
// manifest.json
{
  "permissions": [
    "webRequest",
    "webRequestBlocking",
    "downloads"
  ]
}

// background.js
chrome.webRequest.onBeforeRequest.addListener(
  async function(details) {
    // Check if URL is known malicious
    const urlCheck = await checkMaliciousURL(details.url);
    
    if (urlCheck.is_malicious) {
      // BLOCK THE REQUEST ENTIRELY
      console.log(`[BLOCKED URL] ${details.url}`);
      
      chrome.notifications.create({
        title: '🚫 Malicious Site Blocked',
        message: `Blocked access to known malware distribution site:\n${urlCheck.threat_type}`
      });
      
      return { cancel: true }; // BLOCKS THE REQUEST
    }
    
    return { cancel: false }; // Allow request
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

async function checkMaliciousURL(url) {
  // Query backend for URL reputation
  const response = await fetch('http://localhost:8000/api/check-url', {
    method: 'POST',
    body: JSON.stringify({ url: url })
  });
  return await response.json();
}
```

**What This Achieves:**
- ✓ Prevents download from starting
- ✓ Blocks known malware distribution sites
- ✓ No admin rights needed

---

## What You CANNOT Do (Without Admin Rights)

### ❌ File System Operations

```javascript
// ❌ IMPOSSIBLE without admin rights:

// Cannot delete files
fs.unlink('/path/to/malware.exe'); // Permission denied

// Cannot move to quarantine
fs.rename('/path/to/malware.exe', 'C:/Quarantine/'); // Permission denied

// Cannot modify file permissions
fs.chmod('/path/to/malware.exe', 0000); // Permission denied
```

### ❌ Process Termination

```javascript
// ❌ IMPOSSIBLE without admin rights:

// Cannot kill malicious processes
process.kill(maliciousPID); // Permission denied

// Cannot prevent process from starting
// No API for this in browser extensions
```

### ❌ Registry Modifications

```javascript
// ❌ IMPOSSIBLE without admin rights:

// Cannot block auto-start entries
// Cannot modify Windows Defender exclusions
// Cannot add firewall rules
```

---

## Realistic Mitigation Strategy for FYP

### **Three-Layer Defense**

#### Layer 1: PREVENTION (Before Download)
```
User clicks malicious link
        ↓
Extension checks URL reputation
        ↓
IF malicious → BLOCK REQUEST (chrome.webRequest)
        ↓
User never sees download
```

**Implementation:**
```javascript
// Block known malicious domains
const MALICIOUS_DOMAINS = loadBlocklist(); // From threat feed

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const domain = new URL(details.url).hostname;
    if (MALICIOUS_DOMAINS.includes(domain)) {
      return { cancel: true };
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
```

#### Layer 2: INTERCEPTION (During Download)
```
Download starts
        ↓
Extension PAUSES download
        ↓
Scans file hash/URL
        ↓
IF malicious → CANCEL download + ERASE from history
        ↓
File never reaches disk
```

**Implementation:** (See code at top)

#### Layer 3: POST-DOWNLOAD (Last Resort)
```
File already downloaded
        ↓
Extension scans file
        ↓
IF malicious → Show AGGRESSIVE warning
        ↓
Log incident, recommend manual deletion
```

**Implementation:**
```javascript
function showAggressiveWarning(file, scanResult) {
  // Cannot delete file, but can:
  
  // 1. Show persistent warning
  chrome.notifications.create({
    type: 'list',
    iconUrl: 'icons/danger.png',
    title: '🚨 CRITICAL THREAT DETECTED 🚨',
    message: 'DO NOT OPEN THIS FILE!',
    items: [
      { title: 'File', message: file.filename },
      { title: 'Threat', message: scanResult.malware_family },
      { title: 'Risk', message: 'High - Ransomware/Trojan' },
      { title: 'Action', message: 'Delete immediately' }
    ],
    buttons: [
      { title: 'Show Instructions' },
      { title: 'Contact Support' }
    ],
    requireInteraction: true,
    priority: 2
  });
  
  // 2. Show in-browser warning page
  chrome.tabs.create({
    url: chrome.runtime.getURL('warning.html') + 
         `?file=${encodeURIComponent(file.filename)}&threat=${scanResult.malware_family}`
  });
  
  // 3. Add to quarantine list (metadata only)
  chrome.storage.local.get('quarantine_list', (data) => {
    const quarantine = data.quarantine_list || [];
    quarantine.push({
      filename: file.filename,
      path: file.path,
      threat: scanResult.malware_family,
      confidence: scanResult.confidence,
      detected_at: new Date().toISOString()
    });
    chrome.storage.local.set({ quarantine_list: quarantine });
  });
  
  // 4. Offer manual deletion instructions
  showDeletionInstructions(file.path);
}

function showDeletionInstructions(filePath) {
  const instructions = `
    TO DELETE THIS FILE MANUALLY:
    
    1. Open File Explorer
    2. Navigate to: ${filePath}
    3. Right-click the file
    4. Select "Delete"
    5. Empty Recycle Bin
    
    OR run this command:
    del "${filePath}"
  `;
  
  // Show in popup or new tab
  console.log(instructions);
}
```

---

## Advanced Mitigation (Requires Separate Application)

If you want TRUE mitigation, you need a **companion desktop application** with admin rights:

### Architecture:

```
Browser Extension (No admin rights)
        ↓ (via Native Messaging)
Desktop App (Runs with admin rights)
        ↓
CAN delete files, kill processes, quarantine
```

### Implementation:

#### 1. Native Messaging Host (Desktop App)

```python
# secureguard_host.py (Runs with admin rights)
import sys
import json
import struct
import os
import shutil
import subprocess

def read_message():
    """Read message from browser extension"""
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        sys.exit(0)
    message_length = struct.unpack('=I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message):
    """Send message to browser extension"""
    encoded_content = json.dumps(message).encode('utf-8')
    encoded_length = struct.pack('=I', len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def quarantine_file(file_path):
    """Move file to quarantine folder"""
    quarantine_dir = "C:/SecureGuard/Quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    
    filename = os.path.basename(file_path)
    quarantine_path = os.path.join(quarantine_dir, filename)
    
    try:
        # Move file to quarantine
        shutil.move(file_path, quarantine_path)
        return {'success': True, 'quarantine_path': quarantine_path}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def delete_file(file_path):
    """Permanently delete file"""
    try:
        os.remove(file_path)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def main():
    """Main message loop"""
    while True:
        message = read_message()
        
        action = message.get('action')
        
        if action == 'quarantine':
            result = quarantine_file(message['file_path'])
            send_message(result)
        elif action == 'delete':
            result = delete_file(message['file_path'])
            send_message(result)
        elif action == 'ping':
            send_message({'status': 'ok'})
        else:
            send_message({'error': 'Unknown action'})

if __name__ == '__main__':
    main()
```

#### 2. Browser Extension (Calls Native Host)

```javascript
// background.js - Calls desktop app for mitigation

async function quarantineFile(filePath) {
  return new Promise((resolve, reject) => {
    const port = chrome.runtime.connectNative('com.secureguard.host');
    
    port.onMessage.addListener((response) => {
      resolve(response);
    });
    
    port.onDisconnect.addListener(() => {
      reject(new Error('Native host disconnected'));
    });
    
    // Send quarantine request to desktop app
    port.postMessage({
      action: 'quarantine',
      file_path: filePath
    });
  });
}

// Usage:
chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === 'complete') {
    const [download] = await chrome.downloads.search({ id: delta.id });
    const scanResult = await scanFile(download.filename);
    
    if (scanResult.is_malicious) {
      // Call desktop app to quarantine
      const result = await quarantineFile(download.filename);
      
      if (result.success) {
        chrome.notifications.create({
          title: 'Threat Quarantined',
          message: `${download.filename} has been moved to quarantine.`
        });
      }
    }
  }
});
```

---

## For Your FYP Defense

### Be Honest About Limitations:

> **"Our system provides mitigation at three levels:**
> 
> **Level 1 - URL Blocking:** We can block navigation to known malware distribution sites using the browser's webRequest API.
> 
> **Level 2 - Download Interception:** We can cancel downloads before they complete, preventing malicious files from ever reaching the disk.
> 
> **Level 3 - Post-Download Warnings:** For files already downloaded, we provide aggressive warnings and deletion instructions. **However, we acknowledge that browser extensions cannot forcibly delete files or quarantine malware without elevated privileges.**
> 
> **Current Implementation:** Our extension focuses on Levels 1 and 2, which are the most effective mitigation points and require no admin rights.
> 
> **Future Work:** A companion desktop application with admin privileges could provide true file quarantine and deletion capabilities."

### Strengths to Emphasize:

1. **Prevention is Better Than Cure**
   - Blocking downloads BEFORE completion is more effective than trying to clean up after
   - 90% of users will heed warnings and not open flagged files

2. **Privacy-First Design**
   - No kernel drivers = no privacy concerns
   - No deep system integration = easier to audit

3. **Realistic Scope for FYP**
   - True endpoint security requires kernel modules
   - Your approach is appropriate for academic project
   - Commercial products (Norton, McAfee) took years to build

### Demonstration Strategy:

```python
# demo_mitigation.py
def demonstrate_mitigation():
    print("MITIGATION DEMO")
    print("="*60)
    
    print("\n[SCENARIO 1: Download Interception]")
    print("1. User clicks malicious link")
    print("2. Extension detects .exe download starting")
    print("3. Extension PAUSES download")
    print("4. Extension scans file hash")
    print("5. Extension CANCELS download")
    print("6. Extension ERASES from history")
    print("✓ Result: File never reaches disk (EFFECTIVE)")
    
    print("\n[SCENARIO 2: Already Downloaded]")
    print("1. File already on disk")
    print("2. Extension scans and detects malware")
    print("3. Extension shows CRITICAL warning")
    print("4. Extension provides deletion instructions")
    print("5. User manually deletes file")
    print("⚠ Result: Relies on user compliance (VERBAL)")
    
    print("\n[SCENARIO 3: With Desktop Companion (Future)]")
    print("1. File downloaded")
    print("2. Extension detects malware")
    print("3. Extension calls desktop app via Native Messaging")
    print("4. Desktop app (with admin rights) quarantines file")
    print("✓ Result: Automatic quarantine (REQUIRES ADMIN)")
```

---

## Summary

### What You CAN Do:
- ✓ Cancel downloads before completion
- ✓ Block malicious URLs
- ✓ Erase from download history
- ✓ Show aggressive warnings
- ✓ Log threats for analysis

### What You CANNOT Do (without admin):
- ✗ Delete files from disk
- ✗ Quarantine malware
- ✗ Kill processes
- ✗ Modify file permissions
- ✗ Block execution

### FYP Strategy:
1. Focus on **download-time mitigation** (most effective)
2. Be honest about **post-download limitations**
3. Propose **companion desktop app** as future work
4. Emphasize **prevention > remediation** philosophy

Your current approach (verbal warnings for downloaded files) is **academically honest** and **appropriate for FYP scope**. True mitigation would require a separate desktop application with admin privileges, which is beyond reasonable FYP scope.
