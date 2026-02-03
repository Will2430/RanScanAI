# SecureGuard Native Messaging Setup Guide

## What is Native Messaging?

Native Messaging allows your browser extension to communicate with a desktop application that has **admin privileges**. This enables true file mitigation capabilities that are impossible in the browser sandbox:

- ✅ **Quarantine files** to secure folder
- ✅ **Delete files** from disk
- ✅ **Kill processes** (if needed)
- ✅ **Access system resources** with admin rights

## Architecture

```
┌─────────────────────┐
│  Browser Extension  │
│   (JavaScript)      │
└──────────┬──────────┘
           │ Native Messaging API
           │ (JSON over stdio)
           ▼
┌─────────────────────┐
│   Desktop App       │
│  (Python + Admin)   │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐
    │  File System │
    │  Operations  │
    └──────────────┘
```

## Installation Steps

### Step 1: Test the Native Host (Optional)

Before installing, you can test the Python script directly:

```powershell
cd native-host
python test_host.py
```

This will simulate messages from the extension and verify the host works correctly.

### Step 2: Install the Native Host

**IMPORTANT: Run as Administrator!**

1. Right-click PowerShell → "Run as Administrator"
2. Navigate to the project:
   ```powershell
   cd C:\Users\User\OneDrive\Test\K\native-host
   ```

3. Run the installer:
   ```powershell
   .\install_host.ps1
   ```

4. When prompted, enter your **Extension ID**:
   - Go to `chrome://extensions/`
   - Enable "Developer mode"
   - Find SecureGuard extension
   - Copy the ID (looks like: `abcdefghijklmnopqrstuvwxyz123456`)
   - Paste it when prompted

### Step 3: Restart Browser

**Close and restart Chrome/Edge completely** (not just refresh).

### Step 4: Verify Connection

1. Load your SecureGuard extension
2. Open the popup or background console
3. Look for: "Native host connected: {status: 'ok', ...}"

If you see "Native host error", check the logs:
```
%LOCALAPPDATA%\SecureGuard\logs\host_YYYYMMDD.log
```

## What Gets Installed

```
C:\Users\User\AppData\Local\SecureGuard\
├── secureguard_host.py       # Python native messaging host
├── secureguard_host.bat       # Launcher
├── com.secureguard.host.json  # Manifest (tells Chrome where to find host)
├── Quarantine\                # Folder for quarantined files
│   └── (malicious files moved here)
└── logs\                      # Host logs
    └── host_20260202.log
```

**Registry Entry:**
```
HKCU\Software\Google\Chrome\NativeMessagingHosts\com.secureguard.host
→ Points to manifest JSON
```

## How It Works

### Extension → Desktop Communication

**JavaScript (Extension):**
```javascript
// Connect to native host
const port = chrome.runtime.connectNative('com.secureguard.host');

// Send message
port.postMessage({
  action: 'quarantine',
  file_path: 'C:\\Users\\User\\Downloads\\malware.exe'
});

// Receive response
port.onMessage.addListener((response) => {
  console.log('File quarantined:', response.quarantine_path);
});
```

**Python (Desktop App):**
```python
# Read message from extension (stdin)
message = read_message()  # {'action': 'quarantine', ...}

# Perform admin action
quarantine_file(message['file_path'])

# Send response (stdout)
send_message({
  'success': True,
  'quarantine_path': 'C:\\Users\\...\\Quarantine\\file.exe'
})
```

### Message Protocol

Messages are sent over **stdin/stdout** in this format:
```
[4-byte length][JSON data]
```

Example:
```
0x0000002A {"action":"quarantine","file_path":"..."}
└─ Length=42  └─ JSON payload
```

## Available Actions

### 1. Quarantine File
```javascript
{
  action: 'quarantine',
  file_path: 'C:\\path\\to\\malware.exe'
}
```
**Response:**
```javascript
{
  success: true,
  action: 'quarantined',
  original_path: 'C:\\path\\to\\malware.exe',
  quarantine_path: 'C:\\Users\\...\\Quarantine\\20260202_123456_malware.exe',
  quarantine_dir: 'C:\\Users\\...\\Quarantine'
}
```

### 2. Delete File
```javascript
{
  action: 'delete',
  file_path: 'C:\\path\\to\\malware.exe'
}
```

### 3. List Quarantined Files
```javascript
{
  action: 'list_quarantine'
}
```
**Response:**
```javascript
{
  success: true,
  count: 3,
  files: [
    {
      quarantine_path: 'C:\\...\\Quarantine\\20260202_123456_virus.exe',
      filename: '20260202_123456_virus.exe',
      original_path: 'C:\\Downloads\\virus.exe',
      timestamp: '2026-02-02T12:34:56',
      size: 524288
    },
    ...
  ]
}
```

### 4. Restore File
```javascript
{
  action: 'restore',
  quarantine_path: 'C:\\...\\Quarantine\\file.exe',
  original_path: 'C:\\Downloads\\file.exe'  // optional
}
```

### 5. Ping (Health Check)
```javascript
{
  action: 'ping'
}
```
**Response:**
```javascript
{
  status: 'ok',
  version: '1.0.0',
  quarantine_dir: 'C:\\Users\\...\\Quarantine'
}
```

## Extension Integration

Your extension now has these capabilities in [background.js](c:\Users\User\OneDrive\Test\K\browser-extension\background.js):

### Auto-Connect on Startup
```javascript
chrome.runtime.onInstalled.addListener(() => {
  connectToNativeHost();  // Establishes connection
});
```

### Quarantine Malicious Downloads
```javascript
if (result.is_malicious && isNativeHostConnected) {
  const response = await sendToNativeHost({
    action: 'quarantine',
    file_path: fullFilePath
  });
  
  if (response.success) {
    console.log('Quarantined:', response.quarantine_path);
  }
}
```

### Check Connection Status
```javascript
chrome.runtime.sendMessage(
  { action: 'checkNativeHostStatus' },
  (response) => {
    console.log('Connected:', response.connected);
  }
);
```

## Troubleshooting

### "Failed to connect to native host"

**Check 1:** Extension ID in manifest
```powershell
notepad $env:LOCALAPPDATA\SecureGuard\com.secureguard.host.json
```
Verify `allowed_origins` has correct extension ID.

**Check 2:** Registry entry
```powershell
Get-ItemProperty -Path "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.secureguard.host"
```
Should point to manifest JSON.

**Check 3:** Python installed
```powershell
python --version
```

**Check 4:** Host logs
```powershell
notepad $env:LOCALAPPDATA\SecureGuard\logs\host_20260202.log
```

### "Native host has exited"

The Python script crashed. Check logs for errors:
```powershell
Get-Content $env:LOCALAPPDATA\SecureGuard\logs\host_*.log | Select-Object -Last 50
```

### Permission Denied

The host needs **admin privileges** for some operations:
```powershell
# Run browser as admin (not recommended long-term)
Start-Process chrome.exe -Verb RunAs

# Or grant specific file/folder permissions to the host
```

## Uninstalling

Run as Administrator:
```powershell
cd C:\Users\User\OneDrive\Test\K\native-host
.\uninstall_host.ps1
```

Choose whether to delete quarantined files or keep them.

## Security Notes

1. **Host is trusted**: Only your extension (with matching ID) can communicate with it
2. **Admin rights**: Required for file deletion, process termination
3. **Audit trail**: All actions logged to `logs/` folder
4. **Quarantine safety**: Files moved, not deleted, so you can restore false positives

## Development Tips

### Debugging Messages

Add this to extension console:
```javascript
nativePort.onMessage.addListener((msg) => {
  console.log('📩 From host:', msg);
});
```

Add this to Python host:
```python
logging.debug(f"Received: {message}")
```

### Testing Without Extension

Use [test_host.py](c:\Users\User\OneDrive\Test\K\native-host\test_host.py):
```powershell
python test_host.py
```

### Viewing Quarantine

```powershell
explorer $env:LOCALAPPDATA\SecureGuard\Quarantine
```

Each file has a `.json` metadata file with original path.

## Next Steps

1. ✅ Install native host (run `install_host.ps1`)
2. ✅ Restart browser
3. ✅ Verify connection in extension console
4. Test with EICAR file:
   - Download EICAR test file
   - Extension should detect it as malicious
   - Click "Quarantine" when prompted
   - Verify file moved to quarantine folder

## Support

If you encounter issues:

1. Check logs: `%LOCALAPPDATA%\SecureGuard\logs\`
2. Test host directly: `python test_host.py`
3. Verify registry: `Get-ItemProperty HKCU:\...\com.secureguard.host`
4. Re-run installer with correct Extension ID

---

**Remember:** This is advanced functionality requiring admin rights. For your FYP demo, you can mention this capability but don't need to implement it fully. The browser-level mitigation (download cancellation) is sufficient to demonstrate the concept.
