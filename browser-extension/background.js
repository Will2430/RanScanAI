// Background service worker for SecureGuard Extension

const API_BASE = 'http://localhost:8000';
const NATIVE_HOST_NAME = 'com.secureguard.host';

// Native messaging port
let nativePort = null;
let isNativeHostConnected = false;

// Create context menu on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scanFile',
    title: 'Scan with SecureGuard',
    contexts: ['link', 'page']
  });
  
  console.log('SecureGuard extension installed');
  
  // Connect to native host
  connectToNativeHost();
});

// Connect to native messaging host
function connectToNativeHost() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    
    nativePort.onMessage.addListener((message) => {
      console.log('Received from native host:', message);
      handleNativeResponse(message);
    });
    
    nativePort.onDisconnect.addListener(() => {
      console.log('Disconnected from native host');
      isNativeHostConnected = false;
      
      if (chrome.runtime.lastError) {
        console.error('Native host error:', chrome.runtime.lastError.message);
      }
      
      // Retry connection after 5 seconds
      setTimeout(connectToNativeHost, 5000);
    });
    
    // Send ping to verify connection
    console.log('[DEBUG] Sending PING to native host...');
    sendToNativeHost({ action: 'ping' })
      .then((response) => {
        if (response && response.status === 'ok') {
          isNativeHostConnected = true;
          console.log('[DEBUG] ✅ Native host CONNECTED:', response);
        } else {
          console.warn('[DEBUG] ⚠️ Unexpected response:', response);
        }
      })
      .catch((error) => {
        console.error('[DEBUG] ❌ Native host ping FAILED:', error);
        isNativeHostConnected = false;
      });
      
  } catch (error) {
    console.error('Failed to connect to native host:', error);
    isNativeHostConnected = false;
  }
}

// Send message to native host and wait for response
function sendToNativeHost(message) {
  return new Promise((resolve, reject) => {
    if (!nativePort) {
      console.error('[DEBUG] ❌ nativePort is NULL');
      reject(new Error('Native host not connected'));
      return;
    }
    
    // Create callback for this specific message
    const messageId = Date.now() + Math.random();
    message.messageId = messageId;
    
    console.log('[DEBUG] 📤 Sending to native host:', message);
    
    const listener = (response) => {
      console.log('[DEBUG] 📥 Received from native host:', response);
      if (response.messageId === messageId || !response.messageId) {
        nativePort.onMessage.removeListener(listener);
        resolve(response);
      }
    };
    
    nativePort.onMessage.addListener(listener);
    
    // Send message
    try {
      nativePort.postMessage(message);
      console.log('[DEBUG] ✅ Message posted successfully');
    } catch (error) {
      console.error('[DEBUG] ❌ Failed to post message:', error);
      reject(error);
    }
    
    // Timeout after 30 seconds
    setTimeout(() => {
      console.warn('[DEBUG] ⏰ Timeout waiting for response');
      nativePort.onMessage.removeListener(listener);
      reject(new Error('Native host timeout'));
    }, 30000);
  });
}

// Handle responses from native host
function handleNativeResponse(response) {
  console.log('Native host response:', response);
  
  if (response.action === 'quarantined') {
    showNotification(
      '🔒 File Quarantined',
      `File moved to secure quarantine: ${response.quarantine_path}`,
      'success'
    );
  } else if (response.action === 'deleted') {
    showNotification(
      '🗑️ File Deleted',
      `Malicious file permanently deleted: ${response.file_path}`,
      'success'
    );
  } else if (!response.success && response.error) {
    showNotification(
      '⚠️ Action Failed',
      `Error: ${response.error}`,
      'error'
    );
  }
}

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scanFile') {
    handleFileScan(info, tab);
  }
});

// Handle file scanning
async function handleFileScan(info, tab) {
  const url = info.linkUrl || info.pageUrl;
  
  // Notify user that scanning is starting
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: 'SecureGuard Scanning',
    message: 'Preparing to scan file...'
  });
  
  try {
    // Download the file
    chrome.downloads.download({
      url: url,
      saveAs: false
    }, (downloadId) => {
      if (downloadId) {
        monitorDownload(downloadId);
      }
    });
  } catch (error) {
    console.error('Scan error:', error);
    showNotification('Error', 'Failed to initiate scan: ' + error.message, 'error');
  }
}

// Monitor download completion
function monitorDownload(downloadId) {
  chrome.downloads.onChanged.addListener(function listener(delta) {
    if (delta.id === downloadId && delta.state && delta.state.current === 'complete') {
      chrome.downloads.search({ id: downloadId }, (items) => {
        if (items && items[0]) {
          scanDownloadedFile(items[0].filename, items[0].id);
        }
      });
      chrome.downloads.onChanged.removeListener(listener);
    }
  });
}

// Scan the downloaded file
async function scanDownloadedFile(filePath, downloadId) {
  try {
    // Check if backend is running
    const healthCheck = await fetch(`${API_BASE}/health`).catch(() => null);
    
    if (!healthCheck || !healthCheck.ok) {
      showNotification(
        'Backend Not Running',
        'Please start the SecureGuard backend service first.',
        'error'
      );
      return;
    }
    
    // Send file path to backend for scanning
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        file_path: filePath,
        download_id: downloadId
      })
    });
    
    const result = await response.json();
    
    // Store scan result
    chrome.storage.local.get({ scanHistory: [] }, (data) => {
      const history = data.scanHistory;
      history.unshift({
        timestamp: new Date().toISOString(),
        filename: filePath.split(/[\\\/]/).pop(),
        ...result
      });
      
      // Keep only last 100 scans
      if (history.length > 100) {
        history.pop();
      }
      
      chrome.storage.local.set({ scanHistory: history });
    });
    
    // Show notification
    if (result.is_malicious) {
      const filename = filePath.split(/[\\\/]/).pop();
      const confidence = (result.confidence * 100).toFixed(1);
      
      showNotification(
        '⚠️ THREAT DETECTED',
        `${filename} appears MALICIOUS (${confidence}% confidence)`,
        'error'
      );
      
      // Use native messaging for true mitigation if available
      console.log('[DEBUG] Quarantine check - Connected:', isNativeHostConnected, 'Confidence:', result.confidence);
      
      if (isNativeHostConnected && result.confidence > 0.6) {
        console.log('[DEBUG] ✅ Eligible for quarantine!');
        // Get the full file path first
        chrome.downloads.search({ id: downloadId }, async (items) => {
          console.log('[DEBUG] Download items:', items);
          if (items && items[0] && items[0].filename) {
            const fullPath = items[0].filename;
            console.log('[DEBUG] File path:', fullPath);
            
            // Ask user what to do
            const action = await promptUserForAction(filename, confidence);
            console.log('[DEBUG] User chose action:', action);
            
            if (action === 'quarantine') {
              console.log('[DEBUG] 🔒 Starting quarantine process...');
              try {
                const response = await sendToNativeHost({
                  action: 'quarantine',
                  file_path: fullPath
                });
                
                if (response.success) {
                  console.log('[DEBUG] ✅ File quarantined successfully:', response.quarantine_path);
                } else {
                  console.error('[DEBUG] ❌ Quarantine failed:', response.error);
                  // Fallback: try to delete via browser
                  chrome.downloads.removeFile(downloadId);
                }
              } catch (error) {
                console.error('[DEBUG] ❌ Native host communication error:', error);
                chrome.downloads.removeFile(downloadId);
              }
            } else if (action === 'delete') {
              console.log('[DEBUG] 🗑️ Starting delete process...');
              try {
                const response = await sendToNativeHost({
                  action: 'delete',
                  file_path: fullPath
                });
                
                if (!response.success) {
                  console.error('[DEBUG] ❌ Delete failed:', response.error);
                  chrome.downloads.removeFile(downloadId);
                }
              } catch (error) {
                console.error('[DEBUG] ❌ Native host communication error:', error);
                chrome.downloads.removeFile(downloadId);
              }
            }
          } else {
            console.warn('[DEBUG] ⚠️ No download item found');
          }
        });
      } else {
        console.log('[DEBUG] ⚠️ Not eligible for quarantine - using fallback');
        if (!isNativeHostConnected) {
          console.log('[DEBUG]   Reason: Native host NOT connected');
        }
        if (result.confidence <= 0.6) {
          console.log('[DEBUG]   Reason: Confidence too low (' + result.confidence + ')');
        }
        // Fallback: browser-level mitigation (cancel/remove)
        if (result.confidence > 0.6) {
          console.log('[DEBUG] 🗑️ Using browser-level removal');
          chrome.downloads.cancel(downloadId);
          chrome.downloads.removeFile(downloadId);
        }
      }
    } else {
      showNotification(
        '✓ File Clean',
        `${filePath.split(/[\\\/]/).pop()} appears safe (${(result.confidence * 100).toFixed(1)}% confidence)`,
        'success'
      );
    }
    
  } catch (error) {
    console.error('Scan error:', error);
    showNotification('Scan Failed', error.message, 'error');
  }
}

// Prompt user for mitigation action
async function promptUserForAction(filename, confidence) {
  // Simpler approach: just auto-quarantine and notify
  // Chrome notification buttons are unreliable on Windows
  
  showNotification(
    '⚠️ AUTO-QUARANTINING',
    `${filename} (${confidence}% malicious) will be quarantined in 3 seconds. Check extension popup to restore if needed.`,
    'error'
  );
  
  // Wait 3 seconds before quarantining
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  return 'quarantine'; // Always quarantine for safety
}

// Show notification
function showNotification(title, message, type = 'basic') {
  const iconMap = {
    success: 'icons/icon48.png',
    error: 'icons/icon48.png',
    basic: 'icons/icon48.png'
  };
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: iconMap[type],
    title: title,
    message: message,
    priority: type === 'error' ? 2 : 1
  });
}

// Message handling from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getScanHistory') {
    chrome.storage.local.get({ scanHistory: [] }, (data) => {
      sendResponse({ history: data.scanHistory });
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'clearHistory') {
    chrome.storage.local.set({ scanHistory: [] }, () => {
      sendResponse({ success: true });
    });
    return true;
  }
  
  if (request.action === 'checkBackendStatus') {
    fetch(`${API_BASE}/health`)
      .then(res => res.json())
      .then(data => sendResponse({ status: 'online', data }))
      .catch(() => sendResponse({ status: 'offline' }));
    return true;
  }
  
  if (request.action === 'checkNativeHostStatus') {
    sendResponse({ 
      connected: isNativeHostConnected,
      hostName: NATIVE_HOST_NAME
    });
    return true;
  }
  
  if (request.action === 'listQuarantine') {
    if (!isNativeHostConnected) {
      sendResponse({ 
        success: false, 
        error: 'Native host not connected' 
      });
      return true;
    }
    
    sendToNativeHost({ action: 'list_quarantine' })
      .then(response => sendResponse(response))
      .catch(error => sendResponse({ 
        success: false, 
        error: error.message 
      }));
    return true;
  }
  
  if (request.action === 'restoreFile') {
    if (!isNativeHostConnected) {
      sendResponse({ 
        success: false, 
        error: 'Native host not connected' 
      });
      return true;
    }
    
    sendToNativeHost({ 
      action: 'restore',
      quarantine_path: request.quarantine_path,
      original_path: request.original_path
    })
      .then(response => sendResponse(response))
      .catch(error => sendResponse({ 
        success: false, 
        error: error.message 
      }));
    return true;
  }
});
