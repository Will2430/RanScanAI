// Popup script for SecureGuard Extension

document.addEventListener('DOMContentLoaded', () => {
  checkBackendStatus();
  checkNativeHostStatus();
  loadScanHistory();
  updateStats();
  
  // Event listeners
  document.getElementById('scanFileBtn').addEventListener('click', openFilePicker);
  document.getElementById('viewHistoryBtn').addEventListener('click', showFullHistory);
  document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);
  document.getElementById('quarantineBtn').addEventListener('click', toggleQuarantineView);
  document.getElementById('refreshQuarantineBtn').addEventListener('click', loadQuarantineList);
  
  // Refresh every 5 seconds
  setInterval(() => {
    checkBackendStatus();
    checkNativeHostStatus();
    loadScanHistory();
    updateStats();
  }, 5000);
});

// Check if backend is running
function checkBackendStatus() {
  chrome.runtime.sendMessage({ action: 'checkBackendStatus' }, (response) => {
    const statusElement = document.getElementById('backendStatus');
    const dot = statusElement.querySelector('.status-dot');
    const text = statusElement.querySelector('.status-text');
    
    if (response && response.status === 'online') {
      dot.className = 'status-dot online';
      text.textContent = 'Backend: Online';
      document.getElementById('scanFileBtn').disabled = false;
    } else {
      dot.className = 'status-dot offline';
      text.textContent = 'Backend: Offline';
      document.getElementById('scanFileBtn').disabled = true;
    }
  });
}

// Check native host status
function checkNativeHostStatus() {
  chrome.runtime.sendMessage({ action: 'checkNativeHostStatus' }, (response) => {
    const statusElement = document.getElementById('nativeHostStatus');
    const dot = statusElement.querySelector('.status-dot');
    const text = statusElement.querySelector('.status-text');
    
    if (response && response.connected) {
      dot.className = 'status-dot online';
      text.textContent = 'Native Host: Connected';
      document.getElementById('quarantineBtn').disabled = false;
    } else {
      dot.className = 'status-dot offline';
      text.textContent = 'Native Host: Disconnected';
      document.getElementById('quarantineBtn').disabled = true;
    }
  });
}

// Load recent scan history
function loadScanHistory() {
  chrome.runtime.sendMessage({ action: 'getScanHistory' }, (response) => {
    if (response && response.history) {
      displayRecentScans(response.history.slice(0, 5)); // Show only 5 most recent
    }
  });
}

// Display recent scans
function displayRecentScans(scans) {
  const container = document.getElementById('recentScans');
  
  if (!scans || scans.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ccc">
          <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" stroke-width="2" stroke-linecap="round"/>
        </svg>
        <p>No scans yet</p>
        <small>Right-click on files to scan them</small>
      </div>
    `;
    return;
  }
  
  container.innerHTML = scans.map(scan => {
    const isMalicious = scan.is_malicious;
    const confidence = (scan.confidence * 100).toFixed(1);
    const timestamp = new Date(scan.timestamp).toLocaleString();
    
    return `
      <div class="scan-item ${isMalicious ? 'malicious' : 'clean'}">
        <div class="scan-icon">
          ${isMalicious ? 
            '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f44336"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" stroke-width="2" stroke-linecap="round"/></svg>' :
            '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4CAF50"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke-width="2" stroke-linecap="round"/></svg>'
          }
        </div>
        <div class="scan-details">
          <div class="scan-filename">${scan.filename}</div>
          <div class="scan-meta">
            <span class="scan-time">${formatTimeAgo(scan.timestamp)}</span>
            <span class="scan-confidence ${isMalicious ? 'danger' : 'success'}">${confidence}% confident</span>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// Update statistics
function updateStats() {
  chrome.runtime.sendMessage({ action: 'getScanHistory' }, (response) => {
    if (response && response.history) {
      const total = response.history.length;
      const threats = response.history.filter(s => s.is_malicious).length;
      const clean = total - threats;
      
      document.getElementById('totalScans').textContent = total;
      document.getElementById('threatsDetected').textContent = threats;
      document.getElementById('cleanFiles').textContent = clean;
    }
  });
}

// Format timestamp to relative time
function formatTimeAgo(timestamp) {
  const now = new Date();
  const past = new Date(timestamp);
  const seconds = Math.floor((now - past) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// Open file picker (trigger file input)
function openFilePicker() {
  // Create file input element
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = '*';
  
  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (file) {
      await scanSelectedFile(file);
    }
  });
  
  fileInput.click();
}

// Scan selected file
async function scanSelectedFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  
  try {
    // Show scanning notification
    showNotification('Scanning...', `Analyzing ${file.name}`, 'info');
    
    const response = await fetch('http://localhost:8000/scan-upload', {
      method: 'POST',
      body: formData
    });
    
    const result = await response.json();
    
    // Store in history
    chrome.storage.local.get({ scanHistory: [] }, (data) => {
      const history = data.scanHistory;
      history.unshift({
        timestamp: new Date().toISOString(),
        filename: file.name,
        ...result
      });
      
      if (history.length > 100) history.pop();
      
      chrome.storage.local.set({ scanHistory: history }, () => {
        loadScanHistory();
        updateStats();
      });
    });
    
    // Show result notification
    if (result.is_malicious) {
      showNotification('⚠️ THREAT DETECTED', 
        `${file.name} appears MALICIOUS (${(result.confidence * 100).toFixed(1)}% confidence)`, 
        'error');
    } else {
      showNotification('✓ File Clean', 
        `${file.name} appears safe (${(result.confidence * 100).toFixed(1)}% confidence)`, 
        'success');
    }
    
  } catch (error) {
    showNotification('Scan Failed', error.message, 'error');
  }
}

// Show notification
function showNotification(title, message, type) {
  // Use browser notification API
  if (Notification.permission === 'granted') {
    new Notification(title, { body: message });
  }
}

// Show full history
function showFullHistory() {
  // Open a new tab with full history
  chrome.tabs.create({ url: 'history.html' });
}

// Clear scan history
function clearHistory() {
  if (confirm('Are you sure you want to clear all scan history?')) {
    chrome.runtime.sendMessage({ action: 'clearHistory' }, () => {
      loadScanHistory();
      updateStats();
    });
  }
}

// Toggle quarantine view
function toggleQuarantineView() {
  const quarantineSection = document.getElementById('quarantineSection');
  const recentScansSection = document.getElementById('recentScansSection');
  
  if (quarantineSection.style.display === 'none') {
    quarantineSection.style.display = 'block';
    recentScansSection.style.display = 'none';
    loadQuarantineList();
  } else {
    quarantineSection.style.display = 'none';
    recentScansSection.style.display = 'block';
  }
}

// Load quarantined files
function loadQuarantineList() {
  chrome.runtime.sendMessage({ action: 'listQuarantine' }, (response) => {
    const container = document.getElementById('quarantineList');
    
    if (!response || !response.success) {
      container.innerHTML = `
        <div class="empty-state">
          <p>❌ ${response?.error || 'Failed to load quarantine'}</p>
          <small>Make sure native host is installed</small>
        </div>
      `;
      return;
    }
    
    if (!response.files || response.files.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ccc">
            <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <p>No quarantined files</p>
          <small>Malicious files will be quarantined here</small>
        </div>
      `;
      return;
    }
    
    container.innerHTML = response.files.map(file => {
      const timestamp = file.timestamp !== 'Unknown' ? new Date(file.timestamp).toLocaleString() : 'Unknown';
      const fileSize = formatFileSize(file.size);
      
      return `
        <div class="quarantine-item">
          <div class="quarantine-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f44336">
              <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </div>
          <div class="quarantine-details">
            <div class="quarantine-filename">${file.filename}</div>
            <div class="quarantine-meta">
              <span>${timestamp}</span>
              <span>${fileSize}</span>
            </div>
            <div class="quarantine-path">${file.original_path}</div>
          </div>
          <button class="btn-restore" data-quarantine-path="${file.quarantine_path}" data-original-path="${file.original_path}">
            Restore
          </button>
        </div>
      `;
    }).join('');
    
    // Add restore button listeners
    container.querySelectorAll('.btn-restore').forEach(btn => {
      btn.addEventListener('click', () => restoreFile(
        btn.dataset.quarantinePath,
        btn.dataset.originalPath
      ));
    });
  });
}

// Restore file from quarantine
function restoreFile(quarantinePath, originalPath) {
  if (!confirm(`Restore file to:\n${originalPath}\n\nAre you sure this file is safe?`)) {
    return;
  }
  
  chrome.runtime.sendMessage({
    action: 'restoreFile',
    quarantine_path: quarantinePath,
    original_path: originalPath
  }, (response) => {
    if (response && response.success) {
      alert('✓ File restored successfully!');
      loadQuarantineList(); // Refresh list
    } else {
      alert(`❌ Failed to restore file:\n${response?.error || 'Unknown error'}`);
    }
  });
}

// Format file size
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
