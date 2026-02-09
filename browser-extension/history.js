// History page script for SecureGuard Extension

let allHistory = [];
let currentFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
  loadHistory();
  setupEventListeners();
});

function setupEventListeners() {
  // Back button
  document.getElementById('backBtn').addEventListener('click', () => {
    window.close();
  });

  // Clear history button
  document.getElementById('clearHistoryBtn').addEventListener('click', clearAllHistory);

  // Export button
  document.getElementById('exportBtn').addEventListener('click', exportToCSV);

  // Filter buttons
  document.querySelectorAll('.filter-chip').forEach(btn => {
    btn.addEventListener('click', (e) => {
      // Remove active from all
      document.querySelectorAll('.filter-chip').forEach(b => b.classList.remove('active'));
      // Add active to clicked
      e.target.classList.add('active');
      // Apply filter
      currentFilter = e.target.dataset.filter;
      renderTable();
    });
  });
}

function loadHistory() {
  chrome.storage.local.get({ scanHistory: [] }, (data) => {
    allHistory = data.scanHistory || [];
    
    if (allHistory.length === 0) {
      showEmptyState();
    } else {
      updateStats();
      renderTable();
    }
  });
}

function updateStats() {
  const total = allHistory.length;
  const threats = allHistory.filter(s => s.is_malicious).length;
  const clean = total - threats;
  const avgConfidence = total > 0 
    ? (allHistory.reduce((sum, s) => sum + (s.confidence || 0), 0) / total * 100).toFixed(1)
    : 0;

  document.getElementById('totalScans').textContent = total;
  document.getElementById('threatsCount').textContent = threats;
  document.getElementById('cleanCount').textContent = clean;
  document.getElementById('avgConfidence').textContent = avgConfidence + '%';
}

function renderTable() {
  const tbody = document.getElementById('historyBody');
  
  // Filter history based on current filter
  let filtered = allHistory;
  if (currentFilter === 'malicious') {
    filtered = allHistory.filter(s => s.is_malicious);
  } else if (currentFilter === 'clean') {
    filtered = allHistory.filter(s => !s.is_malicious);
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="no-data">
          No ${currentFilter === 'all' ? '' : currentFilter} scans found
        </td>
      </tr>
    `;
    return;
  }

  // Sort by timestamp (newest first)
  const sorted = filtered.sort((a, b) => 
    new Date(b.timestamp) - new Date(a.timestamp)
  );

  tbody.innerHTML = sorted.map(scan => {
    const isMalicious = scan.is_malicious;
    const confidence = (scan.confidence * 100).toFixed(1);
    const filename = scan.filename || 'Unknown File';
    const fileType = getFileType(filename);
    const timestamp = new Date(scan.timestamp).toLocaleString();
    const timeAgo = formatTimeAgo(scan.timestamp);

    const statusBadge = isMalicious
      ? `<span class="badge badge-malicious">⚠️ Malicious</span>`
      : `<span class="badge badge-clean">✓ Clean</span>`;

    const confidenceClass = confidence > 80 ? 'high' : confidence > 50 ? 'medium' : 'low';

    return `
      <tr>
        <td class="cell-filename" title="${filename}">
          ${filename}
        </td>
        <td>
          <span class="file-type">${fileType}</span>
        </td>
        <td>
          ${statusBadge}
        </td>
        <td>
          <span class="confidence ${confidenceClass}">${confidence}%</span>
        </td>
        <td class="cell-time" title="${timestamp}">
          ${timeAgo}
        </td>
      </tr>
    `;
  }).join('');
}

function getFileType(filename) {
  if (!filename) return 'UNKNOWN';
  
  const ext = filename.split('.').pop().toUpperCase();
  
  // Common file type categorization
  const categories = {
    // Executable
    'EXE': 'EXE', 'DLL': 'DLL', 'COM': 'COM', 'SCR': 'SCR', 'BAT': 'BAT', 'CMD': 'CMD',
    'MSI': 'MSI', 'PS1': 'PS1',
    // Documents
    'PDF': 'PDF', 'DOC': 'DOC', 'DOCX': 'DOC', 'XLS': 'XLS', 'XLSX': 'XLS', 'PPT': 'PPT',
    'PPTX': 'PPT', 'RTF': 'DOC', 'WORD': 'DOC',
    // Archives
    'ZIP': 'ZIP', 'RAR': 'RAR', '7Z': '7Z', 'TAR': 'TAR', 'GZ': 'GZ', 'ISO': 'ISO',
    // Scripts
    'VBS': 'VBS', 'JS': 'JS', 'JSE': 'JS', 'VB': 'VBS', 'REG': 'REG', 'WS': 'VBS',
    // Images
    'JPG': 'JPG', 'JPEG': 'JPG', 'PNG': 'PNG', 'GIF': 'GIF', 'BMP': 'BMP', 'SVG': 'SVG', 'TIFF': 'TIFF',
    // Audio/Video
    'MP3': 'MP3', 'MP4': 'MP4', 'AVI': 'AVI', 'MKV': 'MKV', 'MOV': 'MOV', 'WAV': 'WAV',
    // Web
    'HTML': 'HTML', 'HTM': 'HTML', 'ASP': 'ASP', 'PHP': 'PHP', 'CFM': 'CFM', 'JSP': 'JSP',
    // Text
    'TXT': 'TXT', 'CSV': 'CSV', 'JSON': 'JSON', 'XML': 'XML', 'LOG': 'LOG', 'MD': 'MD',
  };

  return categories[ext] || ext || 'UNKNOWN';
}

function formatTimeAgo(timestamp) {
  const now = new Date();
  const past = new Date(timestamp);
  const seconds = Math.floor((now - past) / 1000);

  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  
  return past.toLocaleDateString();
}

function showEmptyState() {
  const tbody = document.getElementById('historyBody');
  tbody.innerHTML = `
    <tr>
      <td colspan="5">
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <h2>No Scan History Yet</h2>
          <p>Download or select a file to start scanning</p>
        </div>
      </td>
    </tr>
  `;
}

function clearAllHistory() {
  if (!confirm('⚠️ Are you sure you want to clear all scan history? This cannot be undone.')) {
    return;
  }

  chrome.storage.local.set({ scanHistory: [] }, () => {
    allHistory = [];
    updateStats();
    showEmptyState();
  });
}

function exportToCSV() {
  if (allHistory.length === 0) {
    alert('No scan history to export');
    return;
  }

  const headers = ['File Name', 'File Type', 'Status', 'Confidence (%)', 'Timestamp'];
  const rows = allHistory.map(scan => [
    scan.filename || 'Unknown',
    getFileType(scan.filename || ''),
    scan.is_malicious ? 'Malicious' : 'Clean',
    (scan.confidence * 100).toFixed(1),
    new Date(scan.timestamp).toLocaleString()
  ]);

  // Create CSV content
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n');

  // Create blob and download
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  
  link.setAttribute('href', url);
  link.setAttribute('download', `secureguard_history_${new Date().toISOString().split('T')[0]}.csv`);
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
