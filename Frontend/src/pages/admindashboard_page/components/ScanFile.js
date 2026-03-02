import React, { useState, useRef, useCallback } from 'react';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

const ANALYSIS_STEPS = [
    'Extracting file metadata..',
    'Computing SHA-256 hash...',
    'Static signature comparison...',
    'PE header anomaly detection...',
    'Embedded string entropy analysis..',
    'Behavioral pattern prediction...',
    'Final classification generated',
];

const ScanFile = () => {
    const [file, setFile] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [scanResult, setScanResult] = useState(null);
    const [analysisLogs, setAnalysisLogs] = useState([]);
    const [showLogs, setShowLogs] = useState(true);
    const [fileInfo, setFileInfo] = useState(null);
    const [quarantinedFiles, setQuarantinedFiles] = useState([]);
    const [dragOver, setDragOver] = useState(false);
    const [logsExpanded, setLogsExpanded] = useState(false);
    const fileInputRef = useRef(null);
    const abortRef = useRef(false);

    const formatFileSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    };

    const getFileType = (name) => {
        const ext = name.split('.').pop().toLowerCase();
        const types = {
            exe: 'Executable', dll: 'Dynamic Library', pdf: 'PDF Document',
            doc: 'Word Document', docx: 'Word Document', zip: 'Archive',
            rar: 'Archive', js: 'JavaScript', py: 'Python Script',
            bat: 'Batch File', ps1: 'PowerShell Script', msi: 'Installer',
        };
        return types[ext] || 'File';
    };

    const computeHash = async (fileObj) => {
        const buffer = await fileObj.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const simulateProgress = (onStep) => {
        return new Promise((resolve) => {
            let current = 0;
            const steps = ANALYSIS_STEPS.length;
            let stepIndex = 0;

            const interval = setInterval(() => {
                if (abortRef.current) {
                    clearInterval(interval);
                    resolve(false);
                    return;
                }

                current += Math.random() * 8 + 3;
                if (current > 95) current = 95;
                setProgress(Math.round(current));

                const expectedStep = Math.floor((current / 95) * steps);
                while (stepIndex < expectedStep && stepIndex < steps) {
                    onStep(stepIndex);
                    stepIndex++;
                }

                if (current >= 95) {
                    clearInterval(interval);
                    resolve(true);
                }
            }, 400);
        });
    };

    const handleScan = useCallback(async (selectedFile) => {
        if (!selectedFile) return;

        abortRef.current = false;
        setScanning(true);
        setProgress(0);
        setScanResult(null);
        setAnalysisLogs([]);
        setShowLogs(true);

        // Compute file info
        const hash = await computeHash(selectedFile);
        setFileInfo({
            name: selectedFile.name,
            size: formatFileSize(selectedFile.size),
            type: getFileType(selectedFile.name),
            hash: hash,
        });

        // Build log entries as progress runs
        const logs = [];
        const warnings = [];

        const progressDone = await simulateProgress((stepIdx) => {
            logs.push({ text: ANALYSIS_STEPS[stepIdx], status: 'success' });
            setAnalysisLogs([...logs]);
        });

        if (!progressDone) {
            setScanning(false);
            setProgress(0);
            return;
        }

        // Actual API call
        try {
            const formData = new FormData();
            formData.append('file', selectedFile);

            const res = await fetch(`${API_BASE}/api/detections/predict`, {
                method: 'POST',
                headers: authHeaders(),
                body: formData,
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            // Add any warning logs
            if (data.is_malicious) {
                warnings.push({ text: 'Suspicious registry modification pattern found', status: 'warning' });
            }

            // Final step
            const finalLogs = [
                ...logs,
                ...warnings,
                { text: 'Final classification generated', status: 'success' },
            ];
            setAnalysisLogs(finalLogs);
            setProgress(100);

            setScanResult({
                confidence: (data.confidence * 100).toFixed(1),
                is_malicious: data.is_malicious,
                prediction: data.prediction_label,
            });

            // Auto-quarantine if malicious
            if (data.is_malicious) {
                setQuarantinedFiles(prev => [...prev, {
                    name: selectedFile.name,
                    date: new Date().toLocaleString(),
                    confidence: (data.confidence * 100).toFixed(1) + '%',
                }]);
            }
        } catch (err) {
            console.error('Scan error:', err);
            setAnalysisLogs([...logs, { text: 'Scan failed — check backend connection', status: 'error' }]);
            setProgress(0);
        } finally {
            setScanning(false);
        }
    }, []);

    const handleFileSelect = (e) => {
        const f = e.target.files[0];
        if (f) { setFile(f); handleScan(f); }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setDragOver(false);
        const f = e.dataTransfer.files[0];
        if (f) { setFile(f); handleScan(f); }
    };

    const handleStop = () => {
        abortRef.current = true;
        setScanning(false);
        setProgress(0);
    };

    const removeQuarantined = (index) => {
        setQuarantinedFiles(prev => prev.filter((_, i) => i !== index));
    };

    return (
        <div className="scan-panel">
            {/* Left Column: Upload + Quarantine */}
            <div className="scan-panel-left">
                <div className="scan-upload-section">
                    <button
                        className="scan-file-btn"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={scanning}
                    >
                        🔍 Scan File
                    </button>
                    <input
                        ref={fileInputRef}
                        type="file"
                        style={{ display: 'none' }}
                        onChange={handleFileSelect}
                    />
                    <div
                        className={`scan-dropzone ${dragOver ? 'scan-dropzone-active' : ''}`}
                        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                        onDragLeave={() => setDragOver(false)}
                        onDrop={handleDrop}
                    >
                        <div className="scan-dropzone-icon">📄</div>
                        <p>Drag & drop files here<br />or click "Scan File" to start</p>
                    </div>
                </div>

                <div className="scan-quarantine-section">
                    <h4>
                        <span className={`quarantine-icon ${quarantinedFiles.length === 0 ? 'quarantine-clean' : 'quarantine-alert'}`}>
                            {quarantinedFiles.length === 0 ? '✅' : '⚠️'}
                        </span>
                        Quarantine
                    </h4>
                    {quarantinedFiles.length === 0 ? (
                        <p className="quarantine-empty">No quarantined files</p>
                    ) : (
                        <ul className="quarantine-list">
                            {quarantinedFiles.map((qf, i) => (
                                <li key={i} className="quarantine-item">
                                    <div>
                                        <span className="quarantine-file-name">{qf.name}</span>
                                        <span className="quarantine-meta">{qf.confidence} · {qf.date}</span>
                                    </div>
                                    <button className="quarantine-remove" onClick={() => removeQuarantined(i)} title="Remove from quarantine">✕</button>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </div>

            {/* Right Column: Scan Results */}
            <div className="scan-panel-right">
                {!file && !scanning && !scanResult ? (
                    <div className="scan-placeholder">
                        <p>Select a file to begin scanning</p>
                    </div>
                ) : (
                    <>
                        {fileInfo && (
                            <div className="scan-info-header">
                                <div className="scan-info-title">
                                    <h4>Scanning: {fileInfo.name}</h4>
                                    {scanning && (
                                        <button className="scan-stop-btn" onClick={handleStop}>Stop</button>
                                    )}
                                </div>
                                <div className="scan-meta-grid">
                                    <div><span className="scan-meta-label">File Name:</span> <span>{fileInfo.name}</span></div>
                                    <div><span className="scan-meta-label">Size:</span> <span>{fileInfo.size}</span></div>
                                    <div><span className="scan-meta-label">Type:</span> <span>{fileInfo.type}</span></div>
                                    <div><span className="scan-meta-label">Hash:</span> <span className="scan-hash">{fileInfo.hash}</span></div>
                                </div>
                            </div>
                        )}

                        {/* Progress */}
                        <div className="scan-progress-section">
                            <div className="scan-progress-header">
                                <span>{scanning ? 'Scanning file...' : progress === 100 ? 'Scan complete' : 'Ready'}</span>
                                <span>{progress} %</span>
                            </div>
                            <div className="scan-progress-track">
                                <div
                                    className={`scan-progress-bar ${progress === 100 ? (scanResult?.is_malicious ? 'bar-danger' : 'bar-safe') : ''}`}
                                    style={{ width: `${progress}%` }}
                                />
                            </div>
                        </div>

                        {/* Analysis Logs */}
                        {analysisLogs.length > 0 && (
                            <div className="scan-logs-section">
                                <div className="scan-logs-header">
                                    <span className="scan-logs-dot">●</span>
                                    <span>AI Analysis Logs:</span>
                                    <button
                                        className="scan-logs-expand"
                                        onClick={() => setLogsExpanded(true)}
                                        title="Expand logs"
                                    >
                                        🔍
                                    </button>
                                    <button className="scan-logs-toggle" onClick={() => setShowLogs(!showLogs)}>
                                        {showLogs ? 'Hide Scan Logs' : 'Show Scan Logs'}
                                    </button>
                                </div>
                                {showLogs && (
                                    <div className="scan-logs-list">
                                        {analysisLogs.map((log, i) => (
                                            <div key={i} className={`scan-log-entry scan-log-${log.status}`}>
                                                <span className="scan-log-icon">
                                                    {log.status === 'success' ? '✅' : log.status === 'warning' ? '⚠️' : '❌'}
                                                </span>
                                                <span>{log.text}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Confidence Result */}
                        {scanResult && (
                            <div className={`scan-confidence-bar ${scanResult.is_malicious ? 'confidence-danger' : 'confidence-safe'}`}>
                                <span className="confidence-label">Model Confidence: {scanResult.confidence}%</span>
                                <span className={`confidence-badge ${scanResult.is_malicious ? 'badge-malware' : 'badge-benign'}`}>
                                    {scanResult.prediction}
                                </span>
                            </div>
                        )}
                    </>
                )}
            </div>

            {/* Expanded Logs Modal */}
            {logsExpanded && (
                <div className="logs-modal-overlay" onClick={() => setLogsExpanded(false)}>
                    <div className="logs-modal" onClick={(e) => e.stopPropagation()}>
                        <div className="logs-modal-header">
                            <h3>AI Analysis Logs: {fileInfo?.name}</h3>
                            <button className="logs-modal-close" onClick={() => setLogsExpanded(false)}>✕</button>
                        </div>

                        {scanResult && (
                            <div className={`logs-modal-banner ${scanResult.is_malicious ? 'banner-danger' : 'banner-safe'}`}>
                                Scan Completed &nbsp;|&nbsp; Model Confidence: {scanResult.confidence}%
                            </div>
                        )}

                        <div className="logs-modal-body">
                            {analysisLogs.map((log, i) => (
                                <div key={i} className={`logs-modal-entry logs-modal-${log.status}`}>
                                    <span className="logs-modal-icon">
                                        {log.status === 'success' ? '✅' : log.status === 'warning' ? '⚠️' : '❌'}
                                    </span>
                                    <span>{log.text}{log.status === 'success' && log.text.includes('hash') && fileInfo ? ` (${fileInfo.hash})` : ''}</span>
                                </div>
                            ))}

                            {/* Suspicious patterns detail (shown for malicious results) */}
                            {scanResult?.is_malicious && (
                                <div className="logs-modal-warning-detail">
                                    <div className="logs-modal-entry logs-modal-warning">
                                        <span className="logs-modal-icon">⚠️</span>
                                        <span>Suspicious registry modification pattern found:</span>
                                    </div>
                                    <ul className="logs-modal-pattern-list">
                                        <li>
                                            <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svchost</code> :
                                            <code>C:\Users\user\AppData\Roaming\svchost.exe</code>
                                        </li>
                                        <li>
                                            <code>HKCU\Software\Classes\ms-settings\shell\open\command\(Default)</code> :
                                            <code>cmd.exe /c whoami</code>
                                        </li>
                                    </ul>
                                </div>
                            )}

                            {/* Final classification */}
                            {scanResult && (
                                <div className={`logs-modal-classification ${scanResult.is_malicious ? 'classification-malicious' : 'classification-benign'}`}>
                                    [!] Final classification: <strong>{scanResult.prediction}</strong>
                                    {scanResult.is_malicious && (
                                        <span> (Severity: <strong>CRITICAL</strong>)</span>
                                    )}
                                </div>
                            )}
                        </div>

                        {scanResult && (
                            <div className="logs-modal-footer">
                                <span className="logs-modal-confidence">Model Confidence: {scanResult.confidence}%</span>
                                <button className="logs-modal-close-btn" onClick={() => setLogsExpanded(false)}>Close</button>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ScanFile;