import React, { useState, useRef, useCallback } from 'react';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

const ScanFile = ({ onScanComplete }) => {
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
    const [behavioralPatterns, setBehavioralPatterns] = useState([]);
    const fileInputRef = useRef(null);
    const esRef = useRef(null);   // holds the active EventSource so Stop can close it

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

    const handleScan = useCallback(async (selectedFile) => {
        if (!selectedFile) return;

        // Close any previous stream
        if (esRef.current) { esRef.current.close(); esRef.current = null; }

        setScanning(true);
        setProgress(5);
        setScanResult(null);
        setAnalysisLogs([]);
        setBehavioralPatterns([]);
        setShowLogs(true);

        // File info + hash
        const hash = await computeHash(selectedFile);
        setFileInfo({
            name: selectedFile.name,
            size: formatFileSize(selectedFile.size),
            type: getFileType(selectedFile.name),
            hash,
        });

        const token = localStorage.getItem('access_token');

        try {
            // ── Step 1: POST → get job_id immediately ──────────────────────
            const formData = new FormData();
            formData.append('file', selectedFile);

            const res = await fetch(`${API_BASE}/predict/staged?run_sandbox=true`, {
                method: 'POST',
                headers: token ? { 'Authorization': 'Bearer ' + token } : {},
                body: formData,
            });

            if (!res.ok) {
                const msg = await res.text();
                throw new Error(`HTTP ${res.status}: ${msg}`);
            }

            const { job_id } = await res.json();

            // ── Step 2: Open SSE stream ─────────────────────────────────────
            // EventSource can't set Authorization header — token goes as query param
            const es = new EventSource(`${API_BASE}/scan/${job_id}/stream?token=${encodeURIComponent(token || '')}`);
            esRef.current = es;

            let logCount = 0;

            es.onmessage = (e) => {
                let msg;
                try { msg = JSON.parse(e.data); } catch { return; }

                if (msg.type === 'log') {
                    logCount++;
                    // Advance progress from 5 → 90 as logs arrive (capped until result)
                    setProgress(Math.min(90, 5 + logCount * 6));
                    setAnalysisLogs(prev => [...prev, { text: msg.msg, status: 'success' }]);

                } else if (msg.type === 'result') {
                    const data = msg.data;
                    console.log('[ScanFile] SSE result received:', data);
                    setProgress(100);
                    setAnalysisLogs(prev => [
                        ...prev,
                        { text: `✔ Final classification: ${data.prediction_label}`, status: 'success' },
                    ]);
                    setScanResult({
                        confidence: (data.confidence * 100).toFixed(1),
                        is_malicious: data.is_malicious,
                        prediction: data.prediction_label,
                        method: data.detection_method,
                        scan_id: data.scan_id ?? null,
                    });
                    if (data.is_malicious) {
                        setQuarantinedFiles(prev => [...prev, {
                            name: selectedFile.name,
                            date: new Date().toLocaleString(),
                            confidence: (data.confidence * 100).toFixed(1) + '%',
                        }]);
                        // Fetch behavioral patterns if we have a scan_id
                        if (data.scan_id) {
                            console.log('[ScanFile] Fetching behavioral patterns for scan_id:', data.scan_id);
                            fetch(`${API_BASE}/logs/scans/${data.scan_id}?include=behavioral_patterns`, {
                                headers: token ? { 'Authorization': 'Bearer ' + token } : {},
                            })
                                .then(r => r.ok ? r.json() : null)
                                .then(body => {
                                    if (!body?.behavioral_patterns?.length) return;
                                    const raw = body.behavioral_patterns[0].raw_patterns;
                                    if (!raw) return;
                                    // Keep only detected:true entries, max 5
                                    const detected = Object.entries(raw)
                                        .filter(([, v]) => v?.detected === true)
                                        .slice(0, 5)
                                        .map(([key, v]) => ({
                                            label: key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
                                            description: v.description || '',
                                            evidence: Array.isArray(v.evidence) ? v.evidence : [],
                                            confidence: v.confidence || '',
                                        }));
                                    setBehavioralPatterns(detected);
                                })
                                .catch(() => {});
                        }
                    }
                    setScanning(false);
                    es.close();
                    esRef.current = null;
                    if (onScanComplete) onScanComplete();

                } else if (msg.type === 'error') {
                    setAnalysisLogs(prev => [...prev, { text: msg.msg, status: 'error' }]);
                    setProgress(0);
                    setScanning(false);
                    es.close();
                    esRef.current = null;
                }
            };

            es.onerror = () => {
                setAnalysisLogs(prev => [...prev, { text: 'Stream connection lost', status: 'error' }]);
                setScanning(false);
                es.close();
                esRef.current = null;
            };

        } catch (err) {
            console.error('Scan error:', err);
            setAnalysisLogs([{ text: `Scan failed — ${err.message}`, status: 'error' }]);
            setProgress(0);
            setScanning(false);
        }
    }, [onScanComplete]);

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
        if (esRef.current) { esRef.current.close(); esRef.current = null; }
        setScanning(false);
        setProgress(0);
        setAnalysisLogs(prev => [...prev, { text: 'Scan stopped by user', status: 'error' }]);
    };

    const removeQuarantined = (index) => {
        setQuarantinedFiles(prev => prev.filter((_, i) => i !== index));
    };

    // ── Log entry renderer (dark-background aware) ──────────────────────────
    const renderLogEntry = (log, i, compact = true) => {
        const text = log.text || '';
        const fs = compact ? '0.95rem' : '1.05rem';

        // Stage RESULT line — only when score/confidence present
        const stageMatch = text.match(/stage\s*([\d.]+)[^:]*:\s*([A-Z_]+)(?:[^(]*\(([^)]*)\))?/i);
        if (stageMatch) {
            const stageNum  = stageMatch[1];
            const verdict   = stageMatch[2].toUpperCase();
            const extra     = stageMatch[3] || '';
            const scoreM    = extra.match(/score\s*[=:]\s*([\d.]+)/i);
            const confM     = extra.match(/conf(?:idence)?\s*[=:]\s*([\d.]+)/i);
            const score     = scoreM ? parseFloat(scoreM[1]) : null;
            const conf      = confM  ? parseFloat(confM[1])  : null;

            if (score !== null || conf !== null) {
                const isClean = /clean|benign|safe/i.test(verdict);
                const isMal   = /malicious|malware|ransomware/i.test(verdict);
                const accent  = isClean ? '#4ADE80' : isMal ? '#F87171' : '#FCD34D';
                const bg      = isClean ? 'rgba(74,222,128,0.12)' : isMal ? 'rgba(248,113,113,0.12)' : 'rgba(252,211,77,0.12)';
                return (
                    <div key={i} style={{
                        display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '7px',
                        background: bg, borderLeft: `3px solid ${accent}`,
                        borderRadius: '6px', padding: compact ? '8px 12px' : '11px 16px',
                        marginBottom: '3px',
                    }}>
                        <span style={{ fontSize: compact ? '1.05rem' : '1.15rem' }}>
                            {isClean ? '✅' : isMal ? '🚨' : '⚠️'}
                        </span>
                        <span style={{
                            background: '#1E293B', color: '#94A3B8',
                            borderRadius: '4px', padding: '2px 8px',
                            fontSize: '0.80rem', fontWeight: 700, letterSpacing: '0.07em'
                        }}>STAGE {stageNum}</span>
                        <span style={{
                            background: accent, color: '#0F172A',
                            borderRadius: '4px', padding: '2px 10px',
                            fontSize: compact ? '0.88rem' : '0.95rem', fontWeight: 800
                        }}>{verdict}</span>
                        {score !== null && (
                            <span style={{ color: '#94A3B8', fontSize: '0.88rem', fontFamily: 'monospace' }}>score: <strong style={{ color: '#E2E8F0' }}>{score.toFixed(4)}</strong></span>
                        )}
                        {conf !== null && (
                            <span style={{
                                background: 'rgba(255,255,255,0.08)', color: accent,
                                border: `1px solid ${accent}55`, borderRadius: '4px',
                                padding: '2px 8px', fontSize: '0.88rem', fontWeight: 700
                            }}>conf: {(conf * 100).toFixed(1)}%</span>
                        )}
                    </div>
                );
            }
        }

        // Soft voting line
        if (/soft\s*vot/i.test(text)) {
            return (
                <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: '8px',
                    background: 'rgba(139,92,246,0.12)', borderLeft: '3px solid #A78BFA',
                    borderRadius: '6px', padding: compact ? '7px 12px' : '9px 16px', marginBottom: '3px'
                }}>
                    <span style={{ color: '#C4B5FD', fontSize: fs, fontFamily: 'monospace' }}>{text}</span>
                </div>
            );
        }

        // Final classification banner
        if (/final\s*class/i.test(text)) {
            const isMal  = /malicious|malware|ransomware/i.test(text);
            const accent = isMal ? '#F87171' : '#4ADE80';
            return (
                <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: '10px',
                    background: isMal ? 'rgba(248,113,113,0.15)' : 'rgba(74,222,128,0.15)',
                    border: `1.5px solid ${accent}`,
                    borderRadius: '7px', padding: compact ? '10px 14px' : '13px 18px',
                    marginTop: '6px', marginBottom: '2px'
                }}>
                    <span style={{ fontSize: compact ? '1.15rem' : '1.3rem' }}>{isMal ? '🚨' : '✅'}</span>
                    <span style={{ color: accent, fontWeight: 700, fontSize: compact ? '1.0rem' : '1.1rem' }}>{text}</span>
                </div>
            );
        }

        // All other entries — plain text
        return (
            <div key={i} style={{ padding: compact ? '3px 12px' : '4px 14px', marginBottom: '1px' }}>
                <span style={{ color: '#CBD5E1', fontSize: fs, lineHeight: 1.6 }}>{text}</span>
            </div>
        );
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
                                        {analysisLogs.map((log, i) => renderLogEntry(log, i, true))}
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
                            {analysisLogs.map((log, i) => {
                                const entry = (log.status === 'success' && log.text.includes('hash') && fileInfo)
                                    ? { ...log, text: `${log.text} (${fileInfo.hash})` }
                                    : log;
                                return renderLogEntry(entry, i, false);
                            })}

                            {/* Behavioral patterns from DB */}
                            {scanResult?.is_malicious && behavioralPatterns.length > 0 && (
                                <div className="logs-modal-warning-detail">
                                    <div className="logs-modal-entry logs-modal-warning">
                                        <span className="logs-modal-icon">⚠️</span>
                                        <span>Detected behavioral patterns ({behavioralPatterns.length}):</span>
                                    </div>
                                    {behavioralPatterns.map((p, i) => (
                                        <div key={i} className="logs-modal-pattern-item">
                                            <div className="logs-modal-pattern-title">
                                                <code>{p.label}</code>
                                                {p.confidence && <span className="pattern-confidence">{p.confidence}</span>}
                                            </div>
                                            <p className="logs-modal-pattern-desc">{p.description}</p>
                                            {p.evidence.length > 0 && (
                                                <ul className="logs-modal-pattern-list">
                                                    {p.evidence.map((ev, j) => <li key={j}><code>{ev}</code></li>)}
                                                </ul>
                                            )}
                                        </div>
                                    ))}
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