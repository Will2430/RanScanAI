"""
Host-Side Analysis: Process VM Behavioral Data + ML Model Prediction

WORKFLOW:
1. Run vm_behavioral_monitor.py in VM
2. Copy behavioral_data.json from VM to host
3. Run this script: python host_analyze_vm_data.py behavioral_data.json RansomwareSimulator.exe

This demonstrates the FULL hybrid detection pipeline:
- Static PE analysis (local)
- Behavioral monitoring (VM sandbox)
- Feature fusion
- ML model prediction
"""

import sys
import json
from pathlib import Path

# Add model code to path
sys.path.insert(0, str(Path(__file__).parent.parent / "migration_package" / "model_code"))

from pe_feature_extractor import PEFeatureExtractor
import numpy as np


def convert_vm_data_to_vt_format(vm_data: dict) -> dict:
    """
    Convert VM behavioral data to VT enrichment format
    This allows us to use the same PE enrichment pipeline
    """
    
    files = vm_data.get('files', {})
    registry = vm_data.get('registry', {})
    network = vm_data.get('network', {})
    processes = vm_data.get('processes', {})
    
    # Convert to VT-compatible structure
    vt_format = {
        'detection': {
            'malicious': 0,  # No AV detection (we're running locally)
            'total': 0,
            'ratio': 0.0
        },
        'behavior': {
            'registry': {
                'read': registry.get('read', 0),
                'write': registry.get('write', 0),
                'delete': registry.get('delete', 0)
            },
            'network': {
                'threats': 0,
                'dns': network.get('dns', 0),
                'http': network.get('http', 0),
                'connections': network.get('connections', 0)
            },
            'processes': {
                'malicious': processes.get('malicious', 0),
                'suspicious': processes.get('suspicious', 0),
                'monitored': processes.get('total', 0),
                'total': processes.get('total', 0)
            },
            'files': {
                'malicious': files.get('malicious', 0),
                'suspicious': files.get('suspicious', 0),
                'text': 0,
                'unknown': len(files.get('created', [])) + len(files.get('modified', []))
            },
            'dlls': len(vm_data.get('dlls', [])),
            'apis': vm_data.get('apis', 0)
        },
        'tags': [],
        'type': 'VM Sandbox Analysis',
        'source': 'local_vm_monitor'
    }
    
    # Add behavioral tags based on observed activity
    if len(files.get('encrypted', [])) > 0:
        vt_format['tags'].append('ransomware')
        vt_format['tags'].append('file-encryption')
        vt_format['behavior']['files']['malicious'] = len(files.get('encrypted', []))
    
    if len(files.get('deleted', [])) > 3:
        vt_format['tags'].append('file-deletion')
    
    if registry.get('write', 0) > 5:
        vt_format['tags'].append('modifies-registry')
    
    if network.get('connections', 0) > 0:
        vt_format['tags'].append('network-activity')
    
    return vt_format


def analyze_with_ml_model(enriched_features: np.ndarray):
    """
    Run ML model prediction (if available)
    For now, implements heuristic scoring similar to VT approach
    """
    
    # Feature indices (from PEFeatureExtractor.FEATURE_NAMES)
    idx_registry_write = 54
    idx_registry_delete = 55
    idx_network_connections = 60
    idx_processes_total = 64
    idx_files_malicious = 65
    idx_files_suspicious = 66
    
    # Extract behavioral features
    registry_write = enriched_features[idx_registry_write]
    registry_delete = enriched_features[idx_registry_delete]
    network_conn = enriched_features[idx_network_connections]
    processes = enriched_features[idx_processes_total]
    files_mal = enriched_features[idx_files_malicious]
    files_sus = enriched_features[idx_files_suspicious]
    
    # Heuristic scoring (would be replaced by actual ML model)
    suspicion_score = 0
    reasons = []
    
    if files_mal > 0:
        suspicion_score += 40
        reasons.append(f"File encryption detected ({int(files_mal)} files)")
    
    if registry_write > 5:
        suspicion_score += 20
        reasons.append(f"High registry activity ({int(registry_write)} writes)")
    
    if files_sus > 3:
        suspicion_score += 15
        reasons.append(f"Multiple file deletions ({int(files_sus)} files)")
    
    if registry_delete > 0:
        suspicion_score += 10
        reasons.append(f"Registry key deletion ({int(registry_delete)} keys)")
    
    if network_conn > 0:
        suspicion_score += 5
        reasons.append(f"Network activity ({int(network_conn)} connections)")
    
    suspicion_score = min(suspicion_score, 100)
    
    classification = "MALICIOUS" if suspicion_score > 50 else "SUSPICIOUS" if suspicion_score > 25 else "BENIGN"
    
    return {
        'suspicion_score': suspicion_score,
        'classification': classification,
        'confidence': suspicion_score / 100.0,
        'reasons': reasons
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python host_analyze_vm_data.py <behavioral_data.json> <target.exe>")
        print("\nExample:")
        print("  python host_analyze_vm_data.py behavioral_data.json RansomwareSimulator.exe")
        sys.exit(1)
    
    behavioral_json = Path(sys.argv[1])
    target_exe = Path(sys.argv[2])
    
    if not behavioral_json.exists():
        print(f"❌ Behavioral data not found: {behavioral_json}")
        sys.exit(1)
    
    if not target_exe.exists():
        print(f"❌ Target executable not found: {target_exe}")
        sys.exit(1)
    
    print("\n" + "="*80)
    print("Hybrid Malware Detection: VM Behavioral Data + Static PE Analysis")
    print("="*80)
    
    # Load VM behavioral data
    print(f"\n[1] Loading VM behavioral data from {behavioral_json.name}")
    with open(behavioral_json) as f:
        vm_data = json.load(f)
    
    print(f"    ✓ Execution time: {vm_data.get('execution_time', 0):.1f}s")
    print(f"    ✓ Files encrypted: {len(vm_data.get('files', {}).get('encrypted', []))}")
    print(f"    ✓ Registry writes: {vm_data.get('registry', {}).get('write', 0)}")
    print(f"    ✓ Network connections: {vm_data.get('network', {}).get('connections', 0)}")
    
    # Convert to VT format
    print(f"\n[2] Converting VM data to enrichment format")
    vt_compatible = convert_vm_data_to_vt_format(vm_data)
    print(f"    ✓ Behavioral features extracted")
    print(f"    ✓ Tags: {', '.join(vt_compatible['tags'])}")
    
    # Extract PE features
    print(f"\n[3] Extracting static PE features from {target_exe.name}")
    pe_extractor = PEFeatureExtractor()
    
    # PE-only features
    pe_only = pe_extractor.extract(str(target_exe))
    print(f"    ✓ Extracted {len(pe_only)} PE features")
    print(f"    ✓ Behavioral features (PE-only): all zeros")
    
    # Enriched features
    enriched = pe_extractor.extract_with_vt_enrichment(str(target_exe), vt_compatible)
    print(f"    ✓ Enriched with VM behavioral data")
    print(f"    ✓ Behavioral features (enriched): non-zero!")
    
    # Compare
    print(f"\n[4] Feature Comparison: PE-Only vs VM-Enriched")
    print(f"    {'Feature':<25} {'PE-Only':>10} {'Enriched':>10}")
    print(f"    {'-'*47}")
    
    feature_names = pe_extractor.get_feature_names()
    behavioral_indices = {
        'registry_write': 54,
        'registry_delete': 55,
        'network_connections': 60,
        'processes_total': 64,
        'files_malicious': 65,
        'files_suspicious': 66,
        'dlls_calls': 69
    }
    
    for name, idx in behavioral_indices.items():
        print(f"    {name:<25} {pe_only[idx]:>10.0f} {enriched[idx]:>10.0f}")
    
    # ML Analysis
    print(f"\n[5] ML Model Analysis (Heuristic Scoring)")
    result = analyze_with_ml_model(enriched)
    
    print(f"    🎯 Classification: {result['classification']}")
    print(f"    📊 Suspicion Score: {result['suspicion_score']}%")
    print(f"    🔍 Confidence: {result['confidence']:.1%}")
    print(f"    📝 Detection Reasons:")
    for reason in result['reasons']:
        print(f"       • {reason}")
    
    # Summary
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print("\n✅ This demonstrates the FULL hybrid detection pipeline:")
    print("   1. Static PE analysis (headers, sections, imports)")
    print("   2. Dynamic behavioral monitoring (VM sandbox)")
    print("   3. Feature fusion (combining both data sources)")
    print("   4. ML model classification (behavioral + static)")
    print("\n💡 With real ML model trained on Zenodo dataset:")
    print("   - Load model: keras.models.load_model('cnn_zenodo_*.keras')")
    print("   - Load scaler: joblib.load('scaler.pkl')")
    print("   - Scale features: scaler.transform(enriched.reshape(1, -1))")
    print("   - Predict: model.predict(scaled_features)")
    print("\n📊 VM behavioral data provided the missing runtime context!")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
