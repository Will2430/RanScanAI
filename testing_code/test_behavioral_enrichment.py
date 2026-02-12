"""
Test behavioral enrichment with the model service
Sends RansomwareSimulator.exe + behavioral_data.json to /predict/staged
"""

import requests
import json
from pathlib import Path

# Paths
exe_path = Path(__file__).parent / "dist" / "RansomwareSimulator.exe"
behavioral_json_path = Path(__file__).parent / "behavioral_data.json"

# Load behavioral data
with open(behavioral_json_path, 'r') as f:
    behavioral_data = f.read()

# Load executable
with open(exe_path, 'rb') as f:
    exe_bytes = f.read()

print("="*70)
print("Testing Behavioral Enrichment")
print("="*70)
print(f"Executable: {exe_path.name} ({len(exe_bytes):,} bytes)")
print(f"Behavioral data: {len(behavioral_data):,} chars")

# Parse behavioral stats
vm_data = json.loads(behavioral_data)
print(f"\nBehavioral Summary:")
print(f"  Files encrypted: {len(vm_data.get('files', {}).get('created', []))}")
print(f"  Registry writes: {vm_data.get('registry', {}).get('write', 0)}")
print(f"  Network connections: {vm_data.get('network', {}).get('connections', 0)}")
print(f"  Suspicious activity: {vm_data.get('summary', {}).get('suspicious_activity', False)}")
print("="*70)

# Test 1: PE-only prediction
print("\n[TEST 1] PE Static Analysis ONLY")
print("-"*70)
response1 = requests.post(
    "http://127.0.0.1:8001/predict/staged",
    files={"file": ("RansomwareSimulator.exe", exe_bytes)},
    data={"run_local_scan": "false"}
)

if response1.status_code == 200:
    result1 = response1.json()
    print(f"Result: {result1['prediction_label']}")
    print(f"Confidence: {result1['confidence']:.2%}")
    print(f"Raw Score: {result1['raw_score']:.4f}")
    print(f"Detection Method: {result1['detection_method']}")
    print(f"Suspicious Indicators: {result1.get('suspicious_indicators', 'None')}")
else:
    print(f"ERROR: {response1.status_code} - {response1.text}")

# Test 2: WITH behavioral enrichment
print("\n[TEST 2] PE Static + Behavioral Enrichment")
print("-"*70)

# NOTE: When sending both file and string data, put string in 'data', not 'files'
# But FastAPI expects form fields, so we need to send behavioral_data as a file-like field
import io
response2 = requests.post(
    "http://127.0.0.1:8001/predict/staged",
    files={
        "file": ("RansomwareSimulator.exe", exe_bytes),
    },
    data={
        "behavioral_data": behavioral_data,  # Send as form data, not file
        "run_local_scan": "false"
    }
)

if response2.status_code == 200:
    result2 = response2.json()
    print(f"Result: {result2['prediction_label']}")
    print(f"Confidence: {result2['confidence']:.2%}")
    print(f"Raw Score: {result2['raw_score']:.4f}")
    print(f"Detection Method: {result2['detection_method']}")
    print(f"Behavioral Enriched: {result2.get('behavioral_enriched', False)}")
    print(f"Behavioral Source: {result2.get('behavioral_source', 'None')}")
else:
    print(f"ERROR: {response2.status_code} - {response2.text}")

print("\n" + "="*70)
print("ANALYSIS:")
print("="*70)
if response1.status_code == 200 and response2.status_code == 200:
    r1 = response1.json()
    r2 = response2.json()
    
    print(f"PE-only prediction: {r1['raw_score']:.4f} ({r1['prediction_label']})")
    print(f"With behavioral:    {r2['raw_score']:.4f} ({r2['prediction_label']})")
    
    if r1['raw_score'] == r2['raw_score']:
        print("\n⚠️  BEHAVIORAL ENRICHMENT HAD NO EFFECT!")
        print("    This indicates the model is dominated by PE static features.")
    else:
        delta = r2['raw_score'] - r1['raw_score']
        print(f"\n✓ Behavioral enrichment changed score by {delta:+.4f}")
        if delta > 0:
            print("    Behavioral features INCREASED maliciousness score")
        else:
            print("    Behavioral features DECREASED maliciousness score (unexpected!)")
            
print("="*70)
