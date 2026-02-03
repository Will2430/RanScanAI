"""
Direct test of the ML model scanning - bypasses FastAPI to see what's actually happening
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent / 'backend'))

from backend.ml_model import MalwareDetector
import json

print("=" * 70)
print("DIRECT ML MODEL TEST")
print("=" * 70)

# Initialize detector
print("\n1. Loading ML model...")
detector = MalwareDetector()
print(f"   ✓ Model loaded: {detector.model_size_mb:.2f} MB")
print(f"   ✓ Accuracy: {detector.model_accuracy:.2%}")
print(f"   ✓ Features: {detector.n_features}")

# Test files
test_files = [
    "demo_files/benign_document.txt",
    "demo_files/eicar_test.com"
]

for test_file in test_files:
    file_path = Path(__file__).parent / test_file
    
    if not file_path.exists():
        print(f"\n⚠️  File not found: {file_path}")
        continue
    
    print(f"\n{'=' * 70}")
    print(f"SCANNING: {file_path.name}")
    print(f"{'=' * 70}")
    print(f"File size: {file_path.stat().st_size} bytes")
    
    try:
        # Scan the file
        result = detector.scan_file(str(file_path))
        
        # Print results nicely
        print("\n📊 SCAN RESULT:")
        print(json.dumps(result, indent=2))
        
        # Interpretation
        print("\n🔍 INTERPRETATION:")
        if result['is_malicious']:
            print(f"   ⚠️  THREAT DETECTED!")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Verdict: {result['label']}")
        else:
            print(f"   ✅ File appears CLEAN")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Verdict: {result['label']}")
        
        print(f"   Scan time: {result['scan_time_ms']:.2f}ms")
        print(f"   Features analyzed: {result['features_count']}")
        
    except Exception as e:
        print(f"\n❌ SCAN FAILED!")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        
        # Print full traceback
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()

print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)
