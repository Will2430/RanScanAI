"""
Quick test of VT free tier behavioral fallback
"""

import sys
sys.path.insert(0, 'model_code')

from vt_integration import VirusTotalEnricher
from pe_feature_extractor import PEFeatureExtractor
import logging

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')

file_path = "C:/Users/User/OneDrive/Test/K/Testing_Code/dist/RansomwareSimulator.exe"

print("\n" + "="*80)
print("Testing VT Free Tier Behavioral Fallback")
print("="*80)

vt = VirusTotalEnricher()
pe_extractor = PEFeatureExtractor()

# Query VT (file already uploaded)
print("\nQuerying VT for RansomwareSimulator.exe...")
vt_result = vt.check_file(file_path, auto_upload=False)

if not vt_result:
    print("❌ File not found in VT - run test_vt_upload.py first")
    sys.exit(1)

print("\n" + "="*80)
print("VT Detection Results")
print("="*80)
det = vt_result['detection']
print(f"Malicious: {det['malicious']}/{det['total']} engines ({det['ratio']:.1%})")

print("\n" + "="*80)
print("VT Behavioral Features (Free Tier Heuristic)")
print("="*80)
behavior = vt_result['behavior']
print(f"Registry writes:      {behavior['registry']['write']}")
print(f"Files suspicious:     {behavior['files']['suspicious']}")
print(f"Processes suspicious: {behavior['processes']['suspicious']}")
print(f"Network connections:  {behavior['network']['connections']}")
print(f"DLLs:                 {behavior['dlls']}")

print("\nTags:", vt_result.get('tags', [])[:10])

print("\n" + "="*80)
print("Enriched PE Features")
print("="*80)

# PE features WITHOUT VT
pe_only = pe_extractor.extract(file_path)
print(f"\nPE-only (no behavioral data):")
print(f"  files_suspicious: {pe_only[66]:.0f}")
print(f"  registry_write: {pe_only[54]:.0f}")

# PE features WITH VT enrichment
enriched = pe_extractor.extract_with_vt_enrichment(file_path, vt_result)
print(f"\nEnriched with VT heuristic:")
print(f"  files_suspicious: {enriched[66]:.0f}")
print(f"  registry_write: {enriched[54]:.0f}")

print("\n✓ Free tier uses detection ratio + tags to estimate behavioral features")
print("💡 Premium API would provide actual sandbox execution traces\n")
