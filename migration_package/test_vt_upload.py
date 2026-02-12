"""
Test VT Upload and Behavioral Enrichment for RansomwareSimulator.exe

This demonstrates the full workflow:
1. Check if file is in VT database
2. Upload if not found (WARNING: FILE BECOMES PUBLIC)
3. Wait for sandbox analysis
4. Re-query for behavioral data
"""

import sys
import time
sys.path.insert(0, 'model_code')

from vt_integration import VirusTotalEnricher
from pe_feature_extractor import PEFeatureExtractor
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    file_path = "C:/Users/User/OneDrive/Test/K/Testing_Code/dist/RansomwareSimulator.exe"
    
    print("\n" + "="*80)
    print("VT Upload & Enrichment Test - RansomwareSimulator.exe")
    print("="*80)
    
    print("\n⚠️  WARNING: Uploading to VT makes the file PUBLIC and permanent!")
    print("⚠️  It will be shared with security researchers and AV vendors!")
    print("⚠️  Only proceed if you understand the implications.\n")
    
    response = input("Upload RansomwareSimulator.exe to VT? (yes/no): ")
    if response.lower() != 'yes':
        print("\n❌ Upload cancelled")
        return
    
    print("\n" + "="*80)
    print("Step 1: Initialize Components")
    print("="*80)
    
    vt = VirusTotalEnricher()
    pe_extractor = PEFeatureExtractor()
    
    print("\n" + "="*80)
    print("Step 2: Check VT (will upload if not found)")
    print("="*80)
    
    vt_result = vt.check_file(file_path, auto_upload=True)
    
    if not vt_result:
        print("\n❌ VT check/upload failed")
        return
    
    if vt_result.get('status') == 'pending_analysis':
        print("\n✓ File uploaded successfully!")
        print(f"   {vt_result.get('message')}")
        print("\n" + "="*80)
        print("Waiting 2 minutes for VT sandbox analysis...")
        print("="*80)
        
        for i in range(120, 0, -10):
            print(f"  {i} seconds remaining...", end='\r')
            time.sleep(10)
        
        print("\n\n" + "="*80)
        print("Step 3: Re-query VT for behavioral data")
        print("="*80)
        
        # Re-query (without auto-upload this time)
        vt_result = vt.check_file(file_path, auto_upload=False)
    
    if not vt_result:
        print("\n❌ VT data still not available - may need more time")
        print("💡 Try running this script again in 5 minutes")
        return
    
    print("\n✓ VT data retrieved!")
    print("\n" + "="*80)
    print("VT Detection Results")
    print("="*80)
    det = vt_result['detection']
    print(f"  Malicious: {det['malicious']}/{det['total']} engines")
    print(f"  Detection rate: {det['ratio']:.1%}")
    
    # Show which AVs detected it
    if 'scans' in vt_result and det['malicious'] > 0:
        print(f"\n  🔍 Detections:")
        scans = vt_result['scans']
        detected_by = []
        for av_name, av_result in scans.items():
            if av_result.get('category') == 'malicious':
                result_name = av_result.get('result', 'unknown')
                detected_by.append(f"    • {av_name}: {result_name}")
        
        for detection in detected_by[:10]:  # Show first 10
            print(detection)
        
        if len(detected_by) > 10:
            print(f"    ... and {len(detected_by) - 10} more")
    
    print("\n" + "="*80)
    print("VT Behavioral Features")
    print("="*80)
    behavior = vt_result['behavior']
    print(f"  Registry writes: {behavior['registry']['write']}")
    print(f"  Registry deletes: {behavior['registry']['delete']}")
    print(f"  Network DNS: {behavior['network']['dns']}")
    print(f"  Network connections: {behavior['network']['connections']}")
    print(f"  Processes created: {behavior['processes']['total']}")
    print(f"  Files modified: {behavior['files']['unknown']}")
    print(f"  DLLs loaded: {behavior['dlls']}")
    
    print("\n" + "="*80)
    print("Step 4: Enrich PE Features with VT Behavioral Data")
    print("="*80)
    
    # Extract PE features WITHOUT VT enrichment
    pe_features_only = pe_extractor.extract(file_path)
    print(f"\n  PE-only features (behavioral all zeros):")
    print(f"    registry_write: {pe_features_only[54]:.0f}")
    print(f"    network_dns: {pe_features_only[58]:.0f}")
    print(f"    processes_total: {pe_features_only[64]:.0f}")
    print(f"    files_unknown: {pe_features_only[68]:.0f}")
    
    # Extract PE features WITH VT enrichment
    enriched_features = pe_extractor.extract_with_vt_enrichment(file_path, vt_result)
    print(f"\n  Enriched features (with VT behavioral data):")
    print(f"    registry_write: {enriched_features[54]:.0f}")
    print(f"    network_dns: {enriched_features[58]:.0f}")
    print(f"    processes_total: {enriched_features[64]:.0f}")
    print(f"    files_unknown: {enriched_features[68]:.0f}")
    
    print("\n" + "="*80)
    print("Summary")
    print("="*80)
    print(f"  ✓ File analyzed by VT sandbox")
    print(f"  ✓ Behavioral features extracted")
    print(f"  ✓ Features ready for ML model prediction")
    print(f"\n  💡 Now the ML model has BOTH static PE structure AND runtime behavior!")
    print(f"     This significantly improves detection accuracy.\n")

if __name__ == "__main__":
    main()
