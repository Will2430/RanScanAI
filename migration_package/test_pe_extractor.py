"""
Test PE Feature Extractor
Quick test to see what features are extracted
"""

import sys
import numpy as np
from pathlib import Path

# Add model_code to path
sys.path.insert(0, str(Path(__file__).parent / 'model_code'))

from pe_feature_extractor import PEFeatureExtractor

def test_extraction(file_path):
    """Test PE feature extraction on a file"""
    
    print("\n" + "="*70)
    print("PE Feature Extractor Test")
    print("="*70)
    
    # Initialize extractor
    extractor = PEFeatureExtractor()
    print(f"\n✓ Extractor initialized")
    print(f"  Total features: {extractor.n_features}")
    print(f"  Feature names: {len(extractor.FEATURE_NAMES)}")
    
    # Check file exists
    file_path = Path(file_path)
    if not file_path.exists():
        print(f"\n✗ File not found: {file_path}")
        return
    
    print(f"\n📂 Extracting features from: {file_path.name}")
    print(f"   File size: {file_path.stat().st_size:,} bytes")
    
    # Extract features
    features = extractor.extract(file_path)
    
    if features is None:
        print("\n✗ Feature extraction failed!")
        return
    
    print(f"\n✓ Features extracted successfully!")
    print(f"  Feature array shape: {features.shape}")
    print(f"  Feature count: {len(features)}")
    print(f"  Data type: {features.dtype}")
    print(f"  Value range: [{features.min():.2f}, {features.max():.2f}]")
    
    # Show first 20 features
    print(f"\n📊 First 20 Features:")
    print(f"{'Index':<6} {'Name':<35} {'Value':<15}")
    print("-" * 60)
    for i in range(min(20, len(features))):
        name = extractor.FEATURE_NAMES[i] if i < len(extractor.FEATURE_NAMES) else "Unknown"
        value = features[i]
        print(f"{i:<6} {name:<35} {value:<15.2f}")
    
    # Show last 20 features (behavioral - should be zeros)
    if len(features) > 20:
        print(f"\n📊 Last 20 Features (Behavioral - should be 0):")
        print(f"{'Index':<6} {'Name':<35} {'Value':<15}")
        print("-" * 60)
        start_idx = len(features) - 20
        for i in range(start_idx, len(features)):
            name = extractor.FEATURE_NAMES[i] if i < len(extractor.FEATURE_NAMES) else "Unknown"
            value = features[i]
            print(f"{i:<6} {name:<35} {value:<15.2f}")
    
    # Statistics by category
    print(f"\n📈 Feature Statistics:")
    
    # DOS Header (0-16)
    dos_features = features[:17]
    print(f"  DOS Header (0-16):        min={dos_features.min():.2f}, max={dos_features.max():.2f}, mean={dos_features.mean():.2f}")
    
    # PE Header (17-38)
    pe_features = features[17:39]
    print(f"  PE Header (17-38):        min={pe_features.min():.2f}, max={pe_features.max():.2f}, mean={pe_features.mean():.2f}")
    
    # .text section (39-45)
    if len(features) > 45:
        text_features = features[39:46]
        print(f"  .text Section (39-45):    min={text_features.min():.2f}, max={text_features.max():.2f}, mean={text_features.mean():.2f}")
    
    # .rdata section (46-52)
    if len(features) > 52:
        rdata_features = features[46:53]
        print(f"  .rdata Section (46-52):   min={rdata_features.min():.2f}, max={rdata_features.max():.2f}, mean={rdata_features.mean():.2f}")
    
    # Behavioral (53+)
    if len(features) > 53:
        behavioral_features = features[53:]
        non_zero = np.count_nonzero(behavioral_features)
        print(f"  Behavioral (53+):         all zeros={non_zero == 0}, non-zero count={non_zero}")
    
    print("\n" + "="*70)
    print("Feature extraction complete!")
    print("="*70 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Use provided file path
        test_file = sys.argv[1]
    else:
        # Try common test files
        test_candidates = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe",
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        ]
        
        test_file = None
        for candidate in test_candidates:
            if Path(candidate).exists():
                test_file = candidate
                break
        
        if test_file is None:
            print("Usage: python test_pe_extractor.py <path_to_exe>")
            print("\nOr provide path to any .exe file to analyze")
            print("\nExample:")
            print("  python test_pe_extractor.py C:\\Windows\\System32\\notepad.exe")
            sys.exit(1)
    
    test_extraction(test_file)
