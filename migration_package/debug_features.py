"""
Debug script to see ALL extracted features and identify outliers
"""

import sys
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "model_code"))

from pe_feature_extractor import PEFeatureExtractor

def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_features.py <exe_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print(f"\n{'='*80}")
    print(f"Extracting ALL features from: {Path(file_path).name}")
    print(f"{'='*80}\n")
    
    extractor = PEFeatureExtractor()
    features = extractor.extract(file_path)
    
    if features is None:
        print("❌ Failed to extract features")
        sys.exit(1)
    
    print(f"Total features: {len(features)}\n")
    
    # Show all features with their names
    feature_names = extractor.get_feature_names()
    
    print(f"{'Index':<6} {'Name':<35} {'Value':>20}")
    print(f"{'-'*65}")
    
    for i, (name, value) in enumerate(zip(feature_names, features)):
        # Highlight large values
        marker = " ⚠️" if value > 1000000 else ""
        print(f"{i:<6} {name:<35} {value:>20,.2f}{marker}")
    
    print(f"\n{'='*80}")
    print(f"Statistics:")
    print(f"  Min: {features.min():,.2f}")
    print(f"  Max: {features.max():,.2f}")
    print(f"  Mean: {features.mean():,.2f}")
    print(f"  Std: {features.std():,.2f}")
    print(f"{'='*80}\n")
    
    # Find features > 1 million
    large_features = [(i, feature_names[i], features[i]) for i in range(len(features)) if features[i] > 1000000]
    
    if large_features:
        print(f"\n⚠️  Features with values > 1 million (potential outliers):")
        for idx, name, val in large_features:
            print(f"  [{idx}] {name}: {val:,.0f}")
    
    print("\n")

if __name__ == "__main__":
    main()
