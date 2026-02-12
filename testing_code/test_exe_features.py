"""
Test feature extraction from compiled malicious executable
Extracts PE features to match your model's expected input
"""

import os
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "migration_package"))

def extract_features_from_exe(exe_path):
    """Extract features from the compiled executable"""
    print(f"Extracting features from: {exe_path}")
    
    # Try to import your feature extractor
    try:
        from feature_extractor import extract_pe_features
        features = extract_pe_features(exe_path)
        print(f"\nExtracted {len(features)} features")
        return features
    except ImportError:
        print("WARNING: Could not import feature_extractor")
        print("Performing basic analysis instead...")
        
        # Basic PE analysis
        import pefile
        pe = pefile.PE(exe_path)
        
        features = {}
        features['machine'] = pe.FILE_HEADER.Machine
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        
        pe.close()
        
        return features


def test_with_model(exe_path, behavioral_data_path=None):
    """Test the executable with your ML model"""
    print("\n" + "="*60)
    print("TESTING WITH ML MODEL")
    print("="*60)
    
    # Extract PE features
    features = extract_features_from_exe(exe_path)
    
    # Load behavioral data if available
    behavioral_data = None
    if behavioral_data_path and Path(behavioral_data_path).exists():
        with open(behavioral_data_path, 'r') as f:
            behavioral_data = json.load(f)
        print(f"\nLoaded behavioral data from: {behavioral_data_path}")
    
    # Try to use your model
    try:
        # Import your model service client
        sys.path.insert(0, str(Path(__file__).parent.parent / "Testing_Code"))
        from test_behavioral_enrichment import test_file_with_behavioral
        
        # Test with model
        result = test_file_with_behavioral(str(exe_path), behavioral_data)
        
        print("\n" + "="*60)
        print("DETECTION RESULT")
        print("="*60)
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result.get('confidence', 'N/A')}")
        print(f"Is Malicious: {result.get('is_malicious', 'N/A')}")
        print("="*60)
        
        return result
        
    except Exception as e:
        print(f"\nCould not test with model: {e}")
        print("\nPlease manually test the executable with your model.")
        print(f"Executable path: {exe_path}")
        
        if features:
            print("\nExtracted features:")
            for key, value in list(features.items())[:20]:
                print(f"  {key}: {value}")


if __name__ == "__main__":
    exe_path = Path(__file__).parent / "dist" / "System_Update.exe"
    behavioral_json = Path(__file__).parent / "behavioral_data.json"
    
    if not exe_path.exists():
        print(f"ERROR: Executable not found at {exe_path}")
        print("Please build it first using: python build_malicious_exe.py")
        sys.exit(1)
    
    test_with_model(exe_path, behavioral_json)
