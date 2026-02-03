import sys
import os

# Add parent directory to path if needed
sys.path.insert(0, os.path.dirname(__file__))

from feature_extractor import FeatureExtractor

def test_feature_extractor():
    """Test the FeatureExtractor class"""
    
    # First, create a sample static_features.txt if it doesn't exist
    features_file = 'static_features.txt'
    if not os.path.exists(features_file):
        print("Creating sample static_features.txt...")
        with open(features_file, 'w') as f:
            f.write('\n'.join([
                'file_size',
                'SizeOfCode',
                'NumberOfSections',
                'SizeOfHeaders',
                'ImageBase',
                'SectionAlignment',
                'FileAlignment',
                'MajorImageVersion',
                'MinorImageVersion',
                'MajorOSVersion',
                'MinorOSVersion',
                'NumberOfRvaAndSizes',
                'SizeOfStackReserve',
                'SizeOfStackCommit',
                'SizeOfHeapReserve',
                'section_count',
                'section_entropy',
                'import_count'
            ]))
    
    # Initialize extractor
    print("\n=== Initializing FeatureExtractor ===")
    extractor = FeatureExtractor(features_file)
    
    # Test with a Windows system executable
    test_file = r'C:\Users\User\Downloads\Antigravity.exe'
    
    if not os.path.exists(test_file):
        print(f"\nTest file not found: {test_file}")
        print("Please provide a path to a PE file:")
        test_file = input("> ").strip()
    
    if os.path.exists(test_file):
        print(f"\n=== Extracting features from: {test_file} ===")
        
        # Test extract() method - returns dict
        features_dict = extractor.extract(test_file)
        print("\nFeatures (dict):")
        for name, value in features_dict.items():
            print(f"  {name}: {value}")
        
        # Test extract_as_vector() method - returns list
        feature_vector = extractor.extract_as_vector(test_file)
        print(f"\nFeature vector (list): {feature_vector}")
        print(f"Vector length: {len(feature_vector)}")
    else:
        print("No valid test file provided.")

if __name__ == '__main__':
    test_feature_extractor()
