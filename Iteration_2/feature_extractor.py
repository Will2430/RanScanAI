import pefile
import os
import math

class FeatureExtractor:
    """
    Extracts static features from PE files (Windows executables)
    """
    
    def __init__(self, feature_names_file='static_features.txt'):
        # Load feature names from training
        with open(feature_names_file, 'r') as f:
            self.feature_names = [line.strip() for line in f]
        
        print(f"Loaded {len(self.feature_names)} feature definitions")
    
    def extract(self, file_path):
        """
        Extract all features from a PE file
        
        Returns:
            dict: Feature name -> value mapping
        """
        features = {}
        
        try:
            # Parse PE file
            pe = pefile.PE(file_path)
            
            # Extract each feature
            features['file_size'] = os.path.getsize(file_path)
            features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
            features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
            features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
            features['MajorOSVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['MinorOSVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            
            # Add more advanced features
            features['section_count'] = len(pe.sections)
            features['section_entropy'] = self._calculate_entropy(pe)
            features['import_count'] = self._count_imports(pe)
            
            pe.close()
            
        except Exception as e:
            print(f"Error parsing PE file: {e}")
            # Return zeros if file can't be parsed (might be packed/corrupted)
            features = {name: 0 for name in self.feature_names}
        
        return features
    
    def extract_as_vector(self, file_path):
        """
        Extract features and return as ordered list (for model input)
        
        Returns:
            list: Feature values in same order as training
        """
        features_dict = self.extract(file_path)
        
        # CRITICAL: Maintain exact order from training!
        feature_vector = [features_dict.get(name, 0) for name in self.feature_names]
        
        return feature_vector
    
    def _calculate_entropy(self, pe):
        """
        Calculate average entropy across all sections
        High entropy (>7.0) often indicates packed/encrypted malware
        """
        if not pe.sections:
            return 0.0
        
        total_entropy = 0
        for section in pe.sections:
            data = section.get_data()
            if len(data) == 0:
                continue
            
            # Calculate Shannon entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
            
            total_entropy += entropy
        
        return total_entropy / len(pe.sections)
    
    def _count_imports(self, pe):
        """
        Count number of imported functions
        Malware often has unusual import patterns
        """
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return 0
        
        import_count = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            import_count += len(entry.imports)
        
        return import_count
