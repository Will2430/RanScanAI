"""
PE Header Manipulation Script
Modifies PE headers of compiled executable to match malicious characteristics
WARNING: This is for educational/testing purposes only
"""

import os
import sys
import struct
from pathlib import Path

def read_pe_headers(exe_path):
    """Read and display PE headers from executable"""
    print(f"\n[INFO] Reading PE headers from: {exe_path}")
    
    try:
        with open(exe_path, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            
            # Check MZ signature
            if dos_header[:2] != b'MZ':
                print("[ERROR] Not a valid PE file (missing MZ signature)")
                return None
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            
            # Read PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            
            if pe_sig != b'PE\x00\x00':
                print("[ERROR] Not a valid PE file (missing PE signature)")
                return None
            
            # Read COFF header (20 bytes)
            coff_header = f.read(20)
            
            # Parse COFF header
            machine = struct.unpack('<H', coff_header[0:2])[0]
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            timestamp = struct.unpack('<I', coff_header[4:8])[0]
            ptr_symbol_table = struct.unpack('<I', coff_header[8:12])[0]
            num_symbols = struct.unpack('<I', coff_header[12:16])[0]
            size_optional_header = struct.unpack('<H', coff_header[16:18])[0]
            characteristics = struct.unpack('<H', coff_header[18:20])[0]
            
            print("\n[PE HEADERS]")
            print("="*60)
            print(f"Machine Type: {hex(machine)} ({'Intel 386' if machine == 0x14c else 'Unknown'})")
            print(f"Number of Sections: {num_sections}")
            print(f"Timestamp: {hex(timestamp)}")
            print(f"Characteristics: {hex(characteristics)}")
            print(f"Size of Optional Header: {size_optional_header}")
            
            # Read Optional header (first 96 bytes for PE32)
            optional_header = f.read(96)
            
            # Parse optional header
            magic = struct.unpack('<H', optional_header[0:2])[0]
            major_linker = optional_header[2]
            minor_linker = optional_header[3]
            size_of_code = struct.unpack('<I', optional_header[4:8])[0]
            size_of_init_data = struct.unpack('<I', optional_header[8:12])[0]
            size_of_uninit_data = struct.unpack('<I', optional_header[12:16])[0]
            entry_point = struct.unpack('<I', optional_header[16:20])[0]
            base_of_code = struct.unpack('<I', optional_header[20:24])[0]
            
            if magic == 0x10b:  # PE32
                base_of_data = struct.unpack('<I', optional_header[24:28])[0]
                image_base = struct.unpack('<I', optional_header[28:32])[0]
            else:  # PE32+
                image_base = struct.unpack('<Q', optional_header[24:32])[0]
            
            section_alignment = struct.unpack('<I', optional_header[32:36])[0]
            file_alignment = struct.unpack('<I', optional_header[36:40])[0]
            
            print(f"\n[OPTIONAL HEADER]")
            print(f"Magic: {hex(magic)} ({'PE32' if magic == 0x10b else 'PE32+'})")
            print(f"Linker Version: {major_linker}.{minor_linker}")
            print(f"Size of Code: {size_of_code} bytes")
            print(f"Size of Initialized Data: {size_of_init_data} bytes")
            print(f"Entry Point: {hex(entry_point)}")
            print(f"Base of Code: {hex(base_of_code)}")
            print(f"Image Base: {hex(image_base)}")
            print(f"Section Alignment: {section_alignment}")
            print(f"File Alignment: {file_alignment}")
            
            # Read sections
            f.seek(pe_offset + 24 + size_optional_header)
            
            print(f"\n[SECTIONS] ({num_sections} sections)")
            print("="*60)
            
            sections = []
            for i in range(num_sections):
                section_header = f.read(40)
                
                name = section_header[0:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', section_header[8:12])[0]
                virtual_address = struct.unpack('<I', section_header[12:16])[0]
                size_of_raw_data = struct.unpack('<I', section_header[16:20])[0]
                ptr_raw_data = struct.unpack('<I', section_header[20:24])[0]
                characteristics = struct.unpack('<I', section_header[36:40])[0]
                
                print(f"\nSection {i+1}: {name}")
                print(f"  Virtual Size: {virtual_size}")
                print(f"  Virtual Address: {hex(virtual_address)}")
                print(f"  Size of Raw Data: {size_of_raw_data}")
                print(f"  Ptr to Raw Data: {hex(ptr_raw_data)}")
                print(f"  Characteristics: {hex(characteristics)}")
                
                sections.append({
                    'name': name,
                    'virtual_size': virtual_size,
                    'virtual_address': virtual_address,
                    'size_of_raw_data': size_of_raw_data,
                    'ptr_raw_data': ptr_raw_data,
                    'characteristics': characteristics
                })
            
            print("="*60)
            
            return {
                'pe_offset': pe_offset,
                'machine': machine,
                'num_sections': num_sections,
                'characteristics': characteristics,
                'size_of_code': size_of_code,
                'entry_point': entry_point,
                'sections': sections
            }
            
    except Exception as e:
        print(f"[ERROR] Failed to read PE headers: {e}")
        import traceback
        traceback.print_exc()
        return None


def analyze_entropy(exe_path):
    """Calculate entropy of executable (high entropy = packed/encrypted)"""
    import math
    from collections import Counter
    
    print(f"\n[INFO] Analyzing entropy of: {exe_path}")
    
    try:
        with open(exe_path, 'rb') as f:
            data = f.read()
        
        # Calculate overall entropy
        byte_counts = Counter(data)
        entropy = 0
        total_bytes = len(data)
        
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
        
        print(f"[ENTROPY] Overall entropy: {entropy:.4f} (max: 8.0)")
        
        # Interpretation
        if entropy > 7.0:
            print(f"[ENTROPY] HIGH - Likely packed/encrypted (SUSPICIOUS)")
        elif entropy > 6.0:
            print(f"[ENTROPY] MODERATE - May be compressed")
        else:
            print(f"[ENTROPY] LOW - Normal executable")
        
        return entropy
        
    except Exception as e:
        print(f"[ERROR] Failed to calculate entropy: {e}")
        return None


def add_suspicious_resources(exe_path):
    """
    Add suspicious resources to executable
    Note: This is a simplified approach - full resource editing requires专门tools
    """
    print(f"\n[INFO] Adding suspicious metadata...")
    print(f"[WARNING] This is a placeholder - full PE modification requires pefile library")
    print(f"[INFO] Install pefile: pip install pefile")
    
    try:
        import pefile
        
        pe = pefile.PE(exe_path)
        
        # Display current characteristics
        print(f"\n[CURRENT CHARACTERISTICS]")
        print(f"DLL Characteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")
        print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
        
        # You could modify characteristics here
        # Example: pe.OPTIONAL_HEADER.DllCharacteristics = 0x8140
        # But we'll keep it safe for now
        
        print(f"\n[INFO] PE loaded successfully with pefile")
        print(f"[INFO] You can now modify PE characteristics as needed")
        
        pe.close()
        
    except ImportError:
        print(f"[INFO] pefile not installed - install with: pip install pefile")
        print(f"[INFO] For now, proceeding without PE modifications")
    except Exception as e:
        print(f"[ERROR] Failed to modify PE: {e}")


def create_feature_extraction_test(exe_path):
    """
    Create a test script to extract features from the compiled executable
    This matches the features your model expects
    """
    print(f"\n[INFO] Creating feature extraction test script...")
    
    test_script = Path(__file__).parent / "test_exe_features.py"
    
    test_code = f'''"""
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
    print(f"Extracting features from: {{exe_path}}")
    
    # Try to import your feature extractor
    try:
        from feature_extractor import extract_pe_features
        features = extract_pe_features(exe_path)
        print(f"\\nExtracted {{len(features)}} features")
        return features
    except ImportError:
        print("WARNING: Could not import feature_extractor")
        print("Performing basic analysis instead...")
        
        # Basic PE analysis
        import pefile
        pe = pefile.PE(exe_path)
        
        features = {{}}
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
    print("\\n" + "="*60)
    print("TESTING WITH ML MODEL")
    print("="*60)
    
    # Extract PE features
    features = extract_features_from_exe(exe_path)
    
    # Load behavioral data if available
    behavioral_data = None
    if behavioral_data_path and Path(behavioral_data_path).exists():
        with open(behavioral_data_path, 'r') as f:
            behavioral_data = json.load(f)
        print(f"\\nLoaded behavioral data from: {{behavioral_data_path}}")
    
    # Try to use your model
    try:
        # Import your model service client
        sys.path.insert(0, str(Path(__file__).parent.parent / "Testing_Code"))
        from test_behavioral_enrichment import test_file_with_behavioral
        
        # Test with model
        result = test_file_with_behavioral(str(exe_path), behavioral_data)
        
        print("\\n" + "="*60)
        print("DETECTION RESULT")
        print("="*60)
        print(f"Prediction: {{result['prediction']}}")
        print(f"Confidence: {{result.get('confidence', 'N/A')}}")
        print(f"Is Malicious: {{result.get('is_malicious', 'N/A')}}")
        print("="*60)
        
        return result
        
    except Exception as e:
        print(f"\\nCould not test with model: {{e}}")
        print("\\nPlease manually test the executable with your model.")
        print(f"Executable path: {{exe_path}}")
        
        if features:
            print("\\nExtracted features:")
            for key, value in list(features.items())[:20]:
                print(f"  {{key}}: {{value}}")


if __name__ == "__main__":
    exe_path = Path(__file__).parent / "dist" / "System_Update.exe"
    behavioral_json = Path(__file__).parent / "behavioral_data.json"
    
    if not exe_path.exists():
        print(f"ERROR: Executable not found at {{exe_path}}")
        print("Please build it first using: python build_malicious_exe.py")
        sys.exit(1)
    
    test_with_model(exe_path, behavioral_json)
'''
    
    try:
        test_script.write_text(test_code)
        print(f"Created test script: {test_script}")
        return test_script
    except Exception as e:
        print(f"Failed to create test script: {e}")
        return None


def main():
    print("="*60)
    print("PE HEADER ANALYSIS & MANIPULATION")
    print("="*60)
    
    # Check for executable
    exe_path = Path(__file__).parent / "dist" / "System_Update.exe"
    
    if not exe_path.exists():
        print(f"\n[ERROR] Executable not found: {exe_path}")
        print(f"[INFO] Please build it first using: python build_malicious_exe.py")
        return
    
    print(f"\nTarget executable: {exe_path}")
    print(f"File size: {exe_path.stat().st_size:,} bytes")
    
    # Read and display PE headers
    headers = read_pe_headers(exe_path)
    
    if headers:
        # Analyze entropy
        entropy = analyze_entropy(exe_path)
        
        # Add suspicious resources (placeholder)
        add_suspicious_resources(exe_path)
        
        # Create test script
        test_script = create_feature_extraction_test(exe_path)
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print(f"\nNext steps:")
        print(f"  1. Run test script: python {test_script.name if test_script else 'test_exe_features.py'}")
        print(f"  2. Verify features match malicious patterns")
        print(f"  3. Test with your ML model")
        print(f"  4. Check detection confidence")
        print("="*60)


if __name__ == "__main__":
    main()
