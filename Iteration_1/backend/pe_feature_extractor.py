"""
PE Feature Extractor for CNN Model
Extracts 78 features matching Zenodo dataset structure
"""

import pefile
import numpy as np
import logging
from pathlib import Path
from typing import Optional, Dict, List, Union

logger = logging.getLogger(__name__)


class PEFeatureExtractor:
    """
    Extract PE features matching Zenodo dataset columns
    Extracts static PE features (headers, sections) - NOT behavioral features
    Behavioral features (registry, network, processes) come from VT API
    """
    
    @staticmethod
    def _count_flags(bitmask: int) -> int:
        """
        Count number of set bits in bitmask (number of flags enabled)
        
        CRITICAL: Zenodo dataset has Characteristics as string lists like:
        "['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE']"
        Training script converts these to COUNT (2 in this example)
        
        PE files return RAW bitmask (e.g., 0x60000020 = 1610612768)
        If we use raw values, scaler produces astronomical values → model 100% confident
        
        Args:
            bitmask: PE characteristic bitmask value
            
        Returns:
            Number of flags set (0-32)
        """
        if bitmask == 0:
            return 0
        # Count set bits: bin(1610612768) = '0b1100000000000000000000000100000'
        # .count('1') = 3 flags set
        return bin(bitmask).count('1')
    
    # Feature names in exact order as Zenodo CSV (excluding md5/sha1/file_extension and Class/Category/Family)
    FEATURE_NAMES = [
        # DOS Header (1-4)
        'EntryPoint', 'PEType', 'MachineType', 'magic_number',
        
        # DOS Header Extended (5-17)
        'bytes_on_last_page', 'pages_in_file', 'relocations', 'size_of_header',
        'min_extra_paragraphs', 'max_extra_paragraphs', 'init_ss_value', 
        'init_sp_value', 'init_ip_value', 'init_cs_value', 'over_lay_number',
        'oem_identifier', 'address_of_ne_header',
        
        # PE Header (18-39)
        'Magic', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
        'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase',
        'SectionAlignment', 'FileAlignment', 'OperatingSystemVersion',
        'ImageVersion', 'SizeOfImage', 'SizeOfHeaders', 'Checksum',
        'Subsystem', 'DllCharacteristics', 'SizeofStackReserve',
        'SizeofStackCommit', 'SizeofHeapCommit', 'SizeofHeapReserve', 'LoaderFlags',
        
        # .text Section (40-46)
        'text_VirtualSize', 'text_VirtualAddress', 'text_SizeOfRawData',
        'text_PointerToRawData', 'text_PointerToRelocations',
        'text_PointerToLineNumbers', 'text_Characteristics',
        
        # .rdata Section (47-53)
        'rdata_VirtualSize', 'rdata_VirtualAddress', 'rdata_SizeOfRawData',
        'rdata_PointerToRawData', 'rdata_PointerToRelocations',
        'rdata_PointerToLineNumbers', 'rdata_Characteristics',
        
        # Behavioral Features (54-71) - SET TO 0, ENRICHED BY VT API
        'registry_read', 'registry_write', 'registry_delete', 'registry_total',
        'network_threats', 'network_dns', 'network_http', 'network_connections',
        'processes_monitored','total_procsses','files_text', 'files_unknown', 
        'dlls_calls', 'apis'
    ]
    
    # PE type mapping
    PE_TYPE_MAP = {
        'PE32': 1,
        'PE32+': 2,
        'Unknown': 0
    }
    
    # Machine type mapping
    MACHINE_TYPE_MAP = {
        332: 1,   # IMAGE_FILE_MACHINE_I386
        512: 2,   # IMAGE_FILE_MACHINE_IA64
        34404: 3, # IMAGE_FILE_MACHINE_AMD64
    }
    
    # Subsystem mapping
    SUBSYSTEM_MAP = {
        1: 1,  # IMAGE_SUBSYSTEM_NATIVE
        2: 2,  # IMAGE_SUBSYSTEM_WINDOWS_GUI
        3: 3,  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    }
    
    def __init__(self):
        """Initialize PE feature extractor"""
        self.n_features = len(self.FEATURE_NAMES)
        logger.info(f"PE Feature Extractor initialized ({self.n_features} features)")
    
    def extract(self, file_path: Union[str, Path]) -> Optional[np.ndarray]:
        """
        Extract PE features from file
        
        Args:
            file_path: Path to PE file
            
        Returns:
            numpy array of 78 features, or None if extraction failed
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
        
        try:
            # Parse PE file
            pe = pefile.PE(str(file_path), fast_load=True)
            
            # Parse all directory entries for complete info
            pe.parse_data_directories()
            
            # Extract features
            features = self._extract_features(pe)
            
            pe.close()
            
            return features
            
        except pefile.PEFormatError as e:
            logger.error(f"Not a valid PE file: {file_path} - {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to extract features from {file_path}: {e}")
            return None
    
    def _extract_features(self, pe: pefile.PE) -> np.ndarray:
        """Extract all 78 features from parsed PE"""
        features = {}
        
        # 1. DOS Header Features (1-4)
        features['EntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # Determine PE type based on Magic value
        # 0x10b = PE32, 0x20b = PE32+
        magic_value = pe.OPTIONAL_HEADER.Magic
        if magic_value == 0x10b:
            features['PEType'] = 1  # PE32
        elif magic_value == 0x20b:
            features['PEType'] = 2  # PE32+
        else:
            features['PEType'] = 0  # Unknown
        
        # Machine type
        features['MachineType'] = self.MACHINE_TYPE_MAP.get(pe.FILE_HEADER.Machine, 0)
        
        # Magic number (DOS)
        features['magic_number'] = pe.DOS_HEADER.e_magic
        
        # 5-17. DOS Header Extended
        features['bytes_on_last_page'] = pe.DOS_HEADER.e_cblp
        features['pages_in_file'] = pe.DOS_HEADER.e_cp
        features['relocations'] = pe.DOS_HEADER.e_crlc
        features['size_of_header'] = pe.DOS_HEADER.e_cparhdr
        features['min_extra_paragraphs'] = pe.DOS_HEADER.e_minalloc
        features['max_extra_paragraphs'] = pe.DOS_HEADER.e_maxalloc
        features['init_ss_value'] = pe.DOS_HEADER.e_ss
        features['init_sp_value'] = pe.DOS_HEADER.e_sp
        features['init_ip_value'] = pe.DOS_HEADER.e_ip
        features['init_cs_value'] = pe.DOS_HEADER.e_cs
        features['over_lay_number'] = pe.DOS_HEADER.e_ovno
        features['oem_identifier'] = pe.DOS_HEADER.e_oemid
        features['address_of_ne_header'] = pe.DOS_HEADER.e_lfanew
        
        # 18-39. PE Optional Header
        features['Magic'] = pe.OPTIONAL_HEADER.Magic
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        
        # BaseOfData only exists in PE32, not PE32+
        if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
            features['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
        else:
            features['BaseOfData'] = 0
        
        # Normalize ImageBase: PE32=0, PE32+=1 (position-independent, not malware indicator)
        # Raw ImageBase: PE32=0x400000 (4MB), PE32+=0x140000000 (5.3GB)
        # Causes 1000x scale difference between 32-bit and 64-bit PEs!
        if magic_value == 0x10b:  # PE32
            features['ImageBase'] = 0
        else:  # PE32+
            features['ImageBase'] = 1
        
        features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        
        # OS Version (combine major.minor)
        features['OperatingSystemVersion'] = (
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion + 
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion / 10.0
        )
        
        # Image Version (combine major.minor)
        features['ImageVersion'] = (
            pe.OPTIONAL_HEADER.MajorImageVersion + 
            pe.OPTIONAL_HEADER.MinorImageVersion / 10.0
        )
        
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features['Checksum'] = pe.OPTIONAL_HEADER.CheckSum
        
        # Subsystem
        features['Subsystem'] = self.SUBSYSTEM_MAP.get(pe.OPTIONAL_HEADER.Subsystem, 0)
        
        # DllCharacteristics - COUNT FLAGS, not raw bitmask
        # Training data: "['IMAGE_DLLCHARACTERISTICS_NX_COMPAT', ...]" → count
        features['DllCharacteristics'] = self._count_flags(pe.OPTIONAL_HEADER.DllCharacteristics)
        
        features['SizeofStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['SizeofStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        features['SizeofHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        features['SizeofHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        
        # 40-46. .text Section Features
        text_section = self._find_section(pe, b'.text')
        if text_section:
            features['text_VirtualSize'] = text_section.Misc_VirtualSize
            features['text_VirtualAddress'] = text_section.VirtualAddress
            features['text_SizeOfRawData'] = text_section.SizeOfRawData
            features['text_PointerToRawData'] = text_section.PointerToRawData
            features['text_PointerToRelocations'] = text_section.PointerToRelocations
            features['text_PointerToLineNumbers'] = text_section.PointerToLinenumbers
            # COUNT FLAGS in characteristics bitmask (NOT raw value)
            features['text_Characteristics'] = self._count_flags(text_section.Characteristics)
        else:
            # No .text section - use zeros
            for name in ['text_VirtualSize', 'text_VirtualAddress', 'text_SizeOfRawData',
                        'text_PointerToRawData', 'text_PointerToRelocations',
                        'text_PointerToLineNumbers', 'text_Characteristics']:
                features[name] = 0
        
        # 47-53. .rdata Section Features
        rdata_section = self._find_section(pe, b'.rdata')
        if rdata_section:
            features['rdata_VirtualSize'] = rdata_section.Misc_VirtualSize
            features['rdata_VirtualAddress'] = rdata_section.VirtualAddress
            features['rdata_SizeOfRawData'] = rdata_section.SizeOfRawData
            features['rdata_PointerToRawData'] = rdata_section.PointerToRawData
            features['rdata_PointerToRelocations'] = rdata_section.PointerToRelocations
            features['rdata_PointerToLineNumbers'] = rdata_section.PointerToLinenumbers
            # COUNT FLAGS in characteristics bitmask (NOT raw value like 1073741824!)
            features['rdata_Characteristics'] = self._count_flags(rdata_section.Characteristics)
        else:
            # No .rdata section - use zeros
            for name in ['rdata_VirtualSize', 'rdata_VirtualAddress', 'rdata_SizeOfRawData',
                        'rdata_PointerToRawData', 'rdata_PointerToRelocations',
                        'rdata_PointerToLineNumbers', 'rdata_Characteristics']:
                features[name] = 0
        
        # 54-71. Behavioral Features - Initialize to 0 (will be enriched by VT API)
        behavioral_features = [
            'registry_read', 'registry_write', 'registry_delete', 'registry_total',
            'network_threats', 'network_dns', 'network_http', 'network_connections',
            'processes_malicious', 'processes_suspicious', 'processes_monitored',
            'total_procsses', 'files_malicious', 'files_suspicious',
            'files_text', 'files_unknown', 'dlls_calls', 'apis'
        ]
        for name in behavioral_features:
            features[name] = 0.0
        
        # Convert to numpy array in correct order
        feature_array = np.array([features[name] for name in self.FEATURE_NAMES], dtype=np.float32)
        
        return feature_array
    
    def _find_section(self, pe: pefile.PE, section_name: bytes) -> Optional[pefile.SectionStructure]:
        """Find section by name"""
        for section in pe.sections:
            if section.Name.strip(b'\x00') == section_name:
                return section
        return None
    
    def extract_with_vt_enrichment(self, file_path: Union[str, Path], 
                                   vt_data: Optional[Dict] = None) -> Optional[np.ndarray]:
        """
        Extract PE features and enrich with VT behavioral data
        
        Args:
            file_path: Path to PE file
            vt_data: VirusTotal enrichment data (behavioral features)
            
        Returns:
            numpy array of 78 features with VT enrichment
        """
        # Extract base PE features
        features = self.extract(file_path)
        
        if features is None:
            return None
        
        # Enrich with VT data if available
        if vt_data:
            features = self._enrich_with_vt(features, vt_data)
        
        return features
    
    def _enrich_with_vt(self, features: np.ndarray, vt_data: Dict) -> np.ndarray:
        """
        Enrich features with VT behavioral data
        
        Matches structure returned by vt_integration.VirusTotalEnricher:
        {
            'detection': {...},
            'behavior': {
                'registry': {'read': int, 'write': int, 'delete': int},
                'network': {'threats': int, 'dns': int, 'http': int, 'connections': int},
                'processes': {'malicious': int, 'suspicious': int, 'monitored': int, 'total': int},
                'files': {'malicious': int, 'suspicious': int, 'text': int, 'unknown': int},
                'dlls': int,
                'apis': int
            }
        }
        
        Args:
            features: Base PE features (78 features)
            vt_data: VT enrichment data from VirusTotalEnricher.check_file()
            
        Returns:
            Enriched feature array
        """
        # Create feature dict for easier manipulation
        feature_dict = {name: features[i] for i, name in enumerate(self.FEATURE_NAMES)}
        
        # Safety check
        if not vt_data or 'behavior' not in vt_data:
            logger.warning("VT data missing or incomplete, skipping enrichment")
            return features
        
        behavior = vt_data['behavior']
        
        # Registry activity
        registry = behavior.get('registry', {})
        feature_dict['registry_read'] = registry.get('read', 0)
        feature_dict['registry_write'] = registry.get('write', 0)
        feature_dict['registry_delete'] = registry.get('delete', 0)
        feature_dict['registry_total'] = sum([
            feature_dict['registry_read'],
            feature_dict['registry_write'],
            feature_dict['registry_delete']
        ])
        
        # Network activity
        network = behavior.get('network', {})
        feature_dict['network_threats'] = network.get('threats', 0)
        feature_dict['network_dns'] = network.get('dns', 0)
        feature_dict['network_http'] = network.get('http', 0)
        feature_dict['network_connections'] = network.get('connections', 0)
        
        # Process activity
        processes = behavior.get('processes', {})
        feature_dict['processes_malicious'] = processes.get('malicious', 0)
        feature_dict['processes_suspicious'] = processes.get('suspicious', 0)
        feature_dict['processes_monitored'] = processes.get('monitored', 0)
        feature_dict['total_procsses'] = processes.get('total', 0)
        
        # File activity
        files = behavior.get('files', {})
        feature_dict['files_malicious'] = files.get('malicious', 0)
        feature_dict['files_suspicious'] = files.get('suspicious', 0)
        feature_dict['files_text'] = files.get('text', 0)
        feature_dict['files_unknown'] = files.get('unknown', 0)
        
        # DLL and API calls (integers directly under behavior)
        feature_dict['dlls_calls'] = behavior.get('dlls', 0)
        feature_dict['apis'] = behavior.get('apis', 0)
        
        # Convert back to array
        enriched_features = np.array([feature_dict[name] for name in self.FEATURE_NAMES], 
                                     dtype=np.float32)
        
        return enriched_features
    
    def get_feature_names(self) -> List[str]:
        """Get list of all feature names"""
        return self.FEATURE_NAMES.copy()
    
    def validate_features(self, features: np.ndarray) -> bool:
        """
        Validate feature array
        
        Args:
            features: Feature array to validate
            
        Returns:
            True if valid
        """
        if features is None:
            return False
        
        if len(features) != self.n_features:
            logger.error(f"Invalid feature count: expected {self.n_features}, got {len(features)}")
            return False
        
        if not np.isfinite(features).all():
            logger.error("Features contain inf or NaN values")
            return False
        
        return True


# Test function
def test_extractor():
    """Test PE feature extraction"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pe_feature_extractor.py <pe_file>")
        sys.exit(1)
    
    logging.basicConfig(level=logging.INFO)
    
    extractor = PEFeatureExtractor()
    features = extractor.extract(sys.argv[1])
    
    if features is not None:
        print(f"\n✓ Successfully extracted {len(features)} features")
        print(f"Feature shape: {features.shape}")
        print(f"Feature range: [{features.min():.2f}, {features.max():.2f}]")
        print(f"\nFirst 10 features:")
        for i, name in enumerate(extractor.FEATURE_NAMES[:10]):
            print(f"  {name:30s} = {features[i]:15.2f}")
    else:
        print(f"\n✗ Failed to extract features")
        sys.exit(1)


if __name__ == "__main__":
    test_extractor()
