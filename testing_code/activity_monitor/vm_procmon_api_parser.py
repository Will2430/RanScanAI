"""
Process Monitor API Sequence Parser
Parses Procmon CSV logs to extract sequential API call patterns

Requirements: Sysinternals Process Monitor (procmon.exe)

Workflow:
1. Start Procmon with filter for your malware process
2. Run malware
3. Stop Procmon and export to CSV
4. Run this script to analyze API sequence

Usage:
    python vm_procmon_api_parser.py procmon_log.csv
"""

import csv
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


class ProcmonAPIParser:
    """Parse Process Monitor CSV for API call sequences"""
    
    def __init__(self, csv_path: str):
        self.csv_path = Path(csv_path)
        self.api_sequence = []
        self.process_filter = None  # Filter by process name
        
    def parse_csv(self, process_name: str = None):
        """Parse Procmon CSV and extract API calls"""
        print(f"📊 Parsing {self.csv_path.name}...")
        
        if process_name:
            print(f"   Filtering for process: {process_name}")
            self.process_filter = process_name.lower()
        
        with open(self.csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for i, row in enumerate(reader):
                # Filter by process if specified
                process = row.get('Process Name', '')
                if self.process_filter and self.process_filter not in process.lower():
                    continue
                
                # Extract key fields
                api_call = {
                    'index': i,
                    'time': row.get('Time of Day', ''),
                    'process': process,
                    'pid': row.get('PID', ''),
                    'operation': row.get('Operation', ''),
                    'path': row.get('Path', ''),
                    'result': row.get('Result', ''),
                    'detail': row.get('Detail', '')
                }
                
                self.api_sequence.append(api_call)
                
                if len(self.api_sequence) % 1000 == 0:
                    print(f"   Parsed {len(self.api_sequence)} operations...")
        
        print(f"✅ Parsed {len(self.api_sequence)} total operations")
    
    def detect_ransomware_patterns(self):
        """Detect ransomware behavioral patterns from API sequence"""
        print("\n🔍 Detecting ransomware patterns...")
        
        patterns = {
            'file_write': [],
            'file_delete': [],
            'file_rename': [],
            'registry_write': [],
            'registry_delete': [],
            'network_connect': [],
            'process_create': [],
            'crypto_operations': [],
            'shadow_copy_commands': []
        }
        
        # Sequential pattern detection
        for i, call in enumerate(self.api_sequence):
            op = call['operation']
            path = call['path']
            detail = call['detail']
            
            # File operations
            if 'WriteFile' in op or 'SetEndOfFile' in op:
                patterns['file_write'].append(call)
            elif 'DeleteFile' in op or 'SetDispositionInformationFile' in op:
                patterns['file_delete'].append(call)
            elif 'SetRenameInformationFile' in op:
                patterns['file_rename'].append(call)
            
            # Registry operations
            elif 'RegSetValue' in op:
                patterns['registry_write'].append(call)
                
                # Check for persistence keys
                if any(key in path.lower() for key in ['\\run', '\\runonce', '\\winlogon']):
                    call['suspicious'] = 'PERSISTENCE_MECHANISM'
            
            elif 'RegDeleteValue' in op or 'RegDeleteKey' in op:
                patterns['registry_delete'].append(call)
            
            # Network operations
            elif 'TCP' in op or 'UDP' in op or 'DNS' in op:
                patterns['network_connect'].append(call)
            
            # Process creation
            elif 'Process Create' in op:
                patterns['process_create'].append(call)
                
                # Check for vssadmin, wmic, bcdedit (shadow copy deletion)
                if 'vssadmin' in path.lower() or 'wmic' in path.lower() or 'bcdedit' in path.lower():
                    patterns['shadow_copy_commands'].append(call)
                    call['suspicious'] = 'SHADOW_COPY_DELETION'
            
            # Crypto operations
            elif 'Crypt' in op:
                patterns['crypto_operations'].append(call)
        
        return patterns
    
    def analyze_file_encryption_sequence(self, patterns):
        """Analyze file encryption behavior from operation sequence"""
        print("\n📁 Analyzing file encryption patterns...")
        
        # Look for: CreateFile → WriteFile → CloseFile → Rename sequences
        encryption_sequences = []
        file_operations = defaultdict(list)
        
        # Group operations by file path
        for call in self.api_sequence:
            path = call.get('path', '')
            if path and any(op in call['operation'] for op in ['CreateFile', 'WriteFile', 'CloseFile', 'SetRenameInformationFile']):
                file_operations[path].append(call)
        
        # Detect encryption pattern: write to file, then rename with suspicious extension
        for path, operations in file_operations.items():
            ops_sequence = [op['operation'] for op in operations]
            
            # Check if renamed to .encrypted, .locked, etc.
            has_rename = any('Rename' in op['operation'] for op in operations)
            has_write = any('Write' in op['operation'] for op in operations)
            
            if has_write and has_rename:
                # Check if renamed to suspicious extension
                for op in operations:
                    if 'Rename' in op['operation']:
                        detail = op.get('detail', '')
                        if any(ext in detail.lower() for ext in ['.encrypted', '.locked', '.crypto', '.crypted', '.crypt']):
                            encryption_sequences.append({
                                'file': path,
                                'operations': ops_sequence,
                                'suspicious': 'LIKELY_ENCRYPTION'
                            })
                            break
        
        print(f"   Found {len(encryption_sequences)} potential file encryption sequences")
        
        # Show first 10 examples
        for seq in encryption_sequences[:10]:
            print(f"   - {Path(seq['file']).name}: {' → '.join(seq['operations'][:5])}")
        
        return encryption_sequences
    
    def create_api_timeline(self, patterns):
        """Create chronological API timeline for ML feature extraction"""
        print("\n⏱️  Creating API call timeline...")
        
        timeline = []
        
        for call in self.api_sequence:
            # Categorize API call
            category = 'OTHER'
            importance = 'LOW'
            
            op = call['operation']
            
            if 'File' in op:
                category = 'FILE_IO'
                if 'Write' in op or 'Delete' in op or 'Rename' in op:
                    importance = 'HIGH'
            elif 'Reg' in op:
                category = 'REGISTRY'
                if 'SetValue' in op:
                    importance = 'MEDIUM'
            elif 'TCP' in op or 'UDP' in op:
                category = 'NETWORK'
                importance = 'MEDIUM'
            elif 'Process' in op:
                category = 'PROCESS'
                importance = 'HIGH'
            elif 'Crypt' in op:
                category = 'CRYPTO'
                importance = 'CRITICAL'
            
            timeline.append({
                'timestamp': call['time'],
                'category': category,
                'operation': op,
                'importance': importance,
                'path': call['path']
            })
        
        return timeline
    
    def generate_behavioral_features(self, patterns):
        """Generate ML-ready behavioral features"""
        print("\n🤖 Generating ML features...")
        
        features = {
            # Counts
            'total_operations': len(self.api_sequence),
            'file_writes': len(patterns['file_write']),
            'file_deletes': len(patterns['file_delete']),
            'file_renames': len(patterns['file_rename']),
            'registry_writes': len(patterns['registry_write']),
            'registry_deletes': len(patterns['registry_delete']),
            'network_connections': len(patterns['network_connect']),
            'process_creates': len(patterns['process_create']),
            'crypto_operations': len(patterns['crypto_operations']),
            
            # Ratios
            'write_to_delete_ratio': (
                len(patterns['file_write']) / len(patterns['file_delete']) 
                if len(patterns['file_delete']) > 0 else 0
            ),
            'rename_percentage': (
                len(patterns['file_rename']) / len(self.api_sequence) * 100
                if len(self.api_sequence) > 0 else 0
            ),
            
            # Behavioral flags
            'has_shadow_copy_deletion': len(patterns['shadow_copy_commands']) > 0,
            'has_persistence_mechanism': any(
                'PERSISTENCE' in call.get('suspicious', '') 
                for call in patterns['registry_write']
            ),
            'has_mass_file_operations': len(patterns['file_write']) > 100,
            'has_crypto_usage': len(patterns['crypto_operations']) > 0,
            
            # Suspicion scores
            'suspicion_score': self._calculate_suspicion_score(patterns),
            'ransomware_probability': self._calculate_ransomware_probability(patterns)
        }
        
        return features
    
    def _calculate_suspicion_score(self, patterns):
        """Calculate suspicion score (0-100)"""
        score = 0
        
        # Mass file operations
        if len(patterns['file_write']) > 100:
            score += 20
        if len(patterns['file_delete']) > 50:
            score += 15
        if len(patterns['file_rename']) > 50:
            score += 25
        
        # Registry persistence
        if any('PERSISTENCE' in call.get('suspicious', '') for call in patterns['registry_write']):
            score += 15
        
        # Shadow copy deletion
        if patterns['shadow_copy_commands']:
            score += 25
        
        return min(score, 100)
    
    def _calculate_ransomware_probability(self, patterns):
        """Calculate ransomware probability (0.0-1.0)"""
        indicators = 0
        
        if len(patterns['file_rename']) > 50:
            indicators += 1
        if len(patterns['file_delete']) > 30:
            indicators += 1
        if patterns['shadow_copy_commands']:
            indicators += 1
        if any('PERSISTENCE' in call.get('suspicious', '') for call in patterns['registry_write']):
            indicators += 1
        if len(patterns['crypto_operations']) > 0:
            indicators += 1
        
        return indicators / 5.0
    
    def save_results(self, patterns, features, output_file: str = "api_analysis.json"):
        """Save analysis results"""
        data = {
            'source_file': str(self.csv_path),
            'timestamp': datetime.now().isoformat(),
            'total_operations': len(self.api_sequence),
            'patterns': {
                'file_writes': len(patterns['file_write']),
                'file_deletes': len(patterns['file_delete']),
                'file_renames': len(patterns['file_rename']),
                'registry_writes': len(patterns['registry_write']),
                'shadow_copy_commands': len(patterns['shadow_copy_commands'])
            },
            'features': features,
            'api_sequence_sample': self.api_sequence[:100]  # First 100 calls
        }
        
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n💾 Analysis saved to: {output_path}")
        return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python vm_procmon_api_parser.py <procmon.csv> [process_name]")
        print("\nExample:")
        print("  python vm_procmon_api_parser.py procmon_log.csv")
        print("  python vm_procmon_api_parser.py procmon_log.csv python.exe")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    process_filter = sys.argv[2] if len(sys.argv) > 2 else None
    
    print("="*80)
    print("Process Monitor API Sequence Parser")
    print("="*80)
    
    # Parse CSV
    parser = ProcmonAPIParser(csv_file)
    parser.parse_csv(process_filter)
    
    # Detect patterns
    patterns = parser.detect_ransomware_patterns()
    
    # Analyze encryption sequences
    encryption_seqs = parser.analyze_file_encryption_sequence(patterns)
    
    # Create timeline
    timeline = parser.create_api_timeline(patterns)
    
    # Generate ML features
    features = parser.generate_behavioral_features(patterns)
    
    # Print summary
    print("\n" + "="*80)
    print("Analysis Summary")
    print("="*80)
    print(f"\n📊 Operation Counts:")
    print(f"   File writes: {len(patterns['file_write'])}")
    print(f"   File deletes: {len(patterns['file_delete'])}")
    print(f"   File renames: {len(patterns['file_rename'])}")
    print(f"   Registry writes: {len(patterns['registry_write'])}")
    print(f"   Network connections: {len(patterns['network_connect'])}")
    
    print(f"\n🚨 Ransomware Indicators:")
    print(f"   Shadow copy deletion: {len(patterns['shadow_copy_commands'])} commands")
    print(f"   Encryption sequences: {len(encryption_seqs)}")
    print(f"   Suspicion score: {features['suspicion_score']}/100")
    print(f"   Ransomware probability: {features['ransomware_probability']:.1%}")
    
    # Save results
    parser.save_results(patterns, features)
    
    print("\n✅ Analysis complete!")
    print("="*80)


if __name__ == "__main__":
    main()
