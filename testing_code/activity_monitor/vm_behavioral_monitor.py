"""
Behavioral Monitor for VM Testing
Monitors ransomware simulator execution and captures behavioral features

USAGE:
1. Copy this file + ransomware simulator to clean VM
2. Run: python vm_behavioral_monitor.py RansomwareSimulator.exe
3. Copy behavioral_data.json back to host machine
4. Analyze with host_analyze.py

Requirements: pip install psutil pywin32
"""

import os
import sys
import time
import json
import psutil
import subprocess
import winreg
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import threading

# Fix Windows console encoding issues with emojis
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


class BehavioralMonitor:
    """Monitor ransomware behavior in real-time"""
    
    def __init__(self, target_exe: str):
        self.target_exe = Path(target_exe)
        self.target_name = self.target_exe.name
        
        # Behavioral data
        self.data = {
            'target': str(self.target_exe),
            'start_time': datetime.now().isoformat(),
            'registry': {
                'read': 0,
                'write': 0,
                'delete': 0,
                'keys_modified': []
            },
            'network': {
                'dns': 0,
                'http': 0,
                'connections': 0,
                'domains': []
            },
            'processes': {
                'created': [],
                'total': 0,
                'suspicious': 0,
                'malicious': 0
            },
            'files': {
                'created': [],
                'modified': [],
                'deleted': [],
                'encrypted': [],
                'suspicious': 0,
                'malicious': 0
            },
            'dlls': [],
            'apis': 0,
            'execution_time': 0
        }
        
        # Snapshot states
        self.initial_files = set()
        self.initial_registry_values = {}  # Store actual registry values
        self.monitored_process = None
        
    def snapshot_filesystem(self, watch_dir: str):
        """Take snapshot of files before execution"""
        watch_path = Path(watch_dir)
        if not watch_path.exists():
            return
        
        print(f"📸 Taking filesystem snapshot of {watch_dir}")
        for file in watch_path.rglob('*'):
            if file.is_file():
                self.initial_files.add(str(file))
        
        print(f"   Found {len(self.initial_files)} files")
    
    def snapshot_registry(self):
        """Take snapshot of registry values in common ransomware locations"""
        print("📸 Taking registry snapshot (ransomware persistence keys)")
        
        # Keys that ransomware commonly targets
        keys_to_monitor = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\TestRansomware"),  # Our simulator's key
        ]
        
        for hive, subkey_path in keys_to_monitor:
            try:
                key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
                
                # Read all values in this key
                values = {}
                i = 0
                while True:
                    try:
                        name, data, type_ = winreg.EnumValue(key, i)
                        values[name] = (data, type_)
                        i += 1
                    except OSError:
                        break
                
                self.initial_registry_values[subkey_path] = values
                winreg.CloseKey(key)
            except FileNotFoundError:
                # Key doesn't exist yet - mark as empty
                self.initial_registry_values[subkey_path] = {}
            except Exception as e:
                # Permission denied or other error
                pass
        
        print(f"   Monitoring {len(self.initial_registry_values)} registry keys")
    
    def monitor_process(self, process: psutil.Process):
        """Monitor process activity"""
        print(f"\n🔍 Monitoring process PID {process.pid}")
        
        try:
            # Get child processes
            children = process.children(recursive=True)
            for child in children:
                self.data['processes']['created'].append({
                    'name': child.name(),
                    'pid': child.pid,
                    'cmdline': ' '.join(child.cmdline()) if child.cmdline() else ''
                })
            
            self.data['processes']['total'] = len(children) + 1
            
            # Monitor network connections
            connections = process.connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    self.data['network']['connections'] += 1
                    if conn.raddr:
                        self.data['network']['domains'].append(f"{conn.raddr.ip}:{conn.raddr.port}")
            
            # Get loaded DLLs (modules)
            try:
                for module in process.memory_maps():
                    dll_path = module.path
                    if dll_path and dll_path.lower().endswith('.dll'):
                        dll_name = Path(dll_path).name
                        if dll_name not in self.data['dlls']:
                            self.data['dlls'].append(dll_name)
            except:
                pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def check_registry_changes(self):
        """Check for registry modifications after execution"""
        print(f"\n📊 Analyzing registry changes...")
        
        writes = 0
        deletes = 0
        keys_modified = []
        
        for subkey_path, initial_values in self.initial_registry_values.items():
            try:
                # Try to open the key
                hive = winreg.HKEY_CURRENT_USER  # All our monitored keys are HKCU
                key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
                
                # Read current values
                current_values = {}
                i = 0
                while True:
                    try:
                        name, data, type_ = winreg.EnumValue(key, i)
                        current_values[name] = (data, type_)
                        i += 1
                    except OSError:
                        break
                
                winreg.CloseKey(key)
                
                # Detect new values (writes)
                for name, (data, type_) in current_values.items():
                    if name not in initial_values:
                        writes += 1
                        keys_modified.append(f"{subkey_path}\\{name}")
                        print(f"   [WRITE] {subkey_path}\\{name} = {data}")
                    elif initial_values[name] != (data, type_):
                        # Value was modified
                        writes += 1
                        keys_modified.append(f"{subkey_path}\\{name} (modified)")
                
                # Detect deleted values
                for name in initial_values:
                    if name not in current_values:
                        deletes += 1
                        keys_modified.append(f"{subkey_path}\\{name} (deleted)")
                        print(f"   [DELETE] {subkey_path}\\{name}")
                
            except FileNotFoundError:
                # Key was deleted
                if initial_values:  # Only count if it had values before
                    deletes += 1
                    print(f"   [DELETE] Entire key: {subkey_path}")
            except Exception as e:
                # Permission denied or other error
                pass
        
        self.data['registry']['write'] = writes
        self.data['registry']['delete'] = deletes
        self.data['registry']['keys_modified'] = keys_modified
        
        print(f"   Registry writes: {writes}")
        print(f"   Registry deletes: {deletes}")
    
    def check_file_changes(self, watch_dir: str):
        """Check for file changes after execution"""
        watch_path = Path(watch_dir)
        if not watch_path.exists():
            return
        
        print(f"\n📊 Analyzing file changes in {watch_dir}")
        current_files = set()
        
        for file in watch_path.rglob('*'):
            if file.is_file():
                current_files.add(str(file))
        
        # New files
        new_files = current_files - self.initial_files
        for file in new_files:
            file_path = Path(file)
            if file_path.suffix.lower() in ['.txt', '.hta', '.html']:
                # Likely ransom note
                self.data['files']['created'].append(str(file))
                self.data['files']['malicious'] += 1
            else:
                self.data['files']['created'].append(str(file))
        
        # Deleted files
        deleted_files = self.initial_files - current_files
        for file in deleted_files:
            self.data['files']['deleted'].append(str(file))
            self.data['files']['suspicious'] += 1
        
        # Check for encrypted files (original deleted + new .encrypted version)
        for deleted in deleted_files:
            encrypted_version = deleted + '.encrypted'
            if encrypted_version in new_files:
                self.data['files']['encrypted'].append(str(deleted))
                self.data['files']['malicious'] += 1
        
        print(f"   Created: {len(new_files)}")
        print(f"   Deleted: {len(deleted_files)}")
        print(f"   Encrypted: {len(self.data['files']['encrypted'])}")
    
    def run_target(self):
        """Execute target and monitor"""
        print(f"\n🚀 Launching {self.target_name}")
        
        # Start process
        try:
            # Handle both .exe and .py files
            if str(self.target_exe).endswith('.py'):
                # Run Python script
                import sys
                python_exe = sys.executable
                process = psutil.Popen([python_exe, str(self.target_exe), '--auto-run'])
            else:
                # Run executable directly
                process = psutil.Popen([str(self.target_exe), '--auto-run'])
            
            self.monitored_process = psutil.Process(process.pid)
            
            print(f"   PID: {process.pid}")
            print(f"   Monitoring for 10 seconds...")
            
            # Monitor for 10 seconds
            start_time = time.time()
            while time.time() - start_time < 10:
                if not self.monitored_process.is_running():
                    print(f"   Process terminated after {time.time() - start_time:.1f}s")
                    break
                
                self.monitor_process(self.monitored_process)
                time.sleep(0.5)
            
            # Terminate if still running
            if self.monitored_process.is_running():
                print("   Terminating process...")
                self.monitored_process.terminate()
                self.monitored_process.wait(timeout=5)
            
            self.data['execution_time'] = time.time() - start_time
            
        except Exception as e:
            print(f"❌ Error executing target: {e}")
            return False
        
        return True
    
    def save_results(self, output_file: str = "behavioral_data.json"):
        """Save behavioral data to JSON"""
        self.data['end_time'] = datetime.now().isoformat()
        
        # Calculate summary stats
        self.data['summary'] = {
            'registry_total': self.data['registry']['write'] + self.data['registry']['delete'],
            'files_total': len(self.data['files']['created']) + len(self.data['files']['modified']) + len(self.data['files']['deleted']),
            'network_total': self.data['network']['connections'],
            'dlls_count': len(self.data['dlls']),
            'suspicious_activity': (
                len(self.data['files']['encrypted']) > 0 or
                len(self.data['files']['deleted']) > 3 or
                self.data['registry']['write'] > 5
            )
        }
        
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"\n✅ Behavioral data saved to {output_path}")
        return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python vm_behavioral_monitor.py <target.exe> [watch_directory]")
        print("\nExample:")
        print("  python vm_behavioral_monitor.py RansomwareSimulator.exe C:/Users/willi/Downloads/RANSOMWARE_TEST_FOLDER")
        sys.exit(1)
    
    target_exe = sys.argv[1]
    watch_dir = sys.argv[2] if len(sys.argv) > 2 else "C:/Users/willi/Downloads/RANSOMWARE_TEST_FOLDER"
    
    print("="*80)
    print("VM Behavioral Monitor for Ransomware Testing")
    print("="*80)
    print(f"\n  RUNNING IN VM ONLY - DO NOT RUN ON HOST MACHINE")
    print(f"Target: {target_exe}")
    print(f"Watch Directory: {watch_dir}")
    
    # Initialize monitor
    monitor = BehavioralMonitor(target_exe)
    
    # Take snapshots
    monitor.snapshot_filesystem(watch_dir)
    monitor.snapshot_registry()
    
    # Run target
    if not monitor.run_target():
        print("\n❌ Execution failed")
        sys.exit(1)
    
    # Analyze changes
    monitor.check_file_changes(watch_dir)
    monitor.check_registry_changes()  # NEW: Detect registry modifications
    
    # Save results
    output_file = monitor.save_results()
    
    # Display summary
    print("\n" + "="*80)
    print("Behavioral Analysis Summary")
    print("="*80)
    print(f"Execution time: {monitor.data['execution_time']:.1f}s")
    print(f"\n📝 Registry:")
    print(f"   Writes: {monitor.data['registry']['write']}")
    print(f"   Deletes: {monitor.data['registry']['delete']}")
    print(f"\n📁 Files:")
    print(f"   Created: {len(monitor.data['files']['created'])}")
    print(f"   Deleted: {len(monitor.data['files']['deleted'])}")
    print(f"   Encrypted: {len(monitor.data['files']['encrypted'])}")
    print(f"   Suspicious: {monitor.data['files']['suspicious']}")
    print(f"\n🌐 Network:")
    print(f"   Connections: {monitor.data['network']['connections']}")
    print(f"\n🔧 Processes:")
    print(f"   Created: {monitor.data['processes']['total']}")
    print(f"\n📚 DLLs:")
    print(f"   Loaded: {len(monitor.data['dlls'])}")
    
    print(f"\n✅ Transfer {output_file} to host machine for ML analysis")
    print("="*80)


if __name__ == "__main__":
    main()
