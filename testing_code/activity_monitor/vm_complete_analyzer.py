"""
Complete Behavioral Analyzer - Real Sandbox Approach
Directly executes malware and monitors its runtime behavior in real-time

USAGE (inside Azure VM):
    python vm_complete_analyzer.py System_Update.exe

OUTPUT:
    - complete_analysis.json (full behavioral analysis + risk scoring)

This analyzer:
1. Takes filesystem/registry snapshots BEFORE execution
2. EXECUTES the malware directly
3. Monitors behavior in real-time (psutil: process tree, network, DLLs)
4. Runs Frida API tracer to capture sequential API calls (optional)
5. Analyzes changes AFTER execution
6. Detects ransomware patterns (including API sequences)
7. Generates risk score + ML features

Requirements:
    pip install psutil pywin32 frida (optional)
"""

import os
import sys
import json
import time
import subprocess
import winreg
import psutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Fix Windows console encoding issues with emojis
import io
if hasattr(sys.stdout, 'reconfigure'):
    # Python 3.7+: reconfigure in-place (safe with subprocess PIPE)
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass  # Already correct encoding or not reconfigurable
elif sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    # Fallback for older Python: replace wrapper (flush before swap)
    sys.stdout.flush()
    sys.stderr.flush()
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


# Stems that identify the known ransomware simulator (case-insensitive).
# Any target whose stem matches one of these uses the designated test folder
# as watch_dir. Everything else watches its own parent directory.
_SIMULATOR_STEMS = {'ransomware_simulator', 'system_update'}


class CompleteAnalyzer:
    """
    Real sandbox analyzer - executes malware and monitors runtime behavior
    """
    
    def __init__(self, target_path: str, watch_dir: str = None):
        try:
            self.target_path = Path(target_path).resolve()  # Convert to absolute path

            # Detect whether the target is the known ransomware simulator so we
            # can switch watch_dir and execution flags accordingly.
            self.is_simulator = self.target_path.stem.lower() in _SIMULATOR_STEMS

            if watch_dir:
                self.watch_dir = Path(watch_dir)
            elif self.is_simulator:
                # Simulator writes files to the designated test folder — watch that.
                try:
                    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
                    from dynamic_path_config.path_config import get_test_folder
                    self.watch_dir = get_test_folder()
                except Exception as _e:
                    print(f"[WARN] get_test_folder() failed ({_e}), using fallback", file=sys.stderr)
                    self.watch_dir = Path.home() / 'Downloads' / 'RANSOMWARE_TEST_FOLDER'
            else:
                # Generic EXE (installer, legit app) — watch its own parent directory.
                # Captures any files the EXE drops alongside itself.
                self.watch_dir = self.target_path.parent
            self.results_dir = Path(__file__).parent / "analysis_results"
            self.results_dir.mkdir(exist_ok=True, parents=True)
            
            # Behavioral data (use lists instead of sets for JSON serialization)
            self.analysis = {
                'target': str(self.target_path),
                'timestamp': datetime.now().isoformat(),
                'snapshots': {
                    'files_before': [],  # Changed from set() to list
                    'files_after': [],   # Changed from set() to list
                    'registry_before': {},
                    'registry_after': {}
                },
                'runtime_data': {
                    'process_tree': [],
                    'network_connections': [],
                    'dlls_loaded': [],
                    'execution_time': 0.0
                },
                'api_sequence': [],
                'behavioral_changes': {},
                'patterns': {},
                'ml_features': {},
                'risk_score': 0.0
            }
        except Exception as e:
            print(f"ERROR in CompleteAnalyzer.__init__: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise
    
    def take_filesystem_snapshot(self):
        """Take snapshot of files before execution"""
        print(f"\n📸 Taking filesystem snapshot: {self.watch_dir}")
        
        if not self.watch_dir.exists():
            print(f"   Creating watch directory...")
            self.watch_dir.mkdir(parents=True, exist_ok=True)
        
        files_before = []
        for file in self.watch_dir.rglob('*'):
            if file.is_file():
                files_before.append(str(file))
        
        self.analysis['snapshots']['files_before'] = files_before
        print(f"   ✓ {len(files_before)} files catalogued")
        return files_before
    
    def take_registry_snapshot(self):
        """Take snapshot of registry before execution"""
        print(f"\n📸 Taking registry snapshot...")
        
        # Monitor common ransomware persistence keys
        keys_to_monitor = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\TestRansomware"),
        ]
        
        registry_before = {}
        for hive, subkey_path in keys_to_monitor:
            try:
                key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
                values = {}
                i = 0
                while True:
                    try:
                        name, data, type_ = winreg.EnumValue(key, i)
                        values[name] = (data, type_)
                        i += 1
                    except OSError:
                        break
                registry_before[subkey_path] = values
                winreg.CloseKey(key)
            except FileNotFoundError:
                registry_before[subkey_path] = {}
            except Exception:
                pass
        
        self.analysis['snapshots']['registry_before'] = registry_before
        print(f"   ✓ {len(registry_before)} registry keys monitored")
        return registry_before
    
    def execute_and_monitor(self, timeout: int = 90):
        """Execute malware and monitor its behavior in real-time"""
        print(f"\n🚀 Executing malware: {self.target_path.name}")
        print(f"   Execution timeout: {timeout} seconds")
        print(f"   ⚠️  MONITORING STARTED - Malware is now running!")
        
        start_time = time.time()
        
        try:
            # Spawn the process
            if str(self.target_path).endswith('.py'):
                # Python script - use absolute path and set working directory
                process = psutil.Popen(
                    [sys.executable, str(self.target_path), '--auto-run'],
                    cwd=str(self.target_path.parent),  # Set working directory to script's folder
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                # Executable — cwd and extra flags depend on whether this is the
                # known simulator or a generic EXE (installer, legit app, etc.).
                exe_cmd = [str(self.target_path)]
                if self.is_simulator:
                    # Simulator understands --auto-run and expects to find the
                    # test folder relative to cwd.
                    exe_cmd.append('--auto-run')
                    exe_cwd = str(self.watch_dir)
                else:
                    # Generic EXE: do NOT inject unknown flags; run from its own
                    # directory so relative-path lookups inside the installer work.
                    exe_cwd = str(self.target_path.parent)
                # Use DEVNULL for stdout/stderr — we monitor the EXE via psutil/Frida,
                # not by reading its console output. PIPE would cause the 64 KB Windows
                # pipe buffer to fill up (the simulator has many print() calls) and the
                # EXE would deadlock waiting for the buffer to drain.
                process = psutil.Popen(
                    exe_cmd,
                    cwd=exe_cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            
            malware_pid = process.pid
            print(f"   ✓ Process spawned (PID: {malware_pid})")
            
            # Early check if process died immediately
            time.sleep(0.5)
            if process.poll() is not None:
                print(f"   ⚠️  WARNING: Process exited immediately with code {process.returncode}")
                stdout, stderr = process.communicate(timeout=1)
                if stdout:
                    print(f"   STDOUT: {stdout[:500]}")
                if stderr:
                    print(f"   STDERR: {stderr[:500]}")
                return False
            
            # Monitor in real-time
            monitored_process = psutil.Process(malware_pid)
            process_tree = []
            network_connections = []
            dlls_loaded = set()
            max_system_processes = 0  # Track total system processes (proxy for processes_monitored)
            
            # Monitor for specified timeout
            elapsed = 0
            last_progress_print = 0
            while elapsed < timeout:
                try:
                    if not monitored_process.is_running():
                        print(f"   ✓ Process terminated naturally after {elapsed:.1f}s")
                        break
                    
                    # Print progress every 10 seconds
                    if elapsed - last_progress_print >= 10:
                        print(f"   ... monitoring ({elapsed:.0f}s elapsed, {len(process_tree)} child procs, {len(network_connections)} net conns)")
                        last_progress_print = elapsed
                    
                    # Capture child processes
                    try:
                        children = monitored_process.children(recursive=True)
                        for child in children:
                            child_info = {
                                'name': child.name(),
                                'pid': child.pid,
                                'cmdline': ' '.join(child.cmdline()) if child.cmdline() else '',
                                'timestamp': elapsed
                            }
                            if child_info not in process_tree:
                                process_tree.append(child_info)
                                print(f"   [PROCESS] Spawned: {child.name()} (PID {child.pid})")
                    except:
                        pass
                    
                    # Capture network connections
                    try:
                        connections = monitored_process.net_connections()
                        for conn in connections:
                            # Capture all connection types (DNS lookups, TCP, UDP, etc.)
                            conn_info = {
                                'remote_ip': conn.raddr.ip if conn.raddr else None,
                                'remote_port': conn.raddr.port if conn.raddr else None,
                                'status': conn.status,
                                'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                                'timestamp': elapsed
                            }
                            if conn_info not in network_connections:
                                network_connections.append(conn_info)
                                if conn_info['remote_ip']:
                                    print(f"   [NETWORK] {conn.status}: {conn_info['remote_ip']}:{conn_info['remote_port']}")
                    except:
                        pass
                    
                    # Capture loaded DLLs
                    try:
                        for module in monitored_process.memory_maps():
                            if module.path and module.path.lower().endswith('.dll'):
                                dll_name = Path(module.path).name
                                if dll_name not in dlls_loaded:
                                    dlls_loaded.add(dll_name)
                    except:
                        pass

                    # Track total system processes (malware often enumerates these)
                    try:
                        system_proc_count = len(psutil.pids())
                        if system_proc_count > max_system_processes:
                            max_system_processes = system_proc_count
                    except:
                        pass
                    
                    time.sleep(0.2)  # Faster polling to catch transient activity
                    elapsed = time.time() - start_time
                
                except psutil.NoSuchProcess:
                    print(f"   ✓ Process terminated after {elapsed:.1f}s")
                    break
            
            # Terminate if still running
            try:
                if monitored_process.is_running():
                    print(f"   ⏱️  Timeout reached - terminating process...")
                    monitored_process.terminate()
                    monitored_process.wait(timeout=5)
            except psutil.TimeoutExpired:
                print(f"   ⚠️  Forcing process termination...")
                monitored_process.kill()
            except psutil.NoSuchProcess:
                pass
            
            # Capture output
            try:
                stdout, stderr = process.communicate(timeout=2)
                return_code = process.returncode
                
                if return_code != 0:
                    print(f"\n   ⚠️  Process exited with code {return_code}")
                
                if stderr and stderr.strip():
                    print(f"\n   ⚠️  Process stderr:")
                    for line in stderr.strip().split('\n')[:20]:  # First 20 lines
                        print(f"      {line}")
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                print(f"   ⚠️  Could not capture output: {e}")
            
            execution_time = time.time() - start_time
            
            # Store runtime data
            self.analysis['runtime_data'] = {
                'process_tree': process_tree,
                'network_connections': network_connections,
                'dlls_loaded': list(dlls_loaded),
                'execution_time': execution_time,
                'main_pid': malware_pid,
                'max_system_processes': max_system_processes  # Total procs seen on system during run
            }
            
            print(f"\n   ✓ Execution complete")
            print(f"   Duration: {execution_time:.2f}s")
            print(f"   Child processes: {len(process_tree)}")
            print(f"   Network connections: {len(network_connections)}")
            print(f"   DLLs loaded: {len(dlls_loaded)}")
            
            return True
        
        except Exception as e:
            print(f"\n   ❌ Error during execution: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def analyze_filesystem_changes(self):
        """Analyze file changes after execution"""
        print(f"\n📊 Analyzing filesystem changes...")
        
        files_after = []
        for file in self.watch_dir.rglob('*'):
            if file.is_file():
                files_after.append(str(file))
        
        self.analysis['snapshots']['files_after'] = files_after
        
        files_before_set = set(self.analysis['snapshots']['files_before'])
        files_after_set = set(files_after)
        
        # Detect changes
        files_created = files_after_set - files_before_set
        files_deleted = files_before_set - files_after_set
        files_encrypted = []
        ransom_notes = []
        
        # Analyze created files
        for file in files_created:
            file_path = Path(file)
            
            # Check for encrypted files (suspicious extensions)
            if any(ext in file_path.suffix.lower() for ext in ['.encrypted', '.locked', '.crypto', '.crypted', '.crypt']):
                files_encrypted.append(file)
            
            # Check for ransom notes
            if any(keyword in file_path.name.lower() for keyword in ['readme', 'decrypt', 'recover', 'ransom', 'help', 'instruction']):
                ransom_notes.append(file)
        
        changes = {
            'files_created': list(files_created),
            'files_deleted': list(files_deleted),
            'files_encrypted': files_encrypted,
            'ransom_notes': ransom_notes,
            'total_created': len(files_created),
            'total_deleted': len(files_deleted),
            'total_encrypted': len(files_encrypted),
            'total_ransom_notes': len(ransom_notes)
        }
        
        self.analysis['behavioral_changes']['filesystem'] = changes
        
        print(f"   Files created: {len(files_created)}")
        print(f"   Files deleted: {len(files_deleted)}")
        print(f"   Files encrypted: {len(files_encrypted)}")
        print(f"   Ransom notes: {len(ransom_notes)}")
        
        return changes
    
    def analyze_registry_changes(self):
        """Analyze registry changes after execution"""
        print(f"\n📊 Analyzing registry changes...")
        
        keys_to_monitor = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\TestRansomware"),
        ]
        
        registry_after = {}
        for hive, subkey_path in keys_to_monitor:
            try:
                key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
                values = {}
                i = 0
                while True:
                    try:
                        name, data, type_ = winreg.EnumValue(key, i)
                        values[name] = (data, type_)
                        i += 1
                    except OSError:
                        break
                registry_after[subkey_path] = values
                winreg.CloseKey(key)
            except FileNotFoundError:
                registry_after[subkey_path] = {}
            except Exception:
                pass
        
        self.analysis['snapshots']['registry_after'] = registry_after
        
        # Analyze changes
        registry_before = self.analysis['snapshots']['registry_before']
        writes = 0
        deletes = 0
        keys_modified = []
        persistence_attempts = []
        
        for subkey_path in registry_before.keys():
            before_values = registry_before.get(subkey_path, {})
            after_values = registry_after.get(subkey_path, {})
            
            # New values (writes)
            for name, (data, type_) in after_values.items():
                if name not in before_values:
                    writes += 1
                    keys_modified.append(f"{subkey_path}\\{name}")
                    
                    # Check if it's a persistence attempt
                    if 'Run' in subkey_path or 'Winlogon' in subkey_path:
                        persistence_attempts.append(f"{subkey_path}\\{name}")
                elif before_values[name] != (data, type_):
                    writes += 1
                    keys_modified.append(f"{subkey_path}\\{name} (modified)")
            
            # Deleted values
            for name in before_values:
                if name not in after_values:
                    deletes += 1
                    keys_modified.append(f"{subkey_path}\\{name} (deleted)")
        
        changes = {
            'writes': writes,
            'deletes': deletes,
            'keys_modified': keys_modified,
            'persistence_attempts': persistence_attempts
        }
        
        self.analysis['behavioral_changes']['registry'] = changes
        
        print(f"   Registry writes: {writes}")
        print(f"   Registry deletes: {deletes}")
        print(f"   Persistence attempts: {len(persistence_attempts)}")
        
        return changes
    
    def detect_patterns(self):
        """Detect ransomware patterns from behavioral changes"""
        print(f"\n🔍 Detecting ransomware patterns...")
        
        patterns = {
            'mass_file_encryption': False,
            'shadow_copy_deletion': False,
            'registry_persistence': False,
            'network_c2_communication': False,
            'ransom_note_creation': False,
            'mass_file_deletion': False,
            'suspicious_process_creation': False,
            'api_encrypt_rename_sequence': False
        }
        
        fs_changes = self.analysis['behavioral_changes'].get('filesystem', {})
        reg_changes = self.analysis['behavioral_changes'].get('registry', {})
        runtime = self.analysis['runtime_data']
        api_seq = self.analysis.get('api_sequence', [])
        api_summary = self.analysis.get('api_summary', {})
        
        # Pattern 1: Mass file encryption
        if api_summary.get('api_crypto_operations', 0) > 50:
            patterns['mass_file_encryption'] = True
            print(f"   ✅ Mass file encryption detected ({api_summary['api_crypto_operations']} operations)")
        
        # Pattern 2: Ransom note creation
        if fs_changes.get('total_ransom_notes', 0) > 0:
            patterns['ransom_note_creation'] = True
            print(f"   ✅ Ransom note creation detected ({fs_changes['total_ransom_notes']} notes)")
        
        # Pattern 3: Mass file deletion
        if fs_changes.get('total_deleted', 0) > 30:
            patterns['mass_file_deletion'] = True
            print(f"   ✅ Mass file deletion detected ({fs_changes['total_deleted']} files)")
        
        # Pattern 4: Registry persistence
        if len(reg_changes.get('persistence_attempts', [])) > 0:
            patterns['registry_persistence'] = True
            print(f"   ✅ Registry persistence detected ({len(reg_changes['persistence_attempts'])} attempts)")
        
        # Pattern 5: Network C2 communication
        if len(api_summary.get('api_network_connection', [])) > 5:
            patterns['network_c2_communication'] = True
            print(f"   ✅ Network C2 detected ({len(api_summary['api_network_connection'])} connections)")
        
        # Pattern 6: Suspicious process creation / injection
        # - Frida api_process_enumerations: NtQuerySystemInformation(5) calls
        # - api_process_opens: OpenProcess / NtOpenProcess (injection precursor)
        # - api_process_injections: WriteProcessMemory / ReadProcessMemory / NtCreateThreadEx
        # - api_token_operations: AdjustTokenPrivileges / OpenProcessToken (privilege escalation)
        frida_proc_enums = api_summary.get('api_process_enumerations', 0)
        api_proc_opens   = api_summary.get('api_process_opens',        0)
        api_proc_inject  = api_summary.get('api_process_injections',   0)
        api_token_ops    = api_summary.get('api_token_operations',     0)
        psutil_spawned   = len(runtime.get('process_tree', []))
        if frida_proc_enums > 0 or psutil_spawned > 0 or api_proc_opens > 0 or api_proc_inject > 0:
            patterns['suspicious_process_creation'] = True
            details = []
            if frida_proc_enums: details.append(f"proc_enum={frida_proc_enums}")
            if api_proc_opens:   details.append(f"OpenProcess={api_proc_opens}")
            if api_proc_inject:  details.append(f"WriteProcessMemory={api_proc_inject}")
            if api_token_ops:    details.append(f"token_ops={api_token_ops}")
            if psutil_spawned:   details.append(f"psutil_children={psutil_spawned}")
            print(f"   ✅ Process activity detected ({', '.join(details)})")
        
        # Pattern 7: API Encrypt-Rename sequence (from Frida API trace)
        if api_seq:
            for i in range(len(api_seq) - 2):
                call1 = api_seq[i]
                call2 = api_seq[i+1] if i+1 < len(api_seq) else {}
                call3 = api_seq[i+2] if i+2 < len(api_seq) else {}
                
                api1 = call1.get('api', '')
                api2 = call2.get('api', '')
                api3 = call3.get('api', '')
                
                # Look for: Write → Write → Rename/MoveFile pattern
                if 'Write' in api1 and 'Write' in api2 and ('Rename' in api3 or 'Move' in api3):
                    # Check if renamed to suspicious extension
                    args3 = str(call3.get('args', {}))
                    if any(ext in args3.lower() for ext in ['.encrypted', '.locked', '.crypto', '.crypt']):
                        patterns['api_encrypt_rename_sequence'] = True
                        print(f"   ✅ API encrypt-rename sequence detected (API trace)")
                        break
        
        self.analysis['patterns'] = patterns
        
        detected_count = sum(patterns.values())
        print(f"\n   Total patterns detected: {detected_count}/{len(patterns)}")
        
        return patterns
    
    def run_api_tracer(self):
        """Run Frida-based API call sequencing (subprocess approach)"""
        print(f"\n🔍 Running API tracer (Frida)...")
        
        # Check if Frida is available
        try:
            import frida
            print(f"   ✓ Frida detected")
        except ImportError:
            print("   ⚠️  Frida not installed - skipping API tracing")
            print("      Install with: pip install frida frida-tools")
            return None
        
        # Check if vm_api_tracer.py exists
        tracer_script = Path(__file__).parent / "vm_api_tracer_ntdll.py"
        if not tracer_script.exists():
            print("   ⚠️  vm_api_tracer.py not found - skipping API tracing")
            return None
        
        # Run API tracer
        print(f"   Target: {self.target_path}")
        try:
            # IMPORTANT: do NOT use capture_output=True or stdout=PIPE here.
            # The tracer + spawned EXE together emit thousands of progress lines.
            # A PIPE buffer is only ~64 KB; once full every print() in the tracer
            # blocks, stalling the Frida on_message loop and starving the API
            # sequence.  Let stdout flow directly to the terminal (no pipe),
            # capture only stderr so we can report errors.
            result = subprocess.run(
                [sys.executable, str(tracer_script), str(self.target_path)],
                stdout=None,             # → flows to terminal in real-time, no pipe
                stderr=subprocess.PIPE,  # only stderr captured (small, error messages)
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60             # 10 min — matches execute_and_monitor budget
            )
            
            if result.returncode == 0:
                print("   ✅ API tracing complete")
                
                # Load api_trace_ntdll.json (NT-level tracer output)
                # The tracer writes this file to its own cwd (activity_monitor/)
                api_json = Path(__file__).parent / "api_trace_ntdll.json"
                if api_json.exists():
                    with open(api_json, 'r') as f:
                        api_data = json.load(f)
                        self.analysis['api_sequence'] = api_data.get('api_sequence', [])
                        # Store the summary counts for ml_features
                        self.analysis['api_summary'] = api_data.get('summary', {})
                    
                    print(f"   Captured {len(self.analysis['api_sequence'])} API calls")
                    return self.analysis['api_sequence']
                else:
                    print(f"   ⚠️  Output file not found: {api_json}")
            else:
                print(f"   ⚠️  API tracer returned code {result.returncode}")
                if result.stderr:
                    print(f"      Error: {result.stderr[:200]}")
        
        except subprocess.TimeoutExpired:
            print("   ⚠️  API tracer timed out (max 600s)")
        except Exception as e:
            print(f"   ⚠️  Error running API tracer: {e}")
        
        return None
    
    def extract_ml_features(self):
        """Extract ML-ready features from runtime data and behavioral changes"""
        print(f"\n📊 Extracting ML features...")
        
        fs_changes = self.analysis['behavioral_changes'].get('filesystem', {})
        reg_changes = self.analysis['behavioral_changes'].get('registry', {})
        runtime = self.analysis['runtime_data']
        patterns = self.analysis['patterns']
        api_seq = self.analysis.get('api_sequence', [])
        # Summary counts from the NT-level tracer (includes registry/network/process hooks)
        api_summary = self.analysis.get('api_summary', {})

        # No fallback values — if Frida captured nothing the counts stay at 0.
        # Substituting self-reported behavioral_data.json would misrepresent what
        # the tracer actually observed and corrupt ML feature vectors for non-simulator targets.

        features = {
            # File operation features
            'file_created_count': fs_changes.get('total_created', 0),
            'file_deleted_count': fs_changes.get('total_deleted', 0),
            'file_encrypted_count': fs_changes.get('total_encrypted', 0),
            'ransom_note_count': fs_changes.get('total_ransom_notes', 0),
            
            # Registry operation features
            'registry_write_count': reg_changes.get('writes', 0),
            'registry_delete_count': reg_changes.get('deletes', 0),
            'persistence_attempt_count': len(reg_changes.get('persistence_attempts', [])),
            
            # Registry reads from NT-level API tracer (NtOpenKey + NtQueryValueKey)
            'registry_read_count': api_summary.get('api_registry_reads', 0),
            
            # Runtime features
            'process_spawn_count': len(runtime.get('process_tree', [])),
            'network_connection_count': len(runtime.get('network_connections', [])),
            'dll_load_count': len(runtime.get('dlls_loaded', [])),
            'execution_time': runtime.get('execution_time', 0.0),
            
            # System-wide process count during malware run (proxy for processes_monitored Zenodo feature)
            'system_process_count': api_summary.get('api_process_enumerations', 0),
            
            # Network counts from NT-level API tracer (ws2_32.dll hooks)
            'api_network_connections': api_summary.get('api_network_connections', 0),
            'api_network_dns': api_summary.get('api_network_dns', 0),
            
            # API sequence features (from Frida trace)
            'api_sequence_length': len(api_seq),
            'api_file_operations': (
                api_summary.get('api_file_operations', 0)
                or len([c for c in api_seq if 'File' in str(c.get('api', ''))])
            ),
            'api_registry_operations': (
                api_summary.get('api_registry_writes', 0)
                or len([c for c in api_seq if 'Reg' in str(c.get('api', ''))])
            ),
            'api_crypto_operations': (
                api_summary.get('api_crypto_operations', 0)
                or len([c for c in api_seq if 'Crypt' in str(c.get('api', ''))])
            ),
            'api_network_operations': (
                api_summary.get('api_network_connections', 0) + api_summary.get('api_network_dns', 0)
                or len([c for c in api_seq if any(x in str(c.get('api', '')) for x in ['connect', 'send', 'socket'])])
            ),
            
            # Pattern-based binary features
            'has_mass_encryption': int(patterns.get('mass_file_encryption', False)),
            'has_shadow_copy_deletion': int(patterns.get('shadow_copy_deletion', False)),
            'has_registry_persistence': int(patterns.get('registry_persistence', False)),
            'has_network_c2': int(patterns.get('network_c2_communication', False)),
            'has_ransom_note': int(patterns.get('ransom_note_creation', False)),
            'has_mass_deletion': int(patterns.get('mass_file_deletion', False)),
            'has_suspicious_process': int(patterns.get('suspicious_process_creation', False)),
            'has_api_encrypt_rename': int(patterns.get('api_encrypt_rename_sequence', False)),
            
            # Derived features
            'file_delete_ratio': (
                fs_changes.get('total_deleted', 0) / max(fs_changes.get('total_created', 0), 1)
            ),
            'encryption_ratio': (
                fs_changes.get('total_encrypted', 0) / max(fs_changes.get('total_created', 0), 1)
            ),
            'pattern_detection_count': sum(patterns.values())
        }
        
        self.analysis['ml_features'] = features
        
        print(f"   Extracted {len(features)} ML features")
        print(f"   Pattern detection count: {features['pattern_detection_count']}")
        print(f"   Registry reads (API trace): {features['registry_read_count']}")
        print(f"   System processes observed: {features['system_process_count']}")
        print(f"   Network connections (API trace): {features['api_network_connections']}")
        print(f"   DNS lookups (API trace): {features['api_network_dns']}")
        if api_seq:
            print(f"   API sequence length: {len(api_seq)}")
        
        return features
    
    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        print(f"\n🎯 Calculating risk score...")
        
        patterns = self.analysis['patterns']
        features = self.analysis['ml_features']
        
        score = 0
        reasons = []
        
        # Pattern-based scoring (70 points max)
        if patterns.get('mass_file_encryption'):
            score += 30
            reasons.append("+30: Mass file encryption detected")
        
        if patterns.get('ransom_note_creation'):
            score += 20
            reasons.append("+20: Ransom note creation")
        
        if patterns.get('mass_file_deletion'):
            score += 10
            reasons.append("+10: Mass file deletion")
        
        if patterns.get('registry_persistence'):
            score += 5
            reasons.append("+5: Registry persistence")
        
        if patterns.get('network_c2_communication'):
            score += 5
            reasons.append("+5: Network C2 communication")
        
        if patterns.get('api_encrypt_rename_sequence'):
            score += 5
            reasons.append("+5: API encrypt-rename sequence detected")
        
        # Feature-based scoring (30 points max)
        if features.get('file_encrypted_count', 0) > 100:
            score += 10
            reasons.append("+10: >100 files encrypted")
        elif features.get('file_encrypted_count', 0) > 50:
            score += 5
            reasons.append("+5: >50 files encrypted")
        
        if features.get('api_registry_writes', 0) > 50:
            score += 10
            reasons.append("+10: >50 registry writes")
        elif features.get('registry_write_count', 0) > 20:
            score += 5
            reasons.append("+5: >20 registry writes")
        
        if features.get('network_connection_count', 0) > 10:
            score += 5
            reasons.append("+5: >10 network connections")
        
        if features.get('system_process_count', 0) > 0:
            score += 5
            reasons.append("+5: Spawned child processes")
        
        if features.get('api_crypto_operations', 0) > 0:
            score += 5
            reasons.append("+5: Crypto API operations detected")
        
        self.analysis['risk_score'] = min(score, 100)
        
        # Risk classification
        if self.analysis['risk_score'] >= 70:
            risk_level = "CRITICAL"
            risk_desc = "Likely ransomware"
        elif self.analysis['risk_score'] >= 50:
            risk_level = "HIGH"
            risk_desc = "Suspicious activity"
        elif self.analysis['risk_score'] >= 30:
            risk_level = "MEDIUM"
            risk_desc = "Potentially malicious"
        else:
            risk_level = "LOW"
            risk_desc = "Likely benign"
        
        self.analysis['risk_level'] = risk_level
        self.analysis['risk_description'] = risk_desc
        
        print(f"\n🚨 Risk Score: {self.analysis['risk_score']}/100")
        print(f"   Level: {risk_level} - {risk_desc}")
        print(f"   Scoring breakdown:")
        for reason in reasons:
            print(f"      {reason}")
        
        return self.analysis['risk_score']
    
    def save_complete_analysis(self):
        """Save complete analysis to JSON file"""
        print(f"\n💾 Saving analysis...")
        # Create timestamped filename to match backend expectations (complete_analysis_*.json)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.results_dir / f"complete_analysis_{timestamp}.json"
        # Also maintain a stable filename for manual inspection
        stable_file = self.results_dir / "complete_analysis.json"
        
        # Add metadata
        self.analysis['metadata'] = {
            'target_file': str(self.target_path),
            'analysis_time': datetime.now().isoformat(),
            'analyzer_version': '2.0',
            'approach': 'real_sandbox_direct_execution'
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.analysis, f, indent=2, ensure_ascii=False)

        # Also write/update a stable file name for compatibility
        try:
            with open(stable_file, 'w', encoding='utf-8') as f:
                json.dump(self.analysis, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"   ⚠️ Could not write stable copy: {e}", file=sys.stderr)

        print(f"   ✅ Analysis saved to: {output_file}")
        print(f"   ℹ️  Stable copy: {stable_file}")

        return output_file


def main():
    """Main execution workflow"""
    # Early debug information to help when invoked as subprocess
    try:
        # Windows encoding fix - use reconfigure() to avoid subprocess pipe flush issues
        if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception as e:
        pass  # Encoding already set or not configurable
    
    try:
        if len(sys.argv) < 2:
            print("Usage: python vm_complete_analyzer.py <target.exe|target.py>")
            print("\nExample:")
            print("  python vm_complete_analyzer.py ..\\ransomware_simulation\\ransomware_simulator.py")
            print("  python vm_complete_analyzer.py malicious_sample.exe")
            sys.exit(1)
        
        target = sys.argv[1]
        
        # Validate target exists
        if not Path(target).exists():
            print(f"ERROR: Target file not found: {target}")
            print(f"Absolute path checked: {Path(target).resolve()}")
            sys.exit(1)
        
        print("="*80)
        print("🔬 COMPLETE MALWARE ANALYZER - Real Sandbox Approach")
        print("="*80)
        print(f"\nTarget: {target}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        print(f"FATAL ERROR during initialization: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    
    try:
        # Initialize analyzer
        print(f"\nInitializing analyzer...")
        analyzer = CompleteAnalyzer(target)
        print(f"✓ Analyzer initialized")
        print(f"   Target stem: {analyzer.target_path.stem!r}  is_simulator={analyzer.is_simulator}")
        print(f"   Watch directory: {analyzer.watch_dir}")
        print(f"   Results directory: {analyzer.results_dir}")
        
        # Phase 1: Take snapshots before execution
        print("\n" + "="*80)
        print("Phase 1: Taking Snapshots")
        print("="*80)
        analyzer.take_filesystem_snapshot()
        analyzer.take_registry_snapshot()
        
        # Phase 2: Execute and monitor in real-time (WITH API tracing if available)
        print("\n" + "="*80)
        print("Phase 2: Execute and Monitor")
        print("="*80)
        
        # Check if we should use API tracer for execution
        use_api_tracer = False
        try:
            import frida
            tracer_script = Path(__file__).parent / "vm_api_tracer_ntdll.py"
            if tracer_script.exists():
                use_api_tracer = True
                print("✓ Frida detected - will use API tracer for execution")
        except ImportError:
            pass
        
        if use_api_tracer:
            # Run API tracer (which will spawn and monitor the target)
            print("\n🔍 Running with API tracing...")
            analyzer.run_api_tracer()
            
            # Also capture basic metrics from the finished process
            print("\n📊 Capturing post-execution metrics...")
            # The process has finished, but we can still get behavioral changes
        else:
            # Fallback to basic monitoring
            print("\n⚠️  API tracing not available, using basic monitoring...")
            analyzer.execute_and_monitor(timeout=60)
        
        # Phase 3: Analyze behavioral changes
        print("\n" + "="*80)
        print("Phase 3: Analyzing Behavioral Changes")
        print("="*80)
        analyzer.analyze_filesystem_changes()
        analyzer.analyze_registry_changes()
        
        # Phase 4: Detect ransomware patterns
        print("\n" + "="*80)
        print("Phase 4: Pattern Detection")
        print("="*80)
        analyzer.detect_patterns()
        
        # Phase 5: Extract ML features
        print("\n" + "="*80)
        print("Phase 5: ML Feature Extraction")
        print("="*80)
        analyzer.extract_ml_features()
        
        # Phase 6: Calculate risk score
        print("\n" + "="*80)
        print("Phase 6: Risk Scoring")
        print("="*80)
        analyzer.calculate_risk_score()
        
        # Save complete analysis
        output_file = analyzer.save_complete_analysis()
        
        # Final summary with robust error handling
        try:
            print("\n" + "="*80)
            print("✅ ANALYSIS COMPLETE")
            print("="*80)
            fs_changes = analyzer.analysis['behavioral_changes'].get('filesystem', {})
            api_summary = analyzer.analysis.get('api_summary', {})
            ml_features = analyzer.analysis.get('ml_features', {})
            print(f"\n📊 Summary...")
            print(f"   Files created: {fs_changes.get('total_created', 0)}")
            print(f"   Files encrypted: {fs_changes.get('total_encrypted', 0)}")
            print(f"   Files deleted: {fs_changes.get('total_deleted', 0)}")
            print(f"   Registry writes: {api_summary.get('api_registry_writes', 0)}")
            print(f"   Network connections: {ml_features.get('api_network_operations', 0)}")
            print(f"   API calls captured: {len(analyzer.analysis.get('api_sequence', []))}")
            print(f"   Patterns detected: {sum(analyzer.analysis['patterns'].values())}/8")
            print(f"   ML features extracted: {len(analyzer.analysis['ml_features'])}")
            print(f"   Risk score: {analyzer.analysis['risk_score']}/100 ({analyzer.analysis['risk_level']})")
            print(f"\n📁 Output: {output_file}")
            print(" Transfer this file to your backend API for ML-based detection")
            print("="*80)
            print("SCRIPT COMPLETED SUCCESSFULLY")
        except Exception as summary_error:
            print(f"\n❌ Error during final summary print: {summary_error}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
