"""
API Call Sequence Tracer using Frida
Captures sequential API calls from ransomware for behavioral analysis

Requirements: pip install frida frida-tools

Usage:
    python vm_api_tracer.py ransomware_simulator.py
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime

# Fix Windows console encoding issues with emojis
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Frida will be imported later when needed


class APITracer:
    """Trace Windows API calls in sequential order"""
    
    def __init__(self):
        self.api_sequence = []
        self.start_time = None
        
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']
            
            # Record API call with timestamp
            if self.start_time is None:
                self.start_time = time.time()
            
            api_call = {
                'timestamp': time.time() - self.start_time,
                'api': payload.get('api'),
                'args': payload.get('args'),
                'return': payload.get('return'),
                'thread_id': payload.get('thread_id')
            }
            
            self.api_sequence.append(api_call)
            
            # Print to console (optional)
            print(f"[{api_call['timestamp']:.3f}s] {api_call['api']} -> {api_call.get('return')}")
        
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")
    
    def get_frida_script(self):
        """
        Frida JavaScript to hook critical ransomware APIs
        """
        return """
        // Ransomware-critical API calls to monitor
        
        // File Operations
        var CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        var WriteFile = Module.findExportByName('kernel32.dll', 'WriteFile');
        var DeleteFileW = Module.findExportByName('kernel32.dll', 'DeleteFileW');
        var MoveFileExW = Module.findExportByName('kernel32.dll', 'MoveFileExW');
        var CopyFileW = Module.findExportByName('kernel32.dll', 'CopyFileW');
        
        // Registry Operations
        var RegOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
        var RegSetValueExW = Module.findExportByName('advapi32.dll', 'RegSetValueExW');
        var RegDeleteValueW = Module.findExportByName('advapi32.dll', 'RegDeleteValueW');
        
        // Network Operations
        var connect = Module.findExportByName('ws2_32.dll', 'connect');
        var send = Module.findExportByName('ws2_32.dll', 'send');
        var WSAStartup = Module.findExportByName('ws2_32.dll', 'WSAStartup');
        
        // Cryptography (ransomware encryption)
        var CryptEncrypt = Module.findExportByName('advapi32.dll', 'CryptEncrypt');
        var CryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
        var CryptGenKey = Module.findExportByName('advapi32.dll', 'CryptGenKey');
        
        // Process/Thread Operations
        var CreateProcessW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
        var CreateThread = Module.findExportByName('kernel32.dll', 'CreateThread');
        var TerminateProcess = Module.findExportByName('kernel32.dll', 'TerminateProcess');
        
        // Volume Shadow Copy (ransomware deletes backups!)
        var CreateProcessW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
        
        // Hook CreateFileW - File creation/opening
        if (CreateFileW) {
            Interceptor.attach(CreateFileW, {
                onEnter: function(args) {
                    this.fileName = args[0].readUtf16String();
                },
                onLeave: function(retval) {
                    if (this.fileName) {
                        send({
                            api: 'CreateFileW',
                            args: { path: this.fileName },
                            return: retval.toString(),
                            thread_id: Process.getCurrentThreadId()
                        });
                    }
                }
            });
        }
        
        // Hook WriteFile - File writing (encryption writes)
        if (WriteFile) {
            Interceptor.attach(WriteFile, {
                onEnter: function(args) {
                    this.handle = args[0];
                    this.bytesToWrite = args[2].toInt32();
                },
                onLeave: function(retval) {
                    send({
                        api: 'WriteFile',
                        args: { 
                            handle: this.handle.toString(), 
                            bytes: this.bytesToWrite 
                        },
                        return: retval.toString(),
                        thread_id: Process.getCurrentThreadId()
                    });
                }
            });
        }
        
        // Hook DeleteFileW - File deletion
        if (DeleteFileW) {
            Interceptor.attach(DeleteFileW, {
                onEnter: function(args) {
                    this.fileName = args[0].readUtf16String();
                },
                onLeave: function(retval) {
                    send({
                        api: 'DeleteFileW',
                        args: { path: this.fileName },
                        return: retval.toString(),
                        thread_id: Process.getCurrentThreadId()
                    });
                }
            });
        }
        
        // Hook MoveFileExW - File renaming (encryption!)
        if (MoveFileExW) {
            Interceptor.attach(MoveFileExW, {
                onEnter: function(args) {
                    this.oldName = args[0].readUtf16String();
                    this.newName = args[1].readUtf16String();
                },
                onLeave: function(retval) {
                    send({
                        api: 'MoveFileExW',
                        args: { 
                            from: this.oldName, 
                            to: this.newName 
                        },
                        return: retval.toString(),
                        thread_id: Process.getCurrentThreadId()
                    });
                }
            });
        }
        
        // Hook RegSetValueExW - Registry modification
        if (RegSetValueExW) {
            Interceptor.attach(RegSetValueExW, {
                onEnter: function(args) {
                    this.valueName = args[1].readUtf16String();
                },
                onLeave: function(retval) {
                    send({
                        api: 'RegSetValueExW',
                        args: { value: this.valueName },
                        return: retval.toString(),
                        thread_id: Process.getCurrentThreadId()
                    });
                }
            });
        }
        
        // Hook CryptEncrypt - Encryption (CRITICAL!)
        if (CryptEncrypt) {
            Interceptor.attach(CryptEncrypt, {
                onEnter: function(args) {
                    this.dataLen = args[3].readU32();
                },
                onLeave: function(retval) {
                    send({
                        api: 'CryptEncrypt',
                        args: { data_length: this.dataLen },
                        return: retval.toString(),
                        thread_id: Process.getCurrentThreadId()
                    });
                }
            });
        }
        
        // Hook CreateProcessW - Process creation (cmd.exe for vssadmin!)
        if (CreateProcessW) {
            Interceptor.attach(CreateProcessW, {
                onEnter: function(args) {
                    var cmdLine = args[1];
                    this.command = cmdLine.readUtf16String();
                },
                onLeave: function(retval) {
                    if (this.command) {
                        send({
                            api: 'CreateProcessW',
                            args: { command: this.command },
                            return: retval.toString(),
                            thread_id: Process.getCurrentThreadId()
                        });
                    }
                }
            });
        }
        
        console.log('[Frida] API hooks installed');
        """
    
    def trace_process(self, target_path: str):
        """Spawn process and trace API calls"""
        import frida  # Import here to avoid error if not installed
        
        print(f"🔍 Starting API tracer for: {target_path}")
        
        # Spawn the process with Frida
        if target_path.endswith('.py'):
            # Python script
            device = frida.get_local_device()
            pid = device.spawn([sys.executable, target_path, '--auto-run'])
            session = device.attach(pid)
        else:
            # Executable
            device = frida.get_local_device()
            pid = device.spawn([target_path, '--auto-run'])
            session = device.attach(pid)
        
        # Load and inject Frida script
        script = session.create_script(self.get_frida_script())
        script.on('message', self.on_message)
        script.load()
        
        # Resume execution
        device.resume(pid)
        
        print(f"✅ Process spawned (PID: {pid})")
        print("📊 Capturing API calls...\n")
        
        # Let it run for 90 seconds (increased for intensive simulations)
        try:
            start_time = time.time()
            duration = 90
            
            while time.time() - start_time < duration:
                elapsed = int(time.time() - start_time)
                if elapsed %10 == 0 and elapsed > 0:
                    print(f"   ⏱️  {elapsed}s elapsed... ({len(self.api_sequence)} calls captured)")
                    time.sleep(1)  # Sleep 1s after printing to avoid duplicate prints
                else:
                    time.sleep(0.5)
                    
        except KeyboardInterrupt:
            print("\n⚠️  Interrupted by user")
        
        # Detach
        session.detach()
        
        print(f"\n✅ Captured {len(self.api_sequence)} API calls")
    
    def analyze_sequence(self):
        """Analyze API call patterns"""
        print("\n📊 Analyzing API call patterns...")
        
        # Detect common ransomware patterns
        patterns = {
            'mass_file_write': 0,
            'mass_file_delete': 0,
            'file_rename_encryption': 0,
            'crypto_api_usage': 0,
            'registry_persistence': 0,
            'shadow_copy_deletion': 0,
            'network_c2': 0
        }
        
        for i, call in enumerate(self.api_sequence):
            api = call['api']
            
            # Count file operations
            if api == 'WriteFile':
                patterns['mass_file_write'] += 1
            elif api == 'DeleteFileW':
                patterns['mass_file_delete'] += 1
            elif api == 'MoveFileExW':
                # Check if renaming to .encrypted, .locked, etc.
                if 'to' in call.get('args', {}):
                    to_path = call['args']['to']
                    if any(ext in to_path.lower() for ext in ['.encrypted', '.locked', '.crypto']):
                        patterns['file_rename_encryption'] += 1
            elif api == 'CryptEncrypt':
                patterns['crypto_api_usage'] += 1
            elif api == 'RegSetValueExW':
                patterns['registry_persistence'] += 1
            elif api == 'CreateProcessW':
                # Check for vssadmin delete shadows
                cmd = call.get('args', {}).get('command', '')
                if 'vssadmin' in cmd.lower() and 'delete' in cmd.lower():
                    patterns['shadow_copy_deletion'] += 1
        
        print("\n🎯 Ransomware Pattern Detection:")
        print(f"   Mass file writes: {patterns['mass_file_write']}")
        print(f"   Mass file deletes: {patterns['mass_file_delete']}")
        print(f"   File encryption renames: {patterns['file_rename_encryption']}")
        print(f"   Crypto API calls: {patterns['crypto_api_usage']}")
        print(f"   Registry modifications: {patterns['registry_persistence']}")
        print(f"   Shadow copy deletion: {patterns['shadow_copy_deletion']}")
        
        # Calculate ransomware probability score
        score = 0
        if patterns['mass_file_write'] > 50:
            score += 25
        if patterns['file_rename_encryption'] > 10:
            score += 30
        if patterns['crypto_api_usage'] > 0:
            score += 20
        if patterns['shadow_copy_deletion'] > 0:
            score += 25
        
        print(f"\n🚨 Ransomware Probability Score: {score}/100")
        
        return patterns
    
    def save_results(self, output_file: str = "api_trace.json"):
        """Save API trace to JSON"""
        data = {
            'target': sys.argv[1] if len(sys.argv) > 1 else 'unknown',
            'timestamp': datetime.now().isoformat(),
            'total_calls': len(self.api_sequence),
            'api_sequence': self.api_sequence,
            'duration': self.api_sequence[-1]['timestamp'] if self.api_sequence else 0
        }
        
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n💾 API trace saved to: {output_path}")
        return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python vm_api_tracer.py <target.exe|target.py>")
        print("\nExample:")
        print("  python vm_api_tracer.py ransomware_simulator.py")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("="*80)
    print("API Call Sequence Tracer (Frida-based)")
    print("="*80)
    
    # Check if Frida is installed
    try:
        import frida
    except ImportError:
        print("\n❌ Frida not installed!")
        print("Install with: pip install frida frida-tools")
        sys.exit(1)
    
    # Create tracer
    tracer = APITracer()
    
    # Trace the target
    tracer.trace_process(target)
    
    # Analyze patterns
    tracer.analyze_sequence()
    
    # Save results
    tracer.save_results()
    
    print("\n✅ Tracing complete!")
    print("="*80)


if __name__ == "__main__":
    main()
