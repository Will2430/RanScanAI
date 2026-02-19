"""
API Call Sequence Tracer using Frida - NTDLL VERSION
Hooks lower-level NT APIs that Python actually uses

Python's pathlib/os → msvcrt → ntdll.dll (THIS IS WHERE WE HOOK!)

Requirements: pip install frida frida-tools

Usage:
    python vm_api_tracer_ntdll.py ransomware_simulator.py
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime

# Fix Windows console encoding
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


class NTAPITracer:
    """Trace NT-level API calls (lower level than kernel32.dll)"""
    
    def __init__(self):
        self.api_sequence = []
        self.start_time = None
        self.file_paths = {}  # Track handle -> path mappings
        
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']
            
            # Handle initialization message
            if payload.get('api') == 'init':
                print(f"   ✓ {payload.get('args', {}).get('message', 'Hooks installed')}")
                return
            
            # Handle debug messages
            if payload.get('api') == 'debug':
                args = payload.get('args', {})
                if 'error' in args:
                    print(f"[DEBUG ERROR] {args['error']}")
                elif 'msg' in args:
                    print(f"[DEBUG] {args['msg']}")
                return
            
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
            
            # Print to console
            api_name = api_call['api']
            args = api_call.get('args', {})
            
            # Format output based on API type
            if 'path' in args:
                print(f"[{api_call['timestamp']:.3f}s] {api_name} -> {args.get('path', 'N/A')}")
            elif 'from_path' in args:
                print(f"[{api_call['timestamp']:.3f}s] {api_name} -> {args.get('from_path')} ➜ {args.get('to_path')}")
            elif 'bytes' in args:
                print(f"[{api_call['timestamp']:.3f}s] {api_name} -> {args.get('bytes')} bytes")
            else:
                print(f"[{api_call['timestamp']:.3f}s] {api_name}")
        
        elif message['type'] == 'error':
            print(f"[ERROR] {message.get('description', 'Unknown error')}")
            if 'stack' in message:
                print(f"   Stack: {message['stack']}")
            if 'lineNumber' in message:
                print(f"   Line: {message['lineNumber']}")
    
    def get_frida_script(self):
        """
        Frida JavaScript to hook NT-level APIs (ntdll.dll)
        Python uses these lower-level functions!
        """
        return """
        // Hook NT-level APIs - Frida 17+ API
        
        var ntdll = Process.getModuleByName('ntdll.dll');
        var advapi32 = Process.getModuleByName('advapi32.dll');
        
        // FILE OPERATIONS (NT Level)
        var NtCreateFile = ntdll.getExportByName('NtCreateFile');
        var NtWriteFile = ntdll.getExportByName('NtWriteFile');
        var NtReadFile = ntdll.getExportByName('NtReadFile');
        var NtSetInformationFile = ntdll.getExportByName('NtSetInformationFile');
        var NtClose = ntdll.getExportByName('NtClose');
        
        // REGISTRY OPERATIONS (NT Level)
        var NtSetValueKey = ntdll.getExportByName('NtSetValueKey');
        
        // Helper to safely read UNICODE_STRING structure
        function readUnicodeString(ptr) {
            try {
                if (!ptr || ptr.isNull()) return null;
                var length = ptr.readU16();
                if (length === 0 || length > 2048) return null;  // Sanity check
                var buffer = ptr.add(8).readPointer();  // Buffer is at offset 8 on x64
                if (!buffer || buffer.isNull()) return null;
                return buffer.readUtf16String(length / 2);
            } catch (e) {
                send({api: 'debug', args: {error: 'readUnicodeString: ' + e.toString()}});
                return null;
            }
        }
        
        // Helper to read OBJECT_ATTRIBUTES and extract path
        function readObjectAttributes(ptr) {
            try {
                if (!ptr || ptr.isNull()) {
                    send({api: 'debug', args: {msg: 'OBJECT_ATTRIBUTES ptr is null'}});
                    return null;
                }
                // OBJECT_ATTRIBUTES structure:
                // +0x00 Length : Uint4B
                // +0x08 RootDirectory : Ptr64
                // +0x10 ObjectName : Ptr64 UNICODE_STRING
                var objectName = ptr.add(0x10).readPointer();
                if (!objectName || objectName.isNull()) {
                    send({api: 'debug', args: {msg: 'ObjectName ptr is null'}});
                    return null;
                }
                var path = readUnicodeString(objectName);
                if (!path) {
                    send({api: 'debug', args: {msg: 'Path extraction returned null'}});
                }
                return path;
            } catch (e) {
                send({api: 'debug', args: {error: 'readObjectAttributes: ' + e.toString()}});
                return null;
            }
        }
        
        // Track file handle -> path mappings
        var fileHandles = {};
        
        // Hook NtCreateFile - File creation/opening
        if (NtCreateFile) {
            Interceptor.attach(NtCreateFile, {
                onEnter: function(args) {
                    send({api: 'debug', args: {msg: 'NtCreateFile hook called'}});
                    this.fileHandlePtr = args[0];
                    this.objectAttributes = args[2];
                    this.filePath = readObjectAttributes(this.objectAttributes);
                },
                onLeave: function(retval) {
                    if (this.filePath && retval.toInt32() === 0) {
                        try {
                            var handle = this.fileHandlePtr.readPointer();
                            var handleKey = handle.toString();
                            fileHandles[handleKey] = this.filePath;
                            
                            send({
                                api: 'NtCreateFile',
                                args: { path: this.filePath },
                                return: '0x' + retval.toString(16),
                                thread_id: Process.getCurrentThreadId()
                            });
                        } catch (e) {}
                    }
                }
            });
        }
        
        // Hook NtWriteFile - File writing
        if (NtWriteFile) {
            Interceptor.attach(NtWriteFile, {
                onEnter: function(args) {
                    this.fileHandle = args[0];
                    this.length = args[6].toInt32();
                },
                onLeave: function(retval) {
                    var status = retval.toInt32();
                    if (status === 0 || status === 0x103) {
                        var handleKey = this.fileHandle.toString();
                        var path = fileHandles[handleKey] || 'unknown';
                        
                        send({
                            api: 'NtWriteFile',
                            args: { 
                                path: path,
                                bytes: this.length 
                            },
                            return: '0x' + retval.toString(16),
                            thread_id: Process.getCurrentThreadId()
                        });
                    }
                }
            });
        }
        
        // Hook NtReadFile - File reading
        if (NtReadFile) {
            Interceptor.attach(NtReadFile, {
                onEnter: function(args) {
                    this.fileHandle = args[0];
                    this.length = args[6].toInt32();
                },
                onLeave: function(retval) {
                    var status = retval.toInt32();
                    if (status === 0 || status === 0x103) {
                        var handleKey = this.fileHandle.toString();
                        var path = fileHandles[handleKey] || 'unknown';
                        
                        send({
                            api: 'NtReadFile',
                            args: { 
                                path: path,
                                bytes: this.length 
                            },
                            return: '0x' + retval.toString(16),
                            thread_id: Process.getCurrentThreadId()
                        });
                    }
                }
            });
        }
        
        // Hook NtSetInformationFile - Used for file rename/delete
        if (NtSetInformationFile) {
            Interceptor.attach(NtSetInformationFile, {
                onEnter: function(args) {
                    this.fileHandle = args[0];
                    this.infoClass = args[4].toInt32();
                    
                    // FileRenameInformation = 10
                    if (this.infoClass === 10) {
                        try {
                            var fileInfo = args[2];
                            var fileNameLength = fileInfo.add(16).readU32();
                            var fileName = fileInfo.add(20).readUtf16String(fileNameLength / 2);
                            this.newName = fileName;
                        } catch (e) {
                            this.newName = null;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) {
                        var handleKey = this.fileHandle.toString();
                        var path = fileHandles[handleKey] || 'unknown';
                        
                        if (this.infoClass === 10 && this.newName) {
                            send({
                                api: 'NtSetInformationFile_Rename',
                                args: { 
                                    from_path: path,
                                    to_path: this.newName
                                },
                                return: '0x' + retval.toString(16),
                                thread_id: Process.getCurrentThreadId()
                            });
                        } else if (this.infoClass === 13) {
                            send({
                                api: 'NtSetInformationFile_Delete',
                                args: { path: path },
                                return: '0x' + retval.toString(16),
                                thread_id: Process.getCurrentThreadId()
                            });
                        }
                    }
                }
            });
        }
        
        // Hook NtClose - Clean up handle tracking
        if (NtClose) {
            Interceptor.attach(NtClose, {
                onEnter: function(args) {
                    var handleKey = args[0].toString();
                    if (fileHandles[handleKey]) {
                        delete fileHandles[handleKey];
                    }
                }
            });
        }
        
        // Hook NtSetValueKey - Registry write
        if (NtSetValueKey) {
            Interceptor.attach(NtSetValueKey, {
                onEnter: function(args) {
                    this.valueName = readUnicodeString(args[1]);
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.valueName) {
                        send({
                            api: 'NtSetValueKey',
                            args: { value_name: this.valueName },
                            return: '0x' + retval.toString(16),
                            thread_id: Process.getCurrentThreadId()
                        });
                    }
                }
            });
        }
        
        send({api: 'init', args: {message: 'NT-level API hooks installed'}});
        """
    
    def trace_process(self, target_path: str):
        """Spawn process and trace API calls"""
        import frida
        
        print(f"🔍 Starting NT-level API tracer for: {target_path}")
        print(f"   Hooking ntdll.dll (lower level - Python uses this!)\n")
        
        # Spawn the process with Frida
        if target_path.endswith('.py'):
            device = frida.get_local_device()
            # Get absolute path
            target_abs = str(Path(target_path).resolve())
            cwd = str(Path(target_path).resolve().parent)
            
            print(f"   Target: {target_abs}")
            print(f"   CWD: {cwd}\n")
            
            pid = device.spawn([sys.executable, target_abs, '--auto-run'], cwd=cwd)
            session = device.attach(pid)
        else:
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
        print("📊 Capturing NT-level API calls...\n")
        
        # Monitor for 90 seconds
        try:
            start_time = time.time()
            duration = 90
            
            while time.time() - start_time < duration:
                elapsed = int(time.time() - start_time)
                if elapsed % 10 == 0 and elapsed > 0:
                    print(f"   ⏱️  {elapsed}s elapsed... ({len(self.api_sequence)} calls captured)")
                    time.sleep(1)
                else:
                    time.sleep(0.5)
                    
        except KeyboardInterrupt:
            print("\n⚠️  Interrupted by user")
        
        # Detach
        session.detach()
        
        print(f"\n✅ Captured {len(self.api_sequence)} NT-level API calls")
    
    def analyze_sequence(self):
        """Analyze API call patterns"""
        print("\n📊 Analyzing API call patterns...")
        
        patterns = {
            'mass_file_creation': 0,
            'mass_file_write': 0,
            'file_rename_operations': 0,
            'file_delete_operations': 0,
            'registry_writes': 0
        }
        
        for call in self.api_sequence:
            api = call.get('api', '')
            
            if 'NtCreateFile' in api:
                patterns['mass_file_creation'] += 1
            elif 'NtWriteFile' in api:
                patterns['mass_file_write'] += 1
            elif 'Rename' in api:
                patterns['file_rename_operations'] += 1
            elif 'Delete' in api:
                patterns['file_delete_operations'] += 1
            elif 'NtSetValueKey' in api:
                patterns['registry_writes'] += 1
        
        print(f"\n   File creations: {patterns['mass_file_creation']}")
        print(f"   File writes: {patterns['mass_file_write']}")
        print(f"   File renames: {patterns['file_rename_operations']}")
        print(f"   File deletes: {patterns['file_delete_operations']}")
        print(f"   Registry writes: {patterns['registry_writes']}")
        
        # Detect ransomware patterns
        if patterns['file_rename_operations'] > 50 and patterns['mass_file_write'] > 50:
            print(f"\n   🚨 RANSOMWARE PATTERN DETECTED: Mass file write + rename")
        
        return patterns
    
    def save_results(self):
        """Save API sequence to JSON"""
        output_file = Path("api_trace_ntdll.json")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_calls': len(self.api_sequence),
            'api_sequence': self.api_sequence
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Saved API trace to: {output_file}")
        return output_file


def main():
    if len(sys.argv) < 2:
        print("Usage: python vm_api_tracer_ntdll.py <target.py|target.exe>")
        print("\nExample:")
        print("  python vm_api_tracer_ntdll.py ransomware_simulator.py")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("="*80)
    print("NT-Level API Call Tracer (Frida + ntdll.dll)")
    print("="*80)
    
    # Check if Frida is installed
    try:
        import frida
    except ImportError:
        print("\n❌ Frida not installed!")
        print("Install with: pip install frida frida-tools")
        sys.exit(1)
    
    # Create tracer
    tracer = NTAPITracer()
    
    # Trace the target
    tracer.trace_process(target)
    
    # Analyze patterns
    tracer.analyze_sequence()
    
    # Save results
    tracer.save_results()
    
    print("\n✅ NT-level tracing complete!")
    print("="*80)


if __name__ == "__main__":
    main()
