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


def _get_base_python() -> str:
    """
    Return the real python.exe from the base installation, not the venv stub.

    On Windows, a venv's python.exe is a ~30 KB launcher stub whose static IAT
    only links kernel32 + VCRUNTIME. It resolves python3xx.dll at runtime via a
    registry lookup, so ws2_32 / dnsapi / bcrypt are NOT in the loader's DLL
    graph when Frida installs hooks at spawn-time — making all network/crypto
    hooks miss on first run.

    The base python.exe has python3xx.dll in its static IAT, which transitively
    pulls in the full DLL chain before the first instruction, so Frida finds all
    modules present and installs hooks correctly.
    """
    cfg = Path(sys.prefix) / 'pyvenv.cfg'
    if cfg.exists():
        for line in cfg.read_text(encoding='utf-8', errors='replace').splitlines():
            if line.lower().startswith('home'):
                base_dir = line.split('=', 1)[1].strip()
                candidate = Path(base_dir) / 'python.exe'
                if candidate.exists():
                    return str(candidate)
    # Not a venv, or pyvenv.cfg missing — use current interpreter directly
    return sys.executable


def _get_spawn_env() -> dict:
    """
    Return an environment dict for the spawned child process.

    The child is always spawned with the BASE python.exe (real IAT, not a venv
    stub) so Frida hooks fire before ws2_32/dnsapi/bcrypt are loaded. But that
    interpreter knows nothing about the current env's site-packages.

    We resolve the correct site-packages using two strategies, in order:

    1. Co-located venv: look for a '.venvv' folder next to THIS script file.
       This works whether the tracer is launched from the venv itself, from
       a conda env (torch-gpu), or from the base Python. The spawned child
       always gets cryptography/frida from the same place.

    2. Current-env fallback: if no co-located venv exists (e.g. fresh checkout)
       inject the current interpreter's site-packages. This handles the case
       where the user installed everything globally or into the active env.

    NOTE: do NOT call this for PyInstaller EXE spawns — passing PYTHONPATH into
    a bundled EXE causes module conflicts that crash it silently.
    """
    env = dict(os.environ)  # Frida spawn() requires a plain dict, not os._Environ

    # Strategy 1: co-located .venvv next to this script
    script_dir = Path(__file__).resolve().parent
    colocated_venv_site = script_dir / '.venvv' / 'Lib' / 'site-packages'
    # Also check the workspace root (one level up), which is where .venvv lives
    workspace_venv_site = script_dir.parent.parent / '.venvv' / 'Lib' / 'site-packages'

    if colocated_venv_site.exists():
        site = str(colocated_venv_site)
    elif workspace_venv_site.exists():
        site = str(workspace_venv_site)
    else:
        # Strategy 2: current interpreter's site-packages
        site = str(Path(sys.prefix) / 'Lib' / 'site-packages')

    existing = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = site + (os.pathsep + existing if existing else '')
    return env


# ── Frida shorthand → canonical Windows API names (matches MalBehavD/Kaggle vocab) ──
# Used to normalise api_sequence before writing JSON so the CNN can consume it directly.
FRIDA_TO_CANONICAL = {
    # Registry
    'reg_read':              'NtOpenKey',
    'reg_write':             'NtSetValueKey',
    # File
    'file_create':           'NtCreateFile',
    'file_write':            'NtWriteFile',
    'file_read':             'NtReadFile',
    'file_rename':           'NtSetInformationFile',
    'file_delete':           'NtSetInformationFile',
    'NtSetInformationFile_Rename': 'NtSetInformationFile',
    'NtSetInformationFile_Delete': 'NtSetInformationFile',
    # Network — user confirmed DnsQuery_A matches dataset vocab
    'dns_query':             'DnsQuery_A',
    'net_connect':           'connect',
    'net_sendto':            'send',
    # Crypto (BCrypt)
    'bcrypt_gen_random':     'BCryptGenRandom',
    'bcrypt_open_alg':       'BCryptOpenAlgorithmProvider',
    'bcrypt_encrypt':        'BCryptEncrypt',
    'bcrypt_decrypt':        'BCryptDecrypt',
    'bcrypt_gen_key':        'BCryptGenerateSymmetricKey',
    'bcrypt_import_key':     'BCryptImportKeyPair',
    # Process
    'proc_enum':             'NtQuerySystemInformation',
}


class NTAPITracer:
    """Trace NT-level API calls (lower level than kernel32.dll)"""
    
    def __init__(self):
        self.api_sequence = []   # batched rename/delete detail events
        self.start_time = None
        self.file_paths = {}
        # Accumulated counter totals from JS-side periodic flushes
        self.counters = {
            'file_creates': 0, 'file_writes': 0, 'file_reads': 0,
            'file_renames': 0, 'file_deletes': 0,
            'reg_reads': 0,    'reg_writes': 0,
            'net_dns': 0,      'net_connect': 0, 'net_sendto': 0,
            'proc_enum': 0,    'crypto_ops':  0,
        }
        
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']
            api = payload.get('api', '')

            if api == 'init':
                print(f"   ✓ {payload.get('args', {}).get('message', 'Hooks installed')}")
                return

            if api == 'debug':
                args = payload.get('args', {})
                print(f"[DEBUG] {args.get('msg') or args.get('error', '')}")
                return

            # Periodic JS-side counter flush (batched renames/deletes included)
            if api == 'counts':
                c = payload.get('args', {})
                # Always take the maximum seen value (counters are monotonic in JS)
                for k in self.counters:
                    self.counters[k] = max(self.counters[k], c.get(k, 0))

                # Absorb batched rename/delete detail events from JS queue drain
                t0 = self.start_time or time.time()
                if self.start_time is None:
                    self.start_time = t0
                ts = time.time() - t0
                for r in payload.get('renames', []):
                    self.api_sequence.append({
                        'timestamp': ts, 'api': 'NtSetInformationFile_Rename',
                        'args': {'from_path': r.get('from', 'unknown'),
                                 'to_path':   r.get('to',   'unknown')}
                    })
                for d in payload.get('deletes', []):
                    self.api_sequence.append({
                        'timestamp': ts, 'api': 'NtSetInformationFile_Delete',
                        'args': {'path': d}
                    })
                for s in payload.get('sequence', []):
                    self.api_sequence.append({
                        'timestamp': float(s.get('t', 0)),
                        'api':  s.get('api', ''),
                        'args': s.get('a', {}),
                    })

                reg    = self.counters['reg_reads']
                dns    = self.counters['net_dns']
                conn   = self.counters['net_connect']
                proc   = self.counters['proc_enum']
                fcr    = self.counters['file_creates']
                crypto = self.counters['crypto_ops']
                print(f"   [counts] reg_reads={reg}  dns={dns}  connects={conn}  "
                      f"proc_enum={proc}  file_creates={fcr}  crypto_ops={crypto}")
                return

        elif message['type'] == 'error':
            print(f"[ERROR] {message.get('description', 'Unknown error')}")
            if 'stack' in message:
                print(f"   Stack: {message['stack']}")
            if 'lineNumber' in message:
                print(f"   Line: {message['lineNumber']}")
    
    def get_frida_script(self):
        """
        Frida JavaScript to hook NT-level APIs (ntdll.dll)

        Design principles to avoid message queue flooding:
          - ALL high-frequency calls (registry, file r/w, net) are ONLY counted
            in JS-side counters (never send() per call).
          - Rename/delete detail events are accumulated in JS-side bounded arrays
            (max 20 entries) and drained atomically inside the periodic flush.
          - Flush interval is 5 s instead of 3 s — one send() per flush cycle.
          - ws2_32 hooks are installed lazily via LoadLibraryW/A so they work
            even when the DLL loads after the script is injected (PyInstaller EXEs).
          - KernelBase/advapi32 registry fallbacks are removed to prevent
            double-counting (they call the ntdll hooks internally anyway).
          - fileHandles map is capped at MAX_HANDLES entries to prevent JS heap
            bloat inside the target process.
          - BCryptEncrypt / BCryptGenRandom / BCryptDecrypt hooks added for
            modern crypto detection.
        """
        return """
        'use strict';

        var ntdll    = Process.getModuleByName('ntdll.dll');
        var kernel32 = Process.findModuleByName('kernel32.dll');

        // ── JS-side counters ──────────────────────────────────────────────────
        var C = {
            file_creates: 0, file_writes:  0, file_reads:   0,
            file_renames: 0, file_deletes: 0,
            reg_reads:    0, reg_writes:   0,
            net_dns:      0, net_connect:  0, net_sendto:   0,
            proc_enum:    0, crypto_ops:   0,
        };

        // ── Bounded event detail queues (drained in flush, never via send()) ──
        var renameQueue = [];
        var deleteQueue = [];
        var MAX_QUEUE   = 20;   // cap per-batch detail; counters still exact

        // ── Sequence recording (sampled — never blocks counters) ─────────────
        // High-frequency hooks (file, registry) are sampled 1-in-25 to avoid
        // overwhelming the JS heap. Low-frequency hooks (dns, connect, crypto)
        // record every call with arguments. All events are drained atomically
        // inside the existing setInterval flush — zero extra send() calls.
        var sequenceQueue = [];
        var MAX_SEQ       = 2000;  // max events buffered between flushes
        var T0            = Date.now();
        function seqPush(api, args) {
            if (sequenceQueue.length >= MAX_SEQ) return;
            sequenceQueue.push({ t: ((Date.now() - T0) / 1000).toFixed(3), api: api, a: args || {} });
        }

        // ── Helpers ───────────────────────────────────────────────────────────
        function readUnicodeString(ptr) {
            try {
                if (!ptr || ptr.isNull()) return null;
                var len = ptr.readU16();
                if (len === 0 || len > 4096) return null;
                var buf = ptr.add(8).readPointer();
                if (!buf || buf.isNull()) return null;
                return buf.readUtf16String(len / 2);
            } catch(e) { return null; }
        }

        function readObjectAttributes(ptr) {
            try {
                if (!ptr || ptr.isNull()) return null;
                var objName = ptr.add(0x10).readPointer();
                if (!objName || objName.isNull()) return null;
                return readUnicodeString(objName);
            } catch(e) { return null; }
        }

        // ── Periodic flush every 5 s — ONE send() per cycle ──────────────────
        setInterval(function() {
            // splice() atomically drains all queues — ONE send() per cycle
            var rdrains = renameQueue.splice(0);
            var ddrains = deleteQueue.splice(0);
            var sdrains = sequenceQueue.splice(0);
            send({
                api:      'counts',
                args:     { file_creates: C.file_creates, file_writes:  C.file_writes,
                            file_reads:   C.file_reads,   file_renames: C.file_renames,
                            file_deletes: C.file_deletes,
                            reg_reads:    C.reg_reads,    reg_writes:   C.reg_writes,
                            net_dns:      C.net_dns,      net_connect:  C.net_connect,
                            net_sendto:   C.net_sendto,   proc_enum:    C.proc_enum,
                            crypto_ops:   C.crypto_ops },
                renames:  rdrains,
                deletes:  ddrains,
                sequence: sdrains,
            });
        }, 1000);

        // ── File handle map with eviction cap ─────────────────────────────────
        var fileHandles     = {};
        var fileHandleCount = 0;
        var MAX_HANDLES     = 500;

        function trackHandle(h, path) {
            if (!fileHandles[h]) fileHandleCount++;
            fileHandles[h] = path;
            // Evict oldest entry when cap exceeded
            if (fileHandleCount > MAX_HANDLES) {
                var keys = Object.keys(fileHandles);
                delete fileHandles[keys[0]];
                fileHandleCount--;
            }
        }

        function releaseHandle(h) {
            if (fileHandles[h]) {
                delete fileHandles[h];
                fileHandleCount--;
            }
        }

        // ── FILE HOOKS ────────────────────────────────────────────────────────
        var NtCreateFile = ntdll.getExportByName('NtCreateFile');
        if (NtCreateFile) {
            Interceptor.attach(NtCreateFile, {
                onEnter: function(args) {
                    this.hp   = args[0];
                    this.path = readObjectAttributes(args[2]);
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) {
                        // Count ALL successful creates, even when path is null.
                        // CreateFileW sometimes passes RootDirectory + relative path,
                        // leaving ObjectName null — don't skip those.
                        if (this.path) {
                            try { trackHandle(this.hp.readPointer().toString(), this.path); } catch(e) {}
                        }
                        C.file_creates++;
                        // Sequence: record every file create that has a resolved path
                        if (this.path) seqPush('file_create', {p: this.path});
                    }
                }
            });
        }

        var NtWriteFile = ntdll.getExportByName('NtWriteFile');
        if (NtWriteFile) {
            Interceptor.attach(NtWriteFile, {
                onEnter: function(args) { C.file_writes++; }
            });
        }

        var NtReadFile = ntdll.getExportByName('NtReadFile');
        if (NtReadFile) {
            Interceptor.attach(NtReadFile, {
                onEnter: function(args) { C.file_reads++; }
            });
        }

        var NtSetInformationFile = ntdll.getExportByName('NtSetInformationFile');
        if (NtSetInformationFile) {
            Interceptor.attach(NtSetInformationFile, {
                onEnter: function(args) {
                    this.fh        = args[0];
                    this.infoClass = args[4].toInt32();
                    this.newName   = null;
                    if (this.infoClass === 10) {   // FileRenameInformation
                        try {
                            var fi = args[2];
                            var fl = fi.add(16).readU32();
                            this.newName = fi.add(20).readUtf16String(fl / 2);
                        } catch(e) {}
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) return;
                    var path = fileHandles[this.fh.toString()] || 'unknown';
                    if (this.infoClass === 10) {
                        C.file_renames++;
                        // Batch into queue — flushed with next setInterval tick
                        if (renameQueue.length < MAX_QUEUE)
                            renameQueue.push({ from: path, to: this.newName || 'unknown' });
                    } else if (this.infoClass === 13) {
                        C.file_deletes++;
                        if (deleteQueue.length < MAX_QUEUE)
                            deleteQueue.push(path);
                    }
                }
            });
        }

        var NtClose = ntdll.getExportByName('NtClose');
        if (NtClose) {
            Interceptor.attach(NtClose, {
                onEnter: function(args) { releaseHandle(args[0].toString()); }
            });
        }

        // ── REGISTRY HOOKS (ntdll only — avoids double-count via KernelBase) ──
        // KernelBase.RegOpenKeyExW → NtOpenKey internally, so hooking both
        // would inflate reads 2x. Hook only at the ntdll boundary.
        var NtSetValueKey = ntdll.getExportByName('NtSetValueKey');
        if (NtSetValueKey) {
            Interceptor.attach(NtSetValueKey, { onEnter: function(args) { C.reg_writes++; } });
            send({api:'debug', args:{msg:'hook:NtSetValueKey OK'}});
        } else { send({api:'debug', args:{msg:'hook:NtSetValueKey NOT FOUND'}}); }

        var NtOpenKey = ntdll.getExportByName('NtOpenKey');
        if (NtOpenKey) {
            var _nokHits = 0;
            Interceptor.attach(NtOpenKey, { onEnter: function(args) {
                C.reg_reads++;
                _nokHits++;
                // Milestone sends — tells us if the hook fires past startup count
                if (_nokHits === 26 || _nokHits === 100 || _nokHits === 500 || _nokHits === 1000) {
                    send({api:'debug', args:{msg:'NtOpenKey milestone _nokHits='+_nokHits+' C.reg_reads='+C.reg_reads}});
                }
                // Sequence: sample 1-in-25 registry opens with key path
                if (C.reg_reads % 25 === 0) seqPush('reg_read', {k: readObjectAttributes(args[2]) || ''});
            }});
            send({api:'debug', args:{msg:'hook:NtOpenKey OK addr='+NtOpenKey}});
        } else { send({api:'debug', args:{msg:'hook:NtOpenKey NOT FOUND'}}); }

        var NtOpenKeyEx = ntdll.getExportByName('NtOpenKeyEx');
        if (NtOpenKeyEx) {
            Interceptor.attach(NtOpenKeyEx, { onEnter: function(args) {
                C.reg_reads++;
                if (C.reg_reads % 25 === 0) seqPush('reg_read', {k: readObjectAttributes(args[2]) || ''});
            } });
            send({api:'debug', args:{msg:'hook:NtOpenKeyEx OK'}});
        } else { send({api:'debug', args:{msg:'hook:NtOpenKeyEx NOT FOUND'}}); }

        var NtEnumerateValueKey = ntdll.getExportByName('NtEnumerateValueKey');
        if (NtEnumerateValueKey) {
            Interceptor.attach(NtEnumerateValueKey, { onEnter: function(args) { C.reg_reads++; } });
            send({api:'debug', args:{msg:'hook:NtEnumerateValueKey OK'}});
        } else { send({api:'debug', args:{msg:'hook:NtEnumerateValueKey NOT FOUND'}}); }

        var NtQueryValueKey = ntdll.getExportByName('NtQueryValueKey');
        if (NtQueryValueKey) {
            Interceptor.attach(NtQueryValueKey, { onEnter: function(args) { C.reg_reads++; } });
            send({api:'debug', args:{msg:'hook:NtQueryValueKey OK'}});
        } else { send({api:'debug', args:{msg:'hook:NtQueryValueKey NOT FOUND'}}); }

        // ── NETWORK HOOKS (lazy — installed when ws2_32/dnsapi actually load) ──
        // Python socket.gethostbyname() calls:
        //   ws2_32!getaddrinfo → ws2_32!GetAddrInfoW → ws2_32!WSALookupServiceBeginW
        //   → dnsapi!DnsQueryEx (the real DNS call)
        //
        // IMPORTANT — module-base guard instead of boolean guard:
        // AV/AMSI DLLs injected after spawn can overwrite Frida's E9 trampolines
        // on high-value exports (NtOpenKey, DnsQueryEx, BCryptGenRandom, etc.).
        // Periodic re-hook (every 3 s) detects this by comparing the stored module
        // base address against the current one; if the DLL was unloaded/reloaded at
        // a new address, or if the first byte is no longer 0xE9, we re-attach.
        var _ws2Base     = null;   // ptr — base of ws2_32.dll when last hooked
        var _dnsapiBase  = null;   // ptr — base of dnsapi.dll when last hooked
        var _bcryptBase  = null;   // ptr — base of bcrypt.dll when last hooked

        // Safely re-attach: catches the "already attached" exception so double-hooks
        // are silently ignored, while NEW hooks (different address) succeed.
        function safeAttach(addr, callbacks) {
            try { Interceptor.attach(addr, callbacks); } catch(e) {}
        }

        // Helper: safely get an export address — returns null instead of throwing.
        function safeExport(modName, name) {
            try { return Module.getExportByName(modName, name); } catch(e) { return null; }
        }

        function hookWs2() {
            var ws2Mod = null;
            Process.enumerateModules().forEach(function(m) {
                if (m.name.toLowerCase() === 'ws2_32.dll') ws2Mod = m;
            });
            if (!ws2Mod) return;
            // Skip if same module base (avoid unnecessary Interceptor.reattach noise)
            if (_ws2Base && _ws2Base.equals(ws2Mod.base)) return;
            _ws2Base = ws2Mod.base;
            var _ghn  = ws2Mod.findExportByName('gethostbyname');
            var _gai  = ws2Mod.findExportByName('getaddrinfo');
            var _conn = ws2Mod.findExportByName('connect');
            var _sto  = ws2Mod.findExportByName('sendto');
            var _wsac = ws2Mod.findExportByName('WSAConnect');
            if (_ghn)  safeAttach(_ghn,  { onEnter: function() {} });
            if (_gai)  safeAttach(_gai,  { onEnter: function() {} });
            if (_conn) safeAttach(_conn, { onEnter: function() { C.net_connect++; seqPush('net_connect', {}); } });
            if (_sto)  safeAttach(_sto,  { onEnter: function() { C.net_sendto++;  seqPush('net_sendto',  {}); } });
            if (_wsac) safeAttach(_wsac, { onEnter: function() { C.net_connect++; seqPush('net_connect', {}); } });
            send({api:'debug', args:{msg:'ws2_32 network hooks installed @ '+ws2Mod.base}});
        }

        function hookDnsapi() {
            var dnsapiMod = null;
            Process.enumerateModules().forEach(function(m) {
                if (m.name.toLowerCase() === 'dnsapi.dll') dnsapiMod = m;
            });
            if (!dnsapiMod) return;
            if (_dnsapiBase && _dnsapiBase.equals(dnsapiMod.base)) return;
            _dnsapiBase = dnsapiMod.base;
            var dnsQueryEx = dnsapiMod.findExportByName('DnsQueryEx');
            var dnsQueryW  = dnsapiMod.findExportByName('DnsQuery_W');
            var installed  = [];
            if (dnsQueryEx) { safeAttach(dnsQueryEx, { onEnter: function(args) {
                C.net_dns++;
                try { var h = args[0].add(8).readPointer().readUtf16String(); seqPush('dns_query', {h: h}); }
                catch(e) { seqPush('dns_query', {}); }
            }}); installed.push('DnsQueryEx'); }
            if (dnsQueryW)  { safeAttach(dnsQueryW,  { onEnter: function(args) {
                C.net_dns++;
                try { var h = args[0].readUtf16String(); seqPush('dns_query', {h: h}); }
                catch(e) { seqPush('dns_query', {}); }
            }}); installed.push('DnsQuery_W'); }
            send({api:'debug', args:{msg:'dnsapi hooks installed: '+installed.join(',')+' @ '+dnsapiMod.base}});
        }

        // Try immediately first (DLLs may already be present)
        try { Module.load('ws2_32.dll'); } catch(e) {}
        try { Module.load('dnsapi.dll'); } catch(e) {}
        hookWs2();
        hookDnsapi();

        // Lazy fallback: watch LoadLibraryW/A for deferred DLL loads
        var _llw = safeExport('kernel32.dll', 'LoadLibraryW')
                || safeExport('KernelBase.dll', 'LoadLibraryW');
        var _lla = safeExport('kernel32.dll', 'LoadLibraryA')
                || safeExport('KernelBase.dll', 'LoadLibraryA');
        if (_llw) {
            Interceptor.attach(_llw, {
                onEnter: function(args) {
                    try { this.name = args[0].readUtf16String().toLowerCase(); } catch(e) { this.name = ''; }
                },
                onLeave: function() {
                    if (this.name) {
                        if (this.name.indexOf('ws2_32') !== -1) hookWs2();
                        if (this.name.indexOf('dnsapi') !== -1) hookDnsapi();
                        if (this.name.indexOf('bcrypt') !== -1) hookBcrypt();
                    }
                }
            });
        }
        if (_lla) {
            Interceptor.attach(_lla, {
                onEnter: function(args) {
                    try { this.name = args[0].readUtf8String().toLowerCase(); } catch(e) { this.name = ''; }
                },
                onLeave: function() {
                    if (this.name) {
                        if (this.name.indexOf('ws2_32') !== -1) hookWs2();
                        if (this.name.indexOf('dnsapi') !== -1) hookDnsapi();
                        if (this.name.indexOf('bcrypt') !== -1) hookBcrypt();
                    }
                }
            });
        }
        // LoadLibraryExW — used by PyInstaller bootloader to load bundled DLLs
        // from the temp extraction dir. Without this hook, dnsapi/bcrypt are
        // never intercepted in PyInstaller EXEs because LoadLibraryW/A are
        // never called for those DLLs.
        var _llew = safeExport('kernel32.dll', 'LoadLibraryExW')
                 || safeExport('KernelBase.dll', 'LoadLibraryExW');
        if (_llew) {
            Interceptor.attach(_llew, {
                onEnter: function(args) {
                    try { this.name = args[0].readUtf16String().toLowerCase(); } catch(e) { this.name = ''; }
                },
                onLeave: function() {
                    if (this.name) {
                        if (this.name.indexOf('ws2_32') !== -1) hookWs2();
                        if (this.name.indexOf('dnsapi') !== -1) hookDnsapi();
                        if (this.name.indexOf('bcrypt') !== -1) hookBcrypt();
                    }
                }
            });
            send({api:'debug', args:{msg:'hook:LoadLibraryExW OK (PyInstaller DLL watcher)'}});
        }

        // ── BCRYPT / WINCRYPT HOOKS (modern + legacy crypto) ──────────────────
        // bcrypt.dll is loaded lazily by Python when ctypes.windll.bcrypt is
        // first accessed. We hook it immediately if available, and also via
        // the LoadLibrary watcher above. A 2-second retry handles cases where
        // the simulator loads bcrypt.dll after process startup.
        var _bcryptHooked = false;
        function hookBcrypt() {
            if (_bcryptHooked) return;
            // Find bcrypt.dll case-insensitively (may be 'bcrypt.dll' or 'Bcrypt.dll')
            var bcryptMod = null;
            Process.enumerateModules().forEach(function(m) {
                if (m.name.toLowerCase() === 'bcrypt.dll') bcryptMod = m;
            });
            if (!bcryptMod) return;
            var _bce  = bcryptMod.findExportByName('BCryptEncrypt');
            var _bcd  = bcryptMod.findExportByName('BCryptDecrypt');
            var _bcgr = bcryptMod.findExportByName('BCryptGenRandom');
            var _bco  = bcryptMod.findExportByName('BCryptOpenAlgorithmProvider');
            var _bcek = bcryptMod.findExportByName('BCryptGenerateSymmetricKey');
            var _bci  = bcryptMod.findExportByName('BCryptImportKeyPair');
            if (_bce)  Interceptor.attach(_bce,  { onEnter: function() { C.crypto_ops++; seqPush('bcrypt_encrypt',   {}); } });
            if (_bcd)  Interceptor.attach(_bcd,  { onEnter: function() { C.crypto_ops++; seqPush('bcrypt_decrypt',   {}); } });
            if (_bcgr) Interceptor.attach(_bcgr, { onEnter: function() { C.crypto_ops++; seqPush('bcrypt_gen_random',{}); } });
            if (_bco)  Interceptor.attach(_bco,  { onEnter: function() { C.crypto_ops++; seqPush('bcrypt_open_alg',  {}); } });
            if (_bcek) Interceptor.attach(_bcek, { onEnter: function() { C.crypto_ops++; seqPush('bcrypt_gen_key',   {}); } });
            if (_bci)  Interceptor.attach(_bci,  { onEnter: function() { C.crypto_ops++; seqPush('bcrypt_import_key',{}); } });
            _bcryptHooked = true;
            var hooked = [_bce?'BCryptEncrypt':'', _bcd?'BCryptDecrypt':'', _bcgr?'BCryptGenRandom':'',
                          _bco?'BCryptOpenAlgorithmProvider':'', _bcek?'BCryptGenerateSymmetricKey':''];
            send({api:'debug', args:{msg:'bcrypt hooks installed: '+hooked.filter(Boolean).join(',')}});
        }
        try { Module.load('bcrypt.dll'); } catch(e) {}
        hookBcrypt();
        // Retry 2 s later in case bcrypt.dll loads during Python import phase
        setTimeout(function() { hookBcrypt(); }, 2000);
        // Legacy WinCrypt fallback
        try {
            var _ce = safeExport('advapi32.dll', 'CryptEncrypt');
            if (_ce) { Interceptor.attach(_ce, { onEnter: function() { C.crypto_ops++; } }); send({api:'debug',args:{msg:'hook:CryptEncrypt OK'}}); }
        } catch(e) {}

        // ── PROCESS ENUMERATION HOOKS ─────────────────────────────────────────
        try {
            var NtQSI = ntdll.getExportByName('NtQuerySystemInformation');
            if (NtQSI) {
                Interceptor.attach(NtQSI, {
                    onEnter: function(args) { if (args[0].toInt32() === 5) C.proc_enum++; }
                });
                send({api:'debug', args:{msg:'hook:NtQSI OK'}});
            }
        } catch(e) {}

        try {
            if (kernel32) {
                var _ep = kernel32.getExportByName('K32EnumProcesses') ||
                          kernel32.getExportByName('EnumProcesses');
                if (_ep) {
                    Interceptor.attach(_ep, { onEnter: function() { C.proc_enum++; } });
                    send({api:'debug', args:{msg:'hook:K32EnumProcesses OK'}});
                }
            }
        } catch(e) {}

        send({api: 'init', args: {message: 'NT-level hooks installed (batched flush every 5 s)'}});
        """
    
    def trace_process(self, target_path: str):
        """Spawn process and trace API calls"""
        import frida
        
        print(f"🔍 Starting NT-level API tracer for: {target_path}")
        print(f"   Hooking ntdll.dll (lower level - Python uses this!)\n")
        
        # Spawn the process with Frida
        device = frida.get_local_device()
        if target_path.endswith('.py'):
            # Get absolute path
            target_abs = str(Path(target_path).resolve())
            cwd = str(Path(target_path).resolve().parent)
            
            print(f"   Target: {target_abs}")
            print(f"   CWD: {cwd}\n")
            
            spawn_env = _get_spawn_env()
            print(f"   Python: {_get_base_python()}")
            print(f"   PYTHONPATH: {spawn_env.get('PYTHONPATH', '(none)')}\n")
            pid = device.spawn([_get_base_python(), target_abs, '--auto-run'], cwd=cwd, env=spawn_env)
        else:
            # PyInstaller EXE — pass --auto-run so the simulator skips interactive prompts.
            # cwd is set to the EXE directory so behavioral_data.json lands there.
            target_abs = str(Path(target_path).resolve())
            cwd = str(Path(target_path).resolve().parent)
            print(f"   Target (EXE): {target_abs}")
            print(f"   CWD: {cwd}\n")
            # PyInstaller EXE: do NOT inject PYTHONPATH. The bootloader manages
            # its own bundled sys.path; an external PYTHONPATH causes module
            # conflicts that crash the EXE silently (--windowed hides the error).
            pid = device.spawn([target_abs, '--auto-run'], cwd=cwd)

        session = device.attach(pid)

        # Detect early process termination (e.g. silent crash of --windowed EXE)
        self._process_exited = False
        def _on_detached(reason, crash):
            self._process_exited = True
            print(f"\n⚠️  Process detached early — reason: {reason}" +
                  (f", crash: {crash}" if crash else ""))
        session.on('detached', _on_detached)

        # ── Child-process gating ───────────────────────────────────────────────
        # PyInstaller with --windowed creates a CHILD process in which Python
        # actually runs. The parent stub just waits. Without child gating, all
        # Frida hooks fire in the parent stub (bootloader only) and Python's
        # calls are invisible. enable_child_gating() delivers child PIDs
        # suspended via device.child-added so we can inject the same script.
        child_sessions = []

        def _on_child_added(child):
            print(f"   [CHILD] Attaching to child PID {child.pid} ...")
            try:
                cs = device.attach(child.pid)
                child_sessions.append(cs)
                cscript = cs.create_script(self.get_frida_script())
                cscript.on('message', self.on_message)
                cscript.load()
                # Unhook child-gating for this child so it can spawn further if needed
                cs.enable_child_gating()
                device.resume(child.pid)
                print(f"   [CHILD] Hooks injected into PID {child.pid}")
            except Exception as e:
                print(f"   [CHILD] Failed to attach: {e}")
                try: device.resume(child.pid)
                except: pass

        device.on('child-added', _on_child_added)
        session.enable_child_gating()

        # Load and inject Frida script BEFORE resuming — hooks are in place at
        # first instruction. For PyInstaller EXEs the bootloader runs first and
        # loads DLLs; ws2_32 hooks are installed lazily via LoadLibrary intercept.
        script = session.create_script(self.get_frida_script())
        script.on('message', self.on_message)
        script.load()
        
        # Resume execution
        device.resume(pid)
        
        print(f"✅ Process spawned (PID: {pid})")
        print("📊 Capturing NT-level API calls...\n")
        
        # Monitor for 90 seconds (or until process exits)
        try:
            start_time = time.time()
            duration = 90
            
            while time.time() - start_time < duration:
                if self._process_exited:
                    print("   Process exited — stopping monitor early.")
                    break
                elapsed = int(time.time() - start_time)
                if elapsed % 10 == 0 and elapsed > 0:
                    print(f"   ⏱️  {elapsed}s elapsed... ({len(self.api_sequence)} calls captured)")
                    time.sleep(1)
                else:
                    time.sleep(0.5)
                    
        except KeyboardInterrupt:
            print("\n⚠️  Interrupted by user")
        
        # Detach (ignore error if process already gone)
        try:
            session.detach()
        except Exception:
            pass
        for cs in child_sessions:
            try: cs.detach()
            except: pass
        try: device.off('child-added', _on_child_added)
        except: pass
        
        print(f"\n✅ Captured {len(self.api_sequence)} NT-level API calls")
    
    def analyze_sequence(self):
        """Analyze API call patterns using JS-side counters + rename/delete events"""
        print("\n📊 Analyzing API call patterns...")

        C = self.counters
        # Supplement counters with any per-event data in api_sequence
        renames = sum(1 for c in self.api_sequence if 'Rename' in c.get('api', ''))
        deletes = sum(1 for c in self.api_sequence if 'Delete' in c.get('api', ''))
        # Use max of counter vs per-event count
        file_renames = max(C['file_renames'], renames)
        file_deletes = max(C['file_deletes'], deletes)

        print(f"\n   File creations:        {C['file_creates']}")
        print(f"   File writes:           {C['file_writes']}")
        print(f"   File reads:            {C['file_reads']}")
        print(f"   File renames:          {file_renames}")
        print(f"   File deletes:          {file_deletes}")
        print(f"   Registry reads:        {C['reg_reads']}")
        print(f"   Registry writes:       {C['reg_writes']}")
        print(f"   Network DNS:           {C['net_dns']}")
        print(f"   Network connects:      {C['net_connect']}")
        print(f"   UDP sendto:            {C['net_sendto']}")
        print(f"   Process enumerations:  {C['proc_enum']}")
        print(f"   Crypto operations:     {C.get('crypto_ops', 0)}")

        if file_renames > 50 and C['file_writes'] > 50:
            print(f"\n   🚨 RANSOMWARE PATTERN DETECTED: Mass file write + rename")
        if C.get('crypto_ops', 0) > 10:
            print(f"   🚨 CRYPTO ACTIVITY DETECTED: {C.get('crypto_ops', 0)} BCrypt/CryptEncrypt calls")

        return {
            'mass_file_creation':     C['file_creates'],
            'mass_file_write':        C['file_writes'],
            'file_rename_operations': file_renames,
            'file_delete_operations': file_deletes,
            'registry_reads':         C['reg_reads'],
            'registry_writes':        C['reg_writes'],
            'network_dns':            C['net_dns'],
            'network_connections':    C['net_connect'],
            'process_enumerations':   C['proc_enum'],
            'crypto_operations':      C.get('crypto_ops', 0),
        }
    
    def save_results(self):
        """Save API trace to JSON using JS-side counters as the source of truth"""
        output_file = Path("api_trace_ntdll.json")

        C = self.counters
        renames = max(C['file_renames'], sum(1 for c in self.api_sequence if 'Rename' in c.get('api', '')))
        deletes = max(C['file_deletes'], sum(1 for c in self.api_sequence if 'Delete' in c.get('api', '')))

        summary = {
            'api_file_operations':      C['file_creates'] + C['file_writes'] + renames + deletes,
            'api_registry_reads':       C['reg_reads'],
            'api_registry_writes':      C['reg_writes'],
            'api_network_connections':  C['net_connect'],
            'api_network_dns':          C['net_dns'],
            'api_process_enumerations': C['proc_enum'],
            'api_crypto_operations':    C.get('crypto_ops', 0),
        }

        # Normalise api_sequence: map Frida shorthand → canonical Windows API names
        # so the output is directly consumable by the CNN's load_kaggle_json() loader.
        normalised_sequence = [
            dict(e, api=FRIDA_TO_CANONICAL.get(e.get('api', ''), e.get('api', '')))
            for e in self.api_sequence
        ]

        # Build flat canonical name list (one sample = one run) for CNN input.
        # Format mirrors Kaggle JSON: {"apis": [["NtOpenKey", "NtCreateFile", ...]]}
        canonical_api_list = [e['api'] for e in normalised_sequence if e.get('api')]

        results = {
            'timestamp': datetime.now().isoformat(),
            'total_calls': sum(C.values()),
            'summary': summary,
            'counters': C,
            'api_sequence': normalised_sequence,
            # CNN-compatible key: list-of-lists, one inner list per traced run
            'apis': [canonical_api_list],
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Saved API trace to: {output_file}")
        print(f"   File creates:    {C['file_creates']}")
        print(f"   File renames:    {renames}")
        print(f"   Registry reads:  {summary['api_registry_reads']}")
        print(f"   Registry writes: {summary['api_registry_writes']}")
        print(f"   DNS lookups:     {summary['api_network_dns']}")
        print(f"   Net connects:    {summary['api_network_connections']}")
        print(f"   Process enums:   {summary['api_process_enumerations']}")
        print(f"   Crypto ops:      {summary['api_crypto_operations']}")
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