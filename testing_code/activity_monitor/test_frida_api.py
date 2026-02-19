"""Test Frida API to see what methods are available"""
import sys
import frida

# Simple test script
test_script = """
console.log("Testing Frida API...");
console.log("Module object: " + typeof Module);

try {
    console.log("Module.findExportByName: " + typeof Module.findExportByName);
} catch (e) {
    console.log("findExportByName error: " + e);
}

try {
    console.log("Module.getExportByName: " + typeof Module.getExportByName);
} catch (e) {
    console.log("getExportByName error: " + e);
}

// Try to get ntdll exports
try{
    var ntdll = Process.getModuleByName('ntdll.dll');
    console.log("ntdll module found: " + ntdll.name);
    var createFile = ntdll.getExportByName('NtCreateFile');
    console.log("NtCreateFile address: " + createFile);
} catch (e) {
    console.log("ntdll error: " + e);
}

console.log("Test complete!");
"""

device = frida.get_local_device()
pid = device.spawn([sys.executable, "-c", "import time; time.sleep(5)"])
session = device.attach(pid)
script = session.create_script(test_script)

def on_message(message, data):
    print(f"[{message['type']}] {message.get('payload', message)}")

script.on('message', on_message)
script.load()
device.resume(pid)

import time
time.sleep(2)
session.detach()
print("Done!")
