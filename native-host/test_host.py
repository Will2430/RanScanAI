"""
Test script for SecureGuard Native Messaging Host
Simulates messages from the Chrome extension
"""

import subprocess
import json
import struct
import sys
import time

def send_message(proc, message):
    """Send a message to the host process"""
    encoded_message = json.dumps(message).encode('utf-8')
    encoded_length = struct.pack('=I', len(encoded_message))
    
    proc.stdin.write(encoded_length)
    proc.stdin.write(encoded_message)
    proc.stdin.flush()
    
    print(f"→ Sent: {message}")

def read_message(proc):
    """Read a message from the host process"""
    raw_length = proc.stdout.read(4)
    if len(raw_length) == 0:
        return None
    
    message_length = struct.unpack('=I', raw_length)[0]
    message_bytes = proc.stdout.read(message_length)
    message = json.loads(message_bytes.decode('utf-8'))
    
    print(f"← Received: {message}")
    return message

def test_ping():
    """Test basic connectivity"""
    print("\n" + "="*60)
    print("TEST 1: Ping (Health Check)")
    print("="*60)
    
    proc = subprocess.Popen(
        ['python', 'secureguard_host.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    try:
        send_message(proc, {'action': 'ping'})
        response = read_message(proc)
        
        if response and response.get('status') == 'ok':
            print("✓ Ping successful!")
            print(f"  Version: {response.get('version')}")
            print(f"  Quarantine: {response.get('quarantine_dir')}")
            return True
        else:
            print("✗ Ping failed!")
            return False
    finally:
        proc.terminate()

def test_quarantine():
    """Test file quarantine"""
    print("\n" + "="*60)
    print("TEST 2: File Quarantine")
    print("="*60)
    
    # Create a test file
    test_file = 'test_malware.txt'
    with open(test_file, 'w') as f:
        f.write('This is a test malware file (safe)')
    
    print(f"Created test file: {test_file}")
    
    proc = subprocess.Popen(
        ['python', 'secureguard_host.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    try:
        import os
        file_path = os.path.abspath(test_file)
        
        send_message(proc, {
            'action': 'quarantine',
            'file_path': file_path
        })
        
        response = read_message(proc)
        
        if response and response.get('success'):
            print("✓ File quarantined successfully!")
            print(f"  Original: {response.get('original_path')}")
            print(f"  Quarantine: {response.get('quarantine_path')}")
            return True
        else:
            print("✗ Quarantine failed!")
            print(f"  Error: {response.get('error')}")
            return False
    finally:
        proc.terminate()

def test_list_quarantine():
    """Test listing quarantined files"""
    print("\n" + "="*60)
    print("TEST 3: List Quarantine")
    print("="*60)
    
    proc = subprocess.Popen(
        ['python', 'secureguard_host.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    try:
        send_message(proc, {'action': 'list_quarantine'})
        response = read_message(proc)
        
        if response and response.get('success'):
            count = response.get('count', 0)
            print(f"✓ Found {count} quarantined file(s)")
            
            for file_info in response.get('files', []):
                print(f"\n  File: {file_info['filename']}")
                print(f"  Original: {file_info['original_path']}")
                print(f"  Time: {file_info['timestamp']}")
                print(f"  Size: {file_info['size']} bytes")
            
            return True
        else:
            print("✗ List failed!")
            return False
    finally:
        proc.terminate()

def main():
    print("="*60)
    print(" SecureGuard Native Messaging Host - Test Suite")
    print("="*60)
    
    results = []
    
    # Run tests
    results.append(("Ping", test_ping()))
    time.sleep(0.5)
    
    results.append(("Quarantine", test_quarantine()))
    time.sleep(0.5)
    
    results.append(("List", test_list_quarantine()))
    
    # Summary
    print("\n" + "="*60)
    print(" Test Results Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n⚠️  Some tests failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
