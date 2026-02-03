#!/usr/bin/env python3
"""
SecureGuard Native Messaging Host
Runs with admin privileges to perform file operations that the browser extension cannot do.

This desktop application communicates with the Chrome extension via Native Messaging API.
"""

import sys
import json
import struct
import os
import shutil
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
log_dir = Path.home() / "AppData" / "Local" / "SecureGuard" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=log_dir / f"host_{datetime.now().strftime('%Y%m%d')}.log",
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Quarantine directory
QUARANTINE_DIR = Path.home() / "AppData" / "Local" / "SecureGuard" / "Quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def read_message():
    """
    Read a message from Chrome extension via stdin.
    Chrome sends messages in the format: [4-byte length][JSON data]
    """
    try:
        # Read the message length (first 4 bytes)
        raw_length = sys.stdin.buffer.read(4)
        
        if len(raw_length) == 0:
            logging.info("No data received, exiting")
            sys.exit(0)
        
        # Unpack the length as a native unsigned integer
        message_length = struct.unpack('=I', raw_length)[0]
        logging.debug(f"Expecting message of length: {message_length}")
        
        # Read the JSON message
        message_bytes = sys.stdin.buffer.read(message_length)
        message_str = message_bytes.decode('utf-8')
        
        logging.debug(f"Received message: {message_str}")
        return json.loads(message_str)
        
    except Exception as e:
        logging.error(f"Error reading message: {e}")
        return None


def send_message(message):
    """
    Send a message to Chrome extension via stdout.
    Format: [4-byte length][JSON data]
    """
    try:
        encoded_message = json.dumps(message).encode('utf-8')
        encoded_length = struct.pack('=I', len(encoded_message))
        
        sys.stdout.buffer.write(encoded_length)
        sys.stdout.buffer.write(encoded_message)
        sys.stdout.buffer.flush()
        
        logging.debug(f"Sent message: {message}")
        
    except Exception as e:
        logging.error(f"Error sending message: {e}")


def quarantine_file(file_path):
    """
    Move a malicious file to the quarantine folder.
    Returns dict with success status and details.
    """
    try:
        source_path = Path(file_path)
        
        if not source_path.exists():
            logging.warning(f"File not found: {file_path}")
            return {
                'success': False,
                'error': 'File not found',
                'file_path': str(file_path)
            }
        
        # Create unique filename in quarantine
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_filename = f"{timestamp}_{source_path.name}"
        quarantine_path = QUARANTINE_DIR / quarantine_filename
        
        # Move file to quarantine
        shutil.move(str(source_path), str(quarantine_path))
        
        # Create metadata file
        metadata = {
            'original_path': str(file_path),
            'quarantine_path': str(quarantine_path),
            'timestamp': datetime.now().isoformat(),
            'action': 'quarantined'
        }
        
        metadata_path = quarantine_path.with_suffix('.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logging.info(f"Quarantined: {file_path} -> {quarantine_path}")
        
        return {
            'success': True,
            'action': 'quarantined',
            'original_path': str(file_path),
            'quarantine_path': str(quarantine_path),
            'quarantine_dir': str(QUARANTINE_DIR)
        }
        
    except Exception as e:
        logging.error(f"Error quarantining file: {e}")
        return {
            'success': False,
            'error': str(e),
            'file_path': str(file_path)
        }


def delete_file(file_path):
    """
    Permanently delete a file.
    Returns dict with success status.
    """
    try:
        source_path = Path(file_path)
        
        if not source_path.exists():
            logging.warning(f"File not found: {file_path}")
            return {
                'success': False,
                'error': 'File not found',
                'file_path': str(file_path)
            }
        
        # Log deletion
        logging.warning(f"DELETING FILE: {file_path}")
        
        # Delete file
        os.remove(str(source_path))
        
        logging.info(f"Deleted: {file_path}")
        
        return {
            'success': True,
            'action': 'deleted',
            'file_path': str(file_path)
        }
        
    except Exception as e:
        logging.error(f"Error deleting file: {e}")
        return {
            'success': False,
            'error': str(e),
            'file_path': str(file_path)
        }


def restore_file(quarantine_path, original_path=None):
    """
    Restore a file from quarantine to its original location (or specified path).
    """
    try:
        q_path = Path(quarantine_path)
        
        if not q_path.exists():
            return {
                'success': False,
                'error': 'File not found in quarantine'
            }
        
        # Read metadata to get original path
        metadata_path = q_path.with_suffix('.json')
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                if original_path is None:
                    original_path = metadata['original_path']
        
        if original_path is None:
            return {
                'success': False,
                'error': 'Original path not specified and metadata not found'
            }
        
        # Restore file
        dest_path = Path(original_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        shutil.move(str(q_path), str(dest_path))
        
        # Delete metadata
        if metadata_path.exists():
            os.remove(str(metadata_path))
        
        logging.info(f"Restored: {quarantine_path} -> {original_path}")
        
        return {
            'success': True,
            'action': 'restored',
            'file_path': str(original_path)
        }
        
    except Exception as e:
        logging.error(f"Error restoring file: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def list_quarantine():
    """
    List all files in quarantine.
    """
    try:
        quarantined_files = []
        
        for file_path in QUARANTINE_DIR.glob('*'):
            if file_path.suffix == '.json':
                continue  # Skip metadata files
            
            # Try to read metadata
            metadata_path = file_path.with_suffix('.json')
            metadata = {}
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            
            quarantined_files.append({
                'quarantine_path': str(file_path),
                'filename': file_path.name,
                'original_path': metadata.get('original_path', 'Unknown'),
                'timestamp': metadata.get('timestamp', 'Unknown'),
                'size': file_path.stat().st_size
            })
        
        return {
            'success': True,
            'count': len(quarantined_files),
            'files': quarantined_files,
            'quarantine_dir': str(QUARANTINE_DIR)
        }
        
    except Exception as e:
        logging.error(f"Error listing quarantine: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def ping():
    """Health check to verify host is running."""
    return {
        'status': 'ok',
        'version': '1.0.0',
        'quarantine_dir': str(QUARANTINE_DIR),
        'log_dir': str(log_dir)
    }


def main():
    """
    Main message loop.
    Continuously read messages from Chrome extension and process them.
    """
    logging.info("="*60)
    logging.info("SecureGuard Native Messaging Host STARTED")
    logging.info(f"Quarantine directory: {QUARANTINE_DIR}")
    logging.info("="*60)
    
    # Also log to stderr for immediate visibility
    print(f"[HOST] Started. Quarantine: {QUARANTINE_DIR}", file=sys.stderr, flush=True)
    
    try:
        while True:
            # Read message from extension
            logging.info("Waiting for message from extension...")
            message = read_message()
            
            if message is None:
                continue
            
            action = message.get('action')
            logging.info("="*60)
            logging.info(f"📨 RECEIVED MESSAGE")
            logging.info(f"Action: {action}")
            logging.info(f"Full message: {json.dumps(message, indent=2)}")
            logging.info("="*60)
            
            # Route to appropriate handler
            if action == 'ping':
                logging.info("🏓 Handling PING")
                response = ping()
                
            elif action == 'quarantine':
                file_path = message.get('file_path')
                logging.info(f"🔒 Handling QUARANTINE for: {file_path}")
                response = quarantine_file(file_path)
                
            elif action == 'delete':
                file_path = message.get('file_path')
                logging.info(f"🗑️ Handling DELETE for: {file_path}")
                response = delete_file(file_path)
                
            elif action == 'restore':
                quarantine_path = message.get('quarantine_path')
                original_path = message.get('original_path')
                logging.info(f"↩️ Handling RESTORE: {quarantine_path} -> {original_path}")
                response = restore_file(quarantine_path, original_path)
                
            elif action == 'list_quarantine':
                logging.info("📋 Handling LIST_QUARANTINE")
                response = list_quarantine()
                
            else:
                logging.warning(f"❌ Unknown action: {action}")
                response = {
                    'success': False,
                    'error': f'Unknown action: {action}'
                }
            
            # Send response back to extension
            logging.info(f"📤 SENDING RESPONSE: {json.dumps(response, indent=2)}")
            send_message(response)
            logging.info("✅ Response sent successfully")
            logging.info("="*60)
            
    except KeyboardInterrupt:
        logging.info("Host stopped by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        send_message({
            'success': False,
            'error': f'Fatal error: {str(e)}'
        })
    