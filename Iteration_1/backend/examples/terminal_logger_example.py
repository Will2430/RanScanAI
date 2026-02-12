"""
Terminal output capture utilities - EXAMPLE IMPLEMENTATION
Copy this to Iteration_1/backend/terminal_logger.py when ready

Captures stdout/stderr or logging output for database storage
"""
import logging
import io
import sys
from contextlib import contextmanager
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class TerminalCapture:
    """
    Context manager to capture stdout and stderr
    
    Usage:
        with TerminalCapture() as capture:
            print("This will be captured")
            sys.stderr.write("This too")
        
        output = capture.get_output()
        print(output['stdout'])  # "This will be captured\n"
        print(output['stderr'])  # "This too"
    """
    
    def __init__(self):
        self.stdout_buffer = io.StringIO()
        self.stderr_buffer = io.StringIO()
        self.original_stdout = None
        self.original_stderr = None
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        """Start capturing"""
        self.start_time = datetime.utcnow()
        
        # Save original streams
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        # Redirect to buffers
        sys.stdout = self.stdout_buffer
        sys.stderr = self.stderr_buffer
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop capturing and restore original streams"""
        self.end_time = datetime.utcnow()
        
        # Restore original streams
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        
        # Don't suppress exceptions
        return False
    
    def get_output(self) -> Dict[str, Any]:
        """
        Get captured output and metadata
        
        Returns:
            dict with keys:
            - stdout: Captured standard output
            - stderr: Captured standard error
            - execution_time_ms: Time elapsed in milliseconds
            - exit_code: 0 if no stderr, 1 if stderr present
        """
        execution_time = 0
        if self.start_time and self.end_time:
            execution_time = (self.end_time - self.start_time).total_seconds() * 1000
        
        stderr_content = self.stderr_buffer.getvalue()
        
        return {
            'stdout': self.stdout_buffer.getvalue(),
            'stderr': stderr_content,
            'execution_time_ms': execution_time,
            'exit_code': 1 if stderr_content else 0
        }


class LoggingCapture:
    """
    Captures logging output instead of raw stdout/stderr
    Better for applications using Python's logging module
    
    Usage:
        with LoggingCapture(__name__) as capture:
            logger.info("This will be captured")
            logger.error("This too")
        
        output = capture.get_output()
        print(output['stdout'])  # Both log messages
    """
    
    def __init__(self, logger_name: str = None):
        """
        Initialize logging capture
        
        Args:
            logger_name: Logger to capture (default: root logger)
        """
        self.logger_name = logger_name
        self.handler = None
        self.stream = io.StringIO()
        self.start_time = None
        self.end_time = None
        self.original_level = None
    
    def __enter__(self):
        """Start capturing logs"""
        self.start_time = datetime.utcnow()
        
        # Create string stream handler
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setLevel(logging.DEBUG)  # Capture all levels
        
        # Format with timestamp and level
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.handler.setFormatter(formatter)
        
        # Get target logger
        target_logger = logging.getLogger(self.logger_name)
        
        # Add handler
        target_logger.addHandler(self.handler)
        
        # Store original level
        self.original_level = target_logger.level
        
        # Ensure we capture everything
        target_logger.setLevel(logging.DEBUG)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop capturing and remove handler"""
        self.end_time = datetime.utcnow()
        
        # Get target logger
        target_logger = logging.getLogger(self.logger_name)
        
        # Remove handler
        if self.handler:
            target_logger.removeHandler(self.handler)
        
        # Restore original level
        if self.original_level is not None:
            target_logger.setLevel(self.original_level)
        
        return False
    
    def get_output(self) -> Dict[str, Any]:
        """
        Get captured logs and metadata
        
        Returns:
            dict with keys:
            - stdout: Captured log messages
            - stderr: Empty string (logs go to stdout)
            - execution_time_ms: Time elapsed in milliseconds
            - exit_code: Always 0 (logging doesn't have exit codes)
        """
        execution_time = 0
        if self.start_time and self.end_time:
            execution_time = (self.end_time - self.start_time).total_seconds() * 1000
        
        return {
            'stdout': self.stream.getvalue(),
            'stderr': '',
            'execution_time_ms': execution_time,
            'exit_code': 0
        }


class DualCapture:
    """
    Captures both stdout/stderr AND logging output
    Use when you have mixed output sources
    
    Usage:
        with DualCapture(__name__) as capture:
            print("From print")
            logger.info("From logger")
        
        output = capture.get_output()
        # Both messages captured
    """
    
    def __init__(self, logger_name: str = None):
        self.terminal_capture = TerminalCapture()
        self.logging_capture = LoggingCapture(logger_name)
    
    def __enter__(self):
        self.terminal_capture.__enter__()
        self.logging_capture.__enter__()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logging_capture.__exit__(exc_type, exc_val, exc_tb)
        self.terminal_capture.__exit__(exc_type, exc_val, exc_tb)
        return False
    
    def get_output(self) -> Dict[str, Any]:
        """Get combined output from both captures"""
        terminal_output = self.terminal_capture.get_output()
        logging_output = self.logging_capture.get_output()
        
        # Combine stdout from both sources
        combined_stdout = terminal_output['stdout'] + logging_output['stdout']
        
        return {
            'stdout': combined_stdout,
            'stderr': terminal_output['stderr'],
            'execution_time_ms': max(
                terminal_output['execution_time_ms'],
                logging_output['execution_time_ms']
            ),
            'exit_code': terminal_output['exit_code']
        }


# ============================================================================
# FORMATTING UTILITIES
# ============================================================================

def format_scan_output(result: Dict[str, Any]) -> str:
    """
    Format scan result dict into human-readable string
    
    Args:
        result: Scan result dictionary with keys:
            - prediction_label
            - confidence
            - scan_time_ms
            - features_count (optional)
            - vt_detection_ratio (optional)
    
    Returns:
        Formatted string for logging
    """
    lines = [
        "=" * 50,
        f"Scan Result: {result['prediction_label']}",
        f"Confidence: {result['confidence']:.2%}",
        f"Scan Time: {result['scan_time_ms']:.2f}ms"
    ]
    
    # Add features count if available
    if 'features_count' in result:
        lines.append(f"Features Analyzed: {result['features_count']}")
    elif 'file_size' in result:
        lines.append(f"File Size: {result['file_size']} bytes")
    
    # Add VT detection if available
    if result.get('vt_detection_ratio'):
        lines.append(f"VirusTotal Detection: {result['vt_detection_ratio']}")
    
    lines.append("=" * 50)
    
    return "\n".join(lines)


def format_vt_output(vt_data: Dict[str, Any]) -> str:
    """
    Format VirusTotal enrichment data
    
    Args:
        vt_data: VT data dictionary
    
    Returns:
        Formatted string
    """
    if not vt_data:
        return "VirusTotal: No data available"
    
    lines = ["VirusTotal Analysis:"]
    
    # Detection ratio
    if 'detection_ratio' in vt_data:
        lines.append(f"  Detection: {vt_data['detection_ratio']}")
    
    # Scan date
    if 'scan_date' in vt_data:
        lines.append(f"  Scan Date: {vt_data['scan_date']}")
    
    # Malware families
    if 'malware_families' in vt_data:
        families = ", ".join(vt_data['malware_families'][:5])  # Top 5
        lines.append(f"  Families: {families}")
    
    return "\n".join(lines)


def truncate_output(text: str, max_length: int = 10000) -> str:
    """
    Truncate long output for database storage
    
    Args:
        text: Text to truncate
        max_length: Maximum length (default: 10KB)
    
    Returns:
        Truncated text with indicator if truncated
    """
    if len(text) <= max_length:
        return text
    
    truncated = text[:max_length]
    truncated += f"\n\n... [TRUNCATED - {len(text) - max_length} bytes omitted] ..."
    
    return truncated


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

@contextmanager
def capture_for_db(command: str, command_type: str):
    """
    Convenience context manager that captures output in DB-ready format
    
    Usage:
        with capture_for_db("scan_file", "malware_scan") as capture:
            result = detector.scan_file(path)
        
        # Get DB-ready dict
        db_data = capture.get_db_data(scan_result=result)
    """
    capture = LoggingCapture(__name__)
    capture.__enter__()
    
    # Add metadata
    capture.command = command
    capture.command_type = command_type
    
    try:
        yield capture
    finally:
        capture.__exit__(None, None, None)
    
    # Add helper method
    def get_db_data(scan_result: Optional[Dict] = None, file_path: Optional[str] = None):
        output = capture.get_output()
        return {
            'command': capture.command,
            'command_type': capture.command_type,
            'stdout': truncate_output(output['stdout']),
            'stderr': truncate_output(output['stderr']),
            'exit_code': output['exit_code'],
            'execution_time_ms': output['execution_time_ms'],
            'scan_result': scan_result,
            'file_path': file_path
        }
    
    capture.get_db_data = get_db_data


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example 1: Capture stdout/stderr
    print("Example 1: Terminal Capture")
    with TerminalCapture() as capture:
        print("This is captured stdout")
        sys.stderr.write("This is captured stderr\n")
    
    output = capture.get_output()
    print(f"Captured stdout: {repr(output['stdout'])}")
    print(f"Captured stderr: {repr(output['stderr'])}")
    print(f"Execution time: {output['execution_time_ms']:.2f}ms")
    print()
    
    # Example 2: Capture logging
    print("Example 2: Logging Capture")
    test_logger = logging.getLogger("test")
    test_logger.setLevel(logging.INFO)
    
    with LoggingCapture("test") as capture:
        test_logger.info("Info message")
        test_logger.warning("Warning message")
        test_logger.error("Error message")
    
    output = capture.get_output()
    print("Captured logs:")
    print(output['stdout'])
    print()
    
    # Example 3: Format scan result
    print("Example 3: Format Scan Result")
    scan_result = {
        'prediction_label': 'MALWARE',
        'confidence': 0.95,
        'scan_time_ms': 123.45,
        'features_count': 78,
        'vt_detection_ratio': '45/70'
    }
    print(format_scan_output(scan_result))
