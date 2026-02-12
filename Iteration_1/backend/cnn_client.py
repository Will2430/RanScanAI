"""
CNN Model Client - HTTP Proxy for Remote Model Service
Use this in Python 3.14 project to call the CNN model service running in Python 3.10
"""

import requests
import logging
from pathlib import Path
from typing import Dict, Any
import time

logger = logging.getLogger(__name__)


class CNNModelClient:
    """
    Client for CNN model service
    Acts as a drop-in replacement for CNNMalwareDetector but makes HTTP calls
    """
    
    def __init__(self, service_url: str = "http://127.0.0.1:8001", timeout: int = 30, use_staged: bool = False):
        """
        Initialize CNN model client
        
        Args:
            service_url: URL of the model service
            timeout: Request timeout in seconds
            use_staged: Whether to use staged analysis by default (PE + VT enrichment)
        """
        self.service_url = service_url.rstrip('/')
        self.timeout = timeout
        self.use_staged = use_staged
        
        # Statistics
        self.scans_performed = 0
        self.threats_detected = 0
        self.total_scan_time = 0.0
        self.vt_calls_made = 0
        
        # Check if service is available
        self._check_health()
    
    def _check_health(self):
        """Check if model service is healthy"""
        try:
            response = requests.get(f"{self.service_url}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                logger.info(f"✓ Connected to CNN model service")
                logger.info(f"  Model loaded: {data.get('model_loaded', False)}")
                logger.info(f"  TensorFlow version: {data.get('tensorflow_version', 'N/A')}")
            else:
                logger.warning(f"Model service returned status {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Cannot connect to model service at {self.service_url}")
            logger.error(f"Make sure the service is running: python model_service.py")
            raise ConnectionError(f"Model service unavailable: {e}")
    
    def scan_file(self, file_path: str, use_signatures: bool = False, use_staged: bool = True) -> Dict[str, Any]:
        """
        Scan a file for malware via model service
        
        Args:
            file_path: Path to file to scan
            use_signatures: Whether to check signatures (always enabled on server)
            use_staged: Override default staged analysis setting for this scan
            
        Returns:
            Scan results dictionary (compatible with CNNMalwareDetector)
        """
        # Determine which mode to use
        staged = use_staged if use_staged is not None else self.use_staged
        
        if staged:
            return self.scan_file_staged(file_path)
        else:
            return self._scan_file_pe_only(file_path)
    
    def _scan_file_pe_only(self, file_path: str) -> Dict[str, Any]:
        """
        Scan with PE static analysis only (fast, no VT API)
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Scan results dictionary
        """
        start_time = time.time()
        
        try:
            # Read file
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Send file to service
            with open(file_path_obj, 'rb') as f:
                files = {'file': (file_path_obj.name, f, 'application/octet-stream')}
                response = requests.post(
                    f"{self.service_url}/predict/bytes",
                    files=files,
                    timeout=self.timeout
                )
            
            if response.status_code != 200:
                raise RuntimeError(f"Model service error: {response.status_code} - {response.text}")
            
            result = response.json()
            
            # Update statistics
            self.scans_performed += 1
            if result['is_malicious']:
                self.threats_detected += 1
            
            scan_time = (time.time() - start_time) * 1000
            self.total_scan_time += scan_time
            
            # Return in format compatible with CNNMalwareDetector
            return {
                'is_malicious': result['is_malicious'],
                'confidence': result['confidence'],
                'prediction_label': result['prediction_label'],
                'label': result['prediction_label'],
                'detection_method': result['detection_method'],
                'raw_score': result['raw_score'],
                'scan_time_ms': result['scan_time_ms'],
                'file_path': str(file_path_obj),
                'file_name': file_path_obj.name,
                'file_size': file_path_obj.stat().st_size,
                'signature_type': result.get('signature_type'),
                'pe_features_extracted': result.get('pe_features_extracted', False),
                'service_url': self.service_url
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to communicate with model service: {e}")
            raise
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    
    def scan_file_staged(self, file_path: str) -> Dict[str, Any]:
        """
        Scan with staged analysis: PE static → VT enrichment if uncertain
        
        This provides the best accuracy by:
        1. Fast PE static analysis first
        2. VT API enrichment only when confidence is uncertain (0.3-0.7)
        3. Conservation of VT API quota
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Scan results dictionary with VT enrichment data if applicable
        """
        start_time = time.time()
        
        try:
            # Read file
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Send file to staged endpoint
            with open(file_path_obj, 'rb') as f:
                files = {'file': (file_path_obj.name, f, 'application/octet-stream')}
                response = requests.post(
                    f"{self.service_url}/predict/staged",
                    files=files,
                    timeout=self.timeout
                )
            
            if response.status_code != 200:
                raise RuntimeError(f"Model service error: {response.status_code} - {response.text}")
            
            result = response.json()
            
            # Update statistics
            self.scans_performed += 1
            if result['is_malicious']:
                self.threats_detected += 1
            if result.get('vt_enriched', False):
                self.vt_calls_made += 1
            
            scan_time = (time.time() - start_time) * 1000
            self.total_scan_time += scan_time
            
            # Return comprehensive result
            return {
                'is_malicious': result['is_malicious'],
                'confidence': result['confidence'],
                'prediction_label': result['prediction_label'],
                'label': result['prediction_label'],
                'detection_method': result['detection_method'],
                'raw_score': result['raw_score'],
                'scan_time_ms': result['scan_time_ms'],
                'file_path': str(file_path_obj),
                'file_name': file_path_obj.name,
                'file_size': file_path_obj.stat().st_size,
                'signature_type': result.get('signature_type'),
                'pe_features_extracted': result.get('pe_features_extracted', False),
                'vt_enriched': result.get('vt_enriched', False),
                'vt_detection_ratio': result.get('vt_detection_ratio'),
                'service_url': self.service_url
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to communicate with model service: {e}")
            raise
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client and service statistics"""
        try:
            # Get service stats
            response = requests.get(f"{self.service_url}/stats", timeout=5)
            service_stats = response.json() if response.status_code == 200 else {}
        except:
            service_stats = {}
        
        # Calculate client stats
        avg_scan_time = self.total_scan_time / self.scans_performed if self.scans_performed > 0 else 0
        
        return {
            'client_info': {
                'service_url': self.service_url,
                'scans_performed': self.scans_performed,
                'threats_detected': self.threats_detected,
                'vt_calls_made': self.vt_calls_made,
                'avg_scan_time_ms': round(avg_scan_time, 2),
                'detection_rate': round(self.threats_detected / self.scans_performed * 100, 2) if self.scans_performed > 0 else 0,
                'staged_analysis_enabled': self.use_staged
            },
            'service_info': service_stats
        }
    
    def is_healthy(self) -> bool:
        """Check if service is healthy"""
        try:
            response = requests.get(f"{self.service_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize client
    client = CNNModelClient()
    
    # Test scan (replace with actual file path)
    test_file = "C:/Users/User/OneDrive/Test/K/dataset/sample.exe"
    if Path(test_file).exists():
        result = client.scan_file(test_file)
        print(f"\nScan Result:")
        print(f"  File: {result['file_name']}")
        print(f"  Label: {result['prediction_label']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        print(f"  Method: {result['detection_method']}")
        print(f"  Scan time: {result['scan_time_ms']:.2f}ms")
