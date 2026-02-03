"""
VirusTotal Integration for SecureGuard
Enriches malware detections with threat intelligence
"""

import requests
import hashlib
import time
import os
from pathlib import Path
from typing import Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class VirusTotalEnricher:
    """
    VirusTotal API integration for threat intelligence enrichment
    Free tier: 500 requests/day, 4 requests/minute
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal enricher
        
        Args:
            api_key: Your VT API key (or set VT_API_KEY env var)
        """
        # Try to get API key from multiple sources (secure approach)
        self.api_key = (
            api_key or  # 1. Passed as parameter
            os.getenv('VT_API_KEY') or  # 2. Environment variable
            self._read_from_credentials() or  # 3. Credentials file
            None  # 4. No key available (will disable VT features)
        )
        
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        self.request_count = 0
        self.last_request_time = 0
        
        if not self.api_key:
            logger.warning("⚠️  No VirusTotal API key configured - VT enrichment disabled")
            logger.info("Get your free API key at: https://www.virustotal.com/gui/my-apikey")
        else:
            logger.info("VirusTotal enricher initialized")
    
    def _read_from_credentials(self) -> Optional[str]:
        """Read API key from Credentials file"""
        try:
            creds_path = Path(__file__).parent / "Credentials"
            if creds_path.exists():
                with open(creds_path, 'r') as f:
                    for line in f:
                        if line.startswith('VT_API_KEY:') or line.startswith('VirusTotal:'):
                            # Format: "VT_API_KEY: your_key_here"
                            return line.split(':', 1)[1].strip()
        except Exception as e:
            logger.debug(f"Could not read credentials file: {e}")
        return None
    
    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key and len(self.api_key) > 0)
    
    def _rate_limit(self):
        """Enforce rate limiting (4 requests/minute for free tier)"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # 15 seconds between requests = 4 requests/minute
        if time_since_last < 15:
            sleep_time = 15 - time_since_last
            logger.info(f"Rate limiting: waiting {sleep_time:.1f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate file hash
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hex digest of hash
        """
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def check_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Check file against VirusTotal
        
        Args:
            file_path: Path to file to check
            
        Returns:
            Enrichment data or None if unavailable
        """
        try:
            # Calculate file hash (SHA-256)
            logger.info(f"Calculating hash for {Path(file_path).name}")
            file_hash = self._calculate_file_hash(file_path, 'sha256')
            logger.info(f"SHA-256: {file_hash}")
            
            # Query VirusTotal
            return self.lookup_hash(file_hash)
            
        except Exception as e:
            logger.error(f"VirusTotal enrichment failed: {e}")
            return None
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Look up file hash in VirusTotal
        
        Args:
            file_hash: SHA-256, SHA-1, or MD5 hash
            
        Returns:
            Detection results or None
        """
        self._rate_limit()
        
        url = f"{self.BASE_URL}/files/{file_hash}"
        
        try:
            logger.info(f"Querying VirusTotal for {file_hash[:16]}...")
            response = requests.get(url, headers=self.headers, timeout=10)
            self.request_count += 1
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data, file_hash)
            
            elif response.status_code == 404:
                logger.info("File not found in VirusTotal database")
                return {
                    'found': False,
                    'hash': file_hash,
                    'message': 'File not in VirusTotal database (likely new/unique sample)',
                    'recommendation': 'Consider uploading for community analysis'
                }
            
            elif response.status_code == 401:
                logger.error("Invalid VirusTotal API key")
                return {
                    'error': True,
                    'message': 'Invalid API key - Get yours at virustotal.com/gui/my-apikey'
                }
            
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return {
                    'error': True,
                    'message': f'API error: {response.status_code}',
                    'details': response.text[:200]
                }
        
        except requests.exceptions.Timeout:
            logger.error("VirusTotal request timeout")
            return {
                'error': True,
                'message': 'Request timeout - VirusTotal may be slow or unavailable'
            }
        
        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return {
                'error': True,
                'message': str(e)
            }
    
    def _parse_response(self, data: Dict, file_hash: str) -> Dict[str, Any]:
        """
        Parse VirusTotal API response
        
        Args:
            data: API response JSON
            file_hash: Original hash queried
            
        Returns:
            Parsed enrichment data
        """
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Detection statistics
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            total_engines = sum(stats.values())
            
            # Get malware family names from top vendors
            results = attributes.get('last_analysis_results', {})
            families = self._extract_families(results)
            
            # File metadata
            file_type = attributes.get('type_description', 'Unknown')
            file_size = attributes.get('size', 0)
            first_seen = attributes.get('first_submission_date', 0)
            
            # Build enrichment response
            enrichment = {
                'found': True,
                'hash': file_hash,
                'detection': {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'undetected': undetected,
                    'total_engines': total_engines,
                    'detection_rate': f"{malicious}/{total_engines}",
                    'percentage': round((malicious / total_engines * 100), 1) if total_engines > 0 else 0
                },
                'families': families,
                'primary_family': families[0] if families else 'Unknown',
                'file_info': {
                    'type': file_type,
                    'size': file_size,
                    'first_seen': time.strftime('%Y-%m-%d', time.gmtime(first_seen)) if first_seen else 'Unknown'
                },
                'verdict': self._get_verdict(malicious, total_engines),
                'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
            
            logger.info(f"VirusTotal: {malicious}/{total_engines} detections - {enrichment['primary_family']}")
            
            return enrichment
            
        except Exception as e:
            logger.error(f"Failed to parse VirusTotal response: {e}")
            return {
                'error': True,
                'message': f'Failed to parse response: {e}'
            }
    
    def _extract_families(self, results: Dict) -> list:
        """
        Extract malware family names from vendor results
        
        Args:
            results: Vendor analysis results
            
        Returns:
            List of family names (deduplicated)
        """
        families = []
        
        # Priority vendors (most reliable naming)
        priority_vendors = [
            'Microsoft', 'Kaspersky', 'Symantec', 'McAfee', 
            'TrendMicro', 'ESET-NOD32', 'Avira', 'BitDefender'
        ]
        
        # First check priority vendors
        for vendor in priority_vendors:
            if vendor in results:
                result = results[vendor].get('result', '')
                if result and result != 'None':
                    # Clean up the family name
                    family = self._clean_family_name(result)
                    if family and family not in families:
                        families.append(family)
        
        # Then check other vendors if needed
        if len(families) < 3:
            for vendor, data in results.items():
                if vendor not in priority_vendors:
                    result = data.get('result', '')
                    if result and result != 'None':
                        family = self._clean_family_name(result)
                        if family and family not in families:
                            families.append(family)
                            if len(families) >= 5:
                                break
        
        return families[:5]  # Return top 5
    
    def _clean_family_name(self, name: str) -> str:
        """Clean up malware family name"""
        # Remove common prefixes
        prefixes = ['Trojan:', 'Virus:', 'Worm:', 'Backdoor:', 'Ransom:', 'Gen:']
        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]
        
        # Remove file extensions
        name = name.split('.')[0]
        
        # Take first word (usually the family name)
        name = name.split('/')[0].split('!')[0]
        
        return name.strip()
    
    def _get_verdict(self, malicious: int, total: int) -> str:
        """
        Get overall verdict based on detections
        
        Args:
            malicious: Number of malicious detections
            total: Total engines
            
        Returns:
            Verdict string
        """
        if total == 0:
            return "Unknown"
        
        percentage = (malicious / total) * 100
        
        if percentage >= 50:
            return "Confirmed Malware"
        elif percentage >= 20:
            return "Likely Malware"
        elif percentage >= 5:
            return "Suspicious"
        elif percentage > 0:
            return "Possibly False Positive"
        else:
            return "Clean"


# Demo usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    enricher = VirusTotalEnricher()
    
    # Test with a known malware hash (WannaCry)
    wannacry_hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    
    print(f"\n🔍 Testing VirusTotal enrichment...")
    print(f"Hash: {wannacry_hash}")
    
    result = enricher.lookup_hash(wannacry_hash)
    
    if result and not result.get('error'):
        print(f"\n✓ Found in VirusTotal")
        print(f"  Detections: {result['detection']['detection_rate']}")
        print(f"  Family: {result['primary_family']}")
        print(f"  Verdict: {result['verdict']}")
    else:
        print(f"\n✗ Not found or error: {result}")
