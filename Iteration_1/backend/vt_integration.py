"""
VirusTotal API Integration for Behavioral Feature Enrichment
Free tier: 4 requests/minute, 500 requests/day
"""

import requests
import hashlib
import time
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from collections import deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for VT API (4 requests/minute for free tier)"""
    
    def __init__(self, requests_per_minute: int = 4, requests_per_day: int = 500):
        self.requests_per_minute = requests_per_minute
        self.requests_per_day = requests_per_day
        
        # Track request timestamps
        self.minute_requests = deque(maxlen=requests_per_minute)
        self.daily_requests = 0
        self.daily_reset_time = datetime.now() + timedelta(days=1)
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = datetime.now()
        
        # Reset daily counter
        if now >= self.daily_reset_time:
            self.daily_requests = 0
            self.daily_reset_time = now + timedelta(days=1)
        
        # Check daily limit
        if self.daily_requests >= self.requests_per_day:
            logger.warning(f"Daily VT API limit reached ({self.requests_per_day})")
            raise Exception("VirusTotal daily API limit exceeded")
        
        # Check minute limit
        if len(self.minute_requests) >= self.requests_per_minute:
            # Get oldest request time
            oldest = self.minute_requests[0]
            elapsed = (now - oldest).total_seconds()
            
            if elapsed < 60:
                # Need to wait
                wait_time = 60 - elapsed + 1  # Add 1 second buffer
                logger.info(f"Rate limit: waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time)
        
        # Record this request
        self.minute_requests.append(datetime.now())
        self.daily_requests += 1


class VirusTotalEnricher:
    """
    VirusTotal API integration for behavioral feature enrichment
    Provides sandbox behavioral data to complement static PE analysis
    """
    
    VT_API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None, config_path: Optional[str] = None):
        """
        Initialize VT enricher
        
        Args:
            api_key: VT API key (if None, loads from config)
            config_path: Path to config file containing API key
        """
        # Load API key
        if api_key:
            self.api_key = api_key
        elif config_path:
            self.api_key = self._load_api_key(config_path)
        else:
            # Try default config location
            default_config = Path(__file__).parent / "config_files" / "vt_config.json"
            self.api_key = self._load_api_key(default_config)
        
        if not self.api_key:
            raise ValueError("No VT API key provided. Set in vt_config.json or pass to constructor")
        
        # Rate limiter
        self.rate_limiter = RateLimiter(requests_per_minute=4, requests_per_day=500)
        
        # Cache for avoiding duplicate requests
        self.cache: Dict[str, Dict] = {}
        
        logger.info("✓ VirusTotal enricher initialized (free tier: 4 req/min, 500/day)")
    
    def _load_api_key(self, config_path: Path) -> Optional[str]:
        """Load API key from config file"""
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.warning(f"VT config not found: {config_path}")
            return None
        
        try:
            with open(config_path) as f:
                config = json.load(f)
            return config.get('api_key')
        except Exception as e:
            logger.error(f"Failed to load VT config: {e}")
            return None
    
    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def _make_request(self, endpoint: str) -> Optional[Dict]:
        """Make VT API request with rate limiting"""
        # Wait if needed for rate limit
        try:
            self.rate_limiter.wait_if_needed()
        except Exception as e:
            logger.error(f"Rate limit error: {e}")
            return None
        
        # Make request
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        url = f"{self.VT_API_BASE}/{endpoint}"
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info("File not found in VT database")
                return None
            elif response.status_code == 429:
                logger.warning("VT rate limit exceeded (429)")
                return None
            else:
                logger.error(f"VT API error {response.status_code}: {response.text}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"VT API request failed: {e}")
            return None
    
    def _upload_file(self, file_path: Path) -> Optional[Dict]:
        """
        Upload file to VirusTotal for analysis
        
        WARNING: Uploaded files are PUBLIC and shared with security community
        
        Args:
            file_path: Path to file to upload
            
        Returns:
            Upload response or None
        """
        # Check file size (max 32MB for free API)
        file_size = file_path.stat().st_size
        if file_size > 32 * 1024 * 1024:
            logger.error(f"File too large for upload: {file_size / 1024 / 1024:.1f}MB (max 32MB)")
            return None
        
        try:
            self.rate_limiter.wait_if_needed()
        except Exception as e:
            logger.error(f"Rate limit error: {e}")
            return None
        
        headers = {
            "x-apikey": self.api_key
        }
        
        url = f"{self.VT_API_BASE}/files"
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                response = requests.post(url, headers=headers, files=files, timeout=60)
            
            if response.status_code == 200:
                logger.info("✓ File uploaded successfully to VT")
                return response.json()
            else:
                logger.error(f"VT upload error {response.status_code}: {response.text}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"VT upload failed: {e}")
            return None
    
    def _empty_behavior(self) -> Dict:
        """Return empty behavioral feature structure"""
        return {
            'registry': {'read': 0, 'write': 0, 'delete': 0},
            'network': {'threats': 0, 'dns': 0, 'http': 0, 'connections': 0},
            'processes': {'malicious': 0, 'suspicious': 0, 'monitored': 0, 'total': 0},
            'files': {'malicious': 0, 'suspicious': 0, 'text': 0, 'unknown': 0},
            'dlls': 0,
            'apis': 0
        }
    
    def check_file(self, file_path: str, auto_upload: bool = False) -> Optional[Dict]:
        """
        Check file on VirusTotal and extract behavioral features
        
        Args:
            file_path: Path to file to check
            auto_upload: If True and file not found, upload it to VT (WARNING: file becomes PUBLIC)
            
        Returns:
            Enrichment data with behavioral features, or None if unavailable
        """
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            logger.error(f"File not found: {file_path}")
            return None
        
        # Compute hash
        file_hash = self._compute_hash(file_path_obj)
        
        # Check cache
        if file_hash in self.cache:
            logger.info(f"Using cached VT data for {file_hash[:16]}...")
            return self.cache[file_hash]
        
        logger.info(f"Querying VT for {file_hash[:16]}...")
        
        # Query VT by hash (doesn't use upload quota)
        data = self._make_request(f"files/{file_hash}")
        
        if not data and auto_upload:
            logger.warning(f"File not in VT database - uploading (file will be PUBLIC)")
            upload_result = self._upload_file(file_path_obj)
            
            if upload_result:
                logger.info("File uploaded successfully - waiting for analysis (this may take 1-5 minutes)...")
                logger.info("Re-query VT in a few minutes to get behavioral data")
                # Return partial data with detection info only
                return {
                    'detection': {'malicious': 0, 'total': 0, 'ratio': 0.0},
                    'behavior': self._empty_behavior(),
                    'status': 'pending_analysis',
                    'message': 'File uploaded to VT - analysis in progress (check back in 2-5 minutes)'
                }
            else:
                return None
        
        if not data:
            return None
        
        # Extract behavioral features
        enrichment = self._extract_behavioral_features(data)
        
        # Cache result
        self.cache[file_hash] = enrichment
        
        return enrichment
    
    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Check file hash on VirusTotal
        
        Args:
            file_hash: SHA256 hash to check
            
        Returns:
            Enrichment data or None
        """
        # Check cache
        if file_hash in self.cache:
            logger.info(f"Using cached VT data for {file_hash[:16]}...")
            return self.cache[file_hash]
        
        logger.info(f"Querying VT for hash {file_hash[:16]}...")
        
        data = self._make_request(f"files/{file_hash}")
        
        if not data:
            return None
        
        enrichment = self._extract_behavioral_features(data)
        self.cache[file_hash] = enrichment
        
        return enrichment
    
    def _extract_behavioral_features(self, vt_response: Dict) -> Dict:
        """
        Extract behavioral features from VT response
        
        Args:
            vt_response: Raw VT API response
            
        Returns:
            Structured behavioral feature dict
        """
        attributes = vt_response.get('data', {}).get('attributes', {})
        
        # Detection stats
        last_analysis = attributes.get('last_analysis_stats', {})
        total_engines = sum(last_analysis.values())
        malicious_count = last_analysis.get('malicious', 0)
        
        last_analysis_results = attributes.get('last_analysis_results', {})
        # Sandbox behavior summary (if available)
        sandbox = attributes.get('sandbox_verdicts', {})
        behavior_data = attributes.get('behavior', {})
        
        # Initialize behavioral features
        enrichment = {
            'detection': {
                'malicious': malicious_count,
                'total': total_engines,
                'ratio': malicious_count / total_engines if total_engines > 0 else 0
            },
            'scans': last_analysis_results,  # ADD THIS LINE - individual AV results
            'behavior': {
                'registry': {
                    'read': 0,
                    'write': 0,
                    'delete': 0
                },
                'network': {
                    'threats': 0,
                    'dns': 0,
                    'http': 0,
                    'connections': 0
                },
                'processes': {
                    'malicious': 0,
                    'suspicious': 0,
                    'monitored': 0,
                    'total': 0
                },
                'files': {
                    'malicious': 0,
                    'suspicious': 0,
                    'text': 0,
                    'unknown': 0
                },
                'dlls': 0,
                'apis': 0
            },
            'tags': attributes.get('tags', []),
            'type': attributes.get('type_description', 'Unknown'),
            'size': attributes.get('size', 0),
            'first_seen': attributes.get('first_submission_date', 0),
            'last_seen': attributes.get('last_analysis_date', 0)
        }
        
        # Extract behavioral data if available
        # Note: Detailed sandbox behavior requires premium API ($$$)
        # Free tier does NOT provide registry/network/process details
        
        has_premium_data = False
        
        if behavior_data:
            # Registry activity
            registry_keys = behavior_data.get('registry_keys_set', [])
            if registry_keys:
                has_premium_data = True
                enrichment['behavior']['registry']['write'] = len(registry_keys)
            
            # Network activity
            dns_lookups = behavior_data.get('dns_lookups', [])
            http_conversations = behavior_data.get('http_conversations', [])
            ip_traffic = behavior_data.get('ip_traffic', [])
            
            if dns_lookups or http_conversations or ip_traffic:
                has_premium_data = True
                enrichment['behavior']['network']['dns'] = len(dns_lookups)
                enrichment['behavior']['network']['http'] = len(http_conversations)
                enrichment['behavior']['network']['connections'] = len(ip_traffic)
            
            # Process activity
            processes_created = behavior_data.get('processes_created', [])
            if processes_created:
                has_premium_data = True
                enrichment['behavior']['processes']['total'] = len(processes_created)
                enrichment['behavior']['processes']['monitored'] = len(processes_created)
            
            # File activity
            files_written = behavior_data.get('files_written', [])
            files_deleted = behavior_data.get('files_deleted', [])
            if files_written or files_deleted:
                has_premium_data = True
                enrichment['behavior']['files']['unknown'] = len(files_written) + len(files_deleted)
            
            # Modules/DLLs
            modules_loaded = behavior_data.get('modules_loaded', [])
            if modules_loaded:
                has_premium_data = True
                enrichment['behavior']['dlls'] = len(modules_loaded)
        
        # FREE TIER FALLBACK: Use detection ratio and tags as behavioral proxy
        if not has_premium_data:
            logger.info("No premium behavioral data available - using detection ratio as proxy")
            
            # Use detection ratio to estimate behavioral risk
            # High detection ratio = likely malicious behavior observed by AVs
            detection_ratio = enrichment['detection']['ratio']
            malicious_count = enrichment['detection']['malicious']
            
            if detection_ratio > 0.15:  # >15% of AVs flagged it
                # Estimate behavioral features based on detection patterns
                # This is a heuristic proxy, not actual sandbox data
                
                # Check tags for behavioral indicators
                tags = enrichment['tags']
                is_ransomware = any('ransom' in tag.lower() for tag in tags)
                is_trojan = any('trojan' in tag.lower() for tag in tags)
                is_packer = any(tag.lower() in ['packed', 'upx', 'themida'] for tag in tags)
                
                # Estimate behavioral features (heuristic)
                if is_ransomware or malicious_count > 10:
                    # Ransomware typically has high file/registry activity
                    enrichment['behavior']['files']['suspicious'] = min(int(malicious_count * 2), 50)
                    enrichment['behavior']['registry']['write'] = min(int(malicious_count), 20)
                    enrichment['behavior']['processes']['suspicious'] = 1
                
                if is_trojan or malicious_count > 5:
                    enrichment['behavior']['network']['connections'] = 1
                    enrichment['behavior']['processes']['suspicious'] = 1
                
                if is_packer:
                    enrichment['behavior']['dlls'] = min(int(malicious_count), 30)
                
                logger.info(f"Estimated behavioral features from {malicious_count} AV detections and tags: {tags[:5]}")
        
        return enrichment
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        return {
            'cached_files': len(self.cache),
            'daily_requests_used': self.rate_limiter.daily_requests,
            'daily_requests_remaining': self.rate_limiter.requests_per_day - self.rate_limiter.daily_requests
        }


# Test function
def test_vt():
    """Test VT integration"""
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    # Test with EICAR hash (known test file)
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    
    try:
        vt = VirusTotalEnricher()
        
        print("\n" + "="*60)
        print("Testing VirusTotal Integration")
        print("="*60)
        
        result = vt.check_hash(eicar_hash)
        
        if result:
            print("\n✓ Successfully retrieved VT data")
            print(f"\nDetection:")
            print(f"  Malicious: {result['detection']['malicious']}/{result['detection']['total']}")
            print(f"  Ratio: {result['detection']['ratio']:.2%}")
            
            print(f"\nBehavioral Features:")
            print(f"  Registry writes: {result['behavior']['registry']['write']}")
            print(f"  Network connections: {result['behavior']['network']['connections']}")
            print(f"  DNS queries: {result['behavior']['network']['dns']}")
            print(f"  Processes: {result['behavior']['processes']['total']}")
            print(f"  DLLs: {result['behavior']['dlls']}")
            
            stats = vt.get_cache_stats()
            print(f"\nCache Stats:")
            print(f"  Cached files: {stats['cached_files']}")
            print(f"  Daily requests: {stats['daily_requests_used']}/{stats['daily_requests_used'] + stats['daily_requests_remaining']}")
        else:
            print("\n✗ Failed to retrieve VT data")
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nMake sure to create config_files/vt_config.json with your API key:")
        print('{\n  "api_key": "YOUR_VT_API_KEY_HERE"\n}')


if __name__ == "__main__":
    test_vt()
