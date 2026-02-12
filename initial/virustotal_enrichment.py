"""
VirusTotal API Integration
Enriches binary detection results with malware family names
"""

import requests
import json
import time
from typing import Dict, Optional

class VirusTotalAPI:
    """
    Free tier: 500 requests/day, 4 requests/minute
    Get your API key: https://www.virustotal.com/gui/my-apikey
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal API client
        
        Args:
            api_key: Your VT API key (or set VT_API_KEY environment variable)
        """
        self.api_key = api_key or "1d3f2196def848986ea09d597790eda7ba8166430e995d1646e03ceb5a1cc63f"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.request_count = 0
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Enforce rate limiting (4 requests/minute for free tier)"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < 15:  # 15 seconds between requests = 4/minute
            sleep_time = 15 - time_since_last
            print(f"  [Rate limiting: waiting {sleep_time:.1f}s...]")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def lookup_hash(self, file_hash: str) -> Dict:
        """
        Look up file hash in VirusTotal
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash
            
        Returns:
            Dictionary with malware family, vendors, and detection info
        """
        self._rate_limit()
        
        url = f"{self.BASE_URL}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            self.request_count += 1
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data)
            elif response.status_code == 404:
                return {
                    'found': False,
                    'message': 'File not found in VirusTotal database'
                }
            elif response.status_code == 401:
                return {
                    'error': True,
                    'message': 'Invalid API key - Get yours at virustotal.com'
                }
            else:
                return {
                    'error': True,
                    'message': f'API error: {response.status_code}'
                }
        
        except requests.exceptions.Timeout:
            return {
                'error': True,
                'message': 'Request timeout'
            }
        except Exception as e:
            return {
                'error': True,
                'message': f'Error: {str(e)}'
            }
    
    def _parse_response(self, data: Dict) -> Dict:
        """Parse VirusTotal API response"""
        attributes = data.get('data', {}).get('attributes', {})
        
        # Get detection stats
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious_count = last_analysis.get('malicious', 0)
        total_engines = sum(last_analysis.values())
        
        # Get popular threat label (consensus from vendors)
        popular_threat = attributes.get('popular_threat_classification', {})
        suggested_threat = popular_threat.get('suggested_threat_label', 'Unknown')
        
        # Get individual vendor detections
        analysis_results = attributes.get('last_analysis_results', {})
        
        # Extract family names from vendors
        families = []
        vendor_names = []
        for vendor, result in analysis_results.items():
            if result.get('category') == 'malicious':
                vendor_names.append(vendor)
                result_name = result.get('result', '')
                if result_name:
                    families.append(result_name)
        
        # Get most common family name
        family_name = suggested_threat if suggested_threat != 'Unknown' else (
            families[0] if families else 'Unknown'
        )
        
        return {
            'found': True,
            'malicious': malicious_count > 0,
            'detection_ratio': f"{malicious_count}/{total_engines}",
            'family_name': family_name,
            'threat_label': suggested_threat,
            'detections': malicious_count,
            'total_engines': total_engines,
            'sample_vendor_names': families[:5],  # First 5 detection names
            'detecting_vendors': vendor_names[:10]  # First 10 vendors
        }
    
    def get_demo_result(self, is_malicious: bool = True) -> Dict:
        """
        Get demo result without API call (for testing without API key)
        """
        if is_malicious:
            return {
                'found': True,
                'malicious': True,
                'detection_ratio': '65/72',
                'family_name': 'WannaCry Ransomware',
                'threat_label': 'ransomware.wannacry',
                'detections': 65,
                'total_engines': 72,
                'sample_vendor_names': [
                    'Trojan.Ransom.WannaCryptor',
                    'Ransom:Win32/WannaCrypt',
                    'HEUR:Trojan-Ransom.Win32.Wanna',
                    'Ransom.WannaCry',
                    'Win32.Ransomware.WannaCry'
                ],
                'demo_mode': True
            }
        else:
            return {
                'found': True,
                'malicious': False,
                'detection_ratio': '0/72',
                'family_name': 'Clean',
                'threat_label': 'clean',
                'detections': 0,
                'total_engines': 72,
                'demo_mode': True
            }


def format_enriched_result(ml_prediction: int, ml_confidence: float, 
                          vt_result: Dict) -> str:
    """
    Format professional output combining ML + VT results
    
    Args:
        ml_prediction: 0 = malicious, 1 = benign
        ml_confidence: Model confidence (0-1)
        vt_result: VirusTotal lookup result
        
    Returns:
        Formatted string for display
    """
    output = []
    output.append("="*70)
    
    if ml_prediction == 0:  # Malicious
        output.append("⚠️  THREAT DETECTED")
        output.append("="*70)
        output.append(f"ML Model:        MALICIOUS (Confidence: {ml_confidence:.1%})")
        
        if vt_result.get('found'):
            if vt_result.get('malicious'):
                output.append(f"VirusTotal:      {vt_result['detection_ratio']} vendors flagged as malicious")
                output.append(f"Malware Family:  {vt_result['family_name']}")
                output.append(f"Threat Type:     {vt_result['threat_label']}")
                
                if 'sample_vendor_names' in vt_result and vt_result['sample_vendor_names']:
                    output.append(f"\nDetection Names:")
                    for name in vt_result['sample_vendor_names'][:3]:
                        output.append(f"  • {name}")
            else:
                output.append(f"VirusTotal:      Clean ({vt_result['detection_ratio']})")
                output.append(f"⚠️  Note:        ML detected threat but VT shows clean")
                output.append(f"                 Possible zero-day or false positive")
        else:
            output.append(f"VirusTotal:      Not found in database")
            output.append(f"⚠️  Note:        Potentially new/unknown malware")
    
    else:  # Benign
        output.append("✓ FILE APPEARS SAFE")
        output.append("="*70)
        output.append(f"ML Model:        BENIGN (Confidence: {ml_confidence:.1%})")
        
        if vt_result.get('found'):
            output.append(f"VirusTotal:      {vt_result['detection_ratio']}")
            if vt_result.get('detections', 0) > 0:
                output.append(f"⚠️  Warning:     {vt_result['detections']} vendors flagged as suspicious")
                output.append(f"                 Recommend manual review")
    
    if vt_result.get('demo_mode'):
        output.append("\n[Demo Mode - Using simulated VirusTotal data]")
    
    output.append("="*70)
    
    return "\n".join(output)


# Example usage
if __name__ == "__main__":
    print("VirusTotal API Integration - Demo\n")
    
    # Initialize (using demo mode without API key)
    vt = VirusTotalAPI()
    
    # Simulate ML detection + VT enrichment
    print("Example 1: Malicious file detected by ML\n")
    ml_pred = 0  # Malicious
    ml_conf = 0.94
    vt_result = vt.get_demo_result(is_malicious=True)
    
    print(format_enriched_result(ml_pred, ml_conf, vt_result))
    
    print("\n\nExample 2: Clean file\n")
    ml_pred = 1  # Benign
    ml_conf = 0.87
    vt_result = vt.get_demo_result(is_malicious=False)
    
    print(format_enriched_result(ml_pred, ml_conf, vt_result))
    
    print("\n" + "="*70)
    print("To use real VirusTotal API:")
    print("1. Get free API key: https://www.virustotal.com/gui/my-apikey")
    print("2. Replace 'YOUR_API_KEY_HERE' in the code")
    print("3. Free tier: 500 requests/day, 4 requests/minute")
    print("="*70)
