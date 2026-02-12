"""
Complete Test Script for Malicious Detection
This script:
1. Runs the ransomware simulator (optional)
2. Builds the executable
3. Extracts features
4. Tests with the ML model
5. Verifies detection as malicious
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime

# Directories
SCRIPT_DIR = Path(__file__).parent
DIST_DIR = SCRIPT_DIR / "dist"
EXE_PATH = DIST_DIR / "System_Update.exe"
BEHAVIORAL_JSON = SCRIPT_DIR / "behavioral_data.json"

# Model service
MODEL_SERVICE_URL = "http://127.0.0.1:8001"


def print_section(title):
    """Print formatted section header"""
    print("\n" + "="*60)
    print(title)
    print("="*60)


def step_1_run_simulator():
    """Step 1: Run the ransomware simulator to generate behavioral data"""
    print_section("STEP 1: Generate Behavioral Data")
    
    print("Running ransomware simulator...")
    print("This will create behavioral_data.json with malicious patterns")
    
    choice = input("\nRun simulator now? (y/n): ").lower()
    if choice != 'y':
        print("Skipping simulator - will use existing behavioral data if available")
        return
    
    simulator_path = SCRIPT_DIR / "ransomware_simulator.py"
    
    try:
        print("\nRunning simulator...")
        result = subprocess.run(
            [sys.executable, str(simulator_path), "--auto-run"],
            capture_output=True,
            text=True,
            timeout=180  # 3 minutes max
        )
        
        if result.returncode == 0:
            print(" Simulator completed successfully")
            
            if BEHAVIORAL_JSON.exists():
                print(f" Behavioral data saved: {BEHAVIORAL_JSON}")
                
                # Display summary
                with open(BEHAVIORAL_JSON, 'r') as f:
                    data = json.load(f)
                
                print("\nBehavioral Summary:")
                print(f"  Registry Reads: {data['registry']['read']}")
                print(f"  Registry Writes: {data['registry']['write']}")
                print(f"  Network Requests: {data['network']['connections']}")
                print(f"  Files Created: {len(data['files']['created'])}")
                print(f"  Files Encrypted: {data['files']['suspicious']}")
            else:
                print("⚠ Warning: behavioral_data.json not created")
        else:
            print(f" Simulator failed with code {result.returncode}")
            print(f"Error: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print(" Simulator timed out (exceeded 3 minutes)")
    except Exception as e:
        print(f" Error running simulator: {e}")


def step_2_build_executable():
    """Step 2: Build the executable using PyInstaller"""
    print_section("STEP 2: Build Malicious Executable")
    
    if EXE_PATH.exists():
        print(f"Executable already exists: {EXE_PATH}")
        choice = input("Rebuild? (y/n): ").lower()
        if choice != 'y':
            print("Using existing executable")
            return True
    
    build_script = SCRIPT_DIR / "build_malicious_exe.py"
    
    if not build_script.exists():
        print(f" Build script not found: {build_script}")
        return False
    
    print("\nBuilding executable... (this may take a few minutes)")
    
    try:
        result = subprocess.run(
            [sys.executable, str(build_script)],
            capture_output=False,  # Show output in real-time
            text=True
        )
        
        if result.returncode == 0 and EXE_PATH.exists():
            print(f"\n Executable built successfully: {EXE_PATH}")
            print(f"  Size: {EXE_PATH.stat().st_size:,} bytes")
            return True
        else:
            print(f"\n Build failed")
            return False
            
    except Exception as e:
        print(f" Error building executable: {e}")
        return False


def step_3_analyze_pe():
    """Step 3: Analyze PE headers"""
    print_section("STEP 3: Analyze PE Headers")
    
    if not EXE_PATH.exists():
        print(f" Executable not found: {EXE_PATH}")
        return None
    
    analysis_script = SCRIPT_DIR / "manipulate_pe_headers.py"
    
    if not analysis_script.exists():
        print(f"⚠ Analysis script not found: {analysis_script}")
        print("Skipping PE analysis")
        return None
    
    print("\nAnalyzing PE structure...")
    
    try:
        result = subprocess.run(
            [sys.executable, str(analysis_script)],
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        
        if result.returncode == 0:
            print("\n PE analysis complete")
            return True
        else:
            print(f"\n PE analysis failed: {result.stderr}")
            return None
            
    except Exception as e:
        print(f" Error during PE analysis: {e}")
        return None


def step_4_test_with_model():
    """Step 4: Test with ML model"""
    print_section("STEP 4: Test with ML Model")
    
    if not EXE_PATH.exists():
        print(f" Executable not found: {EXE_PATH}")
        return None
    
    # Check if model service is running
    print(f"Checking model service at {MODEL_SERVICE_URL}...")
    
    try:
        import requests
        
        response = requests.get(f"{MODEL_SERVICE_URL}/health", timeout=5)
        if response.status_code == 200:
            print(" Model service is running")
        else:
            print(f" Model service returned status {response.status_code}")
    except ImportError:
        print(" requests library not installed - install with: pip install requests")
        print("Continuing anyway...")
    except Exception as e:
        print(f" Warning: Could not connect to model service: {e}")
        print(f"Make sure the model service is running at {MODEL_SERVICE_URL}")
        choice = input("\nContinue anyway? (y/n): ").lower()
        if choice != 'y':
            return None
    
    # Load behavioral data
    behavioral_data = None
    if BEHAVIORAL_JSON.exists():
        with open(BEHAVIORAL_JSON, 'r') as f:
            behavioral_data = json.load(f)
        print(f" Loaded behavioral data: {BEHAVIORAL_JSON}")
    else:
        print(" No behavioral data found - testing with PE features only")
    
    # Test with model
    print("\nTesting executable with ML model...")
    
    try:
        import requests
        
        # Prepare request
        files = {'file': open(EXE_PATH, 'rb')}
        data = {}
        
        if behavioral_data:
            data['behavioral_data'] = json.dumps(behavioral_data)
        
        # Send request
        print(f"Uploading to {MODEL_SERVICE_URL}/predict/staged...")
        response = requests.post(
            f"{MODEL_SERVICE_URL}/predict/staged",
            files=files,
            data=data,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            
            print("\n" + "="*60)
            print("DETECTION RESULT")
            print("="*60)
            print(f"File: {EXE_PATH.name}")
            print(f"Prediction: {result.get('prediction', 'Unknown')}")
            print(f"Confidence: {result.get('confidence', 'N/A')}")
            print(f"Is Malicious: {result.get('is_malicious', result.get('prediction') == 'malicious')}")
            
            if 'features_used' in result:
                print(f"Features Used: {result['features_used']}")
            
            if 'behavioral_features' in result:
                print(f"Behavioral Features: {result['behavioral_features']}")
            
            print("="*60)
            
            # Check if detected as malicious
            is_malicious = (
                result.get('is_malicious') or 
                result.get('prediction') == 'malicious' or
                result.get('prediction') == 1 or
                result.get('prediction') == '1'
            )
            
            if is_malicious:
                print("\n SUCCESS! Model detected the executable as MALICIOUS")
                print(f"  Confidence: {result.get('confidence', 'N/A')}")
                return result
            else:
                print("\n FAILURE! Model did NOT detect as malicious")
                print(f"  Prediction: {result.get('prediction')}")
                print(f"  This may indicate:")
                print(f"    - Model needs retraining")
                print(f"    - Feature extraction issues")
                print(f"    - Insufficient behavioral data")
                return result
        else:
            print(f"\n Model request failed with status {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except ImportError:
        print(" requests library required - install with: pip install requests")
        return None
    except Exception as e:
        print(f" Error testing with model: {e}")
        import traceback
        traceback.print_exc()
        return None


def step_5_generate_report():
    """Step 5: Generate test report"""
    print_section("STEP 5: Generate Report")
    
    report_path = SCRIPT_DIR / f"detection_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    report_lines = [
        "MALICIOUS DETECTION TEST REPORT",
        "="*60,
        f"Generated: {datetime.now().isoformat()}",
        f"Executable: {EXE_PATH}",
        "",
        "FILE INFORMATION:",
        f"  File Size: {EXE_PATH.stat().st_size:,} bytes" if EXE_PATH.exists() else "  File not found",
        f"  Created: {datetime.fromtimestamp(EXE_PATH.stat().st_ctime).isoformat()}" if EXE_PATH.exists() else "",
        "",
    ]
    
    # Add behavioral data summary
    if BEHAVIORAL_JSON.exists():
        with open(BEHAVIORAL_JSON, 'r') as f:
            behavioral = json.load(f)
        
        report_lines.extend([
            "BEHAVIORAL DATA:",
            f"  Status: {behavioral.get('status', 'Unknown')}",
            f"  Execution Time: {behavioral.get('execution_time', 0):.2f}s",
            f"  Registry Reads: {behavioral['registry']['read']}",
            f"  Registry Writes: {behavioral['registry']['write']}",
            f"  Network Connections: {behavioral['network']['connections']}",
            f"  DNS Lookups: {behavioral['network']['dns']}",
            f"  Files Created: {len(behavioral['files']['created'])}",
            f"  Files Encrypted: {behavioral['files']['suspicious']}",
            f"  Process Enumerations: {behavioral['processes']['total']}",
            "",
        ])
    
    report_lines.extend([
        "TEST RESULTS:",
        "  See console output above for detailed results",
        "",
        "CONCLUSION:",
        "  The executable should be detected as MALICIOUS due to:",
        "     High volume of file operations (500+)",
        "     Extensive registry manipulation (2000+)",
        "     Suspicious network activity (1000+)",
        "     Ransomware-like behavioral patterns",
        "     PE characteristics matching malware",
        "",
        "="*60,
    ])
    
    report_content = "\n".join(report_lines)
    
    try:
        report_path.write_text(report_content)
        print(f"\n Report saved: {report_path}")
    except Exception as e:
        print(f" Failed to save report: {e}")


def main():
    """Main test orchestration"""
    print("="*60)
    print("MALICIOUS DETECTION TEST SUITE")
    print("="*60)
    print("\nThis script will:")
    print("  1. Run ransomware simulator (optional)")
    print("  2. Build malicious executable")
    print("  3. Analyze PE headers")
    print("  4. Test with ML model")
    print("  5. Generate report")
    
    choice = input("\nContinue? (y/n): ").lower()
    if choice != 'y':
        print("Aborted.")
        return
    
    # Run all steps
    start_time = time.time()
    
    # Optional: Run simulator
    run_sim = input("\nGenerate new behavioral data? (y/n): ").lower()
    if run_sim == 'y':
        step_1_run_simulator()
    
    # Build executable
    if not step_2_build_executable():
        print("\n Cannot continue without executable")
        return
    
    # Analyze PE
    step_3_analyze_pe()
    
    # Test with model
    result = step_4_test_with_model()
    
    # Generate report
    step_5_generate_report()
    
    # Final summary
    elapsed = time.time() - start_time
    
    print("\n" + "="*60)
    print("TEST SUITE COMPLETE")
    print("="*60)
    print(f"Total time: {elapsed:.2f}s")
    print(f"\nExecutable: {EXE_PATH}")
    print(f"Behavioral data: {BEHAVIORAL_JSON}")
    
    if result:
        is_malicious = (
            result.get('is_malicious') or 
            result.get('prediction') == 'malicious' or
            result.get('prediction') == 1
        )
        
        if is_malicious:
            print("\n SUCCESS ")
            print("Your model successfully detected the malicious executable!")
        else:
            print("\ NEEDS IMPROVEMENT ")
            print("Model did not flag as malicious - consider:")
            print("  - Retraining with more aggressive features")
            print("  - Adjusting detection thresholds")
            print("  - Verifying feature extraction")
    
    print("="*60)


if __name__ == "__main__":
    main()
