"""
Complete Detection System Demo
Demonstrates binary ML classification + VirusTotal enrichment
"""

import joblib
import pandas as pd
import numpy as np
from Initial.virustotal_enrichment import VirusTotalAPI, format_enriched_result

class MalwareDetectionSystem:
    """
    Complete detection system combining ML + threat intelligence
    """
    
    def __init__(self, model_path='malware_detector_v1.pkl', 
                 features_path='model_features.txt',
                 vt_api_key=None):
        """Initialize detection system"""
        print("Loading detection system...")
        
        # Load ML model
        try:
            self.model = joblib.load(model_path)
            print(f"✓ Model loaded from {model_path}")
        except FileNotFoundError:
            print(f"✗ Model not found. Run baseline_model.py first!")
            raise
        
        # Load feature names
        try:
            with open(features_path, 'r') as f:
                self.feature_names = [line.strip() for line in f]
            print(f"✓ Features loaded ({len(self.feature_names)} features)")
        except FileNotFoundError:
            print(f"✗ Features file not found")
            raise
        
        # Initialize VirusTotal API
        self.vt = VirusTotalAPI(vt_api_key)
        print(f"✓ VirusTotal integration ready (Demo mode)")
        print()
    
    def analyze_sample(self, features: dict, file_hash: str = None, 
                      use_vt: bool = True) -> dict:
        """
        Analyze a file sample
        
        Args:
            features: Dictionary of feature values
            file_hash: MD5/SHA-1/SHA-256 hash for VT lookup
            use_vt: Whether to enrich with VirusTotal data
            
        Returns:
            Analysis results
        """
        # Prepare features for model
        feature_values = [features.get(f, 0) for f in self.feature_names]
        X = np.array([feature_values])
        
        # ML prediction
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = probabilities[prediction]
        
        result = {
            'prediction': 'Benign' if prediction == 1 else 'Malicious',
            'prediction_code': prediction,
            'confidence': confidence,
            'probabilities': {
                'malicious': probabilities[0],
                'benign': probabilities[1]
            }
        }
        
        # Enrich with VirusTotal if hash provided
        if use_vt and file_hash:
            vt_result = self.vt.get_demo_result(is_malicious=(prediction == 0))
            result['virustotal'] = vt_result
        
        return result
    
    def display_result(self, result: dict):
        """Display formatted analysis result"""
        if 'virustotal' in result:
            print(format_enriched_result(
                result['prediction_code'],
                result['confidence'],
                result['virustotal']
            ))
        else:
            print("="*70)
            print(f"Prediction: {result['prediction']}")
            print(f"Confidence: {result['confidence']:.1%}")
            print(f"  P(Malicious): {result['probabilities']['malicious']:.1%}")
            print(f"  P(Benign):    {result['probabilities']['benign']:.1%}")
            print("="*70)


def demo_with_dataset():
    """Demo using actual samples from the dataset"""
    print("="*70)
    print("MALWARE DETECTION SYSTEM - DEMO")
    print("="*70)
    print()
    
    # Load system
    detector = MalwareDetectionSystem()
    
    # Load some samples from dataset
    print("Loading test samples from dataset...")
    df = pd.read_csv('Dataset/Kaggle (Amdjed) .csv')
    
    # Get feature columns
    feature_cols = [col for col in df.columns if col not in ['FileName', 'md5Hash', 'Benign']]
    
    # Select 3 malicious and 2 benign samples
    malicious_samples = df[df['Benign'] == 0].head(3)
    benign_samples = df[df['Benign'] == 1].head(2)
    
    samples = pd.concat([malicious_samples, benign_samples])
    
    print(f"Testing {len(samples)} samples...\n")
    
    # Analyze each sample
    for idx, row in samples.iterrows():
        print(f"\n{'='*70}")
        print(f"Sample: {row['FileName']}")
        print(f"Hash:   {row['md5Hash']}")
        print(f"Actual: {'Benign' if row['Benign'] == 1 else 'Malicious'}")
        print(f"{'='*70}\n")
        
        # Prepare features
        features = {col: row[col] for col in feature_cols}
        
        # Analyze
        result = detector.analyze_sample(
            features=features,
            file_hash=row['md5Hash'],
            use_vt=True
        )
        
        # Display
        detector.display_result(result)
        
        # Check if correct
        actual = 'Malicious' if row['Benign'] == 0 else 'Benign'
        if result['prediction'] == actual:
            print("\n✓ CORRECT PREDICTION")
        else:
            print("\n✗ INCORRECT PREDICTION")
        
        print("\n" + "="*70)
        
        # Pause between samples
        if idx < len(samples) - 1:
            input("\nPress Enter for next sample...")
    
    print("\n" + "="*70)
    print("DEMO COMPLETE")
    print("="*70)
    print("\nWhat you just saw:")
    print("  1. Lightweight ML model (instant detection)")
    print("  2. Binary classification (malicious/benign)")
    print("  3. VirusTotal enrichment (family names)")
    print("  4. Professional output suitable for end-users")
    print("\nThis is a production-ready architecture!")
    print("="*70)


if __name__ == "__main__":
    demo_with_dataset()
