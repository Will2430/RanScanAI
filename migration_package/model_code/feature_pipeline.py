"""
Unified Feature Extraction Pipeline
Orchestrates PE extraction, VT enrichment, and model inference
"""

import numpy as np
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import joblib

from iteration_1.backend.pe_feature_extractor import PEFeatureExtractor
from iteration_1.backend.vt_integration import VirusTotalEnricher

logger = logging.getLogger(__name__)


class FeaturePipeline:
    """
    Unified pipeline for feature extraction and malware detection
    
    Pipeline stages:
    1. PE static feature extraction (always)
    2. Feature scaling (always)
    3. VT behavioral enrichment (optional, based on confidence)
    4. Model prediction
    """
    
    def __init__(self, model_path: Optional[str] = None, 
                 scaler_path: Optional[str] = None,
                 vt_api_key: Optional[str] = None,
                 enable_vt: bool = True):
        """
        Initialize feature pipeline
        
        Args:
            model_path: Path to trained model (if None, only extracts features)
            scaler_path: Path to scaler pickle file
            vt_api_key: VT API key (if None, loads from config)
            enable_vt: Whether to enable VT enrichment
        """
        # Initialize PE extractor
        self.pe_extractor = PEFeatureExtractor()
        logger.info(f"✓ PE extractor initialized ({self.pe_extractor.n_features} features)")
        
        # Load scaler
        self.scaler = None
        if scaler_path:
            scaler_path_obj = Path(scaler_path)
            if scaler_path_obj.exists():
                self.scaler = joblib.load(scaler_path_obj)
                logger.info(f"✓ Scaler loaded from {scaler_path_obj}")
            else:
                logger.warning(f"Scaler not found: {scaler_path}")
        
        # Load model (optional)
        self.model = None
        if model_path:
            model_path_obj = Path(model_path)
            if model_path_obj.exists():
                try:
                    import tensorflow as tf
                    self.model = tf.keras.models.load_model(str(model_path))
                    logger.info(f"✓ Model loaded from {model_path}")
                except Exception as e:
                    logger.error(f"Failed to load model: {e}")
        
        # Initialize VT enricher (optional)
        self.vt_enricher = None
        if enable_vt:
            try:
                self.vt_enricher = VirusTotalEnricher(api_key=vt_api_key)
                logger.info("✓ VT enricher initialized")
            except Exception as e:
                logger.warning(f"VT enricher not available: {e}")
        
        # Thresholds for staged analysis
        self.confidence_low = 0.3
        self.confidence_high = 0.7
    
    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """
        Extract PE features from file
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Feature array (78 features) or None if extraction failed
        """
        return self.pe_extractor.extract(file_path)
    
    def extract_and_scale(self, file_path: str) -> Optional[np.ndarray]:
        """
        Extract and scale features
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Scaled feature array or None
        """
        features = self.extract_features(file_path)
        
        if features is None:
            return None
        
        if self.scaler is None:
            logger.warning("No scaler available - returning unscaled features")
            return features
        
        # Scale features
        scaled = self.scaler.transform(features.reshape(1, -1))
        return scaled.flatten()
    
    def predict(self, file_path: str, use_vt_enrichment: bool = True) -> Dict[str, Any]:
        """
        Full prediction pipeline with optional VT enrichment
        
        Args:
            file_path: Path to PE file
            use_vt_enrichment: Whether to use VT enrichment for uncertain cases
            
        Returns:
            Prediction results dictionary
        """
        if self.model is None:
            raise ValueError("No model loaded - cannot make predictions")
        
        file_path_obj = Path(file_path)
        
        # Extract PE features
        logger.info(f"Extracting PE features from {file_path_obj.name}")
        features = self.extract_features(str(file_path_obj))
        
        if features is None:
            return {
                'is_malicious': False,
                'confidence': 0.5,
                'label': 'UNKNOWN',
                'method': 'extraction_failed',
                'error': 'PE feature extraction failed'
            }
        
        # Scale features
        if self.scaler is None:
            return {
                'is_malicious': False,
                'confidence': 0.5,
                'label': 'UNKNOWN',
                'method': 'no_scaler',
                'error': 'Scaler not loaded'
            }
        
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        features_cnn = features_scaled.reshape(1, -1, 1)
        
        # Initial prediction
        logger.info("Running initial prediction (PE static)")
        prediction_prob = float(self.model.predict(features_cnn, verbose=0)[0][0])
        
        # Determine if VT enrichment needed
        vt_enriched = False
        vt_data = None
        
        if use_vt_enrichment and self.vt_enricher is not None:
            # Check if confidence is in uncertain range
            if self.confidence_low <= prediction_prob <= self.confidence_high:
                logger.info(f"Confidence {prediction_prob:.3f} uncertain - calling VT API")
                
                try:
                    vt_data = self.vt_enricher.check_file(str(file_path))
                    
                    if vt_data:
                        # Enrich features
                        enriched_features = self.pe_extractor._enrich_with_vt(features, vt_data)
                        
                        # Re-predict
                        enriched_scaled = self.scaler.transform(enriched_features.reshape(1, -1))
                        enriched_cnn = enriched_scaled.reshape(1, -1, 1)
                        prediction_prob = float(self.model.predict(enriched_cnn, verbose=0)[0][0])
                        
                        vt_enriched = True
                        logger.info(f"VT enrichment complete - new confidence: {prediction_prob:.3f}")
                except Exception as e:
                    logger.error(f"VT enrichment failed: {e}")
        
        # Final result
        is_malicious = prediction_prob >= 0.5
        confidence = prediction_prob if is_malicious else (1 - prediction_prob)
        
        result = {
            'is_malicious': bool(is_malicious),
            'confidence': float(confidence),
            'label': 'MALICIOUS' if is_malicious else 'CLEAN',
            'raw_score': float(prediction_prob),
            'method': 'pe_vt_enriched' if vt_enriched else 'pe_static',
            'file_path': str(file_path_obj),
            'file_name': file_path_obj.name,
            'vt_enriched': vt_enriched
        }
        
        # Add VT data if available
        if vt_data:
            result['vt_detection'] = {
                'malicious': vt_data['detection']['malicious'],
                'total': vt_data['detection']['total'],
                'ratio': vt_data['detection']['ratio']
            }
        
        return result
    
    def batch_predict(self, file_paths: list, use_vt_enrichment: bool = True) -> list:
        """
        Predict on batch of files
        
        Args:
            file_paths: List of file paths
            use_vt_enrichment: Whether to use VT enrichment
            
        Returns:
            List of prediction results
        """
        results = []
        
        for file_path in file_paths:
            try:
                result = self.predict(file_path, use_vt_enrichment)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to process {file_path}: {e}")
                results.append({
                    'is_malicious': False,
                    'confidence': 0.0,
                    'label': 'ERROR',
                    'method': 'error',
                    'error': str(e),
                    'file_path': str(file_path)
                })
        
        return results


# CLI tool
def main():
    """CLI tool for feature extraction and prediction"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PE Feature Extraction and Malware Detection')
    parser.add_argument('file', help='PE file to analyze')
    parser.add_argument('--model', help='Path to trained model')
    parser.add_argument('--scaler', help='Path to scaler pickle')
    parser.add_argument('--no-vt', action='store_true', help='Disable VT enrichment')
    parser.add_argument('--extract-only', action='store_true', help='Only extract features, no prediction')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    # Initialize pipeline
    pipeline = FeaturePipeline(
        model_path=args.model,
        scaler_path=args.scaler,
        enable_vt=not args.no_vt
    )
    
    print(f"\n{'='*70}")
    print(f"Analyzing: {args.file}")
    print(f"{'='*70}\n")
    
    if args.extract_only:
        # Extract features only
        features = pipeline.extract_features(args.file)
        
        if features is not None:
            print(f"✓ Extracted {len(features)} features")
            print(f"\nFirst 10 features:")
            for i, name in enumerate(pipeline.pe_extractor.FEATURE_NAMES[:10]):
                print(f"  {name:30s} = {features[i]:15.2f}")
        else:
            print("✗ Feature extraction failed")
    
    else:
        # Full prediction
        if args.model is None:
            print("Error: --model required for prediction")
            return
        
        result = pipeline.predict(args.file, use_vt_enrichment=not args.no_vt)
        
        print(f"Result: {result['label']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Method: {result['method']}")
        print(f"Raw score: {result['raw_score']:.4f}")
        
        if result.get('vt_enriched'):
            vt = result.get('vt_detection', {})
            print(f"\nVirusTotal Detection:")
            print(f"  {vt.get('malicious', 0)}/{vt.get('total', 0)} engines detected as malicious")
            print(f"  Detection ratio: {vt.get('ratio', 0):.2%}")


if __name__ == "__main__":
    main()
