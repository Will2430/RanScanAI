"""
1D CNN Deep Learning Model for SecureGuard
Byte-level malware detection using Convolutional Neural Networks
Designed to handle multiple file types and reduce false positives
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from pathlib import Path
import json
import joblib
import time
import logging
from typing import Dict, Any, Tuple, List
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

logger = logging.getLogger(__name__)


class CNNMalwareDetector:
    """
    1D CNN-based malware detector using byte sequences
    Features:
    - Byte-level file analysis (first N bytes)
    - Works with ANY file type (.exe, .pdf, .doc, .txt, etc.)
    - Signature detection (EICAR, known patterns)
    - Reduced false positives through learned patterns
    """
    
    def __init__(self, model_path: str = None, max_bytes: int = 100000):
        """
        Initialize CNN detector
        
        Args:
            model_path: Path to saved model (.h5 or .keras)
            max_bytes: Maximum bytes to read from files (100KB default)
        """
        self.max_bytes = max_bytes
        self.model = None
        self.model_path = model_path
        
        # Statistics
        self.scans_performed = 0
        self.threats_detected = 0
        self.total_scan_time = 0.0
        
        # Known signatures
        self.signatures = {
            'eicar': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            'eicar_alt': b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
        }
        
        if model_path and Path(model_path).exists():
            self.load_model(model_path)
    
    def build_model(self, input_shape: Tuple[int, int] = None) -> keras.Model:
        """
        Build 1D CNN architecture optimized for malware detection
        
        Architecture:
        - Multiple 1D Conv layers to detect byte patterns
        - MaxPooling to reduce dimensionality
        - Dropout for regularization
        - Dense layers for classification
        - Batch normalization for stable training
        """
        if input_shape is None:
            input_shape = (self.max_bytes, 1)
        
        model = models.Sequential([
            # Input layer
            layers.Input(shape=input_shape),
            
            # First conv block - detect small patterns (3-5 bytes)
            layers.Conv1D(filters=64, kernel_size=3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.2),
            
            # Second conv block - detect medium patterns (5-10 bytes)
            layers.Conv1D(filters=128, kernel_size=5, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.3),
            
            # Third conv block - detect larger patterns (10-20 bytes)
            layers.Conv1D(filters=256, kernel_size=7, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.3),
            
            # Fourth conv block - high-level features
            layers.Conv1D(filters=128, kernel_size=5, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.4),
            
            # Global pooling to handle variable-length sequences
            layers.GlobalAveragePooling1D(),
            
            # Dense layers for classification
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            
            # Output layer (sigmoid for binary classification)
            layers.Dense(1, activation='sigmoid')
        ])
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=[
                'accuracy',
                keras.metrics.Precision(name='precision'),
                keras.metrics.Recall(name='recall'),
                keras.metrics.AUC(name='auc')
            ]
        )
        
        self.model = model
        return model
    
    def bytes_to_vector(self, file_bytes: bytes) -> np.ndarray:
        """
        Convert raw bytes to normalized vector for CNN input
        
        Args:
            file_bytes: Raw file bytes
            
        Returns:
            Normalized numpy array of shape (max_bytes, 1)
        """
        # Truncate or pad to max_bytes
        if len(file_bytes) > self.max_bytes:
            file_bytes = file_bytes[:self.max_bytes]
        else:
            # Pad with zeros
            file_bytes = file_bytes + b'\x00' * (self.max_bytes - len(file_bytes))
        
        # Convert to numpy array and normalize to [0, 1]
        byte_array = np.frombuffer(file_bytes, dtype=np.uint8)
        byte_array = byte_array.astype(np.float32) / 255.0
        
        # Reshape for CNN input (samples, timesteps, features)
        return byte_array.reshape(-1, 1)
    
    def check_signatures(self, file_bytes: bytes) -> Dict[str, bool]:
        """
        Check for known malware signatures (EICAR, etc.)
        
        Args:
            file_bytes: Raw file bytes
            
        Returns:
            Dictionary of signature matches
        """
        matches = {}
        for name, signature in self.signatures.items():
            matches[name] = signature in file_bytes
        return matches
    
    def extract_features_from_file(self, file_path: str) -> np.ndarray:
        """
        Extract byte-level features from file
        
        Args:
            file_path: Path to file
            
        Returns:
            Feature vector for CNN
        """
        try:
            with open(file_path, 'rb') as f:
                file_bytes = f.read(self.max_bytes)
            
            return self.bytes_to_vector(file_bytes)
        
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            # Return zero vector on error
            return np.zeros((self.max_bytes, 1), dtype=np.float32)
    
    def scan_file(self, file_path: str, use_signatures: bool = True) -> Dict[str, Any]:
        """
        Scan a file for malware using CNN and signature detection
        
        Args:
            file_path: Path to file to scan
            use_signatures: Whether to check signatures first
            
        Returns:
            Scan results dictionary
        """
        start_time = time.time()
        
        try:
            # Read file bytes
            with open(file_path, 'rb') as f:
                file_bytes = f.read(self.max_bytes)
            
            # Check signatures first (fast detection)
            signature_matches = self.check_signatures(file_bytes) if use_signatures else {}
            eicar_detected = signature_matches.get('eicar', False) or signature_matches.get('eicar_alt', False)
            
            # If EICAR detected, return immediately
            if eicar_detected:
                scan_time = (time.time() - start_time) * 1000
                self.scans_performed += 1
                self.threats_detected += 1
                self.total_scan_time += scan_time
                
                return {
                    'is_malicious': True,
                    'confidence': 1.0,
                    'prediction_label': 'MALICIOUS',
                    'label': 'MALICIOUS',
                    'detection_method': 'signature',
                    'signature_type': 'EICAR',
                    'scan_time_ms': round(scan_time, 2),
                    'file_path': str(file_path),
                    'file_name': Path(file_path).name,
                    'file_size': len(file_bytes)
                }
            
            # If no model loaded, return benign (conservative)
            if self.model is None:
                logger.warning("No CNN model loaded - returning benign")
                scan_time = (time.time() - start_time) * 1000
                return {
                    'is_malicious': False,
                    'confidence': 0.5,
                    'prediction_label': 'CLEAN',
                    'label': 'CLEAN',
                    'detection_method': 'none',
                    'scan_time_ms': round(scan_time, 2),
                    'file_path': str(file_path),
                    'file_name': Path(file_path).name,
                    'file_size': len(file_bytes),
                    'warning': 'No model loaded'
                }
            
            # Extract features for CNN
            features = self.bytes_to_vector(file_bytes)
            features_batch = np.expand_dims(features, axis=0)  # Add batch dimension
            
            # Get CNN prediction
            prediction_prob = float(self.model.predict(features_batch, verbose=0)[0][0])
            
            # Threshold for classification (0.5 default)
            is_malicious = prediction_prob >= 0.5
            confidence = prediction_prob if is_malicious else (1 - prediction_prob)
            
            # Calculate scan time
            scan_time = (time.time() - start_time) * 1000
            
            # Update statistics
            self.scans_performed += 1
            if is_malicious:
                self.threats_detected += 1
            self.total_scan_time += scan_time
            
            return {
                'is_malicious': bool(is_malicious),
                'confidence': float(confidence),
                'prediction_label': 'MALICIOUS' if is_malicious else 'CLEAN',
                'label': 'MALICIOUS' if is_malicious else 'CLEAN',
                'detection_method': 'cnn',
                'raw_score': float(prediction_prob),
                'scan_time_ms': round(scan_time, 2),
                'file_path': str(file_path),
                'file_name': Path(file_path).name,
                'file_size': len(file_bytes)
            }
            
        except Exception as e:
            logger.error(f"Scan failed for {file_path}: {e}")
            raise
    
    def load_model(self, model_path: str):
        """Load trained CNN model from disk"""
        try:
            logger.info(f"Loading CNN model from {model_path}")
            self.model = keras.models.load_model(model_path)
            self.model_path = model_path
            logger.info("✓ CNN model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def save_model(self, save_path: str):
        """Save trained model to disk"""
        if self.model is None:
            raise ValueError("No model to save")
        
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        self.model.save(save_path)
        logger.info(f"✓ Model saved to {save_path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        avg_scan_time = self.total_scan_time / self.scans_performed if self.scans_performed > 0 else 0
        
        stats = {
            'model_info': {
                'type': '1D CNN',
                'max_bytes': self.max_bytes,
                'input_shape': f"({self.max_bytes}, 1)"
            },
            'performance': {
                'scans_performed': self.scans_performed,
                'threats_detected': self.threats_detected,
                'avg_scan_time_ms': round(avg_scan_time, 2),
                'detection_rate': round(self.threats_detected / self.scans_performed * 100, 2) if self.scans_performed > 0 else 0
            }
        }
        
        if self.model:
            stats['model_info']['parameters'] = self.model.count_params()
            stats['model_info']['layers'] = len(self.model.layers)
        
        return stats


def load_zenodo_dataset(csv_path: str, sample_limit: int = None) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load Zenodo dataset for training
    
    Args:
        csv_path: Path to Zenodo CSV file
        sample_limit: Optional limit on number of samples
        
    Returns:
        X (features), y (labels)
    """
    logger.info(f"Loading Zenodo dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    
    if sample_limit:
        df = df.sample(n=min(sample_limit, len(df)), random_state=42)
    
    logger.info(f"Dataset shape: {df.shape}")
    
    # Identify label column (usually 'Label', 'Class', or 'Malware')
    label_col = None
    for col in ['Label', 'Class', 'Malware', 'label', 'class']:
        if col in df.columns:
            label_col = col
            break
    
    if label_col is None:
        raise ValueError("Could not find label column in dataset")
    
    logger.info(f"Using '{label_col}' as label column")
    
    # Separate features and labels
    y = df[label_col]
    X = df.drop(columns=[label_col])
    
    # Convert labels to binary (0 = benign, 1 = malicious)
    # Handle different label formats
    if y.dtype == 'object':
        # String labels
        y = y.map(lambda x: 1 if str(x).lower() in ['malicious', 'malware', '1', 'ransomware'] else 0)
    else:
        # Numeric labels - ensure 0/1
        y = (y != 0).astype(int)
    
    logger.info(f"Class distribution: {y.value_counts().to_dict()}")
    logger.info(f"Features: {len(X.columns)}")
    
    return X, y


# Demo usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create detector
    detector = CNNMalwareDetector(max_bytes=100000)
    
    # Build model
    model = detector.build_model()
    print("\n" + "="*60)
    print("1D CNN Model Architecture")
    print("="*60)
    model.summary()
    
    print("\n" + "="*60)
    print(f"Total parameters: {model.count_params():,}")
    print(f"Input shape: ({detector.max_bytes}, 1)")
    print(f"Max file size: {detector.max_bytes / 1024:.1f} KB")
    print("="*60)
