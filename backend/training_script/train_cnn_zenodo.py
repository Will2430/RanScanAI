"""
Training Script for 1D CNN Malware Detector
Uses Zenodo dataset with tabular features converted to byte-like sequences
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
import json
import logging
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ZenodoCNNTrainer:
    """
    Train 1D CNN on Zenodo dataset
    Since Zenodo has tabular features (not raw bytes), we'll:
    1. Normalize features
    2. Reshape to 1D sequence for CNN
    3. Train with data augmentation
    """
    
    def __init__(self, dataset_path: str, output_dir: str = "models"):
        self.dataset_path = Path(dataset_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.model = None
        self.history = None
        
    def load_and_prepare_data(self, test_size: float = 0.2, val_size: float = 0.1):
        """Load Zenodo dataset and prepare for CNN training"""
        logger.info(f"Loading dataset from {self.dataset_path}")
        
        # Load dataset
        df = pd.read_csv(self.dataset_path)
        logger.info(f"Dataset shape: {df.shape}")
        logger.info(f"Columns: {df.columns.tolist()[:10]}...")  # Show first 10 columns
        
        # Find label column
        label_col = None
        for col in ['Label', 'Class', 'Malware', 'label', 'class', 'target']:
            if col in df.columns:
                label_col = col
                break
        
        if label_col is None:
            # Check last column
            logger.warning("No standard label column found, using last column")
            label_col = df.columns[-1]
        
        logger.info(f"Using '{label_col}' as label column")
        
        # Separate features and labels
        y = df[label_col].copy()
        
        # Drop label column
        columns_to_drop = [label_col]
        
        # CRITICAL: Drop data leakage columns (unique IDs and target-related info)
        leakage_columns = [
            'md5', 'MD5', 'sha1', 'SHA1', 'sha256', 'SHA256', 'sha512', 'SHA512',
            'hash', 'Hash', 'file_hash', 'FileHash',
            'family', 'Family', 'malware_family', 'MalwareFamily',
            'category', 'Category', 'type', 'Type',
            'file_name', 'FileName', 'filename', 'name', 'Name',
            'file_extension', 'FileExtension', 'extension', 'Extension', 'file_extension','processes_malicious', 'processes_suspicious', 
            'files_malicious', 'files_suspicious'
        ]
        
        for leak_col in leakage_columns:
            if leak_col in df.columns and leak_col not in columns_to_drop:
                columns_to_drop.append(leak_col)
                logger.info(f"  ⚠️  Dropping data leakage column: '{leak_col}'")
        
        X = df.drop(columns=columns_to_drop)
        
        logger.info(f"Dropped {len(columns_to_drop)} columns (label + leakage)")
        logger.info(f"Remaining features: {len(X.columns)}")
        
        # Convert labels to binary (1 = malicious, 0 = benign)
        if y.dtype == 'object':
            y = y.map(lambda x: 1 if str(x).lower() in ['malicious', 'malware', '1', 'ransomware', 'infected'] else 0)
        else:
            y = (y != 0).astype(int)
        
        # Handle non-numeric features (should be minimal after dropping leakage columns)
        # Define mappings matching PE feature extractor
        PE_TYPE_MAP = {'PE32': 1, 'PE32+': 2, 'Unknown': 0}
        MACHINE_TYPE_MAP = {
            'Intel 386 or later, and compatibles': 1,  # IMAGE_FILE_MACHINE_I386
            'Intel Itanium': 2,  # IMAGE_FILE_MACHINE_IA64  
            'AMD AMD64': 3,      # IMAGE_FILE_MACHINE_AMD64
        }
        SUBSYSTEM_MAP = {
            'IMAGE_SUBSYSTEM_NATIVE': 1,
            'IMAGE_SUBSYSTEM_WINDOWS_GUI': 2,
            'IMAGE_SUBSYSTEM_WINDOWS_CUI': 3,
        }
        
        # PARSE HEX FIELDS (e.g., "0x00000000000108EC (Section: .text)")
        hex_fields = ['AddressOfEntryPoint', 'EntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase']
        for field in hex_fields:
            if field in X.columns and X[field].dtype == 'object':
                logger.info(f"  Parsing hex field '{field}'")
                def parse_hex(val):
                    if pd.isna(val):
                        return 0
                    val_str = str(val)
                    # Remove section annotation: "0x12345 (Section: .text)" -> "0x12345"
                    if '(' in val_str:
                        val_str = val_str.split('(')[0].strip()
                    try:
                        return int(val_str, 16)
                    except:
                        return 0
                X[field] = X[field].apply(parse_hex)
        
        # PARSE CHARACTERISTICS FIELDS: Convert to flag counts (NOT raw bitmasks)
        # Zenodo format can be: "['IMAGE_SCN_CNT_CODE']" (string list) OR 1610612736 (numeric bitmask)
        # PE extractor returns: _count_flags(1610612736) = 3 (number of set bits)
        # MUST MATCH to prevent scale mismatch!
        characteristics_fields = [col for col in X.columns if 'Characteristics' in col or 'DllCharacteristics' in col]
        
        def count_flags(bitmask):
            """Count number of set bits in bitmask (matches PE extractor)"""
            if pd.isna(bitmask) or bitmask == 0:
                return 0
            return bin(int(bitmask)).count('1')
        
        for field in characteristics_fields:
            if field in X.columns:
                if X[field].dtype == 'object':
                    # String format: "['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE']"
                    logger.info(f"  Parsing list field '{field}' (string format)")
                    def parse_list(val):
                        if pd.isna(val):
                            return 0
                        val_str = str(val)
                        if val_str.startswith('[') and val_str.endswith(']'):
                            items = [item.strip().strip("'\"") for item in val_str[1:-1].split(',')]
                            return len([item for item in items if item])
                        return 0
                    X[field] = X[field].apply(parse_list)
                else:
                    # Numeric format: 1610612736 (bitmask) → convert to flag count
                    logger.info(f"  Converting bitmask field '{field}' to flag count (prevents scale explosion)")
                    X[field] = X[field].apply(count_flags)
        
        # NORMALIZE ImageBase: Convert to PE type indicator (prevents 32-bit vs 64-bit scale mismatch)
        # PE32 ImageBase: ~0x400000 (4 million) → normalize to 0
        # PE32+ ImageBase: ~0x140000000 (5.3 billion) → normalize to 1
        # This matches PE feature extractor behavior
        if 'ImageBase' in X.columns and 'PEType' in X.columns:
            logger.info(f"  Normalizing ImageBase based on PEType (prevents 32/64-bit scale mismatch)")
            # If ImageBase > 100 million, likely PE32+ (set to 1), else PE32 (set to 0)
            X['ImageBase'] = (X['ImageBase'] > 100000000).astype(int)
        
        for col in X.columns:
            if X[col].dtype == 'object':
                # Check if it's hex format (starts with '0x') - might still have some
                sample_val = str(X[col].iloc[0]) if len(X) > 0 else ""
                if sample_val.startswith('0x'):
                    logger.info(f"  Converting remaining hex column '{col}' to integer")
                    try:
                        # Convert hex strings to integers
                        X[col] = X[col].apply(lambda x: int(str(x).split('(')[0].strip(), 16) if pd.notna(x) else 0)
                    except ValueError as e:
                        logger.warning(f"  Failed to convert hex column '{col}': {e}, using factorize")
                        X[col] = pd.factorize(X[col])[0]
                # Apply PE-style mappings for known columns
                elif col == 'PEType':
                    logger.info(f"  Mapping column '{col}' using PE_TYPE_MAP")
                    X[col] = X[col].map(PE_TYPE_MAP).fillna(0).astype(int)
                elif col == 'MachineType':
                    logger.info(f"  Mapping column '{col}' using MACHINE_TYPE_MAP")
                    X[col] = X[col].map(MACHINE_TYPE_MAP).fillna(0).astype(int)
                elif col == 'Subsystem':
                    logger.info(f"  Mapping column '{col}' using SUBSYSTEM_MAP")
                    X[col] = X[col].map(SUBSYSTEM_MAP).fillna(0).astype(int)
                else:
                    # Try to convert to numeric first, then factorize if fails
                    try:
                        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
                        logger.info(f"  Converted column '{col}' to numeric")
                    except:
                        logger.warning(f"  Converting categorical column '{col}' to numeric via factorize")
                        X[col] = pd.factorize(X[col])[0]
        
        # Handle missing values
        X = X.fillna(0)
        
        # Remove infinite values
        X = X.replace([np.inf, -np.inf], 0)
        
        logger.info(f"Features: {len(X.columns)}")
        logger.info(f"Class distribution:\n{y.value_counts()}")
        logger.info(f"Class balance: {y.mean():.2%} malicious")
        
        # Show first 20 feature names for verification
        logger.info(f"\nFirst 20 features used for training:")
        for i, col in enumerate(X.columns[:20]):
            logger.info(f"  {i+1}. {col}")
        if len(X.columns) > 20:
            logger.info(f"  ... and {len(X.columns) - 20} more features")
        
        # Split data
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_size/(1-test_size), random_state=42, stratify=y_temp
        )
        
        logger.info(f"Train samples: {len(X_train)}")
        logger.info(f"Validation samples: {len(X_val)}")
        logger.info(f"Test samples: {len(X_test)}")
        
        # Normalize features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Reshape for CNN (samples, timesteps, features)
        # Treat each feature as a timestep with 1 channel
        X_train_cnn = X_train_scaled.reshape(X_train_scaled.shape[0], X_train_scaled.shape[1], 1)
        X_val_cnn = X_val_scaled.reshape(X_val_scaled.shape[0], X_val_scaled.shape[1], 1)
        X_test_cnn = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)
        
        self.X_train = X_train_cnn
        self.X_val = X_val_cnn
        self.X_test = X_test_cnn
        self.y_train = y_train.values
        self.y_val = y_val.values
        self.y_test = y_test.values
        self.n_features = X_train_scaled.shape[1]
        
        logger.info(f"CNN input shape: {self.X_train.shape}")
        
        # Save scaler for inference (CRITICAL FIX)
        scaler_path = self.output_dir / "scaler.pkl"
        import joblib
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"✓ Scaler saved to {scaler_path}")
        
        # Save feature names for validation
        feature_names_path = self.output_dir / "feature_names.json"
        with open(feature_names_path, 'w') as f:
            json.dump(X.columns.tolist(), f, indent=2)
        logger.info(f"✓ Feature names saved to {feature_names_path}")
        
        return self
    
    def build_model_for_tabular(self):
        """Build CNN optimized for tabular features (not raw bytes)"""
        
        input_shape = (self.n_features, 1)
        
        # L2 regularization to reduce overfitting
        l2_reg = keras.regularizers.l2(0.001)
        
        model = keras.Sequential([
            keras.layers.Input(shape=input_shape),
            
            # First conv block - small kernel for feature relationships
            keras.layers.Conv1D(64, kernel_size=3, activation='relu', padding='same'),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.3),  # Increased from 0.3
            
            # Second conv block - larger kernel
            keras.layers.Conv1D(128, kernel_size=5, activation='relu', padding='same'),
            keras.layers.BatchNormalization(),
            keras.layers.MaxPooling1D(pool_size=2),
            keras.layers.Dropout(0.3),  # Increased from 0.3
            
            # Third conv block
            keras.layers.Conv1D(256, kernel_size=7, activation='relu', padding='same'),
            keras.layers.BatchNormalization(),
            keras.layers.MaxPooling1D(pool_size=2),
            keras.layers.Dropout(0.4),  # Increased from 0.4
            
            # Fourth conv block
            keras.layers.Conv1D(128, kernel_size=5, activation='relu', padding='same'),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.4),  # Increased from 0.4
            
            # Global pooling
            keras.layers.GlobalAveragePooling1D(),
            
            # Dense layers with L2 regularization
            keras.layers.Dense(256, activation='relu', kernel_regularizer=l2_reg),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.5),  # Increased from 0.5
            
            keras.layers.Dense(128, activation='relu', kernel_regularizer=l2_reg),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.5),  # Increased from 0.5
            
            keras.layers.Dense(64, activation='relu', kernel_regularizer=l2_reg),
            keras.layers.Dropout(0.5),  # Increased from 0.5
            
            # Output
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        # Compile with class weights to handle imbalance
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
        logger.info("✓ Model built successfully (with L2 regularization to reduce overfitting)")
        return model
    
    def train(self, epochs: int = 10, batch_size: int = 32):
        """Train the CNN model"""
        
        if self.model is None:
            raise ValueError("Model not built. Call build_model_for_tabular() first")
        
        # Calculate class weights
        n_malicious = np.sum(self.y_train)
        n_benign = len(self.y_train) - n_malicious
        class_weight = {
            0: len(self.y_train) / (2 * n_benign),
            1: len(self.y_train) / (2 * n_malicious)
        }
        
        logger.info(f"Class weights: {class_weight}")
        
        # Callbacks
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = self.output_dir / f"cnn_zenodo_{timestamp}.keras"
        
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=7,  # Reduced from 10 for earlier stopping
                restore_best_weights=True,
                verbose=1
            ),
            keras.callbacks.ModelCheckpoint(
                str(model_path),
                monitor='val_auc',
                save_best_only=True,
                mode='max',
                verbose=1
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7,
                verbose=1
            )
        ]
        
        logger.info(f"Training for {epochs} epochs with batch size {batch_size}")
        logger.info(f"Model will be saved to: {model_path}")
        
        # Train
        self.history = self.model.fit(
            self.X_train, self.y_train,
            validation_data=(self.X_val, self.y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=class_weight,
            callbacks=callbacks,
            verbose=1
        )
        
        self.model_path = model_path
        logger.info(f"✓ Training complete! Model saved to {model_path}")
        
        return self
    
    def evaluate(self):
        """Evaluate model on test set"""
        
        if self.model is None:
            raise ValueError("No model to evaluate")
        
        logger.info("\n" + "="*60)
        logger.info("Evaluating on test set...")
        logger.info("="*60)
        
        # Predictions
        y_pred_proba = self.model.predict(self.X_test, verbose=0)
        y_pred = (y_pred_proba >= 0.5).astype(int).flatten()
        
        # Metrics
        test_loss, test_acc, test_precision, test_recall, test_auc = self.model.evaluate(
            self.X_test, self.y_test, verbose=0
        )
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(
            self.y_test, y_pred,
            target_names=['Benign', 'Malicious'],
            digits=4
        ))
        
        # Confusion matrix
        cm = confusion_matrix(self.y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"                Benign  Malicious")
        print(f"Actual Benign   {cm[0][0]:6d}  {cm[0][1]:6d}")
        print(f"       Malicious {cm[1][0]:6d}  {cm[1][1]:6d}")
        
        # Calculate metrics
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        print(f"\nDetailed Metrics:")
        print(f"  Accuracy:  {test_acc:.4f}")
        print(f"  Precision: {test_precision:.4f}")
        print(f"  Recall:    {test_recall:.4f}")
        print(f"  F1-Score:  {2 * test_precision * test_recall / (test_precision + test_recall):.4f}")
        print(f"  AUC-ROC:   {test_auc:.4f}")
        print(f"  FPR:       {fpr:.4f} (False Positive Rate)")
        print(f"  FNR:       {fnr:.4f} (False Negative Rate)")
        
        # Save metrics
        metrics = {
            'accuracy': float(test_acc),
            'precision': float(test_precision),
            'recall': float(test_recall),
            'auc': float(test_auc),
            'f1_score': float(2 * test_precision * test_recall / (test_precision + test_recall)),
            'fpr': float(fpr),
            'fnr': float(fnr),
            'confusion_matrix': cm.tolist(),
            'n_features': int(self.n_features),
            'model_type': '1D CNN',
            'dataset': 'Zenodo',
            'timestamp': datetime.now().isoformat()
        }
        
        # Save metadata
        metadata_path = self.output_dir / "cnn_model_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.info(f"\n✓ Metrics saved to {metadata_path}")
        
        # Plot training history
        self.plot_training_history()
        
        return metrics
    
    def plot_training_history(self):
        """Plot training curves"""
        
        if self.history is None:
            logger.warning("No training history to plot")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Accuracy
        axes[0, 0].plot(self.history.history['accuracy'], label='Train')
        axes[0, 0].plot(self.history.history['val_accuracy'], label='Validation')
        axes[0, 0].set_title('Model Accuracy')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Accuracy')
        axes[0, 0].legend()
        axes[0, 0].grid(True)
        
        # Loss
        axes[0, 1].plot(self.history.history['loss'], label='Train')
        axes[0, 1].plot(self.history.history['val_loss'], label='Validation')
        axes[0, 1].set_title('Model Loss')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Loss')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # AUC
        axes[1, 0].plot(self.history.history['auc'], label='Train')
        axes[1, 0].plot(self.history.history['val_auc'], label='Validation')
        axes[1, 0].set_title('AUC-ROC')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('AUC')
        axes[1, 0].legend()
        axes[1, 0].grid(True)
        
        # Precision & Recall
        axes[1, 1].plot(self.history.history['precision'], label='Precision (Train)')
        axes[1, 1].plot(self.history.history['recall'], label='Recall (Train)')
        axes[1, 1].plot(self.history.history['val_precision'], label='Precision (Val)', linestyle='--')
        axes[1, 1].plot(self.history.history['val_recall'], label='Recall (Val)', linestyle='--')
        axes[1, 1].set_title('Precision & Recall')
        axes[1, 1].set_xlabel('Epoch')
        axes[1, 1].set_ylabel('Score')
        axes[1, 1].legend()
        axes[1, 1].grid(True)
        
        plt.tight_layout()
        
        # Save plot
        plot_path = self.output_dir / "training_history.png"
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        logger.info(f"✓ Training history plot saved to {plot_path}")
        
        plt.close()


def main():
    """Main training pipeline"""
    
    print("\n" + "="*80)
    print("SecureGuard - 1D CNN Training on Zenodo Dataset")
    print("="*80 + "\n")
    
    # Configuration
    DATASET_PATH = "C:/Users/willi/OneDrive/Test/K/Dataset/Zenedo.csv"
    OUTPUT_DIR = "C:/Users/willi/OneDrive/Test/K/models"
    
    # Initialize trainer
    trainer = ZenodoCNNTrainer(
        dataset_path=DATASET_PATH,
        output_dir=OUTPUT_DIR
    )
    
    # Load and prepare data
    trainer.load_and_prepare_data(test_size=0.2, val_size=0.1)
    
    # Build model
    model = trainer.build_model_for_tabular()
    print("\n" + "="*80)
    print("Model Architecture")
    print("="*80)
    model.summary()
    
    # Train model
    print("\n" + "="*80)
    print("Starting Training")
    print("="*80 + "\n")
    trainer.train(epochs=10, batch_size=64)
    
    # Evaluate
    print("\n" + "="*80)
    print("Final Evaluation")
    print("="*80)
    metrics = trainer.evaluate()
    
    print("\n" + "="*80)
    print("Training Complete!")
    print("="*80)
    print(f"\nModel saved to: {trainer.model_path}")
    print(f"Accuracy: {metrics['accuracy']:.2%}")
    print(f"AUC-ROC: {metrics['auc']:.4f}")
    print(f"False Positive Rate: {metrics['fpr']:.2%}")
    print(f"False Negative Rate: {metrics['fnr']:.2%}")
    print("\nYou can now use this model with ml_model_cnn.py!")
    

if __name__ == "__main__":
    main()
