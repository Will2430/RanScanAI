"""
Fixed CNN training script with better class imbalance handling.

Three strategies:
1. BALANCED_DATASET: Oversample benign to 1:2 ratio (best performance)
2. MODERATE_WEIGHTS: Use gentle class weights instead of aggressive 'balanced'
3. NO_WEIGHTS: Remove class weights entirely

Recommended: BALANCED_DATASET
"""

import numpy as np
import pandas as pd
import json
import os
from pathlib import Path
from collections import Counter
import pickle
import logging

from keras import layers, models, callbacks
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FixedCNNTrainer:
    def __init__(self, kaggle_dir, malbehavd_path, strategy='BALANCED_DATASET'):
        """
        Initialize trainer.
        
        Args:
            strategy: 'BALANCED_DATASET', 'MODERATE_WEIGHTS', or 'NO_WEIGHTS'
        """
        self.kaggle_dir = kaggle_dir
        self.malbehavd_path = malbehavd_path
        self.strategy = strategy
        self.vocab = None
        self.vocab_size = 0
        self.max_sequence_length = 2000
        self.min_api_freq = 5
        
        logger.info(f"Using strategy: {strategy}")
    
    def load_malbehavd_benign(self):
        """Load benign samples from MalBehavD dataset."""
        logger.info(f"Loading MalBehavD from {self.malbehavd_path}...")
        df = pd.read_csv(self.malbehavd_path)
        
        # Filter benign samples (label = 0)
        benign_df = df[df['labels'] == 0].copy()
        logger.info(f"Found {len(benign_df)} benign samples in MalBehavD")
        
        # Extract API call sequences from numbered columns
        sequences = []
        for idx, row in benign_df.iterrows():
            sequence = []
            for col in df.columns:
                if col.isdigit():
                    api_call = row[col]
                    if pd.notna(api_call) and api_call != '':
                        sequence.append(str(api_call))
            if sequence:
                sequences.append(sequence)
        
        logger.info(f"Extracted {len(sequences)} benign sequences from MalBehavD")
        return sequences
    
    def load_kaggle_json(self, filename):
        """Load samples from a Kaggle JSON file."""
        filepath = os.path.join(self.kaggle_dir, filename)
        logger.info(f"Loading {filename}...")
        
        with open(filepath, 'r') as f:
            json_data = json.load(f)
        
        sequences = []
        if 'apis' in json_data and isinstance(json_data['apis'], list):
            for api_sequence in json_data['apis']:
                if isinstance(api_sequence, list):
                    clean_sequence = [str(api) for api in api_sequence if api]
                    if clean_sequence:
                        sequences.append(clean_sequence)
        
        logger.info(f"Loaded {len(sequences)} sequences from {filename}")
        return sequences
    
    def load_all_datasets(self):
        """Load and combine all datasets."""
        logger.info("\n" + "="*60)
        logger.info("LOADING DATASETS")
        logger.info("="*60)
        
        # Load benign samples from MalBehavD
        benign_malbehavd = self.load_malbehavd_benign()
        
        # Load benign samples from Kaggle
        benign_kaggle = self.load_kaggle_json('benign.json')
        
        # Load malicious samples from Kaggle
        malicious_368 = self.load_kaggle_json('368.json')
        malicious_389 = self.load_kaggle_json('389.json')
        
        # Combine
        all_benign = benign_malbehavd + benign_kaggle
        all_malicious = malicious_368 + malicious_389
        
        logger.info("\n" + "="*60)
        logger.info("RAW DATASET STATISTICS")
        logger.info("="*60)
        logger.info(f"Total benign samples: {len(all_benign)}")
        logger.info(f"Total malicious samples: {len(all_malicious)}")
        logger.info(f"Class ratio (benign:malicious): 1:{len(all_malicious)/len(all_benign):.2f}")
        
        # Apply strategy
        if self.strategy == 'BALANCED_DATASET':
            all_benign, all_malicious = self.balance_dataset(all_benign, all_malicious)
        
        # Create labels
        benign_labels = [0] * len(all_benign)
        malicious_labels = [1] * len(all_malicious)
        
        # Combine everything
        all_sequences = all_benign + all_malicious
        all_labels = benign_labels + malicious_labels
        
        logger.info("\n" + "="*60)
        logger.info("FINAL DATASET STATISTICS")
        logger.info("="*60)
        logger.info(f"Total benign samples: {len(all_benign)}")
        logger.info(f"Total malicious samples: {len(all_malicious)}")
        logger.info(f"Total samples: {len(all_sequences)}")
        logger.info(f"Class ratio (benign:malicious): 1:{len(all_malicious)/len(all_benign):.2f}")
        
        return all_sequences, np.array(all_labels)
    
    def balance_dataset(self, benign_sequences, malicious_sequences):
        """
        Oversample benign to achieve 1:2 ratio (benign:malicious).
        This is much better than aggressive class weights.
        """
        n_benign = len(benign_sequences)
        n_malicious = len(malicious_sequences)
        
        # Target: benign = malicious / 2
        target_benign = n_malicious // 2
        
        if target_benign > n_benign:
            logger.info(f"\nOversampling benign from {n_benign} to {target_benign}...")
            
            # Randomly oversample benign
            indices = np.random.choice(n_benign, target_benign, replace=True)
            balanced_benign = [benign_sequences[i] for i in indices]
            
            return balanced_benign, malicious_sequences
        else:
            logger.info("Benign already sufficient, no oversampling needed")
            return benign_sequences, malicious_sequences
    
    def build_vocabulary(self, sequences):
        """Build vocabulary from API call sequences."""
        logger.info("\n" + "="*60)
        logger.info("BUILDING VOCABULARY")
        logger.info("="*60)
        
        # Count API call frequencies
        api_counter = Counter()
        for sequence in sequences:
            # Convert to lowercase
            lowercase_sequence = [api.lower() for api in sequence]
            api_counter.update(lowercase_sequence)
        
        logger.info(f"Total unique API calls: {len(api_counter)}")
        
        # Filter by minimum frequency
        filtered_apis = {api: count for api, count in api_counter.items() 
                        if count >= self.min_api_freq}
        
        logger.info(f"API calls after frequency filter (>={self.min_api_freq}): {len(filtered_apis)}")
        
        # Create vocabulary (reserve 0 for padding, 1 for <UNK>)
        vocab = {'<PAD>': 0, '<UNK>': 1}
        for idx, (api, _) in enumerate(sorted(filtered_apis.items()), start=2):
            vocab[api] = idx
        
        self.vocab = vocab
        self.vocab_size = len(vocab)
        
        logger.info(f"Vocabulary size: {self.vocab_size}")
        logger.info(f"Top 10 most common APIs:")
        for api, count in api_counter.most_common(10):
            logger.info(f"  {api}: {count}")
        
        return vocab
    
    def sequences_to_indices(self, sequences):
        """Convert API sequences to index sequences."""
        indexed_sequences = []
        for sequence in sequences:
            indices = []
            for api in sequence:
                api_lower = api.lower()
                indices.append(self.vocab.get(api_lower, 1))  # 1 = <UNK>
            indexed_sequences.append(indices)
        return indexed_sequences
    
    def pad_sequences(self, sequences):
        """Pad or truncate sequences to max_sequence_length."""
        padded = np.zeros((len(sequences), self.max_sequence_length), dtype=np.int32)
        for i, seq in enumerate(sequences):
            if len(seq) > self.max_sequence_length:
                padded[i] = seq[:self.max_sequence_length]
            else:
                padded[i, :len(seq)] = seq
        return padded
    
    def build_model(self):
        """Build 1D CNN model."""
        model = models.Sequential([
            layers.Input(shape=(self.max_sequence_length,)),
            layers.Embedding(
                input_dim=self.vocab_size,
                output_dim=64,
                mask_zero=True
            ),
            layers.Conv1D(64, kernel_size=3, activation='relu', padding='same'),
            layers.MaxPooling1D(pool_size=2),
            layers.Conv1D(64, kernel_size=5, activation='relu', padding='same'),
            layers.GlobalMaxPooling1D(),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid')
        ], name='malware_cnn')
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'AUC', 'Precision', 'Recall']
        )
        
        # Build model
        model.build(input_shape=(None, self.max_sequence_length))
        
        logger.info("\n" + "="*60)
        logger.info("MODEL ARCHITECTURE")
        logger.info("="*60)
        model.summary(print_fn=logger.info)
        
        return model
    
    def get_class_weights(self, y_train):
        """Get class weights based on strategy."""
        if self.strategy == 'NO_WEIGHTS':
            logger.info("\nStrategy: NO_WEIGHTS - Not using class weights")
            return None
        
        elif self.strategy == 'MODERATE_WEIGHTS':
            # Gentle weights based on ratio
            n_benign = sum(y_train == 0)
            n_malicious = sum(y_train == 1)
            ratio = n_malicious / n_benign
            
            # Square root dampening (less aggressive than 'balanced')
            benign_weight = np.sqrt(ratio)
            malicious_weight = 1.0
            
            class_weights = {0: benign_weight, 1: malicious_weight}
            logger.info(f"\nStrategy: MODERATE_WEIGHTS")
            logger.info(f"Class weights: {class_weights}")
            return class_weights
        
        elif self.strategy == 'BALANCED_DATASET':
            logger.info("\nStrategy: BALANCED_DATASET - Dataset already balanced, no weights needed")
            return None
        
        return None
    
    def train(self, epochs=30, batch_size=32, validation_split=0.15, test_split=0.15):
        """Train the model."""
        # Load data
        sequences, labels = self.load_all_datasets()
        
        # Build vocabulary
        vocab = self.build_vocabulary(sequences)
        
        # Save vocabulary
        with open('api_vocab_fixed.pkl', 'wb') as f:
            pickle.dump(vocab, f)
        logger.info("Vocabulary saved to api_vocab_fixed.pkl")
        
        # Convert sequences to indices
        logger.info("\nConverting sequences to indices...")
        indexed_sequences = self.sequences_to_indices(sequences)
        
        # Pad sequences
        logger.info("Padding sequences...")
        X = self.pad_sequences(indexed_sequences)
        y = labels
        
        # Split data
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_split, random_state=42, stratify=y
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=validation_split/(1-test_split), 
            random_state=42, stratify=y_temp
        )
        
        logger.info("\n" + "="*60)
        logger.info("DATA SPLITS")
        logger.info("="*60)
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"  Benign: {sum(y_train == 0)} ({sum(y_train == 0)/len(y_train)*100:.1f}%)")
        logger.info(f"  Malicious: {sum(y_train == 1)} ({sum(y_train == 1)/len(y_train)*100:.1f}%)")
        logger.info(f"Validation set: {len(X_val)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        
        # Get class weights
        class_weights = self.get_class_weights(y_train)
        
        # Build model
        model = self.build_model()
        
        # Callbacks
        callback_list = [
            callbacks.EarlyStopping(
                monitor='val_loss',
                patience=7,
                restore_best_weights=True,
                verbose=1
            ),
            callbacks.ModelCheckpoint(
                'best_fixed_cnn_model.keras',
                monitor='val_auc',
                mode='max',
                save_best_only=True,
                verbose=1
            ),
            callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=3,
                min_lr=1e-6,
                verbose=1
            )
        ]
        
        # Train
        logger.info("\nStarting training...")
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=class_weights,
            callbacks=callback_list,
            verbose=1
        )
        
        # Evaluate on test set
        logger.info("\n" + "="*60)
        logger.info("EVALUATION ON TEST SET")
        logger.info("="*60)
        
        test_results = model.evaluate(X_test, y_test, verbose=0)
        logger.info(f"Test Loss: {test_results[0]:.4f}")
        logger.info(f"Test Accuracy: {test_results[1]:.4f}")
        logger.info(f"Test AUC: {test_results[2]:.4f}")
        logger.info(f"Test Precision: {test_results[3]:.4f}")
        logger.info(f"Test Recall: {test_results[4]:.4f}")
        
        # Check predictions distribution
        logger.info("\n" + "="*60)
        logger.info("PREDICTION DISTRIBUTION")
        logger.info("="*60)
        y_pred = model.predict(X_test, verbose=0)
        y_pred_binary = (y_pred > 0.5).astype(int).flatten()
        
        logger.info(f"Predicted Benign: {sum(y_pred_binary == 0)} ({sum(y_pred_binary == 0)/len(y_pred_binary)*100:.1f}%)")
        logger.info(f"Predicted Malicious: {sum(y_pred_binary == 1)} ({sum(y_pred_binary == 1)/len(y_pred_binary)*100:.1f}%)")
        
        # Confusion Matrix
        from sklearn.metrics import confusion_matrix, classification_report
        cm = confusion_matrix(y_test, y_pred_binary)
        logger.info("\nConfusion Matrix:")
        logger.info(f"              Predicted Benign  Predicted Malicious")
        logger.info(f"Actually Benign:      {cm[0][0]:6d}            {cm[0][1]:6d}")
        logger.info(f"Actually Malicious:   {cm[1][0]:6d}            {cm[1][1]:6d}")
        
        logger.info("\nClassification Report:")
        logger.info("\n" + classification_report(y_test, y_pred_binary, 
                                                  target_names=['Benign', 'Malicious']))
        
        logger.info("\n" + "="*60)
        logger.info("TRAINING COMPLETE")
        logger.info("="*60)
        logger.info("Model saved to: best_fixed_cnn_model.keras")
        logger.info("Vocabulary saved to: api_vocab_fixed.pkl")
        
        return history

def main():
    # Paths
    KAGGLE_DIR = r"C:\Users\willi\Downloads\archive\data\Processed"
    MALBEHAVD_PATH = r"C:\Users\willi\OneDrive\Test\K\dataset\MalBehavD-V1-dataset.csv"
    
    # Choose strategy (RECOMMENDED: 'BALANCED_DATASET')
    STRATEGY = 'BALANCED_DATASET'  # Options: 'BALANCED_DATASET', 'MODERATE_WEIGHTS', 'NO_WEIGHTS'
    
    trainer = FixedCNNTrainer(KAGGLE_DIR, MALBEHAVD_PATH, strategy=STRATEGY)
    history = trainer.train(epochs=10, batch_size=32)

if __name__ == "__main__":
    main()
