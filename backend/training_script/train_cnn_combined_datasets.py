"""
Combined Dataset CNN Training Script
Combines benign samples from MalBehavD + Kaggle with malicious samples from Kaggle
for binary malware classification using 1D CNN on API call sequences.
"""

import os
import json
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, regularizers, callbacks
import matplotlib.pyplot as plt
import logging


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class CombinedDatasetCNNTrainer:
    def __init__(self, 
                 malbehavd_path,
                 kaggle_dir,
                 max_sequence_length=2000,
                 min_api_freq=5,
                 embedding_dim=64):
        """
        Initialize the trainer with dataset paths.
        
        Args:
            malbehavd_path: Path to MalBehavD-V1-dataset.csv
            kaggle_dir: Directory containing Kaggle JSON files (benign.json, 368.json, 389.json)
            max_sequence_length: Maximum length of API call sequences
            min_api_freq: Minimum frequency for API calls to be included in vocabulary
            embedding_dim: Dimension of embedding layer
        """
        self.malbehavd_path = malbehavd_path
        self.kaggle_dir = kaggle_dir
        self.max_sequence_length = max_sequence_length
        self.min_api_freq = min_api_freq
        self.embedding_dim = embedding_dim
        
        self.word_to_idx = {}
        self.idx_to_word = {}
        self.vocab_size = 0
        
    def load_malbehavd_benign(self):
        """Load benign samples from MalBehavD dataset."""
        logger.info("Loading benign samples from MalBehavD...")
        df = pd.read_csv(self.malbehavd_path)
        
        # Filter benign samples (label = 0)
        benign_df = df[df['labels'] == 0].copy()
        logger.info(f"Found {len(benign_df)} benign samples in MalBehavD")
        
        # Extract API call sequences from numbered columns
        sequences = []
        for idx, row in benign_df.iterrows():
            sequence = []
            # Columns are numbered '0', '1', '2', etc.
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
        logger.info (f"Loading {filename}...")
        
        with open(filepath, 'r') as f:
            json_data = json.load(f)
        
        # The JSON structure has 'apis' key containing the list of API call sequences
        sequences = []
        if 'apis' in json_data and isinstance(json_data['apis'], list):
            for api_sequence in json_data['apis']:
                if isinstance(api_sequence, list):
                    # Filter out empty strings and convert to strings
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
        
        # Combine all sequences
        all_benign = benign_malbehavd + benign_kaggle
        all_malicious = malicious_368 + malicious_389
        
        # Create labels
        benign_labels = [0] * len(all_benign)
        malicious_labels = [1] * len(all_malicious)
        
        # Combine everything
        all_sequences = all_benign + all_malicious
        all_labels = benign_labels + malicious_labels
        
        logger.info("\n" + "="*60)
        logger.info("DATASET STATISTICS")
        logger.info("="*60)
        logger.info(f"Total benign samples: {len(all_benign)}")
        logger.info(f"  - From MalBehavD: {len(benign_malbehavd)}")
        logger.info(f"  - From Kaggle: {len(benign_kaggle)}")
        logger.info(f"Total malicious samples: {len(all_malicious)}")
        logger.info(f"  - From 368.json: {len(malicious_368)}")
        logger.info(f"  - From 389.json: {len(malicious_389)}")
        logger.info(f"Total samples: {len(all_sequences)}")
        logger.info(f"Class ratio (benign:malicious): 1:{len(all_malicious)/len(all_benign):.2f}")
        
        return all_sequences, np.array(all_labels)
    
    def build_vocabulary(self, sequences):
        """Build vocabulary from API call sequences."""
        logger.info("\n" + "="*60)
        logger.info("BUILDING VOCABULARY")
        logger.info("="*60)
        
        # Count API call frequencies
        api_counter = Counter()
        for sequence in sequences:
            api_counter.update(sequence)
        
        logger.info(f"Total unique API calls: {len(api_counter)}")
        
        # Filter by minimum frequency
        filtered_apis = {api: count for api, count in api_counter.items() 
                        if count >= self.min_api_freq}
        
        logger.info(f"API calls with frequency >= {self.min_api_freq}: {len(filtered_apis)}")
        
        # Build word_to_idx mapping (reserve 0 for padding, 1 for unknown)
        self.word_to_idx = {'<PAD>': 0, '<UNK>': 1}
        for idx, api in enumerate(sorted(filtered_apis.keys()), start=2):
            self.word_to_idx[api] = idx
        
        self.idx_to_word = {idx: word for word, idx in self.word_to_idx.items()}
        self.vocab_size = len(self.word_to_idx)
        
        logger.info(f"Vocabulary size: {self.vocab_size}")
        
        # Show top 10 most common API calls
        logger.info("\nTop 10 most common API calls:")
        for api, count in api_counter.most_common(10):
            logger.info(f"  {api}: {count}")
        
        return self.word_to_idx
    
    def sequence_to_indices(self, sequence):
        """Convert API call sequence to indices."""
        return [self.word_to_idx.get(api, 1) for api in sequence]  # 1 is <UNK>
    
    def pad_sequences(self, sequences):
        """Pad sequences to max_sequence_length."""
        padded = np.zeros((len(sequences), self.max_sequence_length), dtype=np.int32)
        
        for i, seq in enumerate(sequences):
            length = min(len(seq), self.max_sequence_length)
            padded[i, :length] = seq[:length]
        
        return padded
    
    def prepare_data(self, sequences, labels):
        """Prepare data for training."""
        print("\n" + "="*60)
        print("PREPARING DATA")
        print("="*60)
        
        # Build vocabulary
        self.build_vocabulary(sequences)
        
        # Convert sequences to indices
        logger.info("Converting sequences to indices...")
        indexed_sequences = [self.sequence_to_indices(seq) for seq in sequences]
        
        # Pad sequences
        logger.info("Padding sequences...")
        padded_sequences = self.pad_sequences(indexed_sequences)
        
        # Calculate sequence length statistics
        seq_lengths = [len(seq) for seq in sequences]
        logger.info(f"\nSequence length statistics:")
        logger.info(f"  Min: {min(seq_lengths)}")
        logger.info(f"  Max: {max(seq_lengths)}")
        logger.info(f"  Mean: {np.mean(seq_lengths):.2f}")
        logger.info(f"  Median: {np.median(seq_lengths):.2f}")
        logger.info(f"  Sequences truncated: {sum(1 for l in seq_lengths if l > self.max_sequence_length)}")
        
        return padded_sequences, labels
    
    def build_model(self):
        """Build 1D CNN model for binary classification."""
        logger.info("\n" + "="*60)
        logger.info("BUILDING MODEL")
        logger.info("="*60)
        
        model = keras.Sequential([
            # Embedding layer
            layers.Embedding(
                input_dim=self.vocab_size,
                output_dim=self.embedding_dim,
                input_length=self.max_sequence_length,
                name='embedding'
            ),
            
            # First Conv1D block
            layers.Conv1D(
                filters=64,
                kernel_size=3,
                activation='relu',
                kernel_regularizer=regularizers.l2(0.01),
                name='conv1d_1'
            ),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            # Second Conv1D block
            layers.Conv1D(
                filters=64,
                kernel_size=5,
                activation='relu',
                kernel_regularizer=regularizers.l2(0.01),
                name='conv1d_2'
            ),
            layers.BatchNormalization(),
            layers.GlobalMaxPooling1D(),
            layers.Dropout(0.4),
            
            # Dense layers
            layers.Dense(64, activation='relu', 
                        kernel_regularizer=regularizers.l2(0.01),
                        name='dense_1'),
            layers.Dropout(0.5),
            layers.Dense(32, activation='relu',
                        kernel_regularizer=regularizers.l2(0.01),
                        name='dense_2'),
            layers.Dropout(0.5),
            
            # Output layer (sigmoid for binary classification)
            layers.Dense(1, activation='sigmoid', name='output')
        ])
        
        # Build the model to initialize layers
        model.build(input_shape=(None, self.max_sequence_length))
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 
                    keras.metrics.Precision(name='precision'),
                    keras.metrics.Recall(name='recall'),
                    keras.metrics.AUC(name='auc')]
        )
        
        logger.info(model.summary())
        
        return model
    
    def train(self, X, y, validation_split=0.2, test_size=0.15, epochs=30, batch_size=32):
        """Train the model."""
        logger.info("\n" + "="*60)
        logger.info("TRAINING")
        logger.info("="*60)
        
        # First split: separate test set
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Second split: separate train and validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=validation_split/(1-test_size), 
            random_state=42, stratify=y_temp
        )
        
        logger.info(f"Training samples: {len(X_train)}")
        logger.info(f"Validation samples: {len(X_val)}")
        logger.info(f"Test samples: {len(X_test)}")
        logger.info(f"\nTraining set class distribution:")
        logger.info(f"  Benign: {sum(y_train == 0)} ({sum(y_train == 0)/len(y_train)*100:.1f}%)")
        logger.info(f"  Malicious: {sum(y_train == 1)} ({sum(y_train == 1)/len(y_train)*100:.1f}%)")
        
        # Calculate class weights
        class_weights_array = compute_class_weight(
            'balanced',
            classes=np.unique(y_train),
            y=y_train
        )
        class_weights = {i: weight for i, weight in enumerate(class_weights_array)}
        logger.info(f"\nClass weights: {class_weights}")
        
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
                'best_combined_cnn_model.keras',
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
        
        test_loss, test_acc, test_precision, test_recall, test_auc = model.evaluate(
            X_test, y_test, verbose=0
        )
        
        logger.info(f"Test Loss: {test_loss:.4f}")
        logger.info(f"Test Accuracy: {test_acc:.4f}")
        logger.info(f"Test Precision: {test_precision:.4f}")
        logger.info(f"Test Recall: {test_recall:.4f}")
        logger.info(f"Test AUC: {test_auc:.4f}")
        logger.info(f"Test F1-Score: {2 * (test_precision * test_recall) / (test_precision + test_recall):.4f}")
        
        # Detailed predictions
        y_pred_proba = model.predict(X_test, verbose=0)
        y_pred = (y_pred_proba > 0.5).astype(int).flatten()
        
        # Confusion matrix
        from sklearn.metrics import confusion_matrix, classification_report
        cm = confusion_matrix(y_test, y_pred)
        logger.info("\nConfusion Matrix:")
        logger.info(f"                Predicted")
        logger.info(f"              Benign  Malicious")
        logger.info(f"Actual Benign    {cm[0][0]:6d}  {cm[0][1]:9d}")
        logger.info(f"       Malicious {cm[1][0]:6d}  {cm[1][1]:9d}")
        
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred, 
                                   target_names=['Benign', 'Malicious'],
                                   digits=4))
        
        # Plot training history
        self.plot_training_history(history)
        
        return model, history
    
    def plot_training_history(self, history):
        """Plot training history."""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Accuracy
        axes[0, 0].plot(history.history['accuracy'], label='Train')
        axes[0, 0].plot(history.history['val_accuracy'], label='Validation')
        axes[0, 0].set_title('Model Accuracy')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Accuracy')
        axes[0, 0].legend()
        axes[0, 0].grid(True)
        
        # Loss
        axes[0, 1].plot(history.history['loss'], label='Train')
        axes[0, 1].plot(history.history['val_loss'], label='Validation')
        axes[0, 1].set_title('Model Loss')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Loss')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # AUC
        axes[1, 0].plot(history.history['auc'], label='Train')
        axes[1, 0].plot(history.history['val_auc'], label='Validation')
        axes[1, 0].set_title('Model AUC')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('AUC')
        axes[1, 0].legend()
        axes[1, 0].grid(True)
        
        # Precision & Recall
        axes[1, 1].plot(history.history['precision'], label='Train Precision')
        axes[1, 1].plot(history.history['val_precision'], label='Val Precision')
        axes[1, 1].plot(history.history['recall'], label='Train Recall')
        axes[1, 1].plot(history.history['val_recall'], label='Val Recall')
        axes[1, 1].set_title('Precision & Recall')
        axes[1, 1].set_xlabel('Epoch')
        axes[1, 1].set_ylabel('Score')
        axes[1, 1].legend()
        axes[1, 1].grid(True)
        
        plt.tight_layout()
        plt.savefig('combined_training_history.png', dpi=300, bbox_inches='tight')
        print("\nTraining history plot saved to 'combined_training_history.png'")


def main():
    """Main training function."""
    
    # Configuration
    MALBEHAVD_PATH = r"C:\Users\willi\OneDrive\Test\K\dataset\MalBehavD-V1-dataset.csv"
    KAGGLE_DIR = r"C:\Users\willi\Downloads\archive\data\Processed"
    
    # Hyperparameters
    MAX_SEQ_LENGTH = 2000
    MIN_API_FREQ = 5
    EMBEDDING_DIM = 64
    EPOCHS = 30
    BATCH_SIZE = 32
    
    print("="*60)
    print("COMBINED DATASET CNN TRAINING")
    print("Binary Classification: Benign vs Malicious")
    print("="*60)
    print(f"\nConfiguration:")
    print(f"  MalBehavD Path: {MALBEHAVD_PATH}")
    print(f"  Kaggle Dir: {KAGGLE_DIR}")
    print(f"  Max Sequence Length: {MAX_SEQ_LENGTH}")
    print(f"  Min API Frequency: {MIN_API_FREQ}")
    print(f"  Embedding Dimension: {EMBEDDING_DIM}")
    print(f"  Epochs: {EPOCHS}")
    print(f"  Batch Size: {BATCH_SIZE}")
    
    # Initialize trainer
    trainer = CombinedDatasetCNNTrainer(
        malbehavd_path=MALBEHAVD_PATH,
        kaggle_dir=KAGGLE_DIR,
        max_sequence_length=MAX_SEQ_LENGTH,
        min_api_freq=MIN_API_FREQ,
        embedding_dim=EMBEDDING_DIM
    )
    
    # Load datasets
    sequences, labels = trainer.load_all_datasets()
    
    # Prepare data
    X, y = trainer.prepare_data(sequences, labels)
    
    # Train model
    model, history = trainer.train(
        X, y,
        validation_split=0.2,
        test_size=0.15,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE
    )
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print("Model saved to: best_combined_cnn_model.keras")
    print("Training history plot saved to: combined_training_history.png")


if __name__ == "__main__":
    main()
