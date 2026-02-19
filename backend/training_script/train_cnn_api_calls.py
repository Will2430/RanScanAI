"""
Training Script for 1D CNN Malware Detector (API Call Sequences)
Dataset: mal-api-2019
Features: Sequential API call names
Labels: Multi-class malware families
"""
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import logging
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow import keras
from tensorflow.keras import layers
from collections import Counter
import json
import pickle
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APISequenceCNNTrainer:
    """
    Train 1D CNN on API call sequences for malware classification
    """
    
    def __init__(self, data_path: str, labels_path: str, output_dir: str = "models"):
        self.data_path = Path(data_path)
        self.labels_path = Path(labels_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.vocab = None
        self.word_to_idx = None
        self.idx_to_word = None
        self.label_encoder = LabelEncoder()
        self.model = None
        self.history = None
        self.max_sequence_length = None
        
    def build_vocabulary(self, sequences, min_freq=2):
        """Build vocabulary from API call sequences"""
        logger.info("Building vocabulary from API call sequences...")
        
        # Count all API calls
        api_counter = Counter()
        for seq in sequences:
            api_calls = seq.split()
            api_counter.update(api_calls)
        
        # Filter by minimum frequency
        vocab = {api: count for api, count in api_counter.items() if count >= min_freq}
        
        # Sort by frequency (most common first)
        sorted_vocab = sorted(vocab.items(), key=lambda x: x[1], reverse=True)
        
        # Create word-to-index mapping (reserve 0 for padding, 1 for unknown)
        self.word_to_idx = {'<PAD>': 0, '<UNK>': 1}
        for idx, (word, _) in enumerate(sorted_vocab, start=2):
            self.word_to_idx[word] = idx
        
        self.idx_to_word = {idx: word for word, idx in self.word_to_idx.items()}
        self.vocab = sorted_vocab
        
        logger.info(f"Vocabulary size: {len(self.word_to_idx)} (min_freq={min_freq})")
        logger.info(f"Total unique API calls: {len(api_counter)}")
        logger.info(f"API calls filtered out: {len(api_counter) - len(sorted_vocab)}")
        logger.info(f"\nTop 20 most frequent API calls:")
        for api, count in sorted_vocab[:20]:
            logger.info(f"  {api}: {count}")
        
        return self.word_to_idx
    
    def sequence_to_indices(self, sequence_text):
        """Convert API call sequence text to list of indices"""
        api_calls = sequence_text.split()
        indices = [self.word_to_idx.get(api, 1) for api in api_calls]  # 1 is <UNK>
        return indices
    
    def pad_sequences(self, sequences, maxlen):
        """Pad sequences to fixed length"""
        padded = np.zeros((len(sequences), maxlen), dtype=np.int32)
        
        for i, seq in enumerate(sequences):
            if len(seq) > maxlen:
                # Truncate from the beginning (keep most recent calls)
                padded[i] = seq[-maxlen:]
            else:
                # Pad at the beginning
                padded[i, -len(seq):] = seq
        
        return padded
    
    def load_and_prepare_data(self, max_seq_length=2000, min_api_freq=2, test_size=0.2, val_size=0.1):
        """Load API call sequences and prepare for training"""
        logger.info(f"Loading data from {self.data_path}")
        logger.info(f"Loading labels from {self.labels_path}")
        
        # Read sequences line by line (memory efficient for large file)
        sequences = []
        with open(self.data_path, 'r') as f:
            for line in f:
                sequences.append(line.strip())
        
        # Read labels
        with open(self.labels_path, 'r') as f:
            labels = [line.strip() for line in f]
        
        assert len(sequences) == len(labels), f"Mismatch: {len(sequences)} sequences vs {len(labels)} labels"
        
        logger.info(f"Loaded {len(sequences)} samples")
        logger.info(f"Label distribution:\n{pd.Series(labels).value_counts()}")
        
        # Calculate sequence length statistics
        seq_lengths = [len(seq.split()) for seq in sequences]
        logger.info(f"\nSequence length statistics:")
        logger.info(f"  Min: {min(seq_lengths)}")
        logger.info(f"  Max: {max(seq_lengths)}")
        logger.info(f"  Mean: {np.mean(seq_lengths):.1f}")
        logger.info(f"  Median: {np.median(seq_lengths):.1f}")
        logger.info(f"  95th percentile: {np.percentile(seq_lengths, 95):.1f}")
        
        # Build vocabulary
        self.build_vocabulary(sequences, min_freq=min_api_freq)
        
        # Convert sequences to indices
        logger.info(f"\nConverting sequences to indices...")
        indexed_sequences = [self.sequence_to_indices(seq) for seq in sequences]
        
        # Set max sequence length
        self.max_sequence_length = max_seq_length
        logger.info(f"Max sequence length: {self.max_sequence_length}")
        
        # Pad sequences
        logger.info("Padding sequences...")
        X = self.pad_sequences(indexed_sequences, self.max_sequence_length)
        
        # Encode labels
        y = self.label_encoder.fit_transform(labels)
        
        logger.info(f"\nClass encoding:")
        for idx, class_name in enumerate(self.label_encoder.classes_):
            logger.info(f"  {idx}: {class_name}")
        
        # Split data
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_size/(1-test_size), random_state=42, stratify=y_temp
        )
        
        logger.info(f"\nTrain samples: {len(X_train)}")
        logger.info(f"Validation samples: {len(X_val)}")
        logger.info(f"Test samples: {len(X_test)}")
        
        self.X_train = X_train
        self.X_val = X_val
        self.X_test = X_test
        self.y_train = y_train
        self.y_val = y_val
        self.y_test = y_test
        self.n_classes = len(self.label_encoder.classes_)
        
        # Save vocabulary and label encoder
        vocab_path = self.output_dir / "api_vocab.pkl"
        with open(vocab_path, 'wb') as f:
            pickle.dump({
                'word_to_idx': self.word_to_idx,
                'idx_to_word': self.idx_to_word,
                'vocab': self.vocab,
                'max_sequence_length': self.max_sequence_length
            }, f)
        logger.info(f"✓ Vocabulary saved to {vocab_path}")
        
        label_encoder_path = self.output_dir / "label_encoder.pkl"
        with open(label_encoder_path, 'wb') as f:
            pickle.dump(self.label_encoder, f)
        logger.info(f"✓ Label encoder saved to {label_encoder_path}")
        
        return self
    
    def build_model(self, embedding_dim=128, lstm_units=0):
        """
        Build 1D CNN model for sequential API calls
        
        Args:
            embedding_dim: Dimension of embedding layer
            lstm_units: If > 0, adds an LSTM layer before CNN layers
        """
        vocab_size = len(self.word_to_idx)
        
        model = keras.Sequential([
            # Embedding layer to convert API call indices to dense vectors
            layers.Embedding(
                input_dim=vocab_size,
                output_dim=embedding_dim,
                input_length=self.max_sequence_length,
                mask_zero=True,  # Mask padding tokens
                name='embedding'
            ),
            
            # Optional LSTM layer for sequential patterns
            layers.LSTM(lstm_units, return_sequences=True, name='lstm') if lstm_units > 0 else layers.Lambda(lambda x: x),
            
            # Conv1D layers to capture local patterns
            layers.Conv1D(256, kernel_size=3, activation='relu', padding='same', name='conv1d_1'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.3),
            
            layers.Conv1D(256, kernel_size=5, activation='relu', padding='same', name='conv1d_2'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.3),
            
            layers.Conv1D(128, kernel_size=7, activation='relu', padding='same', name='conv1d_3'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.4),
            
            # Global pooling to aggregate features
            layers.GlobalMaxPooling1D(),
            
            # Dense layers for classification
            layers.Dense(256, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            
            layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
            layers.Dropout(0.5),
            
            # Output layer (multi-class)
            layers.Dense(self.n_classes, activation='softmax', name='output')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.model = model
        logger.info(f"✓ Model built successfully")
        logger.info(f"  Vocabulary size: {vocab_size}")
        logger.info(f"  Embedding dimension: {embedding_dim}")
        logger.info(f"  Max sequence length: {self.max_sequence_length}")
        logger.info(f"  Number of classes: {self.n_classes}")
        
        return model
    
    def train(self, epochs=30, batch_size=32):
        """Train the CNN model"""
        
        if self.model is None:
            raise ValueError("Model not built. Call build_model() first.")
        
        # Calculate class weights to handle imbalance
        class_counts = np.bincount(self.y_train)
        total_samples = len(self.y_train)
        class_weight = {i: total_samples / (self.n_classes * count) 
                       for i, count in enumerate(class_counts)}
        
        logger.info(f"Class weights: {class_weight}")
        
        # Callbacks
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = self.output_dir / f"cnn_api_calls_{timestamp}.keras"
        
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=7,
                restore_best_weights=True,
                verbose=1
            ),
            keras.callbacks.ModelCheckpoint(
                str(model_path),
                monitor='val_accuracy',
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
            raise ValueError("Model not trained. Call train() first.")
        
        logger.info("\n" + "="*60)
        logger.info("Evaluating on test set...")
        logger.info("="*60)
        
        # Predictions
        y_pred_proba = self.model.predict(self.X_test, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        # Metrics
        test_loss, test_acc = self.model.evaluate(self.X_test, self.y_test, verbose=0)
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(
            self.y_test, y_pred,
            target_names=self.label_encoder.classes_,
            digits=4
        ))
        
        # Confusion matrix
        cm = confusion_matrix(self.y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"Rows: True labels, Columns: Predicted labels")
        print(f"Classes: {', '.join(self.label_encoder.classes_)}")
        print(cm)
        
        # Overall metrics
        print(f"\nOverall Metrics:")
        print(f"  Accuracy: {test_acc:.4f}")
        print(f"  Loss: {test_loss:.4f}")
        
        # Save metrics
        metrics = {
            'accuracy': float(test_acc),
            'loss': float(test_loss),
            'confusion_matrix': cm.tolist(),
            'classes': self.label_encoder.classes_.tolist(),
            'n_classes': int(self.n_classes),
            'vocab_size': len(self.word_to_idx),
            'max_sequence_length': int(self.max_sequence_length),
            'model_type': '1D CNN',
            'dataset': 'mal-api-2019',
            'timestamp': datetime.now().isoformat()
        }
        
        # Save metadata
        metadata_path = self.output_dir / "cnn_api_model_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.info(f"\n✓ Metrics saved to {metadata_path}")
        
        # Plot training history
        self.plot_training_history()
        
        # Plot confusion matrix
        self.plot_confusion_matrix(cm)
        
        return metrics
    
    def plot_training_history(self):
        """Plot training curves"""
        
        if self.history is None:
            logger.warning("No training history available")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        # Accuracy
        axes[0].plot(self.history.history['accuracy'], label='Train')
        axes[0].plot(self.history.history['val_accuracy'], label='Validation')
        axes[0].set_title('Model Accuracy')
        axes[0].set_xlabel('Epoch')
        axes[0].set_ylabel('Accuracy')
        axes[0].legend()
        axes[0].grid(True)
        
        # Loss
        axes[1].plot(self.history.history['loss'], label='Train')
        axes[1].plot(self.history.history['val_loss'], label='Validation')
        axes[1].set_title('Model Loss')
        axes[1].set_xlabel('Epoch')
        axes[1].set_ylabel('Loss')
        axes[1].legend()
        axes[1].grid(True)
        
        plt.tight_layout()
        plot_path = self.output_dir / "training_history_api.png"
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        logger.info(f"✓ Training history plot saved to {plot_path}")
        plt.close()
    
    def plot_confusion_matrix(self, cm):
        """Plot confusion matrix heatmap"""
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        ax.figure.colorbar(im, ax=ax)
        
        # Show all ticks
        ax.set(xticks=np.arange(cm.shape[1]),
               yticks=np.arange(cm.shape[0]),
               xticklabels=self.label_encoder.classes_,
               yticklabels=self.label_encoder.classes_,
               title='Confusion Matrix',
               ylabel='True label',
               xlabel='Predicted label')
        
        # Rotate the tick labels
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        
        # Add text annotations
        thresh = cm.max() / 2.
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, format(cm[i, j], 'd'),
                       ha="center", va="center",
                       color="white" if cm[i, j] > thresh else "black")
        
        plt.tight_layout()
        plot_path = self.output_dir / "confusion_matrix_api.png"
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        logger.info(f"✓ Confusion matrix plot saved to {plot_path}")
        plt.close()


def main():
    """Main training pipeline"""
    
    print("\n" + "="*80)
    print("SecureGuard - 1D CNN Training on API Call Sequences")
    print("="*80 + "\n")
    
    # Configuration
    DATA_PATH = "C:/Users/willi/Downloads/mal-api-2019/all_analysis_data.txt"
    LABELS_PATH = "C:/Users/willi/Downloads/mal-api-2019/labels.csv"
    OUTPUT_DIR = "C:/Users/willi/OneDrive/Test/K/models"
    
    # Hyperparameters
    MAX_SEQ_LENGTH = 2000  # Truncate/pad sequences to this length
    MIN_API_FREQ = 5       # Minimum frequency for API call to be in vocabulary
    EMBEDDING_DIM = 128    # Dimension of embedding vectors
    LSTM_UNITS = 0         # Set to 64-128 to add LSTM layer (slower but may improve accuracy)
    EPOCHS = 10
    BATCH_SIZE = 32
    
    # Initialize trainer
    trainer = APISequenceCNNTrainer(
        data_path=DATA_PATH,
        labels_path=LABELS_PATH,
        output_dir=OUTPUT_DIR
    )
    
    # Load and prepare data
    trainer.load_and_prepare_data(
        max_seq_length=MAX_SEQ_LENGTH,
        min_api_freq=MIN_API_FREQ,
        test_size=0.2,
        val_size=0.1
    )
    
    # Build model
    model = trainer.build_model(
        embedding_dim=EMBEDDING_DIM,
        lstm_units=LSTM_UNITS
    )
    
    print("\n" + "="*80)
    print("Model Architecture")
    print("="*80)
    model.summary()
    
    # Train model
    print("\n" + "="*80)
    print("Starting Training")
    print("="*80 + "\n")
    trainer.train(epochs=EPOCHS, batch_size=BATCH_SIZE)
    
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
    print(f"\nNext steps:")
    print("1. Review the confusion matrix to see per-class performance")
    print("2. Check training_history_api.png for overfitting")
    print("3. Integrate the model with your malware detection system")
    

if __name__ == "__main__":
    main()
