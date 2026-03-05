"""
Fixed CNN training script with better class imbalance handling.

Four strategies:
1. BALANCED_DATASET: Oversample benign to 1:2 ratio (simple, fast)
2. SMOTE: Synthetic Minority Over-sampling on the TRAINING set only (best for imbalance)
3. MODERATE_WEIGHTS: Use gentle class weights instead of aggressive 'balanced'
4. NO_WEIGHTS: Remove class weights entirely

Recommended: SMOTE (requires: pip install imbalanced-learn)
"""

import numpy as np
import pandas as pd
import json
import os
from pathlib import Path
from collections import Counter
import pickle
import logging
import keras
from keras import layers, models, callbacks
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime
try:
    from imblearn.over_sampling import SMOTE
    SMOTE_AVAILABLE = True
except ImportError:
    SMOTE_AVAILABLE = False
    logger_pre = logging.getLogger(__name__)
    logger_pre.warning("imbalanced-learn not installed. Run: pip install imbalanced-learn")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FixedCNNTrainer:
    def __init__(self, kaggle_dir, malbehavd_path, strategy='SMOTE'):
        """
        Initialize trainer.
        
        Args:
            strategy: 'SMOTE', 'BALANCED_DATASET', 'MODERATE_WEIGHTS', or 'NO_WEIGHTS'
        """
        self.kaggle_dir = kaggle_dir
        self.malbehavd_path = malbehavd_path
        self.strategy = strategy
        self.vocab = None
        self.vocab_size = 0
        self.max_sequence_length = 3000  # Increased: captures more of the active execution phase
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
    
    def load_db_augment_samples(self):
        """
        Load uncertain samples exported from the DB pipeline.
        Reads backend/training_script/augment_data/augment_cnn.json which is written
        by export_approved_samples_for_retraining() before each retrain trigger.

        Returns:
            (sequences, labels) where sequences is list of list[str] API call names
            and labels is list of ints in training convention: 0=benign, 1=malicious
            (already converted from USQ convention by export_approved_samples_for_retraining).
        """
        augment_path = Path(__file__).resolve().parent / "augment_data" / "augment_cnn.json"
        if not augment_path.exists():
            logger.info("[DB-AUGMENT] No augment_cnn.json found — skipping DB augment samples")
            return [], []

        try:
            with open(augment_path) as f:
                records = json.load(f)

            sequences, labels = [], []
            for r in records:
                seq = r.get("api_sequence", [])
                lbl = r.get("label", 0)
                if isinstance(seq, list) and seq:
                    sequences.append(seq)
                    labels.append(int(lbl))

            logger.info(f"[DB-AUGMENT] Loaded {len(sequences)} DB-sourced samples from {augment_path.name}")
            return sequences, labels
        except Exception as e:
            logger.warning(f"[DB-AUGMENT] Failed to load augment_cnn.json: {e}")
            return [], []
        
    
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

        # Load self-collected benign traces (batch_benign_tracer output)
        benign_batch_path = (
            Path(__file__).resolve().parent.parent.parent
            / "benign_traces" / "combined_benign.json"
        )
        if benign_batch_path.exists():
            benign_batch = self.load_kaggle_json(str(benign_batch_path))
            logger.info(f"Loaded {len(benign_batch)} self-collected benign traces")
        else:
            benign_batch = []
            logger.info("No self-collected benign traces found (run batch_benign_tracer.py)")

        # Combine
        all_benign = benign_malbehavd + benign_kaggle + benign_batch
        all_malicious = malicious_368 + malicious_389

        # ── DB augment samples (from retrain pipeline) ─────────────────────
        db_seqs, db_labels = self.load_db_augment_samples()
        for seq, lbl in zip(db_seqs, db_labels):
            if lbl == 0:   # 0 = benign (training convention)
                all_benign.append(seq)
            else:          # 1 = malicious (training convention)
                all_malicious.append(seq)
        # ───────────────────────────────────────────────────────────────────
        
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
    
    def apply_smote(self, X_train, y_train):
        """Apply SMOTE to the training set only (never val/test — that would be data leakage).
        
        SMOTE interpolates synthetic minority samples in the padded integer feature space.
        k_neighbors is set conservatively to avoid over-smoothing on small datasets.
        """
        if not SMOTE_AVAILABLE:
            raise ImportError("Run: pip install imbalanced-learn")
        
        n_benign = int(sum(y_train == 0))
        n_malicious = int(sum(y_train == 1))
        minority_class = 0 if n_benign < n_malicious else 1
        minority_count = min(n_benign, n_malicious)
        
        logger.info(f"\nApplying SMOTE to training set...")
        logger.info(f"  Before — Benign: {n_benign}, Malicious: {n_malicious}")
        
        # k_neighbors must be < minority class count; cap at 5
        k_neighbors = min(5, minority_count - 1)
        if k_neighbors < 1:
            logger.warning("Too few minority samples for SMOTE, skipping.")
            return X_train, y_train
        
        smote = SMOTE(
            sampling_strategy='auto',   # oversample minority to match majority
            k_neighbors=k_neighbors,
            random_state=42
        )
        X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
        
        n_benign_after = int(sum(y_resampled == 0))
        n_malicious_after = int(sum(y_resampled == 1))
        logger.info(f"  After  — Benign: {n_benign_after}, Malicious: {n_malicious_after}")
        logger.info(f"  Added {len(X_resampled) - len(X_train)} synthetic samples")
        
        return X_resampled, y_resampled

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
    
    def augment_by_windowing(self, sequences, labels, window_stride=200, max_windows=30):
        """Sliding window augmentation on raw API-name sequences (before indexing/padding).

        Applied to BOTH classes — any sequence longer than max_sequence_length is split
        into overlapping windows of exactly max_sequence_length calls.  Each window is
        an independent training sample covering a different execution phase.

        For malicious samples this captures init / privilege escalation / payload /
        cleanup phases as separate samples.  For long benign Frida traces it provides
        diverse coverage of normal behaviour.

        Any resulting class imbalance is handled by the post-windowing 1:1 balancer.
        Only ever called on training data to prevent leakage.
        """
        L = self.max_sequence_length
        aug_seqs, aug_labels = [], []

        for seq, label in zip(sequences, labels):
            n = len(seq)
            if n <= L:
                aug_seqs.append(seq)
                aug_labels.append(label)
                continue

            # Long sequence — extract overlapping windows
            added = 0
            for start in range(0, n - L + 1, window_stride):
                aug_seqs.append(seq[start : start + L])
                aug_labels.append(label)
                added += 1
                if added >= max_windows:
                    break

            # Always include the pure-tail window (captures late-phase behaviour)
            tail = seq[n - L:]
            if tail not in aug_seqs[-3:]:   # avoid exact duplicate if stride aligned
                aug_seqs.append(tail)
                aug_labels.append(label)

        n_benign_out    = sum(1 for l in aug_labels if l == 0)
        n_malicious_out = sum(1 for l in aug_labels if l == 1)
        logger.info(f"  Windowing (both classes): {len(sequences)} raw sequences "
                    f"→ {len(aug_seqs)} training samples "
                    f"(benign={n_benign_out}, malicious={n_malicious_out})")
        return aug_seqs, np.array(aug_labels)

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
        """Pad or truncate sequences to max_sequence_length.
        
        Truncation strategy: take first 25% + last 75% of the sequence.
        Rationale: malware initialises (DLL loads, privilege setup) early but
        executes its payload (file writes, encryption, injection) later.
        Head-only truncation discards the entire payload phase for long traces.
        """
        L = self.max_sequence_length
        head_len = L // 4        # 750 calls: captures init / DLL loading
        tail_len = L - head_len  # 2250 calls: captures active payload phase

        padded = np.zeros((len(sequences), L), dtype=np.int32)
        for i, seq in enumerate(sequences):
            n = len(seq)
            if n > L:
                # Splice: first head_len + last tail_len
                spliced = seq[:head_len] + seq[n - tail_len:]
                padded[i] = spliced
            else:
                padded[i, :n] = seq
        return padded
    
    def focal_loss(self, alpha=0.50, gamma=2.0):
        def loss(y_true, y_pred):
            y_pred = keras.ops.clip(y_pred, keras.backend.epsilon(), 1.0 - keras.backend.epsilon())
            pt = keras.ops.where(keras.ops.equal(y_true, 1), y_pred, 1 - y_pred)
            return -keras.ops.mean(alpha * keras.ops.power(1. - pt, gamma) * keras.ops.log(pt))
        return loss
    
    def build_model(self):
        """Build 1D CNN + BiLSTM hybrid model.

        Architecture rationale:
        - Multi-scale Conv1D (kernels 3, 5, 7) captures short API n-gram patterns
          (e.g. OpenProcessToken -> AdjustTokenPrivileges -> WriteProcessMemory)
        - Bidirectional LSTM preserves sequential order context that GlobalMaxPooling
          previously destroyed — order of API calls matters for intent detection
        - BatchNormalization stabilises training across the large vocab embedding space
        - Average + Max pooling concatenation retains both typical and peak activations
        """
        inputs = layers.Input(shape=(self.max_sequence_length,))

        # Embedding
        x = layers.Embedding(
            input_dim=self.vocab_size,
            output_dim=128,
            mask_zero=True
        )(inputs)
        x = layers.SpatialDropout1D(0.2)(x)

        # Multi-scale convolution towers (captures API n-gram patterns at 3, 5, 7 scales)
        conv3 = layers.Conv1D(64, kernel_size=3, activation='relu', padding='same')(x)
        conv5 = layers.Conv1D(64, kernel_size=5, activation='relu', padding='same')(x)
        conv7 = layers.Conv1D(64, kernel_size=7, activation='relu', padding='same')(x)
        x = layers.Concatenate()([conv3, conv5, conv7])          # (seq_len, 192)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)

        # Second conv block — pattern refinement
        x = layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        
         # BiLSTM — preserves sequential order; crucial for injection chain detection
        x = layers.Bidirectional(layers.LSTM(64, return_sequences=True, dropout=0.2))(x)
        
        # Dual pooling — keeps both peak signals and average context
        avg_pool = layers.GlobalAveragePooling1D()(x)
        max_pool = layers.GlobalMaxPooling1D()(x)
        x = layers.Concatenate()([avg_pool, max_pool])           # (256,)

        # Classifier head
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(0.4)(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        outputs = layers.Dense(1, activation='sigmoid')(x)

        model = keras.Model(inputs, outputs, name='malware_cnn_hybrid')
        
        optimizer = keras.optimizers.Adam(learning_rate=1e-4)
        model.compile(
            optimizer=optimizer,
            loss=self.focal_loss(alpha=0.75, gamma=2.0),
            metrics=[
                'accuracy',
                keras.metrics.AUC(name='auc'),
                keras.metrics.Precision(name='precision'),
                keras.metrics.Recall(name='recall')
            ]
        )

        logger.info("\n" + "="*60)
        logger.info("MODEL ARCHITECTURE")
        logger.info("="*60)
        model.summary(print_fn=logger.info)
        
        return model
    
    def get_class_weights(self, y_train):
        """Get class weights based on strategy."""
        if self.strategy in ('NO_WEIGHTS', 'SMOTE', 'BALANCED_DATASET'):
            # SMOTE and BALANCED_DATASET already handle imbalance via resampling; no weights needed
            logger.info(f"\nStrategy: {self.strategy} - No additional class weights applied")
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
        
        return None
    
    def train(self, epochs=30, batch_size=32, validation_split=0.15, test_split=0.15):
        """Train the model."""
        # Load data
        sequences, labels = self.load_all_datasets()

        # Setup output directory and timestamp
        models_dir = Path(__file__).resolve().parent.parent.parent / "models"
        models_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = models_dir
        self.timestamp = timestamp
        logger.info(f"Output directory: {models_dir}")
        logger.info(f"Run timestamp: {timestamp}")

        # ── Split at the RAW SEQUENCE level so windowing never touches val/test ──
        indices = np.arange(len(sequences))
        idx_temp, idx_test = train_test_split(
            indices, test_size=test_split, random_state=42, stratify=labels
        )
        idx_train, idx_val = train_test_split(
            idx_temp,
            test_size=validation_split / (1 - test_split),
            random_state=42,
            stratify=labels[idx_temp]
        )

        train_seqs  = [sequences[i] for i in idx_train]
        val_seqs    = [sequences[i] for i in idx_val]
        test_seqs   = [sequences[i] for i in idx_test]
        y_train_raw = labels[idx_train]
        y_val       = labels[idx_val]
        self.y_test  = labels[idx_test]

        # Build vocabulary on ALL sequences (before augmentation) so every
        # API name seen in val/test is also represented in the vocab.
        vocab = self.build_vocabulary(sequences)
        vocab_path = models_dir / f"api_vocab_fixed_{timestamp}.pkl"
        with open(vocab_path, 'wb') as f:
            pickle.dump(vocab, f)
        logger.info(f"Vocabulary saved to {vocab_path}")

        # ── Sliding window augmentation — training set only ──────────────────
        logger.info("\nApplying sliding window augmentation to training sequences...")
        train_seqs_aug, y_train = self.augment_by_windowing(train_seqs, y_train_raw)

        # ── Post-windowing class balance (oversample minority UP to majority) ──
        # Benign Frida traces are often short (<3000 calls) so windowing barely
        # expands them, while long Kaggle malicious sequences generate 30 windows
        # each → malicious can hit 40k while benign stays at ~1k.
        # Downsampling malicious to 1k would throw away most training data.
        # Instead: oversample (with replacement) the minority class up to match
        # the majority — keeps ALL windows from both classes, no data wasted.
        n_benign_w    = int(sum(y_train == 0))
        n_malicious_w = int(sum(y_train == 1))
        majority_count = max(n_benign_w, n_malicious_w)
        minority_label = 0 if n_benign_w < n_malicious_w else 1
        minority_count = min(n_benign_w, n_malicious_w)

        if minority_count < majority_count:
            logger.info(f"\nPost-windowing balance: "
                        f"Benign={n_benign_w}, Malicious={n_malicious_w} — "
                        f"oversampling minority (label={minority_label}) "
                        f"from {minority_count} → {majority_count} (1:1).")
            min_idx = np.where(y_train == minority_label)[0]
            rng = np.random.default_rng(42)
            # Sample with replacement to reach majority count
            extra = rng.choice(min_idx, majority_count - minority_count, replace=True)
            extra_seqs   = [train_seqs_aug[i] for i in extra]
            extra_labels = y_train[extra]
            train_seqs_aug = train_seqs_aug + extra_seqs
            y_train = np.concatenate([y_train, extra_labels])
            logger.info(f"  After balance — Benign: {sum(y_train==0)}, "
                        f"Malicious: {sum(y_train==1)}")
        else:
            logger.info(f"\nPost-windowing counts OK — "
                        f"Benign: {n_benign_w}, Malicious: {n_malicious_w}")

        # ── Convert + pad all splits ─────────────────────────────────────────
        logger.info("\nConverting sequences to indices...")
        X_train = self.pad_sequences(self.sequences_to_indices(train_seqs_aug))
        X_val   = self.pad_sequences(self.sequences_to_indices(val_seqs))
        self.X_test = self.pad_sequences(self.sequences_to_indices(test_seqs))

        logger.info("\n" + "="*60)
        logger.info("DATA SPLITS (after windowing augmentation)")
        logger.info("="*60)
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"  Benign:    {sum(y_train == 0)} ({sum(y_train == 0)/len(y_train)*100:.1f}%)")
        logger.info(f"  Malicious: {sum(y_train == 1)} ({sum(y_train == 1)/len(y_train)*100:.1f}%)")
        logger.info(f"Validation set: {len(X_val)} samples")
        logger.info(f"Test set:       {len(self.X_test)} samples")

        # Apply SMOTE on training set only (after split to prevent leakage)
        if self.strategy == 'SMOTE':
            X_train, y_train = self.apply_smote(X_train, y_train)
        
        # Get class weights
        class_weights = self.get_class_weights(y_train)
        
        # Build model
        self.model = self.build_model()
        
        # Callbacks
        callback_list = [
            callbacks.EarlyStopping(
                monitor='val_loss',
                patience=7,
                restore_best_weights=True,
                verbose=1
            ),
            callbacks.ModelCheckpoint(
                str(self.output_dir / f"best_fixed_cnn_{self.timestamp}.keras"),
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
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=class_weights,
            callbacks=callback_list,
            shuffle=True,
            verbose=1
        )
                 
        return self.history
    
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
            'n_features': int(self.max_sequence_length),
            'vocab_size': int(self.vocab_size),
            'model_type': '1D CNN',
            'dataset': 'Zenodo',
            'timestamp': datetime.now().isoformat(),
            'path_to_model': str(self.output_dir / f"best_fixed_cnn_{self.timestamp}.keras")
        }
        
        # Save metadata
        metadata_path = self.output_dir / f"cnn_fixed_metadata_{self.timestamp}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.info(f"\n✓ Metrics saved to {metadata_path}")
    
        
        return metrics
    
       
def main():
    # Paths
    KAGGLE_DIR = r"C:\Users\User\Downloads\dataset\archive\data\Processed"
    KAGGLE_DIR_2 = r"C:\Users\willi\Downloads\archive\data\Processed"
    MALBEHAVD_PATH = r"C:\Users\User\Downloads\dataset\MalBehavD-V1-dataset.csv"
    MALBEHAVD_PATH_2 = r"C:\Users\willi\Downloads\MalBehavD-V1-dataset (1).csv"
    
    # Choose strategy (RECOMMENDED: 'SMOTE')
    STRATEGY = 'NO_WEIGHTS'  # Options: 'SMOTE', 'BALANCED_DATASET', 'MODERATE_WEIGHTS', 'NO_WEIGHTS'
    
    trainer = FixedCNNTrainer(KAGGLE_DIR, MALBEHAVD_PATH, strategy=STRATEGY)
    trainer.train(epochs=1, batch_size=64)  # 64 cuts epoch time ~40% vs 32
    metrics = trainer.evaluate()
    print(f"Accuracy: {metrics['accuracy']:.2%}")
    print(f"AUC-ROC: {metrics['auc']:.4f}")
    print(f"False Positive Rate: {metrics['fpr']:.2%}")
    print(f"False Negative Rate: {metrics['fnr']:.2%}")

if __name__ == "__main__":
    main()
