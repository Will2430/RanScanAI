"""
Adaptive Learning System - Automated Retraining
Periodically retrains the model with new validated samples
"""

import pandas as pd
import numpy as np
import json
import os
import joblib
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from feedback_collector import FeedbackCollector


class ModelRetrainer:
    """
    Handles automated model retraining with feedback samples
    """
    
    def __init__(self, 
                 original_dataset_path: str = "Dataset/Zenedo.csv",
                 current_model_path: str = "malware_detector_zenodo_v1.pkl",
                 backup_dir: str = "adaptive_learning/model_backups"):
        
        self.original_dataset_path = original_dataset_path
        self.current_model_path = current_model_path
        self.backup_dir = backup_dir
        self.feedback_collector = FeedbackCollector()
        
        os.makedirs(backup_dir, exist_ok=True)
    
    def load_original_data(self):
        """Load the original training dataset"""
        print("[RETRAIN] Loading original training data...")
        df = pd.read_csv(self.original_dataset_path)
        
        # Prepare features
        drop_cols = ['md5', 'sha1', 'Class', 'Category', 'Family']
        feature_cols = [col for col in df.columns if col not in drop_cols]
        
        X = df[feature_cols].copy()
        y = (df['Class'] == 'Benign').astype(int)
        
        # Handle categorical features
        categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
        if categorical_cols:
            from sklearn.preprocessing import LabelEncoder
            for col in categorical_cols:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
        
        # Fill missing values
        X = X.fillna(0)
        
        print(f"[RETRAIN] Original data: {len(X):,} samples, {len(feature_cols)} features")
        
        return X, y, feature_cols
    
    def prepare_feedback_samples(self, feedback_df: pd.DataFrame, feature_cols: list):
        """
        Convert feedback samples to training data format
        
        Args:
            feedback_df: DataFrame from feedback collector
            feature_cols: List of expected feature columns
            
        Returns:
            X, y: Features and labels for new samples
        """
        print(f"[RETRAIN] Processing {len(feedback_df)} feedback samples...")
        
        new_samples = []
        labels = []
        
        for idx, row in feedback_df.iterrows():
            try:
                # Parse features JSON
                features = json.loads(row['features_json'])
                
                # Use VT as ground truth
                # If VT says malicious (>5 detections), label as 0 (malicious)
                # If VT says clean, label as 1 (benign)
                label = 0 if row['vt_malicious'] else 1
                
                # Ensure all expected features are present
                feature_vector = []
                for col in feature_cols:
                    feature_vector.append(features.get(col, 0))
                
                new_samples.append(feature_vector)
                labels.append(label)
                
            except Exception as e:
                print(f"[RETRAIN] ⚠️  Skipping sample {row['file_hash'][:8]}: {e}")
                continue
        
        if not new_samples:
            return None, None
        
        X_new = pd.DataFrame(new_samples, columns=feature_cols)
        y_new = pd.Series(labels)
        
        print(f"[RETRAIN] ✓ Prepared {len(X_new)} valid samples")
        print(f"           Malicious: {(y_new == 0).sum()}, Benign: {(y_new == 1).sum()}")
        
        return X_new, y_new
    
    def retrain_model(self, min_samples: int = 50):
        """
        Main retraining function
        
        Args:
            min_samples: Minimum number of feedback samples required
            
        Returns:
            bool: True if retrained successfully
        """
        print("\n" + "="*80)
        print("ADAPTIVE LEARNING - MODEL RETRAINING")
        print("="*80)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # 1. Check if retraining is needed
        if not self.feedback_collector.should_retrain(threshold=min_samples):
            pending = self.feedback_collector.get_pending_samples_count()
            print(f"[RETRAIN] Not enough samples ({pending}/{min_samples}). Skipping retraining.")
            return False
        
        # 2. Load original data
        X_orig, y_orig, feature_cols = self.load_original_data()
        
        # 3. Get feedback samples
        feedback_df = self.feedback_collector.get_samples_for_retraining()
        X_new, y_new = self.prepare_feedback_samples(feedback_df, feature_cols)
        
        if X_new is None or len(X_new) < min_samples:
            print(f"[RETRAIN] ❌ Insufficient valid samples after processing")
            return False
        
        # 4. Combine datasets
        print(f"\n[RETRAIN] Combining datasets...")
        X_combined = pd.concat([X_orig, X_new], ignore_index=True)
        y_combined = pd.concat([y_orig, y_new], ignore_index=True)
        
        print(f"           Original: {len(X_orig):,} samples")
        print(f"           New:      {len(X_new):,} samples")
        print(f"           Combined: {len(X_combined):,} samples")
        
        # 5. Split for validation
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_combined,
            test_size=0.2,
            random_state=42,
            stratify=y_combined
        )
        
        # 6. Train new model
        print(f"\n[RETRAIN] Training new model...")
        new_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        
        new_model.fit(X_train, y_train)
        
        # 7. Evaluate new model
        train_acc = new_model.score(X_train, y_train)
        test_acc = new_model.score(X_test, y_test)
        y_pred = new_model.predict(X_test)
        
        print(f"\n[RETRAIN] New Model Performance:")
        print(f"           Training Accuracy: {train_acc:.4f}")
        print(f"           Test Accuracy:     {test_acc:.4f}")
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tp) if (fp + tp) > 0 else 0
        
        print(f"           False Positive Rate: {fpr:.4f}")
        
        # 8. Load old model for comparison
        if os.path.exists(self.current_model_path):
            old_model = joblib.load(self.current_model_path)
            old_acc = old_model.score(X_test, y_test)
            print(f"\n[RETRAIN] Comparison:")
            print(f"           Old Model: {old_acc:.4f}")
            print(f"           New Model: {test_acc:.4f}")
            print(f"           Δ Change:  {(test_acc - old_acc):+.4f} ({(test_acc - old_acc) / old_acc * 100:+.2f}%)")
        else:
            old_acc = 0.9933  # Baseline
        
        # 9. Decide whether to deploy
        # Deploy if new model is within 1% of old model or better
        tolerance = 0.01
        should_deploy = test_acc >= (old_acc - tolerance)
        
        if should_deploy:
            print(f"\n[RETRAIN] ✓ New model meets quality threshold!")
            
            # Backup old model
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(self.backup_dir, f"model_v{timestamp}.pkl")
            
            if os.path.exists(self.current_model_path):
                os.rename(self.current_model_path, backup_path)
                print(f"           Old model backed up: {backup_path}")
            
            # Save new model
            joblib.dump(new_model, self.current_model_path)
            print(f"           New model deployed: {self.current_model_path}")
            
            # Mark feedback samples as processed
            processed_hashes = feedback_df['file_hash'].tolist()
            self.feedback_collector.mark_samples_processed(processed_hashes)
            
            # Update version manager
            from model_version_manager import ModelVersionManager
            version_mgr = ModelVersionManager()
            version_mgr.update_version(
                new_accuracy=test_acc,
                samples_added=len(X_new)
            )
            
            # Log the update
            log_file = "adaptive_learning/retraining_log.txt"
            with open(log_file, 'a') as f:
                f.write(f"{datetime.now().isoformat()} | "
                       f"Retrained with {len(X_new)} samples | "
                       f"Accuracy: {old_acc:.4f} → {test_acc:.4f} | "
                       f"FPR: {fpr:.4f}\n")
            
            print(f"\n[RETRAIN] ✓ Retraining complete!")
            print("="*80)
            
            return True
        
        else:
            print(f"\n[RETRAIN] ❌ New model underperforms (acc={test_acc:.4f} < {old_acc:.4f})")
            print(f"           Keeping old model. Review feedback samples manually.")
            print("="*80)
            
            return False


def main():
    """Main entry point for scheduled retraining"""
    retrainer = ModelRetrainer()
    
    # Attempt retraining with minimum 50 samples
    success = retrainer.retrain_model(min_samples=50)
    
    if success:
        print("\n✓ Model successfully updated with new knowledge!")
    else:
        print("\n⚠️  Retraining skipped or failed. Check logs.")
    
    # Print feedback statistics
    print("\n" + "="*80)
    print("FEEDBACK STATISTICS")
    print("="*80)
    stats = retrainer.feedback_collector.get_statistics()
    for key, value in stats.items():
        print(f"{key:.<30} {value:>5,}")
    print("="*80)


if __name__ == "__main__":
    main()
