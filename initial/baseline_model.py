"""
Baseline Binary Malware Classifier
Trains a lightweight Random Forest model on the Kaggle dataset
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
import numpy as np

def load_and_prepare_data(filepath):
    """Load dataset and prepare for training"""
    print("Loading dataset...")
    df = pd.read_csv(filepath)
    
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}\n")
    
    # Check label distribution
    print(f"Label column: 'Benign'")
    print(f"Label distribution:\n{df['Benign'].value_counts()}")
    benign_pct = (df['Benign'].sum() / len(df)) * 100
    malicious_pct = 100 - benign_pct
    print(f"  Benign: {benign_pct:.1f}%")
    print(f"  Malicious: {malicious_pct:.1f}%\n")
    
    # Separate features and labels
    # Drop non-feature columns (filename, hash)
    feature_cols = [col for col in df.columns if col not in ['FileName', 'md5Hash', 'Benign']]
    
    X = df[feature_cols]
    y = df['Benign']
    
    # Store hash column for later enrichment
    hashes = df['md5Hash']
    
    print(f"Features used: {len(feature_cols)}")
    print(f"Sample features: {feature_cols[:5]}\n")
    
    return X, y, hashes, feature_cols

def train_model(X_train, y_train):
    """Train Random Forest classifier"""
    print("Training Random Forest model...")
    print("  - Using 100 trees with max_depth=15")
    print("  - This keeps the model lightweight for SME deployment\n")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    model.fit(X_train, y_train)
    print("✓ Training complete\n")
    
    return model

def evaluate_model(model, X_train, X_test, y_train, y_test):
    """Evaluate model performance"""
    print("="*80)
    print("MODEL EVALUATION")
    print("="*80)
    
    # Training accuracy
    train_acc = model.score(X_train, y_train)
    print(f"\nTraining Accuracy: {train_acc:.2%}")
    
    # Test accuracy
    test_acc = model.score(X_test, y_test)
    print(f"Test Accuracy: {test_acc:.2%}")
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"               Malicious  Benign")
    print(f"Actual Malicious  {cm[0,0]:6d}   {cm[0,1]:6d}")
    print(f"       Benign     {cm[1,0]:6d}   {cm[1,1]:6d}")
    
    # Calculate metrics
    true_neg, false_pos, false_neg, true_pos = cm.ravel()
    
    # Detection rate (True Positive Rate)
    detection_rate = true_neg / (true_neg + false_pos) if (true_neg + false_pos) > 0 else 0
    # False positive rate
    fpr = false_pos / (false_pos + true_pos) if (false_pos + true_pos) > 0 else 0
    
    print(f"\nKey Metrics:")
    print(f"  Malware Detection Rate: {detection_rate:.2%}")
    print(f"  False Positive Rate: {fpr:.2%}")
    print(f"  (FPR should be <5% for production)")
    
    # Classification report
    print(f"\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Malicious', 'Benign'],
                                digits=4))
    
    # Feature importance
    feature_importance = model.feature_importances_
    return test_acc, feature_importance

def save_model_artifacts(model, feature_cols, test_acc):
    """Save model and metadata"""
    print("="*80)
    print("SAVING MODEL")
    print("="*80)
    
    # Save model
    model_path = 'malware_detector_v1.pkl'
    joblib.dump(model, model_path)
    print(f"✓ Model saved: {model_path}")
    
    # Save feature names
    feature_path = 'model_features.txt'
    with open(feature_path, 'w') as f:
        f.write('\n'.join(feature_cols))
    print(f"✓ Features saved: {feature_path}")
    
    # Save metadata
    metadata = {
        'accuracy': test_acc,
        'n_features': len(feature_cols),
        'model_type': 'RandomForestClassifier',
        'n_estimators': 100,
        'max_depth': 15
    }
    
    import json
    with open('model_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"✓ Metadata saved: model_metadata.json")
    
    print(f"\n✓ Model ready for deployment!")
    print(f"  Test Accuracy: {test_acc:.2%}")
    
    # Get model size
    import os
    temp_path = 'temp.pkl'
    joblib.dump(model, temp_path)
    model_size = os.path.getsize(temp_path) / 1024
    print(f"  Model Size: {model_size:.1f} KB")
    os.remove(temp_path)

def main():
    print("="*80)
    print("MALWARE DETECTION MODEL - TRAINING PIPELINE")
    print("="*80)
    print()
    
    # Load data
    X, y, hashes, feature_cols = load_and_prepare_data('Dataset/Kaggle (Amdjed) .csv')
    
    # Split data
    print("Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.2, 
        random_state=42, 
        stratify=y
    )
    print(f"  Training samples: {len(X_train):,}")
    print(f"  Test samples: {len(X_test):,}\n")
    
    # Train
    model = train_model(X_train, y_train)
    
    # Evaluate
    test_acc, feature_importance = evaluate_model(model, X_train, X_test, y_train, y_test)
    
    # Show top features
    print("\n" + "="*80)
    print("TOP 10 MOST IMPORTANT FEATURES")
    print("="*80)
    feature_imp_df = pd.DataFrame({
        'feature': feature_cols,
        'importance': feature_importance
    }).sort_values('importance', ascending=False)
    
    print()
    for i, row in feature_imp_df.head(10).iterrows():
        print(f"  {row['feature']:30s} {row['importance']:.4f}")
    
    # Save
    print()
    save_model_artifacts(model, feature_cols, test_acc)
    
    print("\n" + "="*80)
    print("✓ TRAINING COMPLETE - Ready for integration with VirusTotal API")
    print("="*80)

if __name__ == "__main__":
    main()
