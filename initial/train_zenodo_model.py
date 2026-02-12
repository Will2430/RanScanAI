"""
Train Hybrid Malware Detection Model using Zenodo Dataset
Demonstrates improvement from using static + dynamic features
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import json

def load_and_prepare_zenodo():
    """Load Zenodo dataset and prepare features"""
    print("Loading Zenodo dataset...")
    df = pd.read_csv('Dataset/Zenedo.csv')
    
    print(f"Dataset shape: {df.shape}")
    print(f"\nClass distribution:")
    print(df['Class'].value_counts())
    print(f"  Balance: {df['Class'].value_counts().iloc[0] / df['Class'].value_counts().iloc[1]:.2f}:1")
    
    # Prepare features
    # Drop non-feature columns
    drop_cols = ['md5', 'sha1', 'Class', 'Category', 'Family']
    feature_cols = [col for col in df.columns if col not in drop_cols]
    
    X = df[feature_cols].copy()  # Use copy to ensure modifications stick
    
    # Convert Class to binary (Malware=0, Benign=1 to match Kaggle model)
    y = (df['Class'] == 'Benign').astype(int)
    
    print(f"\nFeatures: {len(feature_cols)}")
    print(f"Samples: {len(df):,}")
    
    # Handle categorical features
    categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
    if categorical_cols:
        print(f"\n[!] Categorical features found: {len(categorical_cols)}")
        print(f"    Examples: {categorical_cols[:5]}")
        print("    Encoding...")
        
        from sklearn.preprocessing import LabelEncoder
        for col in categorical_cols:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
        
        print("    [OK] Encoded to numeric")
    
    # Handle missing values
    missing = X.isnull().sum().sum()
    if missing > 0:
        print(f"\n[!] Missing values: {missing:,}")
        print("   Filling with 0...")
        X = X.fillna(0)
    else:
        print("\n[OK] No missing values")
    
    # Categorize features for analysis
    static_features = []
    dynamic_features = []
    network_features = []
    
    for col in feature_cols:
        col_lower = col.lower()
        if any(kw in col_lower for kw in ['registry', 'process', 'file', 'dll', 'api']):
            dynamic_features.append(col)
        elif any(kw in col_lower for kw in ['network', 'dns', 'http', 'connection', 'threat']):
            network_features.append(col)
        else:
            static_features.append(col)
    
    print(f"\nFeature Breakdown:")
    print(f"  Static (PE headers): {len(static_features)}")
    print(f"  Dynamic (behavior): {len(dynamic_features)}")
    print(f"  Network: {len(network_features)}")
    
    return X, y, feature_cols, static_features, dynamic_features, network_features

def train_model(X_train, y_train):
    """Train Random Forest with same config as Kaggle for fair comparison"""
    print("\nTraining Random Forest model...")
    print("  Configuration: 100 trees, max_depth=15 (same as Kaggle model)")
    
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
    print("[OK] Training complete\n")
    
    return model

def evaluate_and_compare(model, X_train, X_test, y_train, y_test):
    """Evaluate model and compare with Kaggle results"""
    print("="*80)
    print("MODEL EVALUATION - ZENODO (HYBRID FEATURES)")
    print("="*80)
    
    # Predictions
    train_acc = model.score(X_train, y_train)
    test_acc = model.score(X_test, y_test)
    y_pred = model.predict(X_test)
    
    print(f"\nAccuracy:")
    print(f"  Training: {train_acc:.2%}")
    print(f"  Test:     {test_acc:.2%}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"               Malicious  Benign")
    print(f"Actual Malicious  {cm[0,0]:6d}   {cm[0,1]:6d}")
    print(f"       Benign     {cm[1,0]:6d}   {cm[1,1]:6d}")
    
    # Calculate key metrics
    tn, fp, fn, tp = cm.ravel()
    detection_rate = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tp) if (fp + tp) > 0 else 0
    precision_mal = tn / (tn + fn) if (tn + fn) > 0 else 0
    recall_mal = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    print(f"\nKey Metrics:")
    print(f"  Malware Detection Rate: {detection_rate:.2%}")
    print(f"  False Positive Rate:    {fpr:.2%}")
    print(f"  Precision (Malicious):  {precision_mal:.2%}")
    
    # Classification report
    print(f"\nDetailed Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Malicious', 'Benign'],
                                digits=4))
    
    # Comparison with Kaggle model
    print("="*80)
    print("COMPARISON: Zenodo (Hybrid) vs Kaggle (Static Only)")
    print("="*80)
    
    kaggle_acc = 0.9941  # From previous training
    kaggle_fpr = 0.0046
    
    print(f"\n{'Metric':<30} {'Kaggle':<15} {'Zenodo':<15} {'Improvement'}")
    print("-" * 80)
    print(f"{'Test Accuracy':<30} {kaggle_acc:<15.2%} {test_acc:<15.2%} {((test_acc - kaggle_acc) / kaggle_acc * 100):+.2f}%")
    print(f"{'False Positive Rate':<30} {kaggle_fpr:<15.2%} {fpr:<15.2%} {((fpr - kaggle_fpr) / kaggle_fpr * 100):+.2f}%")
    print(f"{'Features Used':<30} {'15':<15} {str(len(model.feature_names_in_)):<15} {'+' + str(len(model.feature_names_in_) - 15)}")
    
    feature_quality = "Basic PE" if test_acc < kaggle_acc else "Static+Dynamic"
    print(f"{'Feature Quality':<30} {'Basic PE':<15} {feature_quality:<15}")
    
    print("\n[!] Key Takeaway:")
    if test_acc > kaggle_acc:
        print("   [+] Hybrid features (static + dynamic) provide better detection!")
    elif abs(test_acc - kaggle_acc) < 0.01:
        print("   [=] Similar accuracy, but Zenodo has richer features for explainability")
    else:
        print("   [-] Kaggle performed better (larger dataset advantage)")
    
    if fpr < kaggle_fpr:
        print("   [+] Lower false positives - more reliable for production!")
    
    return test_acc, model.feature_importances_

def analyze_feature_importance(feature_cols, feature_importance, 
                              static_features, dynamic_features, network_features):
    """Analyze which feature types are most important"""
    print("\n" + "="*80)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("="*80)
    
    # Create dataframe of features and importance
    feat_df = pd.DataFrame({
        'feature': feature_cols,
        'importance': feature_importance
    }).sort_values('importance', ascending=False)
    
    print("\n[*] TOP 15 MOST IMPORTANT FEATURES:\n")
    for i, row in feat_df.head(15).iterrows():
        # Categorize
        if row['feature'] in dynamic_features:
            category = "DYNAMIC"
            icon = "[D]"
        elif row['feature'] in network_features:
            category = "NETWORK"
            icon = "[N]"
        else:
            category = "STATIC"
            icon = "[S]"
        
        print(f"  {icon} {row['feature']:<35} {row['importance']:>6.4f}  [{category}]")
    
    # Calculate importance by category
    static_importance = feat_df[feat_df['feature'].isin(static_features)]['importance'].sum()
    dynamic_importance = feat_df[feat_df['feature'].isin(dynamic_features)]['importance'].sum()
    network_importance = feat_df[feat_df['feature'].isin(network_features)]['importance'].sum()
    
    print(f"\n[*] IMPORTANCE BY FEATURE TYPE:\n")
    print(f"  [S] Static (PE headers):  {static_importance:.2%}")
    print(f"  [D] Dynamic (behavior):   {dynamic_importance:.2%}")
    print(f"  [N] Network:              {network_importance:.2%}")
    
    print(f"\n[!] Insight:")
    if dynamic_importance > static_importance:
        print("   Dynamic behavior features are more important than static PE headers!")
        print("   This validates the hybrid approach for your FYP objective #3.")
    elif network_importance > 0.1:
        print("   Network features play a significant role in detection!")
        print("   This is valuable for detecting C2 communication.")
    else:
        print("   Static features dominate, but dynamic features add value.")

def save_model_artifacts(model, feature_cols, test_acc):
    """Save the Zenodo model"""
    print("\n" + "="*80)
    print("SAVING MODEL ARTIFACTS")
    print("="*80)
    
    # Save model
    model_path = 'malware_detector_zenodo_v1.pkl'
    joblib.dump(model, model_path)
    print(f"\n[OK] Model saved: {model_path}")
    
    # Save features
    with open('zenodo_features.txt', 'w') as f:
        f.write('\n'.join(feature_cols))
    print(f"[OK] Features saved: zenodo_features.txt")
    
    # Save metadata
    metadata = {
        'dataset': 'Zenodo',
        'accuracy': test_acc,
        'n_features': len(feature_cols),
        'feature_types': 'static + dynamic + network',
        'model_type': 'RandomForestClassifier',
        'n_estimators': 100,
        'max_depth': 15,
        'balanced': True
    }
    
    with open('zenodo_model_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"[OK] Metadata saved: zenodo_model_metadata.json")
    
    # Get model size
    import os
    model_size_kb = os.path.getsize(model_path) / 1024
    print(f"\n[OK] Model ready for deployment!")
    print(f"  Accuracy: {test_acc:.2%}")
    print(f"  Model size: {model_size_kb:.1f} KB")

def main():
    print("="*80)
    print("ZENODO HYBRID MODEL TRAINING")
    print("Static + Dynamic + Network Features")
    print("="*80)
    print()
    
    # Load data
    X, y, feature_cols, static_features, dynamic_features, network_features = load_and_prepare_zenodo()
    
    # Split
    print("\nSplitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"  Training samples: {len(X_train):,}")
    print(f"  Test samples: {len(X_test):,}")
    
    # Train
    model = train_model(X_train, y_train)
    
    # Evaluate
    test_acc, feature_importance = evaluate_and_compare(
        model, X_train, X_test, y_train, y_test
    )
    
    # Analyze features
    analyze_feature_importance(
        feature_cols, feature_importance,
        static_features, dynamic_features, network_features
    )
    
    # Save
    save_model_artifacts(model, feature_cols, test_acc)
    
    print("\n" + "="*80)
    print("[OK] TRAINING COMPLETE")
    print("="*80)
    print("\nYou now have TWO models:")
    print("  1. Kaggle model (15 static features, 99.41% accuracy)")
    print("  2. Zenodo model (76 hybrid features, see results above)")
    print("\nFor your FYP, use Zenodo model - it demonstrates:")
    print("  [+] Hybrid approach (objective #3)")
    print("  [+] Static + dynamic analysis")
    print("  [+] Better feature interpretability")
    print("="*80)

if __name__ == "__main__":
    main()
