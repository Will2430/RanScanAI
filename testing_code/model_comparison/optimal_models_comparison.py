"""
Compare optimal models for Zenodo dataset
Why 1D CNN is NOT optimal for tabular data
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import lightgbm as lgb
from sklearn.neural_network import MLPClassifier
import time

print("=" * 80)
print("OPTIMAL MODELS FOR ZENODO DATASET")
print("=" * 80)

# Load dataset
df = pd.read_csv('../Dataset/Zenedo.csv')

# Prepare features
label_col = 'Class'
exclude_cols = ['md5', 'sha1', 'Class', 'Category', 'Family']
feature_cols = [col for col in df.columns if col not in exclude_cols]

X = df[feature_cols].fillna(0).values
y = (df[label_col] == 'Malicious').astype(int).values

print(f"\nDataset: {len(df)} samples, {len(feature_cols)} features")
print(f"Malicious: {(y==1).sum()} | Benign: {(y==0).sum()}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\n" + "=" * 80)
print("WHY 1D CNN IS NOT OPTIMAL FOR YOUR DATA:")
print("=" * 80)
print("""
1. **Tabular Data** - CNNs are for spatial/sequential patterns (images, audio)
   Your data: Flat feature vectors (PE headers + behavioral counts)
   
2. **No Spatial Relationships** - CNN assumes nearby features are related
   Your features: Independent measurements (e.g., registry_read next to network_dns)
   No meaningful "neighborhood" structure
   
3. **Feature Heterogeneity** - Different scales, types, meanings
   CNN treats all features uniformly
   
4. **Better Alternatives** - Gradient boosting, Random Forest, MLP
   These handle tabular data natively

5. **Overfitting** - CNN complex architecture + small dataset (2K samples)
   = Model memorizes instead of learning
""")

print("\n" + "=" * 80)
print("TESTING OPTIMAL MODELS:")
print("=" * 80)

results = {}

# ============================================================================
# 1. XGBoost (RECOMMENDED for your data)
# ============================================================================
print("\n1. XGBoost - BEST for tabular data")
print("-" * 80)
start = time.time()
xgb_model = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    eval_metric='logloss'
)
xgb_model.fit(X_train, y_train)
xgb_pred = xgb_model.predict(X_test)
xgb_proba = xgb_model.predict_proba(X_test)[:, 1]
train_time_xgb = time.time() - start

print(f"   Training time: {train_time_xgb:.2f}s")
print(f"   Test AUC: {roc_auc_score(y_test, xgb_proba):.4f}")
print(classification_report(y_test, xgb_pred, target_names=['Benign', 'Malicious']))

# Check confidence distribution
print(f"   Confidence score distribution:")
print(f"      Mean: {xgb_proba.mean():.4f}")
print(f"      Std: {xgb_proba.std():.4f}")
print(f"      Min: {xgb_proba.min():.4f}, Max: {xgb_proba.max():.4f}")
print(f"      % with confidence > 0.99: {(xgb_proba > 0.99).sum() / len(xgb_proba) * 100:.2f}%")

results['XGBoost'] = {
    'auc': roc_auc_score(y_test, xgb_proba),
    'predictions': xgb_pred,
    'probas': xgb_proba,
    'time': train_time_xgb
}

# ============================================================================
# 2. LightGBM (RECOMMENDED for speed + performance)
# ============================================================================
print("\n2. LightGBM - Fast and accurate")
print("-" * 80)
start = time.time()
lgb_model = lgb.LGBMClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    verbose=-1
)
lgb_model.fit(X_train, y_train)
lgb_pred = lgb_model.predict(X_test)
lgb_proba = lgb_model.predict_proba(X_test)[:, 1]
train_time_lgb = time.time() - start

print(f"   Training time: {train_time_lgb:.2f}s")
print(f"   Test AUC: {roc_auc_score(y_test, lgb_proba):.4f}")
print(classification_report(y_test, lgb_pred, target_names=['Benign', 'Malicious']))

print(f"   Confidence score distribution:")
print(f"      Mean: {lgb_proba.mean():.4f}")
print(f"      Std: {lgb_proba.std():.4f}")
print(f"      Min: {lgb_proba.min():.4f}, Max: {lgb_proba.max():.4f}")
print(f"      % with confidence > 0.99: {(lgb_proba > 0.99).sum() / len(lgb_proba) * 100:.2f}%")

results['LightGBM'] = {
    'auc': roc_auc_score(y_test, lgb_proba),
    'predictions': lgb_pred,
    'probas': lgb_proba,
    'time': train_time_lgb
}

# ============================================================================
# 3. Random Forest
# ============================================================================
print("\n3. Random Forest - Robust baseline")
print("-" * 80)
start = time.time()
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)
rf_proba = rf_model.predict_proba(X_test)[:, 1]
train_time_rf = time.time() - start

print(f"   Training time: {train_time_rf:.2f}s")
print(f"   Test AUC: {roc_auc_score(y_test, rf_proba):.4f}")
print(classification_report(y_test, rf_pred, target_names=['Benign', 'Malicious']))

print(f"   Confidence score distribution:")
print(f"      Mean: {rf_proba.mean():.4f}")
print(f"      Std: {rf_proba.std():.4f}")
print(f"      Min: {rf_proba.min():.4f}, Max: {rf_proba.max():.4f}")
print(f"      % with confidence > 0.99: {(rf_proba > 0.99).sum() / len(rf_proba) * 100:.2f}%")

results['RandomForest'] = {
    'auc': roc_auc_score(y_test, rf_proba),
    'predictions': rf_pred,
    'probas': rf_proba,
    'time': train_time_rf
}

# ============================================================================
# 4. MLP (Neural Network for tabular data)
# ============================================================================
print("\n4. MLP - Simple neural network")
print("-" * 80)
start = time.time()
mlp_model = MLPClassifier(
    hidden_layers=(128, 64, 32),
    activation='relu',
    max_iter=200,
    random_state=42,
    early_stopping=True,
    validation_fraction=0.2
)
mlp_model.fit(X_train_scaled, y_train)
mlp_pred = mlp_model.predict(X_test_scaled)
mlp_proba = mlp_model.predict_proba(X_test_scaled)[:, 1]
train_time_mlp = time.time() - start

print(f"   Training time: {train_time_mlp:.2f}s")
print(f"   Test AUC: {roc_auc_score(y_test, mlp_proba):.4f}")
print(classification_report(y_test, mlp_pred, target_names=['Benign', 'Malicious']))

print(f"   Confidence score distribution:")
print(f"      Mean: {mlp_proba.mean():.4f}")
print(f"      Std: {mlp_proba.std():.4f}")
print(f"      Min: {mlp_proba.min():.4f}, Max: {mlp_proba.max():.4f}")
print(f"      % with confidence > 0.99: {(mlp_proba > 0.99).sum() / len(mlp_proba) * 100:.2f}%")

results['MLP'] = {
    'auc': roc_auc_score(y_test, mlp_proba),
    'predictions': mlp_pred,
    'probas': mlp_proba,
    'time': train_time_mlp
}

# ============================================================================
# COMPARISON
# ============================================================================
print("\n" + "=" * 80)
print("MODEL COMPARISON:")
print("=" * 80)
print(f"\n{'Model':<15} {'AUC':>10} {'Train Time':>15} {'Confidence Issue':>20}")
print("-" * 80)
for name, res in results.items():
    confidence_issue = "❌ YES" if (res['probas'] > 0.99).sum() / len(res['probas']) > 0.5 else "✅ NO"
    print(f"{name:<15} {res['auc']:>10.4f} {res['time']:>12.2f}s {confidence_issue:>20}")

# Feature importance (XGBoost)
print("\n" + "=" * 80)
print("TOP 20 MOST IMPORTANT FEATURES (XGBoost):")
print("=" * 80)
feature_importance = xgb_model.feature_importances_
feature_names = feature_cols
importance_df = pd.DataFrame({
    'feature': feature_names,
    'importance': feature_importance
}).sort_values('importance', ascending=False)

for idx, row in importance_df.head(20).iterrows():
    print(f"   {row['feature']:40s}: {row['importance']:.4f}")

print("\n" + "=" * 80)
print("FINAL RECOMMENDATIONS:")
print("=" * 80)
print("""
🏆 BEST MODEL: XGBoost or LightGBM

WHY:
1. ✅ Designed for tabular data (your use case)
2. ✅ Handles mixed feature types (PE headers + behavioral counts)
3. ✅ Feature importance built-in (interpretable)
4. ✅ Robust to overfitting with proper regularization
5. ✅ Fast training on small-medium datasets
6. ✅ Industry standard for malware detection

AVOID:
❌ 1D CNN - Designed for sequential data (time series, text)
   Not suitable for flat feature vectors

IF YOUR CNN HAS CONFIDENCE=1:
🚨 Data leakage or shortcut learning
   Run diagnose_model_confidence.py to identify the issue

NEXT STEPS:
1. Use XGBoost/LightGBM as baseline
2. Add hyperparameter tuning (GridSearchCV)
3. Try ensemble (XGBoost + LightGBM + RF)
4. Add calibration (Platt scaling or isotonic regression)
""")
