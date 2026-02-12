"""
Diagnostic script to identify why CNN has confidence=1 for all predictions
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Load your Zenodo dataset
df = pd.read_csv('../Dataset/Zenedo.csv')

print("=" * 80)
print("DIAGNOSTIC REPORT: Model Confidence Issues")
print("=" * 80)

# Prepare features
label_col = 'Class'
exclude_cols = ['md5', 'sha1', 'Class', 'Category', 'Family']
feature_cols = [col for col in df.columns if col not in exclude_cols]

X = df[feature_cols].values
y = (df[label_col] == 'Malicious').astype(int).values

print(f"\n1. DATASET STATISTICS")
print(f"   Total samples: {len(df)}")
print(f"   Malicious: {(y == 1).sum()} ({(y == 1).sum() / len(y) * 100:.2f}%)")
print(f"   Benign: {(y == 0).sum()} ({(y == 0).sum() / len(y) * 100:.2f}%)")
print(f"   Features: {len(feature_cols)}")

# Check for perfect separators
print(f"\n2. CHECKING FOR PERFECT SEPARATORS (Data Leakage)")
print("-" * 80)
perfect_separators = []
for col in feature_cols:
    # Check if any single feature perfectly separates classes
    benign_vals = set(df[df[label_col] == 'Benign'][col].unique())
    malicious_vals = set(df[df[label_col] == 'Malicious'][col].unique())
    overlap = benign_vals.intersection(malicious_vals)
    
    if len(overlap) == 0 and len(benign_vals) > 0 and len(malicious_vals) > 0:
        perfect_separators.append(col)
        print(f"   ⚠️  '{col}' perfectly separates classes!")
        print(f"       Benign values: {sorted(list(benign_vals))[:5]}")
        print(f"       Malicious values: {sorted(list(malicious_vals))[:5]}")

if not perfect_separators:
    print("   ✓ No perfect separators found")
else:
    print(f"\n   🚨 CRITICAL: {len(perfect_separators)} features can perfectly separate classes!")
    print(f"   These features likely cause confidence=1:")
    for feat in perfect_separators[:10]:
        print(f"      - {feat}")

# Check feature importance with simple correlation
print(f"\n3. TOP CORRELATED FEATURES WITH LABEL")
print("-" * 80)
correlations = []
for col in feature_cols:
    try:
        corr = np.corrcoef(df[col].fillna(0), y)[0, 1]
        if not np.isnan(corr):
            correlations.append((col, abs(corr)))
    except:
        pass

correlations.sort(key=lambda x: x[1], reverse=True)
print("   Top 10 most correlated features:")
for feat, corr in correlations[:10]:
    print(f"      {feat:30s}: {corr:.4f}")

# Check if any feature has correlation > 0.99 (near perfect)
near_perfect = [(f, c) for f, c in correlations if c > 0.99]
if near_perfect:
    print(f"\n   🚨 CRITICAL: {len(near_perfect)} features have correlation > 0.99!")
    print("   Model likely relies on these for 'perfect' predictions:")
    for feat, corr in near_perfect:
        print(f"      - {feat}: {corr:.4f}")

# Check for duplicate rows
print(f"\n4. CHECKING FOR DUPLICATES")
print("-" * 80)
duplicates = df.duplicated(subset=feature_cols).sum()
print(f"   Duplicate rows: {duplicates}")
if duplicates > 0:
    print(f"   ⚠️  {duplicates} duplicate samples may cause overfitting")

# Check train/test split
print(f"\n5. TRAIN/TEST SPLIT ANALYSIS")
print("-" * 80)
# Simulate your split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"   Train size: {len(X_train)} ({len(X_train) / len(X) * 100:.1f}%)")
print(f"   Test size: {len(X_test)} ({len(X_test) / len(X) * 100:.1f}%)")
print(f"   Train malicious: {(y_train == 1).sum()} ({(y_train == 1).sum() / len(y_train) * 100:.2f}%)")
print(f"   Test malicious: {(y_test == 1).sum()} ({(y_test == 1).sum() / len(y_test) * 100:.2f}%)")

# Check feature variance
print(f"\n6. FEATURE VARIANCE CHECK")
print("-" * 80)
feature_stds = df[feature_cols].std()
zero_var = feature_stds[feature_stds == 0]
if len(zero_var) > 0:
    print(f"   ⚠️  {len(zero_var)} features have zero variance:")
    for feat in zero_var.index[:10]:
        print(f"      - {feat}")
else:
    print("   ✓ All features have non-zero variance")

# Check for NaN/Inf
print(f"\n7. DATA QUALITY CHECK")
print("-" * 80)
nan_counts = df[feature_cols].isna().sum()
has_nans = nan_counts[nan_counts > 0]
if len(has_nans) > 0:
    print(f"   Features with NaN values:")
    for feat, count in has_nans.items():
        print(f"      {feat:30s}: {count} ({count / len(df) * 100:.2f}%)")
else:
    print("   ✓ No NaN values found")

# Recommendation
print(f"\n" + "=" * 80)
print("RECOMMENDATIONS:")
print("=" * 80)

if perfect_separators or near_perfect:
    print("🚨 CRITICAL ISSUE DETECTED:")
    print("   Your model achieves confidence=1 because certain features")
    print("   perfectly or near-perfectly separate the classes.")
    print()
    print("   SOLUTIONS:")
    print("   1. Remove these features - they're likely artifacts or labels")
    print("   2. Check if these represent actual malware behavior or data leakage")
    print("   3. Use cross-validation to verify the issue exists across folds")
    print()
    print(f"   Features to investigate: {perfect_separators[:5] if perfect_separators else [f for f, c in near_perfect[:5]]}")
else:
    print("✓ No obvious data leakage detected")
    print("  Issue may be:")
    print("  - Model architecture (1D CNN not suitable for tabular data)")
    print("  - Overfitting (model too complex for dataset size)")
    print("  - Poor calibration (softmax outputs not calibrated)")

print("\n" + "=" * 80)
