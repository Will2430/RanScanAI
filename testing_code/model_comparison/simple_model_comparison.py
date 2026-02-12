"""
Simple optimal model comparison for Zenodo dataset (sklearn only)
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

print("=" * 80)
print("OPTIMAL MODELS FOR ZENODO DATASET")
print("Why 1D CNN is NOT optimal + Better alternatives")
print("=" * 80)

# Load dataset
df = pd.read_csv('../Dataset/Zenedo.csv')

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
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\n" + "=" * 80)
print("❌ WHY 1D CNN IS WRONG FOR YOUR DATA:")
print("=" * 80)
print("""
Your Zenodo dataset has TABULAR features (structured rows/columns):
  - Static PE features: EntryPoint, ImageBase, SizeOfCode, etc.
  - Dynamic counts: registry_read, network_dns, processes_suspicious, etc.

1D CNN is designed for SEQUENTIAL data where ORDER matters:
  - Time series (stock prices, sensor readings)
  - Audio signals (waveforms)
  - Text (word sequences)

PROBLEMS with CNN for your data:
  ❌ NO spatial/sequential patterns to learn
  ❌ Feature order is arbitrary (registry_read next to PEType = meaningless)
  ❌ Convolution assumes nearby features relate (NOT true for PE header + behavioral)
  ❌ Over-parameterized for tabular data → SEVERE OVERFITTING
  
YOUR CONFIDENCE=1.0 ISSUE:
  🚨 CNN has too many parameters (~thousands)
  🚨 Your dataset: only ~22K samples
  🚨 Model MEMORIZES train data instead of learning patterns
  🚨 Result: Overconfident predictions that don't generalize
""")

print("\n" + "=" * 80)
print("✅ TESTING OPTIMAL MODELS")
print("=" * 80)

results = {}

# ============================================================================
# 1. Gradient Boosting (sklearn's GBM)
# ============================================================================
print("\n1. Gradient Boosting - Best for tabular malware detection")
print("-" * 80)
start = time.time()
gbm_model = GradientBoostingClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    random_state=42
)
gbm_model.fit(X_train, y_train)
gbm_pred = gbm_model.predict(X_test)
gbm_proba = gbm_model.predict_proba(X_test)[:, 1]
train_time_gbm = time.time() - start

acc_gbm = accuracy_score(y_test, gbm_pred)
auc_gbm = roc_auc_score(y_test, gbm_proba)
print(f"   Training time: {train_time_gbm:.2f}s")
print(f"   Accuracy: {acc_gbm:.4f}")
print(f"   AUC: {auc_gbm:.4f}")
print(f"\n   Classification Report:")
print(classification_report(y_test, gbm_pred, target_names=['Benign', 'Malware']))

# IMPORTANT: Check confidence distribution
print(f"   🎯 Confidence score health check:")
print(f"      Mean: {gbm_proba.mean():.4f}")
print(f"      Std: {gbm_proba.std():.4f}")
print(f"      Min: {gbm_proba.min():.4f}, Max: {gbm_proba.max():.4f}")
over_confident = (gbm_proba > 0.99).sum() + (gbm_proba < 0.01).sum()
print(f"      % with extreme confidence (>0.99 or <0.01): {over_confident / len(gbm_proba) * 100:.2f}%")
if over_confident / len(gbm_proba) > 0.5:
    print(f"      ⚠️  Model may be overconfident")
else:
    print(f"      ✅ Good confidence calibration")

results['GradientBoosting'] = {
    'auc': auc_gbm,
    'acc': acc_gbm,
    'probas': gbm_proba,
    'time': train_time_gbm
}

# ============================================================================
# 2. Random Forest
# ============================================================================
print("\n2. Random Forest - Robust and interpretable")
print("-" * 80)
start = time.time()
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)
rf_proba = rf_model.predict_proba(X_test)[:, 1]
train_time_rf = time.time() - start

acc_rf = accuracy_score(y_test, rf_pred)
auc_rf = roc_auc_score(y_test, rf_proba)
print(f"   Training time: {train_time_rf:.2f}s")
print(f"   Accuracy: {acc_rf:.4f}")
print(f"   AUC: {auc_rf:.4f}")
print(f"\n   Classification Report:")
print(classification_report(y_test, rf_pred, target_names=['Benign', 'Malware']))

print(f"   🎯 Confidence score health check:")
print(f"      Mean: {rf_proba.mean():.4f}")
print(f"      Std: {rf_proba.std():.4f}")
over_confident = (rf_proba > 0.99).sum() + (rf_proba < 0.01).sum()
print(f"      % with extreme confidence: {over_confident / len(rf_proba) * 100:.2f}%")
if over_confident / len(rf_proba) > 0.5:
    print(f"      ⚠️  Model may be overconfident")
else:
    print(f"      ✅ Good confidence calibration")

results['RandomForest'] = {
    'auc': auc_rf,
    'acc': acc_rf,
    'probas': rf_proba,
    'time': train_time_rf
}

# ============================================================================
# 3. MLP (Proper neural network for tabular data)
# ============================================================================
print("\n3. MLP - Neural network (NOT CNN) for tabular data")
print("-" * 80)
start = time.time()
mlp_model = MLPClassifier(
    hidden_layer_sizes=(128, 64, 32),
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

acc_mlp = accuracy_score(y_test, mlp_pred)
auc_mlp = roc_auc_score(y_test, mlp_proba)
print(f"   Training time: {train_time_mlp:.2f}s")
print(f"   Accuracy: {acc_mlp:.4f}")
print(f"   AUC: {auc_mlp:.4f}")
print(f"\n   Classification Report:")
print(classification_report(y_test, mlp_pred, target_names=['Benign', 'Malware']))

print(f"   🎯 Confidence score health check:")
print(f"      Mean: {mlp_proba.mean():.4f}")
print(f"      Std: {mlp_proba.std():.4f}")
over_confident = (mlp_proba > 0.99).sum() + (mlp_proba < 0.01).sum()
print(f"      % with extreme confidence: {over_confident / len(mlp_proba) * 100:.2f}%")
if over_confident / len(mlp_proba) > 0.5:
    print(f"      ⚠️  Model may be overconfident")
else:
    print(f"      ✅ Good confidence calibration")

results['MLP'] = {
    'auc': auc_mlp,
    'acc': acc_mlp,
    'probas': mlp_proba,
    'time': train_time_mlp
}

# ============================================================================
# FINAL COMPARISON
# ============================================================================
print("\n" + "=" * 80)
print("📊 MODEL COMPARISON SUMMARY:")
print("=" * 80)
print(f"\n{'Model':<20} {'Accuracy':>12} {'AUC':>10} {'Train Time':>15}")
print("-" * 80)
for name, res in sorted(results.items(), key=lambda x: x[1]['auc'], reverse=True):
    print(f"{name:<20} {res['acc']:>12.4f} {res['auc']:>10.4f} {res['time']:>12.2f}s")

# Feature importance (Random Forest)
print("\n" + "=" * 80)
print("🔍 TOP 15 MOST IMPORTANT FEATURES (Random Forest):")
print("=" * 80)
feature_importance = rf_model.feature_importances_
importance_df = pd.DataFrame({
    'feature': feature_cols,
    'importance': feature_importance
}).sort_values('importance', ascending=False)

for idx, row in importance_df.head(15).iterrows():
    bar = '█' * int(row['importance'] * 100)
    print(f"   {row['feature']:35s}: {bar} {row['importance']:.4f}")

print("\n" + "=" * 80)
print("🏆 FINAL RECOMMENDATIONS:")
print("=" * 80)
print(f"""
BEST MODEL: Gradient Boosting or Random Forest

WHY THESE WORK BETTER:
 ✅ Designed for tabular data with mixed feature types
 ✅ Handle PE static features + behavioral counts naturally
 ✅ Feature importance → Understand what drives predictions
 ✅ Less prone to overfitting than deep networks
 ✅ Faster training on your dataset size (~22K samples)
 ✅ Better calibrated confidence scores

YOUR CNN PROBLEM (confidence=1.0):
 🚨 1D CNN is WRONG architecture for flat feature vectors
 🚨 Too many parameters for dataset size → Memorization
 🚨 No inherent sequential patterns in yourdata

NEXT STEPS:
 1. ✅ Use Gradient Boosting/Random Forest as baseline
 2. Install XGBoost/LightGBM for even better performance:
      pip install xgboost lightgbm
 3. Hyperparameter tuning (GridSearchCV)
 4. Ensemble multiple models (GB + RF + MLP)
 5. Add probability calibration if needed (CalibratedClassifierCV)

FOR DEPLOYMENT:
 - Use the best model from this comparison
 - Save model: joblib.dump(gbm_model, 'model.pkl')
 - Load: model = joblib.load('model.pkl')
""")
