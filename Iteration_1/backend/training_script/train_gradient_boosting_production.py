"""
Train production-ready Gradient Boosting model for Zenodo dataset
Removes data leakage features and saves to models directory
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score, confusion_matrix
import joblib
import json
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


logger.info("=" * 80)
logger.info("TRAINING PRODUCTION GRADIENT BOOSTING MODEL")
logger.info("Clean features only (no data leakage)")
logger.info("=" * 80)

# Paths - relative to script location
script_dir = Path(__file__).parent
project_root = script_dir.parent
dataset_path = project_root / 'Dataset' / 'Zenedo.csv'
models_dir = project_root / 'models'
models_dir.mkdir(exist_ok=True)

# Load dataset
df = pd.read_csv(dataset_path)
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

# Store feature names
feature_cols = X.columns.tolist()

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

print(f"\n   Training: {len(X_train)} samples")
print(f"   Testing: {len(X_test)} samples")

# Train Gradient Boosting model
print("\n" + "=" * 80)
print("TRAINING GRADIENT BOOSTING CLASSIFIER")
print("=" * 80)

model = GradientBoostingClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=5,
    min_samples_split=2,
    min_samples_leaf=1,
    random_state=42,
    verbose=1
)

print("\nTraining...")
start_time = datetime.now()
model.fit(X_train_scaled, y_train)
training_time = (datetime.now() - start_time).total_seconds()

print(f"\n✓ Training completed in {training_time:.2f}s")

# Evaluate
print("\n" + "=" * 80)
print("EVALUATION RESULTS")
print("=" * 80)

y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_pred_proba)

print(f"\n📊 Performance Metrics:")
print(f"   Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"   ROC AUC: {auc:.4f}")

print(f"\n📈 Detailed Classification Report:")
print(classification_report(y_test, y_pred, 
                          target_names=['Benign', 'Malware'],
                          digits=4))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
print(f"\n📋 Confusion Matrix:")
print(f"                Predicted")
print(f"                Benign  Malware")
print(f"   Actual Benign   {cm[0,0]:<6}  {cm[0,1]:<6}")
print(f"          Malware  {cm[1,0]:<6}  {cm[1,1]:<6}")

# Cross-validation
print(f"\n🔄 5-Fold Cross-Validation:")
cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='accuracy')
print(f"   CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

# Feature importance
print(f"\n🔍 Top 10 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(10).iterrows():
    print(f"   {row['feature']:<25} {row['importance']:.4f} ({row['importance']*100:.2f}%)")

# Save model
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
model_filename = f'gradient_boosting_zenodo_{timestamp}.pkl'
scaler_filename = f'scaler_gb_{timestamp}.pkl'
features_filename = f'features_gb_{timestamp}.json'
metadata_filename = f'gradient_boosting_metadata_{timestamp}.json'

print("\n" + "=" * 80)
print("SAVING MODEL")
print("=" * 80)

# Save model
model_path = models_dir / model_filename
joblib.dump(model, model_path)
print(f"\n✓ Model saved: {model_path}")

# Save scaler
scaler_path = models_dir / scaler_filename
joblib.dump(scaler, scaler_path)
print(f"✓ Scaler saved: {scaler_path}")

# Save feature names
features_path = models_dir / features_filename
with open(features_path, 'w') as f:
    json.dump(feature_cols, f, indent=2)
print(f"✓ Features saved: {features_path}")

# Save metadata
metadata = {
    'model_type': 'GradientBoostingClassifier',
    'timestamp': timestamp,
    'dataset': str(dataset_path),
    'n_samples': len(df),
    'n_features': len(feature_cols),
    'feature_names': feature_cols,
    'leaked_features_removed': [col for col in columns_to_drop if col != label_col],
    'training_samples': len(X_train),
    'test_samples': len(X_test),
    'performance': {
        'accuracy': float(accuracy),
        'roc_auc': float(auc),
        'cv_mean': float(cv_scores.mean()),
        'cv_std': float(cv_scores.std())
    },
    'hyperparameters': {
        'n_estimators': model.n_estimators,
        'learning_rate': model.learning_rate,
        'max_depth': model.max_depth,
        'min_samples_split': model.min_samples_split,
        'min_samples_leaf': model.min_samples_leaf,
        'random_state': model.random_state
    },
    'training_time_seconds': training_time,
    'confusion_matrix': cm.tolist(),
    'feature_importance': feature_importance.to_dict('records')[:20]  # Top 20
}

metadata_path = models_dir / metadata_filename
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=2)
print(f"✓ Metadata saved: {metadata_path}")

print("\n" + "=" * 80)
print("✅ PRODUCTION MODEL READY")
print("=" * 80)
print(f"\nModel files saved to: {models_dir.absolute()}")
print(f"\n📝 Quick stats:")
print(f"   - Clean accuracy: {accuracy*100:.2f}% (honest performance)")
print(f"   - Features used: {len(feature_cols)} (no leakage)")
print(f"   - Model size: {model_path.stat().st_size / 1024:.1f} KB")
print(f"\n💡 This model is ready for production deployment!")
print(f"   No data leakage, realistic performance baseline")
