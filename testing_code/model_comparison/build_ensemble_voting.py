"""
Build Ensemble Voting Classifier from trained models
Combines Random Forest + Gradient Boosting + XGBoost using soft voting
"""
import joblib
import json
import numpy as np
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score, confusion_matrix
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

print("=" * 80)
print("BUILDING ENSEMBLE VOTING CLASSIFIER")
print("Soft voting: RF + GB + XGBoost")
print("=" * 80)

# Paths
script_dir = Path(__file__).parent
project_root = script_dir.parent.parent
models_dir = project_root / 'models'

# Find latest models
print("\n🔍 Scanning for trained models...")

# Find Random Forest (from initial training)
rf_candidates = list(models_dir.glob('*random*.pkl'))
if not rf_candidates:
    # Try alternative names
    rf_candidates = list(models_dir.glob('*zenodo*.pkl'))
    rf_candidates = [f for f in rf_candidates if 'gradient' not in f.name.lower() and 'xgb' not in f.name.lower()]

# Find Gradient Boosting
gb_candidates = sorted(models_dir.glob('gradient_boosting_zenodo_*.pkl'), reverse=True)

# Find XGBoost
xgb_candidates = sorted(models_dir.glob('xgboost_zenodo_*.pkl'), reverse=True)

print(f"\n📁 Found models:")
print(f"   Random Forest: {len(rf_candidates)} file(s)")
print(f"   Gradient Boosting: {len(gb_candidates)} file(s)")
print(f"   XGBoost: {len(xgb_candidates)} file(s)")

# Select models
if not rf_candidates:
    print("\n⚠️  WARNING: No Random Forest model found!")
    print("   Training Random Forest from initial/train_zenodo_model.py...")
    print("   Or manually copy/rename the RF model to models/ directory")
    # For now, we'll try to load from a known location
    rf_path = project_root / 'zenodo_model.pkl'
    if not rf_path.exists():
        raise FileNotFoundError(
            "Random Forest model not found. Please run:\n"
            "  python initial/train_zenodo_model.py\n"
            "Or ensure zenodo_model.pkl exists in the project root."
        )
else:
    rf_path = rf_candidates[0]

if not gb_candidates:
    raise FileNotFoundError(
        "Gradient Boosting model not found. Please run:\n"
        "  python backend/training_script/train_gradient_boosting_production.py"
    )
gb_path = gb_candidates[0]

if not xgb_candidates:
    raise FileNotFoundError(
        "XGBoost model not found. Please run:\n"
        "  python backend/training_script/train_xgboost_zenodo.py"
    )
xgb_path = xgb_candidates[0]

print(f"\n✓ Selected models:")
print(f"   RF:  {rf_path.name}")
print(f"   GB:  {gb_path.name}")
print(f"   XGB: {xgb_path.name}")

# Load models
print("\n📦 Loading models...")
rf_model = joblib.load(rf_path)
gb_model = joblib.load(gb_path)
xgb_model = joblib.load(xgb_path)
print("✓ All models loaded successfully")

# Load scaler (use the one from GB or XGB training, they should be the same)
scaler_candidates = sorted(models_dir.glob('scaler_*.pkl'), reverse=True)
if scaler_candidates:
    scaler_path = scaler_candidates[0]
    scaler = joblib.load(scaler_path)
    print(f"✓ Scaler loaded: {scaler_path.name}")
else:
    print("⚠️  No scaler found - ensemble will expect pre-scaled features")
    scaler = None

# Create voting ensemble
print("\n🏗️  Building ensemble...")
ensemble = VotingClassifier(
    estimators=[
        ('random_forest', rf_model),
        ('gradient_boosting', gb_model),
        ('xgboost', xgb_model)
    ],
    voting='soft',  # Average predicted probabilities
    weights=None    # Equal weight to all models
)

# Note: VotingClassifier wraps already-fitted models
# We don't need to call .fit() again - it will use the pre-trained models
print("✓ Ensemble created with soft voting")
print("   Weights: Equal (1/3 each)")
print("   Voting method: Soft (average probabilities)")

# Save ensemble
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
ensemble_filename = f'ensemble_voting_{timestamp}.pkl'
ensemble_path = models_dir / ensemble_filename

joblib.dump(ensemble, ensemble_path)
print(f"\n✓ Ensemble saved: {ensemble_path}")

# Save metadata
metadata = {
    'model_type': 'VotingClassifier',
    'voting_method': 'soft',
    'timestamp': timestamp,
    'n_estimators': 3,
    'estimators': {
        'random_forest': {
            'path': rf_path.name,
            'type': type(rf_model).__name__
        },
        'gradient_boosting': {
            'path': gb_path.name,
            'type': type(gb_model).__name__
        },
        'xgboost': {
            'path': xgb_path.name,
            'type': type(xgb_model).__name__
        }
    },
    'weights': 'equal',
    'scaler': scaler_path.name if scaler else None
}

metadata_path = models_dir / f'ensemble_metadata_{timestamp}.json'
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=2)
print(f"✓ Metadata saved: {metadata_path}")

print("\n" + "=" * 80)
print("✅ ENSEMBLE READY")
print("=" * 80)
print(f"\nEnsemble composition:")
print(f"   1. Random Forest (RF)      - {type(rf_model).__name__}")
print(f"   2. Gradient Boosting (GB)  - {type(gb_model).__name__}")
print(f"   3. XGBoost (XGB)           - {type(xgb_model).__name__}")
print(f"\nVoting strategy:")
print(f"   Method: Soft voting (probability averaging)")
print(f"   Formula: P_ensemble = (P_rf + P_gb + P_xgb) / 3")
print(f"\nUsage:")
print(f"   ```python")
print(f"   import joblib")
print(f"   ensemble = joblib.load('{ensemble_path.name}')")
print(f"   scaler = joblib.load('{scaler_path.name if scaler else 'scaler.pkl'}')")
print(f"   ")
print(f"   # For new sample")
print(f"   features_scaled = scaler.transform(features)")
print(f"   prediction = ensemble.predict(features_scaled)")
print(f"   probability = ensemble.predict_proba(features_scaled)")
print(f"   ```")

print("\n" + "=" * 80)
print("NEXT STEPS:")
print("=" * 80)
print("1. Load test data and validate ensemble performance")
print("2. Run multi_model_benchmark.py for side-by-side comparison")
print("3. Test with ransomware_simulator.py output")
print("4. Compare ensemble vs individual models")
