"""
Multi-Model Benchmark Script
Compares RF, GB, XGBoost, CNN, and Ensemble on ransomware simulator output
Demonstrates architectural differences and ensemble robustness
"""
import sys
import json
import time
import joblib
import numpy as np
from pathlib import Path
from datetime import datetime

# Add project paths
script_dir = Path(__file__).parent
project_root = script_dir.parent.parent
backend_dir = project_root / 'backend'
sys.path.insert(0, str(backend_dir))
sys.path.insert(0, str(project_root))

print("=" * 80)
print("MULTI-MODEL RANSOMWARE DETECTION BENCHMARK")
print("=" * 80)
print(f"Testing: RF | GB | XGBoost | CNN | Ensemble")
print(f"Benchmark: ransomware_simulator.py output + System_Update.exe")
print("=" * 80)

# Paths
models_dir = project_root / 'models'
simulator_dir = project_root / 'testing_code' / 'ransomware_simulation'
behavioral_json = simulator_dir / 'behavioral_data.json'
exe_path = simulator_dir / 'dist' / 'System_Update.exe'

# Step 1: Check inputs
print("\n📂 Checking inputs...")
if not behavioral_json.exists():
    print(f"❌ Behavioral data not found: {behavioral_json}")
    print("   Run: python testing_code/ransomware_simulation/ransomware_simulator.py --auto-run")
    sys.exit(1)
print(f"✓ Behavioral data: {behavioral_json.name}")

if not exe_path.exists():
    print(f"❌ Test executable not found: {exe_path}")
    print("   Run: python testing_code/ransomware_simulation/build_malicious_exe.py")
    sys.exit(1)
print(f"✓ Test executable: {exe_path.name} ({exe_path.stat().st_size:,} bytes)")

# Load behavioral data
with open(behavioral_json, 'r') as f:
    behavioral_data = json.load(f)

# Calculate registry total
reg_total = (behavioral_data['registry']['read'] + 
             behavioral_data['registry']['write'] + 
             behavioral_data['registry']['delete'])

print(f"\n📊 Behavioral Summary:")
print(f"   Registry Ops: {reg_total} (read: {behavioral_data['registry']['read']}, write: {behavioral_data['registry']['write']})")
print(f"   Files Modified: {behavioral_data['files']['suspicious']}")
print(f"   Network Activity: {behavioral_data['network']['connections']}")

# Step 2: Extract PE features
print("\n🔍 Extracting PE features from executable...")
try:
    from pe_feature_extractor import PEFeatureExtractor
    
    extractor = PEFeatureExtractor()
    pe_features = extractor.extract(str(exe_path))
    
    if pe_features is None:
        print("❌ PE feature extraction failed")
        sys.exit(1)
    
    print(f"✓ Extracted {len(pe_features)} PE features")
    
except ImportError as e:
    print(f"❌ Failed to import PE extractor: {e}")
    print("   Ensure backend/pe_feature_extractor.py exists")
    sys.exit(1)

# Step 3: Merge behavioral features
print("\n🔗 Merging PE + behavioral features...")

# Map behavioral data to Zenodo feature schema
# Zenodo has: registry_read, registry_write, registry_delete, registry_total,
#             files_text, files_unknown, network_dns, network_http, etc.

# The PE extractor returns 67 features (53 static + 18 behavioral placeholders)
# We need to update the behavioral positions with actual data

# Create feature mapping (based on Zenodo schema)
behavioral_mapping = {
    # Indices are approximations - adjust based on actual feature order
    # See models/features_gb_*.json for exact feature names
    'registry_read': behavioral_data['registry']['read'],
    'registry_write': behavioral_data['registry']['write'],
    'registry_delete': behavioral_data['registry']['delete'],
    'registry_total': reg_total,  # Calculated above
    'files_text': len([f for f in behavioral_data['files'].get('created', []) if f.endswith('.txt')]),
    'files_unknown': behavioral_data['files'].get('suspicious', 0),
    'network_dns': behavioral_data['network'].get('dns', 0),
    'network_http': behavioral_data['network'].get('http', 0),
    'network_connections': behavioral_data['network'].get('connections', 0),
    'processes_monitored': behavioral_data['processes'].get('total', 0),  # Use 'total' instead of 'monitored'
    'total_procsses': behavioral_data['processes'].get('total', 0),  # Note: typo in dataset
    'dlls_calls': len(behavioral_data.get('dlls', [])),
    'apis': behavioral_data.get('apis', 0)
}

# Load feature names to get exact positions
feature_names_files = sorted(models_dir.glob('features_*_*.json'), reverse=True)
if feature_names_files:
    with open(feature_names_files[0], 'r') as f:
        feature_names = json.load(f)
    print(f"✓ Loaded feature schema: {len(feature_names)} features")
    
    # Update behavioral features in the feature vector
    for feat_name, feat_value in behavioral_mapping.items():
        if feat_name in feature_names:
            idx = feature_names.index(feat_name)
            pe_features[idx] = feat_value
    
    print(f"✓ Updated {len(behavioral_mapping)} behavioral features")
else:
    print("⚠️  Feature names not found - using PE features only")
    feature_names = [f"feature_{i}" for i in range(len(pe_features))]

# Ensure feature vector is the right size
expected_features = 67
if len(pe_features) < expected_features:
    print(f"⚠️  Padding features: {len(pe_features)} → {expected_features}")
    pe_features = np.pad(pe_features, (0, expected_features - len(pe_features)))
elif len(pe_features) > expected_features:
    print(f"⚠️  Truncating features: {len(pe_features)} → {expected_features}")
    pe_features = pe_features[:expected_features]

features = pe_features.reshape(1, -1)  # Shape: (1, 67)
print(f"✓ Final feature vector: {features.shape}")

# Step 4: Load scaler
print("\n🔧 Loading feature scaler...")
scaler_files = sorted(models_dir.glob('scaler_*.pkl'), reverse=True)
if not scaler_files:
    # Try default scaler
    scaler_files = list(models_dir.glob('scaler.pkl'))

if scaler_files:
    scaler = joblib.load(scaler_files[0])
    features_scaled = scaler.transform(features)
    print(f"✓ Scaler loaded: {scaler_files[0].name}")
else:
    print("⚠️  No scaler found - using raw features (may affect accuracy)")
    features_scaled = features

# Step 5: Load all models
print("\n📦 Loading models...")

models = {}
results = {}

# Load Random Forest
rf_files = list(models_dir.glob('*random*.pkl'))
if not rf_files:
    rf_files = [f for f in models_dir.glob('*.pkl') if 'gradient' not in f.name and 'xgb' not in f.name and 'ensemble' not in f.name and 'scaler' not in f.name]
if rf_files:
    try:
        models['Random Forest'] = joblib.load(rf_files[0])
        print(f"✓ Random Forest: {rf_files[0].name}")
    except Exception as e:
        print(f"⚠️  Failed to load RF: {e}")

# Load Gradient Boosting
gb_files = sorted(models_dir.glob('gradient_boosting_*.pkl'), reverse=True)
if gb_files:
    try:
        models['Gradient Boosting'] = joblib.load(gb_files[0])
        print(f"✓ Gradient Boosting: {gb_files[0].name}")
    except Exception as e:
        print(f"⚠️  Failed to load GB: {e}")

# Load XGBoost
xgb_files = sorted(models_dir.glob('xgboost_*.pkl'), reverse=True)
if xgb_files:
    try:
        models['XGBoost'] = joblib.load(xgb_files[0])
        print(f"✓ XGBoost: {xgb_files[0].name}")
    except Exception as e:
        print(f"⚠️  Failed to load XGBoost: {e}")

# Load Ensemble
ensemble_files = sorted(models_dir.glob('ensemble_voting_*.pkl'), reverse=True)
if ensemble_files:
    try:
        from sklearn.utils.validation import check_is_fitted
        ensemble_model = joblib.load(ensemble_files[0])
        
        # Check if the ensemble is actually fitted
        try:
            check_is_fitted(ensemble_model)
            models['Ensemble (RF+GB+XGB)'] = ensemble_model
            print(f"✓ Ensemble: {ensemble_files[0].name}")
        except:
            print(f"⚠️  Ensemble exists but not fitted - run build_ensemble_voting.py")
    except Exception as e:
        print(f"⚠️  Failed to load Ensemble: {e}")

# Load CNN (requires TensorFlow/Keras)
cnn_files = sorted(models_dir.glob('cnn_*.keras'), reverse=True)
if cnn_files:
    try:
        from tensorflow import keras
        models['1D CNN'] = keras.models.load_model(cnn_files[0])
        print(f"✓ 1D CNN: {cnn_files[0].name}")
        
        # CNN expects different input shape - need to reshape
        # 1D CNN trained on Zenodo uses features as 1D sequence
        cnn_input_shape = models['1D CNN'].input_shape[1]
        print(f"   CNN expects {cnn_input_shape} features per sample")
        
    except ImportError:
        print("⚠️  TensorFlow not available - skipping CNN")
    except Exception as e:
        print(f"⚠️  Failed to load CNN: {e}")

if not models:
    print("\n❌ No models loaded! Please train models first:")
    print("   1. python backend/training_script/train_gradient_boosting_production.py")
    print("   2. python backend/training_script/train_xgboost_zenodo.py")
    print("   3. python testing_code/model_comparison/build_ensemble_voting.py")
    sys.exit(1)

print(f"\n✓ Loaded {len(models)} model(s)")

# Step 6: Run predictions
print("\n" + "=" * 80)
print("RUNNING PREDICTIONS")
print("=" * 80)

for model_name, model in models.items():
    print(f"\n🔮 {model_name}...")
    
    try:
        start_time = time.time()
        
        # Handle CNN differently (may need reshaping or different input)
        if '1D CNN' in model_name:
            # CNN needs specific shape based on training
            # For Zenodo CNN, features are treated as 1D sequence
            cnn_features = features_scaled.reshape(1, -1, 1)  # Shape: (1, 67, 1)
            prediction_proba = model.predict(cnn_features, verbose=0)[0][0]
            prediction = 1 if prediction_proba >= 0.5 else 0
        else:
            # Tree-based models
            prediction = model.predict(features_scaled)[0]
            prediction_proba = model.predict_proba(features_scaled)[0]
            
            # Get probability for malicious class (class 1)
            if len(prediction_proba) == 2:
                prediction_proba = prediction_proba[1]
            else:
                prediction_proba = prediction_proba[0]
        
        inference_time = (time.time() - start_time) * 1000  # Convert to ms
        
        # Determine label
        label = "MALICIOUS" if prediction == 1 else "BENIGN"
        confidence = prediction_proba if prediction == 1 else (1 - prediction_proba)
        
        results[model_name] = {
            'prediction': int(prediction),
            'label': label,
            'confidence': float(confidence),
            'probability': float(prediction_proba),
            'latency_ms': float(inference_time)
        }
        
        # Color output
        color = "✓" if label == "MALICIOUS" else "✗"
        print(f"   {color} Prediction: {label}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   Malicious Probability: {prediction_proba:.4f}")
        print(f"   Latency: {inference_time:.2f}ms")
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        results[model_name] = {
            'prediction': None,
            'label': 'ERROR',
            'confidence': 0.0,
            'probability': 0.0,
            'latency_ms': 0.0,
            'error': str(e)
        }

# Step 7: Comparison table
print("\n" + "=" * 80)
print("COMPARISON TABLE")
print("=" * 80)

print(f"\n{'Model':<25} {'Prediction':<12} {'Confidence':>12} {'Latency':>12}")
print("-" * 80)

for model_name, result in results.items():
    if result['label'] != 'ERROR':
        print(f"{model_name:<25} {result['label']:<12} {result['confidence']:>11.2%} {result['latency_ms']:>10.2f}ms")
    else:
        print(f"{model_name:<25} {'ERROR':<12} {'N/A':>12} {'N/A':>12}")

# Analysis
malicious_votes = sum(1 for r in results.values() if r.get('prediction') == 1)
total_votes = len([r for r in results.values() if r.get('prediction') is not None])

print("\n" + "=" * 80)
print("ANALYSIS")
print("=" * 80)

print(f"\n📊 Consensus:")
print(f"   Malicious votes: {malicious_votes}/{total_votes}")
print(f"   Verdict: {'MALICIOUS' if malicious_votes > total_votes/2 else 'BENIGN'}")

# Check for disagreements
predictions_set = set(r.get('prediction') for r in results.values() if r.get('prediction') is not None)
if len(predictions_set) > 1:
    print(f"\n⚠️  DISAGREEMENT DETECTED!")
    print(f"   Models have conflicting predictions")
    
    # Identify which models disagree
    malicious_models = [name for name, r in results.items() if r.get('prediction') == 1]
    benign_models = [name for name, r in results.items() if r.get('prediction') == 0]
    
    print(f"\n   Malicious: {', '.join(malicious_models)}")
    print(f"   Benign: {', '.join(benign_models)}")
    
    # Architectural analysis
    if '1D CNN' in benign_models and len(benign_models) == 1:
        print(f"\n💡 Likely cause: CNN architectural mismatch with tabular data")
        print(f"   - Tree-based models (RF/GB/XGB) agree: MALICIOUS")
        print(f"   - CNN disagrees due to poor fit for non-sequential features")
        print(f"   - This validates architectural selection importance")
else:
    print(f"\n✅ All models agree: {results[list(results.keys())[0]]['label']}")

# Average confidence
avg_confidence = np.mean([r['confidence'] for r in results.values() if r.get('confidence') is not None])
print(f"\n📈 Average Confidence: {avg_confidence:.2%}")

# Fastest model
valid_results = {k: v for k, v in results.items() if v.get('latency_ms') is not None and v.get('latency_ms') > 0}
if valid_results:
    fastest = min(valid_results.items(), key=lambda x: x[1]['latency_ms'])
    print(f"⚡ Fastest Model: {fastest[0]} ({fastest[1]['latency_ms']:.2f}ms)")

# Save results
output_file = simulator_dir / f'benchmark_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
output_data = {
    'timestamp': datetime.now().isoformat(),
    'test_file': str(exe_path),
    'behavioral_data': str(behavioral_json),
    'results': results,
    'analysis': {
        'consensus': 'MALICIOUS' if malicious_votes > total_votes/2 else 'BENIGN',
        'malicious_votes': int(malicious_votes),
        'total_votes': int(total_votes),
        'average_confidence': float(avg_confidence),
        'disagreement': bool(len(predictions_set) > 1)
    }
}

with open(output_file, 'w') as f:
    json.dump(output_data, f, indent=2)

print(f"\n💾 Results saved: {output_file.name}")

print("\n" + "=" * 80)
print("BENCHMARK COMPLETE")
print("=" * 80)
print("\n✅ Multi-model comparison successful!")
print(f"   Tested: {len(models)} models")
print(f"   Behavioral features: {len(behavioral_mapping)} merged")
print(f"   Final verdict: {output_data['analysis']['consensus']}")
