# Models Directory

## ⚠️ Large Model Files

**Model files (.keras, .h5, .pkl) are NOT committed to git due to their large size.**

### Excluded Files (see .gitignore)
- `*.keras` - TensorFlow/Keras model files
- `*.h5` - HDF5 model files  
- `*.pkl` - Pickle files (scalers, preprocessors)

### Model Metadata Files (Committed)
- `*_metadata.json` - Model performance metrics and configuration
- `features_*.json` - Feature names and order

## Getting Model Files

**Option 1: Train the models yourself**
```bash
# For CNN model
python iteration_1/training_scripts/train_cnn_zenodo.py

# For Gradient Boosting model
python iteration_1/training_scripts/train_gradient_boosting.py
```

**Option 2: Download pre-trained models**
- Contact the project maintainers for model file links
- Models are stored separately (cloud storage, Git LFS, or release artifacts)

## Model File Locations

After training or downloading, place model files here:
```
models/
├── cnn_zenodo_YYYYMMDD_HHMMSS.keras
├── scaler_cnn_YYYYMMDD_HHMMSS.pkl
├── gradient_boosting_zenodo_YYYYMMDD_HHMMSS.pkl
├── scaler_gb_YYYYMMDD_HHMMSS.pkl
└── *_metadata.json (these ARE committed)
```

## Current Models

Check `*_metadata.json` files to see model performance metrics without downloading the large model files.
