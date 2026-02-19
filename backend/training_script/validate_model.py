"""
Validate the trained CNN model by testing on actual training samples.
This checks if the model can predict ANY samples as malicious.
"""

import keras
import pickle
import numpy as np
import json
import pandas as pd
from pathlib import Path

# Paths
MODEL_PATH = r"C:\Users\willi\OneDrive\Test\K\backend\training_script\best_fixed_cnn_model.keras"
VOCAB_PATH = r"C:\Users\willi\OneDrive\Test\K\backend\training_script\api_vocab_fixed.pkl"
KAGGLE_DIR = r"C:\Users\willi\Downloads\archive\data\Processed"
MALBEHAVD_PATH = r"C:\Users\willi\OneDrive\Test\K\dataset\MalBehavD-V1-dataset.csv"

MAX_SEQ_LENGTH = 2000

def load_vocab():
    """Load the API vocabulary."""
    with open(VOCAB_PATH, 'rb') as f:
        return pickle.load(f)

def load_kaggle_sample(filename):
    """Load a single Kaggle JSON sample."""
    filepath = Path(KAGGLE_DIR) / filename
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data.get('apis', [])

def load_malbehavd_sample(row_index):
    """Load a single MalBehavD sample by row index."""
    df = pd.read_csv(MALBEHAVD_PATH)
    row = df.iloc[row_index]
    
    # Extract API calls from numbered columns
    api_sequence = []
    for i in range(1, 11):  # Assuming 10 columns
        col_name = str(i)
        if col_name in row and pd.notna(row[col_name]):
            value = str(row[col_name]).strip().lower()
            if value and value != 'nan':
                api_sequence.append(value)
    
    return api_sequence, int(row['Label'])

def sequence_to_indices(api_sequence, vocab):
    """Convert API sequence to indices."""
    indices = []
    for api in api_sequence:
        api_lower = api.lower()
        indices.append(vocab.get(api_lower, 1))  # 1 = <UNK>
    return indices

def pad_sequence(indices, max_length):
    """Pad or truncate sequence to max_length."""
    if len(indices) > max_length:
        return indices[:max_length]
    else:
        return indices + [0] * (max_length - len(indices))

def test_samples(model, vocab):
    """Test model on various samples from training data."""
    print("=" * 80)
    print("VALIDATING MODEL ON TRAINING SAMPLES")
    print("=" * 80)
    
    # Test some Kaggle malicious samples
    print("\n\n--- Testing MALICIOUS samples from Kaggle (368.json) ---")
    try:
        mal_apis = load_kaggle_sample("368.json")
        if mal_apis:
            # Test first sample
            sample = mal_apis[0] if isinstance(mal_apis[0], list) else mal_apis[:500]
            indices = sequence_to_indices(sample, vocab)
            padded = pad_sequence(indices, MAX_SEQ_LENGTH)
            X = np.array([padded])
            
            prediction = model.predict(X, verbose=0)[0][0]
            print(f"Sample 1: {len(sample)} API calls")
            print(f"Prediction: {'MALICIOUS' if prediction > 0.5 else 'BENIGN'}")
            print(f"Malicious probability: {prediction:.4f}")
            print(f"Confidence: {max(prediction, 1-prediction):.2%}")
    except Exception as e:
        print(f"Error testing Kaggle sample: {e}")
    
    # Test some benign samples from 389.json
    print("\n\n--- Testing MALICIOUS samples from Kaggle (389.json) ---")
    try:
        mal_apis_2 = load_kaggle_sample("389.json")
        if mal_apis_2:
            sample = mal_apis_2[0] if isinstance(mal_apis_2[0], list) else mal_apis_2[:500]
            indices = sequence_to_indices(sample, vocab)
            padded = pad_sequence(indices, MAX_SEQ_LENGTH)
            X = np.array([padded])
            
            prediction = model.predict(X, verbose=0)[0][0]
            print(f"Sample 1: {len(sample)} API calls")
            print(f"Prediction: {'MALICIOUS' if prediction > 0.5 else 'BENIGN'}")
            print(f"Malicious probability: {prediction:.4f}")
            print(f"Confidence: {max(prediction, 1-prediction):.2%}")
    except Exception as e:
        print(f"Error testing Kaggle sample 389: {e}")
    
    # Test benign samples from MalBehavD
    print("\n\n--- Testing BENIGN samples from MalBehavD ---")
    try:
        # Test 3 benign samples
        for i in [0, 5, 10]:
            api_sequence, label = load_malbehavd_sample(i)
            if label == 0:  # Benign
                indices = sequence_to_indices(api_sequence, vocab)
                padded = pad_sequence(indices, MAX_SEQ_LENGTH)
                X = np.array([padded])
                
                prediction = model.predict(X, verbose=0)[0][0]
                print(f"\nBenign Sample {i+1}: {len(api_sequence)} API calls")
                print(f"Prediction: {'MALICIOUS' if prediction > 0.5 else 'BENIGN'}")
                print(f"Malicious probability: {prediction:.4f}")
                print(f"Confidence: {max(prediction, 1-prediction):.2%}")
    except Exception as e:
        print(f"Error testing MalBehavD benign samples: {e}")
    
    # Test benign sample from Kaggle
    print("\n\n--- Testing BENIGN sample from Kaggle (benign.json) ---")
    try:
        benign_apis = load_kaggle_sample("benign.json")
        if benign_apis:
            sample = benign_apis[0] if isinstance(benign_apis[0], list) else benign_apis[:500]
            indices = sequence_to_indices(sample, vocab)
            padded = pad_sequence(indices, MAX_SEQ_LENGTH)
            X = np.array([padded])
            
            prediction = model.predict(X, verbose=0)[0][0]
            print(f"Sample 1: {len(sample)} API calls")
            print(f"Prediction: {'MALICIOUS' if prediction > 0.5 else 'BENIGN'}")
            print(f"Malicious probability: {prediction:.4f}")
            print(f"Confidence: {max(prediction, 1-prediction):.2%}")
    except Exception as e:
        print(f"Error testing Kaggle benign sample: {e}")
    
    print("\n" + "=" * 80)
    print("VALIDATION COMPLETE")
    print("=" * 80)

def main():
    print("Loading model and vocabulary...")
    model = keras.models.load_model(MODEL_PATH)
    vocab = load_vocab()
    
    print(f"Model loaded: {MODEL_PATH}")
    print(f"Vocabulary size: {len(vocab)}")
    print(f"Max sequence length: {MAX_SEQ_LENGTH}")
    
    test_samples(model, vocab)

if __name__ == "__main__":
    main()
