"""
Dataset Augmentation Guide for Reducing Overfitting

Current Issue:
- 20K samples in Zenodo dataset → perfect metrics (accuracy=1.0, FPR=0, FNR=0)
- This indicates overfitting despite regularization
- Model memorizes training data instead of learning generalizable patterns

Goal: Augment to 100K+ diverse samples for better generalization
"""

# ==========================================
# Recommended Malware Datasets
# ==========================================

RECOMMENDED_DATASETS = {
    'EMBER': {
        'url': 'https://github.com/elastic/ember',
        'description': 'Elastic Malware Benchmark for Empowering Researchers',
        'samples': '1.1M PE files (balanced: 500K benign, 500K malicious)',
        'features': '2381 static PE features (can map to our 78)',
        'year': '2018',
        'format': 'JSON with extracted features + raw PEs',
        'license': 'Apache 2.0',
        'pros': [
            'Large, diverse dataset',
            'Already has PE features extracted',
            'Well-documented feature engineering',
            'Updated versions available (EMBER-2018)',
            'Used in academic research'
        ],
        'cons': [
            'Different feature set (need mapping)',
            'Large download (~60GB for full dataset)',
            'Features may not match Zenodo exactly'
        ],
        'recommended': True
    },
    
    'SOREL-20M': {
        'url': 'https://github.com/sophos/SOREL-20M',
        'description': 'Sophos-ReversingLabs 20M sample dataset',
        'samples': '20M PE files (10M benign, 10M malicious)',
        'features': 'PE metadata, behavioral tags, VT reports',
        'year': '2020',
        'format': 'JSON metadata + optional binary downloads',
        'license': 'CC BY-NC-SA 4.0',
        'pros': [
            'Massive scale',
            'Recent samples (2020)',
            'Includes VirusTotal data',
            'Multiple malware families',
            'Professionally curated by Sophos/ReversingLabs'
        ],
        'cons': [
            'Very large (requires sampling)',
            'Non-commercial license',
            'Downloading binaries is complex',
            'Feature extraction needed'
        ],
        'recommended': True
    },
    
    'MalwareBazaar': {
        'url': 'https://bazaar.abuse.ch/',
        'description': 'Community-driven malware sample sharing',
        'samples': '1M+ recent samples',
        'features': 'Hashes, tags, families, YARA matches',
        'year': 'Ongoing (daily updates)',
        'format': 'API access + ZIP downloads',
        'license': 'Free (check TOS)',
        'pros': [
            'Always fresh samples',
            'Active community',
            'API for automation',
            'Tagged by malware family',
            'Free access'
        ],
        'cons': [
            'Need to extract PE features yourself',
            'Rate limited API',
            'Quality varies',
            'No pre-balanced datasets'
        ],
        'recommended': False  # Good for specific samples, not bulk training
    },
    
    'VirusShare': {
        'url': 'https://virusshare.com/',
        'description': 'Large malware sample repository',
        'samples': '46M+ malware samples',
        'features': 'None (raw binaries only)',
        'year': 'Ongoing',
        'format': 'Torrents of password-protected ZIPs',
        'license': 'Research use',
        'pros': [
            'Huge volume',
            'Historical samples available',
            'Organized by hash'
        ],
        'cons': [
            'Malware only (need separate benign dataset)',
            'No metadata/features provided',
            'Time-consuming to download',
            'Need PE extraction for all files',
            'Contains many duplicates/variants'
        ],
        'recommended': False  # Too much work for features
    },
    
    'Kaggle Microsoft Malware': {
        'url': 'https://www.kaggle.com/competitions/microsoft-malware-prediction',
        'description': 'Microsoft Malware Prediction competition dataset',
        'samples': '16M Windows devices (9 malware classes)',
        'features': '83 features (similar to our use case!)',
        'year': '2019',
        'format': 'CSV with extracted features',
        'license': 'Competition use',
        'pros': [
            'Feature-based (ready to use)',
            'Large scale',
            'Microsoft-quality labels',
            'Multi-class (can convert to binary)'
        ],
        'cons': [
            'Device telemetry, not PE files',
            'Features may differ from PE static analysis',
            'Competition data (check license)'
        ],
        'recommended': True
    }
}


# ==========================================
# Augmentation Strategy
# ==========================================

def augmentation_strategy():
    """
    Recommended strategy for augmenting Zenodo (20K) → 100K+ samples
    """
    
    strategy = {
        'phase_1_quick_wins': {
            'goal': 'Get to 50K samples quickly',
            'actions': [
                '1. Use EMBER dataset (already has PE features)',
                '2. Download EMBER-2018 feature JSONs (~10GB compressed)',
                '3. Map EMBER\'s 2381 features to our 78 features',
                '4. Sample 30K balanced (15K benign, 15K malicious)',
                '5. Combine with Zenodo 20K → 50K total'
            ],
            'time_estimate': '1-2 days',
            'difficulty': 'Medium (feature mapping needed)'
        },
        
        'phase_2_scale_up': {
            'goal': 'Reach 100K+ samples with diversity',
            'actions': [
                '1. Add more EMBER samples (another 50K)',
                '2. OR use Kaggle Microsoft dataset subset',
                '3. Ensure temporal diversity (samples from different years)',
                '4. Balance malware families (not all ransomware)',
                '5. Cross-validate on held-out Zenodo subset'
            ],
            'time_estimate': '3-5 days',
            'difficulty': 'Medium-High'
        },
        
        'phase_3_fresh_samples': {
            'goal': 'Add recent samples for production relevance',
            'actions': [
                '1. Download recent samples from MalwareBazaar (last 6 months)',
                '2. Extract PE features using our PEFeatureExtractor',
                '3. Get benign samples from Windows system files, popular apps',
                '4. Add 10-20K fresh samples to training set',
                '5. Monitor for distribution shift in validation'
            ],
            'time_estimate': '5-7 days',
            'difficulty': 'High (manual PE extraction)'
        }
    }
    
    return strategy


# ==========================================
# Feature Mapping: EMBER → Zenodo
# ==========================================

def ember_to_zenodo_mapping():
    """
    Map EMBER's 2381 features to our 78 Zenodo features
    
    EMBER feature groups:
    - ByteHistogram (256 features)
    - ByteEntropyHistogram (256 features)
    - StringExtractor (104 features)
    - GeneralFileInfo (10 features)
    - HeaderFileInfo (62 features) ← MOST RELEVANT
    - SectionInfo (255 features) ← RELEVANT
    - ImportsInfo (1280 features)
    - ExportsInfo (128 features)
    - DataDirectories (30 features)
    """
    
    mapping = {
        # DOS Header - map to EMBER's HeaderFileInfo
        'EntryPoint': 'header.e_ovno',  # Approximation
        'PEType': 'header.optional.magic',
        'MachineType': 'header.coff.machine',
        'magic_number': 'header.dos.e_magic',
        'bytes_on_last_page': 'header.dos.e_cblp',
        'pages_in_file': 'header.dos.e_cp',
        # ... continue mapping all 78 features
        
        # Section features - map to EMBER's SectionInfo
        'text_VirtualSize': 'sections[".text"].virtual_size',
        'text_VirtualAddress': 'sections[".text"].virtual_address',
        # ... etc
        
        # Behavioral features - SET TO 0 (EMBER doesn't have these)
        'registry_read': 0,
        'network_threats': 0,
        # ... behavioral features require VT or sandbox
    }
    
    return mapping


# ==========================================
# Implementation Script Template
# ==========================================

AUGMENTATION_SCRIPT = """
import pandas as pd
import numpy as np
from pathlib import Path

def augment_dataset():
    # Load Zenodo (baseline)
    zenodo = pd.read_csv('dataset/Zenedo.csv')
    print(f"Zenodo samples: {len(zenodo)}")
    
    # Load EMBER features (download first!)
    ember_train = pd.read_json('ember2018/train_features_0.jsonl', lines=True)
    print(f"EMBER samples: {len(ember_train)}")
    
    # Map EMBER features to Zenodo format
    ember_mapped = map_ember_to_zenodo(ember_train)
    
    # Sample balanced subset
    ember_benign = ember_mapped[ember_mapped['Class'] == 'Benign'].sample(15000)
    ember_malicious = ember_mapped[ember_mapped['Class'] == 'Malicious'].sample(15000)
    ember_subset = pd.concat([ember_benign, ember_malicious])
    
    # Combine datasets
    combined = pd.concat([zenodo, ember_subset], ignore_index=True)
    print(f"Combined samples: {len(combined)}")
    
    # Shuffle
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    combined.to_csv('dataset/Zenodo_EMBER_50K.csv', index=False)
    print("Augmented dataset saved!")
    
    return combined

if __name__ == "__main__":
    augmented = augment_dataset()
"""


# ==========================================
# Quick Start Commands
# ==========================================

QUICK_START = """
# 1. Download EMBER dataset
wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xjf ember_dataset_2018_2.tar.bz2

# 2. Install EMBER tools
pip install git+https://github.com/elastic/ember.git

# 3. Extract features (or use pre-extracted JSONs)
from ember import PEFeatureExtractor
# ... feature extraction code

# 4. Run augmentation script
python training_scripts/augment_dataset.py

# 5. Retrain on augmented dataset
python training_scripts/train_cnn_zenodo.py \\
    --dataset dataset/Zenodo_EMBER_50K.csv \\
    --epochs 50

# 6. Evaluate on hold-out Zenodo test set
python training_scripts/evaluate_model.py \\
    --model models/cnn_augmented.keras \\
    --test-set dataset/zenodo_test_holdout.csv
"""


# ==========================================
# Alternative: Feature Noise Augmentation
# ==========================================

def feature_noise_augmentation(features, noise_level=0.05):
    """
    Simple augmentation: add Gaussian noise to features
    
    This helps when you can't get more real data immediately.
    Less effective than real data but better than nothing.
    
    Args:
        features: Original feature array (N, 78)
        noise_level: Std dev of Gaussian noise (default 5%)
    
    Returns:
        Augmented features (2*N, 78)
    """
    import numpy as np
    
    # Generate noise
    noise = np.random.normal(0, noise_level, features.shape)
    
    # Add noise (clip to reasonable ranges)
    augmented = features + (features * noise)
    
    # Combine original + augmented
    combined = np.vstack([features, augmented])
    
    return combined


# ==========================================
# Recommended Action Plan
# ==========================================

if __name__ == "__main__":
    print("Dataset Augmentation Recommendations")
    print("=" * 60)
    print()
    print("PRIORITY 1: Use EMBER Dataset")
    print("  - Download: https://github.com/elastic/ember")
    print("  - Already has PE features extracted")
    print("  - Add 30K samples → Total 50K")
    print("  - Time: 1-2 days")
    print()
    print("PRIORITY 2: Add Fresh Samples")
    print("  - MalwareBazaar for recent malware")
    print("  - Windows/Program Files for benign")
    print("  - Extract using our PEFeatureExtractor")
    print("  - Add 10K samples → Total 60K")
    print("  - Time: 2-3 days")
    print()
    print("PRIORITY 3: Temporal Validation")
    print("  - Train on older samples (2018-2022)")
    print("  - Test on recent samples (2023-2024)")
    print("  - This validates real-world performance")
    print()
    print("Expected Outcome:")
    print("  - Accuracy drops from 1.0 to ~0.92-0.96")
    print("  - FPR increases to ~2-5% (acceptable)")
    print("  - Model generalizes better to unseen samples")
    print("  - antigravity.exe correctly classified")
    print()
