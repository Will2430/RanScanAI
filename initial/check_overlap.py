import pandas as pd

# Load datasets
mlran_metadata = pd.read_csv('Dataset/MLran/mlran_dataset_metadata.csv')
zenedo = pd.read_csv('Dataset/Zenedo.csv')

print("="*80)
print("DATASET OVERLAP ANALYSIS")
print("="*80)

# Normalize hashes
mlran_metadata['sha1'] = mlran_metadata['sha1'].astype(str).str.strip().str.lower()
mlran_metadata['md5'] = mlran_metadata['md5'].astype(str).str.strip().str.lower()
zenedo['sha1'] = zenedo['sha1'].astype(str).str.strip().str.lower()
zenedo['md5'] = zenedo['md5'].astype(str).str.strip().str.lower()

print(f"\nMLRan Metadata: {len(mlran_metadata)} samples")
print(f"  Unique SHA1: {mlran_metadata['sha1'].nunique()}")
print(f"  Unique MD5: {mlran_metadata['md5'].nunique()}")

print(f"\nZenedo: {len(zenedo)} samples")
print(f"  Unique SHA1: {zenedo['sha1'].nunique()}")
print(f"  Unique MD5: {zenedo['md5'].nunique()}")

# Check overlap
mlran_sha1_set = set(mlran_metadata['sha1'].dropna())
zenedo_sha1_set = set(zenedo['sha1'].dropna())
common_sha1 = mlran_sha1_set.intersection(zenedo_sha1_set)

mlran_md5_set = set(mlran_metadata['md5'].dropna())
zenedo_md5_set = set(zenedo['md5'].dropna())
common_md5 = mlran_md5_set.intersection(zenedo_md5_set)

print(f"\n{'='*80}")
print("OVERLAP:")
print(f"  Common SHA1: {len(common_sha1)} samples")
print(f"  Common MD5: {len(common_md5)} samples")
print(f"{'='*80}")

# Show sample hashes from each
print(f"\nSample MLRan SHA1 hashes (first 5):")
print(mlran_metadata['sha1'].head().tolist())

print(f"\nSample Zenedo SHA1 hashes (first 5):")
print(zenedo['sha1'].head().tolist())

# Check if MLRan X_train has more samples
try:
    x_train = pd.read_csv('Dataset/MLran/MLRan_X_train_RFE.csv')
    print(f"\nMLRan X_train: {len(x_train)} samples")
    
    # Check if X_train IDs match metadata
    if 'sample_id' in x_train.columns:
        common_ids = set(mlran_metadata['sample_id']).intersection(set(x_train['sample_id']))
        print(f"  Common IDs with metadata: {len(common_ids)}")
except Exception as e:
    print(f"\nCould not load X_train: {e}")

print(f"\n{'='*80}")
print("CONCLUSION:")
print(f"The datasets have minimal overlap ({len(common_sha1)} samples).")
print(f"This is why the merged dataset is so small.")
print(f"{'='*80}")