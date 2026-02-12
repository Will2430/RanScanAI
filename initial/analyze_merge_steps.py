import pandas as pd

print("="*80)
print("ANALYZING MERGE STEPS")
print("="*80)

# Load datasets
metadata = pd.read_csv('Dataset/MLran/mlran_dataset_metadata.csv')
x_train = pd.read_csv('Dataset/MLran/MLRan_X_train_RFE.csv')
zenedo = pd.read_csv('Dataset/Zenedo.csv')

print(f'\n1. MLRan metadata: {len(metadata)} samples')
print(f'   - Unique sample_ids: {metadata["sample_id"].nunique()}')
print(f'   - Unique sha1: {metadata["sha1"].nunique()}')

print(f'\n2. MLRan X_train: {len(x_train)} samples')
print(f'   - Unique sample_ids: {x_train["sample_id"].nunique()}')

print(f'\n3. Zenedo: {len(zenedo)} samples')
print(f'   - Unique sha1: {zenedo["sha1"].nunique()}')

# Normalize hashes
metadata['sha1'] = metadata['sha1'].astype(str).str.strip().str.lower()
zenedo['sha1'] = zenedo['sha1'].astype(str).str.strip().str.lower()

# Step 1: Merge metadata with zenedo
print(f'\n{"-"*80}')
print("STEP 1: Merge metadata + zenedo on sha1")
print(f'{"-"*80}')

merged_meta_zenedo = pd.merge(
    metadata, 
    zenedo, 
    on='sha1', 
    how='inner', 
    suffixes=('_mlran', '_zenedo')
)

print(f'After merge: {len(merged_meta_zenedo)} samples')
print(f'Unique sha1: {merged_meta_zenedo["sha1"].nunique()}')
print(f'Unique sample_ids: {merged_meta_zenedo["sample_id"].nunique()}')

# Check duplicates
sha1_counts = merged_meta_zenedo['sha1'].value_counts()
duplicated_sha1 = sha1_counts[sha1_counts > 1]
print(f'\nDuplicated sha1 hashes: {len(duplicated_sha1)}')
if len(duplicated_sha1) > 0:
    print(f'Total duplicate rows: {(sha1_counts - 1).sum()}')
    print(f'Example duplicates:')
    print(duplicated_sha1.head())

# Step 2: Merge with x_train
print(f'\n{"-"*80}')
print("STEP 2: Merge with x_train on sample_id")
print(f'{"-"*80}')

# Check overlap first
common_ids = set(merged_meta_zenedo['sample_id']).intersection(set(x_train['sample_id']))
print(f'\nCommon sample_ids: {len(common_ids)}')
print(f'In merged but not in x_train: {len(set(merged_meta_zenedo["sample_id"]) - set(x_train["sample_id"]))}')

final = pd.merge(
    merged_meta_zenedo, 
    x_train, 
    on='sample_id', 
    how='inner'
)

print(f'\nAfter merge: {len(final)} samples')
print(f'Unique sha1: {final["sha1"].nunique()}')
print(f'Unique sample_ids: {final["sample_id"].nunique()}')

# Step 3: After deduplication
print(f'\n{"-"*80}')
print("STEP 3: After deduplication by sha1")
print(f'{"-"*80}')

final_dedup = final.drop_duplicates(subset=['sha1'], keep='first')
print(f'After dedup: {len(final_dedup)} samples')
print(f'Unique sha1: {final_dedup["sha1"].nunique()}')

print(f'\n{"="*80}')
print("SUMMARY OF SAMPLE LOSS:")
print(f'{"="*80}')
print(f'Start (overlap sha1):              101 samples')
print(f'After metadata+zenedo merge:       {len(merged_meta_zenedo)} samples (includes duplicates)')
print(f'After x_train merge:               {len(final)} samples')
print(f'After deduplication:               {len(final_dedup)} samples')
print(f'\nLoss from x_train not having data: {len(merged_meta_zenedo)} -> {len(final)} = {len(merged_meta_zenedo) - len(final)} samples lost')
print(f'Loss from deduplication:           {len(final)} -> {len(final_dedup)} = {len(final) - len(final_dedup)} duplicates removed')
