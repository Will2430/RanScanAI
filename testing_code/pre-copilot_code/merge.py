import pandas as pd
import json
import sys
import os

def load_datasets(mlran_folder, zenedo_path):
    """Load all required datasets"""
    print("Loading datasets...")
    
    # Load MLRan datasets
    metadata = pd.read_csv(os.path.join(mlran_folder, 'mlran_dataset_metadata.csv'))
    x_train = pd.read_csv(os.path.join(mlran_folder, 'MLRan_X_train_RFE.csv'))
    
    # Load RFE feature names
    with open(os.path.join(mlran_folder, 'RFE_selected_feature_names_dic.json'), 'r') as f:
        rfe_features = json.load(f)
    
    # Load Zenedo
    zenedo = pd.read_csv(zenedo_path)
    
    print(f"  Metadata: {len(metadata)} records")
    print(f"  X_train: {len(x_train)} records")
    print(f"  Zenedo: {len(zenedo)} records")
    print(f"  RFE features: {len(rfe_features)} features")
    
    return metadata, x_train, zenedo, rfe_features

def prepare_mlran_features(x_train, rfe_features):
    """Rename MLRan features from numeric to descriptive names"""
    print("\nPreparing MLRan features...")
    
    # Create mapping from column index to feature name
    feature_mapping = {}
    for col in x_train.columns:
        if col in ['sample_id', 'sample_type', 'family_label', 'type_label']:
            continue
        if col in rfe_features:
            feature_mapping[col] = rfe_features[col]
    
    # Rename columns
    x_train_renamed = x_train.rename(columns=feature_mapping)
    
    print(f"  Renamed {len(feature_mapping)} features")
    return x_train_renamed

def normalize_hashes(df, hash_cols=['md5', 'sha1', 'sha256']):
    """Normalize hash values for matching"""
    for col in hash_cols:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.lower()
    return df

def merge_on_hashes(metadata, zenedo):
    """Merge datasets using hash values (md5, sha1, sha256)"""
    print("\nMerging datasets on hash values...")
    
    # Normalize hashes
    metadata = normalize_hashes(metadata)
    zenedo = normalize_hashes(zenedo)
    
    # Try merging on different hash types
    merged = None
    merge_key = None
    
    # Priority: sha256 > sha1 > md5
    for hash_col in ['sha256', 'sha1', 'md5']:
        if hash_col in metadata.columns and hash_col in zenedo.columns:
            merged = pd.merge(
                metadata,
                zenedo,
                on=hash_col,
                how='inner',
                suffixes=('_mlran', '_zenedo')
            )
            if len(merged) > 0:
                merge_key = hash_col
                print(f"  Merged on '{hash_col}': {len(merged)} common samples")
                break
    
    if merged is None or len(merged) == 0:
        print("  WARNING: No common samples found between datasets!")
        return None, None
    
    return merged, merge_key

def merge_with_features(merged_metadata, x_train, merge_key):
    """Merge the combined metadata with MLRan features"""
    print("\nMerging with feature data...")
    
    # Merge on sample_id
    final = pd.merge(
        merged_metadata,
        x_train,
        left_on='sample_id',
        right_on='sample_id',
        how='inner',
        suffixes=('', '_xtrain')
    )
    
    print(f"  Final dataset: {len(final)} samples")
    return final

def deduplicate_samples(df, merge_key):
    """Remove duplicate samples, keeping first occurrence"""
    print("\nDeduplicating samples...")
    
    original_count = len(df)
    unique_count = df[merge_key].nunique()
    
    if original_count > unique_count:
        print(f"  Found {original_count - unique_count} duplicate samples")
        # Keep first occurrence of each hash
        df_dedup = df.drop_duplicates(subset=[merge_key], keep='first')
        print(f"  Kept {len(df_dedup)} unique samples")
        return df_dedup
    else:
        print(f"  No duplicates found")
        return df

def handle_duplicate_columns(df):
    """Handle duplicate column names by keeping first occurrence"""
    print("\nHandling duplicate columns...")
    
    # Find duplicates
    duplicate_cols = df.columns[df.columns.duplicated()].unique()
    
    if len(duplicate_cols) > 0:
        print(f"  Found {len(duplicate_cols)} duplicate column names:")
        for col in duplicate_cols:
            print(f"    - {col}")
        
        # Keep first occurrence
        df = df.loc[:, ~df.columns.duplicated()]
        print(f"  Kept first occurrence of each duplicate")
    else:
        print("  No duplicate columns found")
    
    return df

def categorize_merged_features(df):
    """Categorize features from merged dataset"""
    print("\nCategorizing features...")
    
    # Metadata columns
    metadata_cols = ['sample_id', 'sha256', 'sha1', 'md5', 'filename', 'file_size',
                     'label', 'source', 'collection_date', 'sample_type', 
                     'ransomware_family', 'family_label', 'ransomware_type', 'type_label',
                     'Class', 'Category', 'Family', 'file_extension']
    
    # MLRan dynamic features (APIs, Registry, etc.)
    mlran_dynamic = [col for col in df.columns if col.startswith(('API:', 'REG:'))]
    
    # Zenedo static features (PE structure)
    zenedo_static = [col for col in df.columns if col in [
        'EntryPoint', 'PEType', 'MachineType', 'magic_number', 'SizeOfCode',
        'SizeOfInitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase',
        'SectionAlignment', 'FileAlignment', 'SizeOfImage', 'SizeOfHeaders',
        'text_VirtualSize', 'text_SizeOfRawData', 'rdata_VirtualSize'
    ]]
    
    # Zenedo behavioral features
    zenedo_behavioral = [col for col in df.columns if col.startswith((
        'registry_', 'network_', 'processes_', 'files_', 'dlls_', 'apis'
    ))]
    
    # Other features
    other_features = [col for col in df.columns 
                     if col not in metadata_cols 
                     and col not in mlran_dynamic 
                     and col not in zenedo_static 
                     and col not in zenedo_behavioral]
    
    feature_categories = {
        'metadata': metadata_cols,
        'mlran_dynamic': mlran_dynamic,
        'zenedo_static': zenedo_static,
        'zenedo_behavioral': zenedo_behavioral,
        'other': other_features
    }
    
    print(f"  Metadata: {len(metadata_cols)} columns")
    print(f"  MLRan Dynamic: {len(mlran_dynamic)} columns")
    print(f"  Zenedo Static: {len(zenedo_static)} columns")
    print(f"  Zenedo Behavioral: {len(zenedo_behavioral)} columns")
    print(f"  Other: {len(other_features)} columns")
    
    return feature_categories

def validate_merged_dataset(df, merge_key):
    """Validate the merged dataset"""
    print("\n=== VALIDATION ===")
    
    # Check for unique samples
    unique_samples = df[merge_key].nunique()
    total_samples = len(df)
    print(f"1. Unique samples by {merge_key}: {unique_samples}/{total_samples}")
    
    if unique_samples < total_samples:
        print(f"   WARNING: {total_samples - unique_samples} duplicate samples found!")
        duplicates = df[df[merge_key].duplicated(keep=False)]
        print(f"   Duplicate {merge_key} values:")
        print(duplicates[[merge_key, 'sample_id']].head(10))
    
    # Check for missing values
    missing_pct = (df.isnull().sum() / len(df) * 100).sort_values(ascending=False)
    high_missing = missing_pct[missing_pct > 50]
    if len(high_missing) > 0:
        print(f"\n2. Columns with >50% missing values: {len(high_missing)}")
        print(high_missing.head(10))
    else:
        print(f"\n2. No columns with >50% missing values")
    
    # Check label consistency
    if 'family_label' in df.columns and 'Family' in df.columns:
        print(f"\n3. Label columns:")
        print(f"   family_label (MLRan): {df['family_label'].nunique()} unique")
        print(f"   Family (Zenedo): {df['Family'].nunique()} unique")
    
    # Feature count
    feature_cols = [col for col in df.columns if col not in [
        'sample_id', 'sha256', 'sha1', 'md5', 'filename'
    ]]
    print(f"\n4. Total feature columns: {len(feature_cols)}")
    
    return True

def save_merged_dataset(df, feature_categories, output_folder, merge_key):
    """Save merged dataset and metadata"""
    print(f"\nSaving merged dataset to {output_folder}...")
    os.makedirs(output_folder, exist_ok=True)
    
    # Save full merged dataset
    output_path = os.path.join(output_folder, 'merged_mlran_zenedo.csv')
    df.to_csv(output_path, index=False)
    print(f"  Saved: {output_path}")
    
    # Save feature categorization
    cat_path = os.path.join(output_folder, 'merged_feature_categories.txt')
    with open(cat_path, 'w') as f:
        for category, features in feature_categories.items():
            f.write(f"\n{category.upper()} ({len(features)} features):\n")
            f.write('-' * 80 + '\n')
            for feat in sorted(features):
                if feat in df.columns:  # Only write if actually in dataset
                    f.write(f"{feat}\n")
    print(f"  Saved: {cat_path}")
    
    # Save summary statistics
    summary_path = os.path.join(output_folder, 'merge_summary.txt')
    with open(summary_path, 'w') as f:
        f.write("=== MERGE SUMMARY ===\n\n")
        f.write(f"Merge Key: {merge_key}\n")
        f.write(f"Total Samples: {len(df)}\n")
        f.write(f"Unique Samples: {df[merge_key].nunique()}\n")
        f.write(f"Total Features: {len(df.columns)}\n\n")
        
        f.write("Feature Categories:\n")
        for category, features in feature_categories.items():
            actual_count = sum(1 for f in features if f in df.columns)
            f.write(f"  {category}: {actual_count}\n")
        
        f.write(f"\nLabel Distribution:\n")
        if 'Class' in df.columns:
            f.write(df['Class'].value_counts().to_string())
    
    print(f"  Saved: {summary_path}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python merge_datasets.py <mlran_folder> <zenedo_csv> <output_folder>")
        print("Example: python merge_datasets.py Dataset/MLran Dataset/Zenedo.csv output/merged")
        sys.exit(1)
    
    mlran_folder = sys.argv[1]
    zenedo_path = sys.argv[2]
    output_folder = sys.argv[3]
    
    print("="*80)
    print("MLRan + Zenedo Dataset Merger")
    print("="*80)
    
    # Step 1: Load datasets
    metadata, x_train, zenedo, rfe_features = load_datasets(mlran_folder, zenedo_path)
    
    # Step 2: Prepare MLRan features
    x_train_prepared = prepare_mlran_features(x_train, rfe_features)
    
    # Step 3: Merge on hash values
    merged_metadata, merge_key = merge_on_hashes(metadata, zenedo)
    
    if merged_metadata is None:
        print("\nERROR: Could not merge datasets. No common samples found.")
        sys.exit(1)
    
    # Step 4: Merge with features
    final_df = merge_with_features(merged_metadata, x_train_prepared, merge_key)
    
    # Step 5: Deduplicate samples
    final_df = deduplicate_samples(final_df, merge_key)
    
    # Step 6: Handle duplicate columns
    final_df = handle_duplicate_columns(final_df)
    
    # Step 7: Categorize features
    feature_categories = categorize_merged_features(final_df)
    
    # Step 8: Validate
    validate_merged_dataset(final_df, merge_key)
    
    # Step 8: Save
    save_merged_dataset(final_df, feature_categories, output_folder, merge_key)
    
    print("\n" + "="*80)
    print("Merge completed successfully!")
    print("="*80)

if __name__ == "__main__":
    main()