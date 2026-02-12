import sys
import os
import glob
import pandas as pd
import re
from uuid import uuid4

csv_folder = sys.argv[1]
out_folder = sys.argv[2]
os.makedirs(out_folder, exist_ok=True)

sha256_re = re.compile(r"[a-fA-F0-9]{64}")

def normalize_row(df, source_name):
    # ensure canonical columns exist
    for col in ['sample_id','sha256','sha1','md5','filename','file_size','label','source','collection_date','orig_path','obs_time','comment']:
        if col not in df.columns:
            df[col] = pd.NA
    df['source'] = source_name
    # canonicalize sha256
    df['sha256'] = df['sha256'].astype(str).str.strip().str.lower()
    # ensure sample_id
    df['sample_id'] = df['sample_id'].fillna('').replace('', pd.NA)
    missing_id_mask = df['sample_id'].isna()
    df.loc[missing_id_mask, 'sample_id'] = [str(uuid4()) for _ in range(missing_id_mask.sum())]
    # file_size to int where possible
    df['file_size'] = pd.to_numeric(df['file_size'], errors='coerce').astype('Int64')
    return df

def categorize_features(columns):
    """Categorize columns into metadata, static, and dynamic features"""
    metadata_cols = ['sample_id', 'sha256', 'sha1', 'md5', 'filename', 'file_size', 
                     'label', 'source', 'collection_date', 'orig_path', 'obs_time', 'comment']
    
    # Static features (PE headers, imports, sections, strings, etc.)
    static_keywords = ['pe_', 'import', 'export', 'section', 'header', 'string', 
                       'entropy', 'size', 'compile', 'resource', 'certificate']
    
    # Dynamic features (API calls, registry, network, file operations, etc.)
    dynamic_keywords = ['api_', 'registry', 'network', 'file_', 'process', 'mutex',
                        'service', 'dll_', 'behavior', 'runtime', 'executed']
    
    static_cols = []
    dynamic_cols = []
    other_cols = []
    
    for col in columns:
        if col in metadata_cols:
            continue
        col_lower = col.lower()
        if any(kw in col_lower for kw in static_keywords):
            static_cols.append(col)
        elif any(kw in col_lower for kw in dynamic_keywords):
            dynamic_cols.append(col)
        else:
            other_cols.append(col)
    
    return metadata_cols, static_cols, dynamic_cols, other_cols

def merge_duplicate_samples(df):
    """Merge samples with same SHA256 while preserving unique static/dynamic features"""
    metadata_cols = ['sample_id', 'sha256', 'sha1', 'md5', 'filename', 'file_size', 
                     'label', 'source', 'collection_date', 'orig_path', 'obs_time', 'comment']
    
    meta_cols, static_cols, dynamic_cols, other_cols = categorize_features(df.columns)
    
    # Group by SHA256
    grouped = df.groupby('sha256', dropna=False)
    
    merged_rows = []
    for sha, group in grouped:
        if pd.isna(sha) or sha == 'nan':
            # Keep rows without valid SHA256 as-is
            merged_rows.extend(group.to_dict('records'))
            continue
        
        # For duplicates, merge intelligently
        merged = {}
        
        # Metadata: take first non-null value or concatenate sources
        for col in meta_cols:
            if col in group.columns:
                if col == 'source':
                    # Concatenate unique sources
                    sources = group[col].dropna().unique()
                    merged[col] = ';'.join(sources) if len(sources) > 0 else pd.NA
                elif col == 'sample_id':
                    # Keep first sample_id
                    merged[col] = group[col].iloc[0]
                elif col == 'label':
                    # Take most common label
                    merged[col] = group[col].mode()[0] if not group[col].mode().empty else group[col].iloc[0]
                else:
                    # First non-null
                    merged[col] = group[col].dropna().iloc[0] if not group[col].dropna().empty else pd.NA
        
        # Static features: aggregate (should be same for same binary)
        for col in static_cols:
            if col in group.columns:
                non_null = group[col].dropna()
                if len(non_null) > 0:
                    # For numeric: mean, for categorical: mode
                    if pd.api.types.is_numeric_dtype(group[col]):
                        merged[col] = non_null.mean()
                    else:
                        merged[col] = non_null.mode()[0] if not non_null.mode().empty else non_null.iloc[0]
                else:
                    merged[col] = pd.NA
        
        # Dynamic features: aggregate across runs (could vary)
        for col in dynamic_cols:
            if col in group.columns:
                non_null = group[col].dropna()
                if len(non_null) > 0:
                    if pd.api.types.is_numeric_dtype(group[col]):
                        # For counts: sum or max, for ratios: mean
                        if 'count' in col.lower() or 'num' in col.lower():
                            merged[col] = non_null.sum()
                        else:
                            merged[col] = non_null.mean()
                    else:
                        # Concatenate unique values
                        unique_vals = non_null.unique()
                        merged[col] = ';'.join(map(str, unique_vals)) if len(unique_vals) <= 5 else non_null.iloc[0]
                else:
                    merged[col] = pd.NA
        
        # Other columns
        for col in other_cols:
            if col in group.columns:
                non_null = group[col].dropna()
                merged[col] = non_null.iloc[0] if len(non_null) > 0 else pd.NA
        
        merged_rows.append(merged)
    
    return pd.DataFrame(merged_rows)

# Main extraction pipeline
all_data = []

# Process each dataset
csv_files = glob.glob(os.path.join(csv_folder, '**', '*.csv'), recursive=True)

for csv_file in csv_files:
    print(f"Processing: {csv_file}")
    try:
        df = pd.read_csv(csv_file, low_memory=False)
        
        # Determine source name from file path
        source_name = os.path.basename(csv_file).replace('.csv', '')
        
        # Normalize
        df = normalize_row(df, source_name)
        
        all_data.append(df)
        
    except Exception as e:
        print(f"Error processing {csv_file}: {e}")

# Combine all datasets
if all_data:
    combined_df = pd.concat(all_data, ignore_index=True, sort=False)
    
    # Save raw combined data
    combined_df.to_csv(os.path.join(out_folder, 'combined_raw.csv'), index=False)
    print(f"Saved raw combined data: {len(combined_df)} records")
    
    # Merge duplicate SHA256 samples
    unique_df = merge_duplicate_samples(combined_df)
    
    # Save unique samples
    unique_df.to_csv(os.path.join(out_folder, 'unique_samples.csv'), index=False)
    print(f"Saved unique samples: {len(unique_df)} records")
    
    # Generate feature categorization report
    meta_cols, static_cols, dynamic_cols, other_cols = categorize_features(unique_df.columns)
    
    with open(os.path.join(out_folder, 'feature_categories.txt'), 'w') as f:
        f.write(f"STATIC FEATURES ({len(static_cols)}):\n")
        f.write('\n'.join(static_cols) + '\n\n')
        f.write(f"DYNAMIC FEATURES ({len(dynamic_cols)}):\n")
        f.write('\n'.join(dynamic_cols) + '\n\n')
        f.write(f"OTHER FEATURES ({len(other_cols)}):\n")
        f.write('\n'.join(other_cols) + '\n')
    
    print(f"Feature categorization saved")
else:
    print("No data processed")

