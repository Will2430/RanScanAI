"""
Check value ranges in Zenodo training data to understand what the model expects
"""

import pandas as pd
import numpy as np

print("\nLoading Zenodo dataset...")
df = pd.read_csv("C:/Users/User/OneDrive/Test/K/Dataset/Zenedo.csv")

print(f"Dataset shape: {df.shape}\n")

# Focus on fields that might have large values
size_fields = [
    'SizeOfCode', 'SizeOfInitializedData', 'SizeOfImage', 
    'Checksum', 'SizeofStackReserve', 'SizeofHeapReserve',
    'ImageBase'
]

print("="*80)
print("VALUE RANGES IN TRAINING DATA (what model expects)")
print("="*80)

for field in size_fields:
    if field in df.columns:
        col_data = df[field]
        
        # Handle string hex format
        if col_data.dtype == 'object':
            # Try to parse as hex
            try:
                col_data = col_data.apply(lambda x: int(str(x).split('(')[0].strip(), 16) if pd.notna(x) and str(x).startswith('0x') else 0)
            except:
                continue
        
        col_data = pd.to_numeric(col_data, errors='coerce').fillna(0)
        
        print(f"\n{field}:")
        print(f"  Min:        {col_data.min():>20,.0f}")
        print(f"  Max:        {col_data.max():>20,.0f}")
        print(f"  Mean:       {col_data.mean():>20,.0f}")
        print(f"  Median:     {col_data.median():>20,.0f}")
        print(f"  95th %ile:  {col_data.quantile(0.95):>20,.0f}")
        print(f"  99th %ile:  {col_data.quantile(0.99):>20,.0f}")

# Check characteristics fields
char_fields = [col for col in df.columns if 'Characteristics' in col or 'DllCharacteristics' in col]

print(f"\n{'='*80}")
print("CHARACTERISTICS FIELDS (should be lists or small numbers)")
print("="*80)

for field in char_fields[:3]:  # Show first 3
    if field in df.columns:
        print(f"\n{field}:")
        print(f"  Sample values:")
        for i, val in enumerate(df[field].head(5)):
            print(f"    {i+1}. {val}")

print("\n")
