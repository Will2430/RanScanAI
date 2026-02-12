"""
Fix Zenodo CSV String Formatting Issues
========================================
Some columns in Zenodo dataset have string formatting like:
- AddressOfEntryPoint: "0x00000000000108EC (Section: .text)"
- Need to extract just the numeric hex value
"""

import pandas as pd
import numpy as np
import re


def parse_hex_field(value):
    """
    Extract hex value from formatted strings
    
    Input: "0x00000000000108EC (Section: .text)" or "0x9FB4"
    Output: numeric value
    """
    if pd.isna(value):
        return 0
    
    if isinstance(value, str):
        # Remove section info in parentheses
        value = value.split('(')[0].strip()
        
        # Convert hex to int
        try:
            return int(value, 16)
        except:
            return 0
    
    # Already numeric
    return int(value) if value else 0


def parse_list_field(value):
    """
    Parse string representations of lists
    
    Input: "['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT']"
    Output: Count of items or encoded value
    """
    if pd.isna(value):
        return 0
    
    if isinstance(value, str):
        # Count items in list-like string
        if value.startswith('[') and value.endswith(']'):
            items = value[1:-1].split(',')
            return len([item.strip() for item in items if item.strip()])
    
    return 0


def clean_zenodo_dataset(csv_path, output_path=None):
    """
    Clean and normalize Zenodo dataset
    
    Args:
        csv_path: Path to Zenodo.csv
        output_path: Optional path to save cleaned CSV
    
    Returns:
        Cleaned DataFrame
    """
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    print(f"Original shape: {df.shape}")
    print(f"Columns: {len(df.columns)}")
    
    # Fix AddressOfEntryPoint format
    if 'AddressOfEntryPoint' in df.columns:
        print("\nFixing AddressOfEntryPoint format...")
        df['AddressOfEntryPoint'] = df['AddressOfEntryPoint'].apply(parse_hex_field)
        print(f"  Sample values: {df['AddressOfEntryPoint'].head(3).tolist()}")
    
    # Fix other potential hex fields
    hex_fields = ['EntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase']
    for field in hex_fields:
        if field in df.columns:
            df[field] = df[field].apply(parse_hex_field)
    
    # Parse list-like fields (DllCharacteristics, Characteristics, etc.)
    list_fields = [col for col in df.columns if 'Characteristics' in col]
    for field in list_fields:
        if field in df.columns and df[field].dtype == 'object':
            print(f"Parsing {field}...")
            df[field] = df[field].apply(parse_list_field)
    
    print(f"\n✓ Cleaned dataset shape: {df.shape}")
    print(f"✓ All columns now numeric: {df.select_dtypes(include=[np.number]).shape[1]}/{df.shape[1]}")
    
    # Save cleaned version
    if output_path:
        df.to_csv(output_path, index=False)
        print(f"\n✓ Saved cleaned dataset to: {output_path}")
    
    return df


def test_parsing():
    """Test parsing functions"""
    
    test_cases = [
        "0x00000000000108EC (Section: .text)",
        "0x9FB4 (Section: AUTO)",
        "0x00001000",
        "['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT']",
    ]
    
    print("Testing parsing functions:\n")
    for test in test_cases:
        if test.startswith('['):
            result = parse_list_field(test)
            print(f"List field: {test[:50]}... → {result}")
        else:
            result = parse_hex_field(test)
            print(f"Hex field: {test:50s} → {result:15d} (0x{result:X})")


if __name__ == "__main__":
    import sys
    
    # Test parsing
    test_parsing()
    
    print("\n" + "="*60)
    print("To clean the full dataset, run:")
    print("  python parse_zenodo_format.py <input_csv> <output_csv>")
    print("\nExample:")
    print("  python parse_zenodo_format.py ../Dataset/Zenedo.csv ../Dataset/Zenedo_cleaned.csv")
    print("="*60)
    
    # If paths provided, clean the dataset
    if len(sys.argv) >= 2:
        input_csv = sys.argv[1]
        output_csv = sys.argv[2] if len(sys.argv) > 2 else input_csv.replace('.csv', '_cleaned.csv')
        
        df = clean_zenodo_dataset(input_csv, output_csv)
