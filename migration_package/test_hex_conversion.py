"""
Test hex conversion issue in Zenodo dataset
"""
import pandas as pd
import numpy as np

# Simulate Zenodo CSV values
hex_values = ['0x108ec', '0x25cf9c', '0x2a7e', '0x64ca0', '0x1b9ae']

print("="*70)
print("HEX CONVERSION TEST - The Critical Bug")
print("="*70)

# What the training script CURRENTLY does (WRONG)
factorized = pd.factorize(hex_values)[0]
print("\n[X] CURRENT (WRONG): Using pd.factorize() on hex strings")
print(f"   Input:  {hex_values}")
print(f"   Output: {factorized}")
print(f"   Problem: Just assigns IDs [0,1,2,3,4] - ignores actual values!")

# What it SHOULD do (CORRECT)
converted = [int(v, 16) for v in hex_values]
print("\n[OK] CORRECT: Converting hex strings to integers")
print(f"   Input:  {hex_values}")
print(f"   Output: {converted}")
print(f"   These are the REAL values!")

print("\n" + "="*70)
print("COMPARISON")
print("="*70)
for i, hex_str in enumerate(hex_values):
    wrong = factorized[i]
    correct = converted[i]
    pe_extract = correct  # What your PE extractor produces
    print(f"{hex_str:>10} -> factorize={wrong:>2} | correct={correct:>8,} | PE extractor={pe_extract:>8,}")

print("\n" + "="*70)
print("THE PROBLEM")
print("="*70)
print("* Training: Model learns from factorized IDs [0,1,2,3,4]")
print("* Prediction: PE extractor gives real values [68844, 2478492, 10878, ...]")
print("* Result: COMPLETE DISTRIBUTION MISMATCH = BAD PREDICTIONS!")
print("="*70 + "\n")
