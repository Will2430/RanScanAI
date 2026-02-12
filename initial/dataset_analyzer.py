"""
Dataset Analyzer for FYP - File Reputation System
Analyzes all available datasets to help you choose the best one
"""

import pandas as pd
import numpy as np
import os
from pathlib import Path

def analyze_dataset(name, path):
    """Analyze a single dataset and return comprehensive stats"""
    print(f"\n{'='*80}")
    print(f"ANALYZING: {name}")
    print(f"{'='*80}")
    
    try:
        # Try to load the dataset
        df = pd.read_csv(path)
        
        print(f"✓ File loaded successfully")
        print(f"\n📊 BASIC STATS:")
        print(f"   Rows: {len(df):,}")
        print(f"   Columns: {len(df.columns)}")
        print(f"   Memory: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        
        # Try to identify the label column
        potential_labels = ['label', 'class', 'target', 'y', 'malware', 'family', 'category']
        label_col = None
        
        for col in df.columns:
            if any(label in col.lower() for label in potential_labels):
                label_col = col
                break
        
        if label_col is None:
            # Assume last column is the label
            label_col = df.columns[-1]
            print(f"\n⚠️  No obvious label column found. Assuming last column: '{label_col}'")
        else:
            print(f"\n✓ Label column detected: '{label_col}'")
        
        # Class distribution
        print(f"\n🏷️  CLASS DISTRIBUTION:")
        class_counts = df[label_col].value_counts()
        for class_name, count in class_counts.items():
            percentage = (count / len(df)) * 100
            print(f"   {class_name}: {count:,} ({percentage:.1f}%)")
        
        print(f"\n   Total classes: {df[label_col].nunique()}")
        
        # Check balance
        if len(class_counts) == 2:
            ratio = class_counts.iloc[0] / class_counts.iloc[1]
            if ratio > 3 or ratio < 0.33:
                print(f"   ⚠️  IMBALANCED (ratio: {ratio:.2f}:1)")
            else:
                print(f"   ✓ Reasonably balanced (ratio: {ratio:.2f}:1)")
        
        # Feature analysis
        feature_cols = [col for col in df.columns if col != label_col]
        print(f"\n🔢 FEATURES:")
        print(f"   Feature count: {len(feature_cols)}")
        
        numeric_features = df[feature_cols].select_dtypes(include=[np.number]).columns
        categorical_features = df[feature_cols].select_dtypes(exclude=[np.number]).columns
        
        print(f"   Numeric: {len(numeric_features)}")
        print(f"   Categorical: {len(categorical_features)}")
        
        # Missing values
        missing = df.isnull().sum().sum()
        if missing > 0:
            print(f"\n⚠️  MISSING VALUES: {missing:,} ({missing/(len(df)*len(df.columns))*100:.2f}%)")
            cols_with_missing = df.isnull().sum()[df.isnull().sum() > 0]
            print(f"   Affected columns: {len(cols_with_missing)}")
        else:
            print(f"\n✓ No missing values")
        
        # Sample feature names
        print(f"\n📋 SAMPLE FEATURES (first 10):")
        for i, col in enumerate(feature_cols[:10]):
            print(f"   {i+1}. {col}")
        if len(feature_cols) > 10:
            print(f"   ... and {len(feature_cols) - 10} more")
        
        # Quality score
        score = 0
        reasons = []
        
        if len(df) >= 5000:
            score += 3
            reasons.append("Good sample size")
        elif len(df) >= 1000:
            score += 2
            reasons.append("Adequate sample size")
        else:
            score += 1
            reasons.append("Small sample size")
        
        if len(feature_cols) >= 20 and len(feature_cols) <= 200:
            score += 2
            reasons.append("Good feature count")
        elif len(feature_cols) > 200:
            score += 1
            reasons.append("Many features (may need reduction)")
        else:
            score += 1
            reasons.append("Few features")
        
        if missing == 0:
            score += 2
            reasons.append("No missing data")
        elif missing < len(df) * 0.05:
            score += 1
            reasons.append("Minimal missing data")
        
        if df[label_col].nunique() >= 2:
            score += 2
            reasons.append("Has multiple classes")
        
        if len(numeric_features) > 0:
            score += 1
            reasons.append("Has numeric features")
        
        print(f"\n⭐ QUALITY SCORE: {score}/10")
        print(f"   Strengths: {', '.join(reasons)}")
        
        return {
            'name': name,
            'rows': len(df),
            'features': len(feature_cols),
            'classes': df[label_col].nunique(),
            'missing': missing,
            'score': score,
            'suitable': score >= 6
        }
        
    except FileNotFoundError:
        print(f"❌ File not found: {path}")
        return None
    except Exception as e:
        print(f"❌ Error loading dataset: {str(e)}")
        return None

def main():
    print("="*80)
    print("DATASET ANALYZER - FYP File Reputation System")
    print("="*80)
    
    # Define all datasets
    datasets = {
        'Kaggle (Amdjed)': 'Dataset/Kaggle (Amdjed) .csv',
        'MalBehavD-V1': 'Dataset/MalBehavD-V1-dataset.csv',
        'UGRansome': 'Dataset/UGRansome.csv',
        'Zenodo': 'Dataset/Zenedo.csv',
        'MLRan (RFE)': 'Dataset/MLran/MLRan_X_train_RFE.csv',
        'Sensors 2023': 'Dataset/Sensors (2023)/sensors-2047104-supplementary.csv'
    }
    
    results = []
    
    for name, path in datasets.items():
        full_path = os.path.join(r'c:\Users\User\OneDrive\Test\K', path)
        result = analyze_dataset(name, full_path)
        if result:
            results.append(result)
    
    # Summary and recommendations
    print(f"\n\n{'='*80}")
    print("SUMMARY & RECOMMENDATIONS")
    print(f"{'='*80}\n")
    
    if results:
        # Sort by score
        results_sorted = sorted(results, key=lambda x: x['score'], reverse=True)
        
        print("📊 DATASET RANKING:\n")
        print(f"{'Rank':<6} {'Dataset':<25} {'Rows':<12} {'Features':<10} {'Classes':<8} {'Score':<6} {'Suitable?'}")
        print("-" * 80)
        
        for i, r in enumerate(results_sorted, 1):
            suitable = "✓ YES" if r['suitable'] else "✗ NO"
            print(f"{i:<6} {r['name']:<25} {r['rows']:<12,} {r['features']:<10} {r['classes']:<8} {r['score']}/10   {suitable}")
        
        # Top recommendation
        top = results_sorted[0]
        print(f"\n{'='*80}")
        print(f"🎯 RECOMMENDED DATASET: {top['name']}")
        print(f"{'='*80}")
        print(f"\nWhy this dataset:")
        print(f"  • Best quality score: {top['score']}/10")
        print(f"  • {top['rows']:,} samples - {'sufficient' if top['rows'] >= 5000 else 'adequate'} for training")
        print(f"  • {top['features']} features - {'good balance' if 20 <= top['features'] <= 200 else 'manageable'}")
        print(f"  • {top['classes']} classes for classification")
        
        print(f"\n💡 NEXT STEPS:")
        print(f"  1. Use {top['name']} as your primary dataset")
        print(f"  2. Build baseline model with default parameters")
        print(f"  3. Achieve >85% accuracy before considering dataset merging")
        print(f"  4. Only merge datasets if you need MORE variety, not if current results are good")
        
        # Alternative option
        if len(results_sorted) > 1 and results_sorted[1]['suitable']:
            alt = results_sorted[1]
            print(f"\n🔄 ALTERNATIVE: {alt['name']} (score: {alt['score']}/10)")
            print(f"   Consider if you need different features or more samples")
    
    else:
        print("❌ No datasets could be analyzed successfully")
        print("   Check file paths and formats")
    
    print(f"\n{'='*80}\n")

if __name__ == "__main__":
    main()
