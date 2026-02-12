"""
Compare Feature Quality Across Datasets
Shows which datasets have the best features for malware detection
"""

import pandas as pd

def analyze_feature_types(dataset_name, csv_path, sample_size=100):
    """Analyze what types of features a dataset contains"""
    print(f"\n{'='*80}")
    print(f"DATASET: {dataset_name}")
    print(f"{'='*80}")
    
    try:
        # Load sample
        df = pd.read_csv(csv_path, nrows=sample_size)
        columns = df.columns.tolist()
        
        # Categorize features
        static_pe = []
        api_calls = []
        dynamic_behavior = []
        network_features = []
        other = []
        
        # Known API call patterns
        api_keywords = ['nt', 'ldr', 'rtl', 'reg', 'create', 'open', 'write', 'read', 
                       'get', 'set', 'load', 'unload', 'query', 'enum', 'coinitialize',
                       'oleinitilaize', 'draw', 'show', 'find', 'delete']
        
        # PE header features
        pe_keywords = ['machine', 'debug', 'rva', 'image', 'version', 'export', 
                      'iat', 'linker', 'section', 'stack', 'dll', 'resource',
                      'magic', 'entrypoint', 'petype', 'checksum', 'subsystem',
                      'base', 'alignment', 'virtualsize', 'rawdata', 'characteristics']
        
        # Dynamic behavior features
        dynamic_keywords = ['registry', 'process', 'file', 'network', 'dns', 'http',
                           'malicious', 'suspicious', 'monitored', 'threat', 'api']
        
        # Network features
        network_keywords = ['ip', 'port', 'address', 'netflow', 'tcp', 'udp', 'protocol',
                           'connection', 'dns', 'http', 'btc', 'bitcoin']
        
        for col in columns:
            col_lower = col.lower()
            
            # Skip metadata columns
            if col_lower in ['filename', 'md5', 'sha1', 'sha256', 'hash', 'label', 'class', 
                            'benign', 'category', 'family', 'prediction', 'time']:
                continue
            
            # Check if it's an API call (starts with uppercase or has specific patterns)
            if any(col.startswith(prefix) for prefix in ['Nt', 'Ldr', 'Rtl', 'Reg', 'Co', 'Ole']) \
               or any(kw in col_lower for kw in api_keywords):
                api_calls.append(col)
            # Check for dynamic behavior
            elif any(kw in col_lower for kw in dynamic_keywords):
                dynamic_behavior.append(col)
            # Check for network features
            elif any(kw in col_lower for kw in network_keywords):
                network_features.append(col)
            # Check for PE header features
            elif any(kw in col_lower for kw in pe_keywords):
                static_pe.append(col)
            # Check if it's a number (likely anonymous feature)
            elif col.isdigit():
                other.append(col)
            else:
                other.append(col)
        
        # Display results
        print(f"\n📊 FEATURE BREAKDOWN:")
        print(f"   Total Features: {len(columns)}")
        
        if static_pe:
            print(f"\n   🔧 Static PE Features: {len(static_pe)}")
            print(f"      Quality: ⭐⭐ (Basic - easily obfuscated)")
            print(f"      Examples: {', '.join(static_pe[:5])}")
        
        if api_calls:
            print(f"\n   🎯 API Calls: {len(api_calls)}")
            print(f"      Quality: ⭐⭐⭐⭐⭐ (EXCELLENT - behavioral signatures)")
            print(f"      Examples: {', '.join(api_calls[:5])}")
        
        if dynamic_behavior:
            print(f"\n   🔥 Dynamic Behavior: {len(dynamic_behavior)}")
            print(f"      Quality: ⭐⭐⭐⭐⭐ (EXCELLENT - runtime activity)")
            print(f"      Examples: {', '.join(dynamic_behavior[:5])}")
        
        if network_features:
            print(f"\n   🌐 Network Features: {len(network_features)}")
            print(f"      Quality: ⭐⭐⭐⭐ (GOOD - C2 indicators)")
            print(f"      Examples: {', '.join(network_features[:5])}")
        
        if other:
            print(f"\n   ❓ Other/Anonymous: {len(other)}")
            if all(f.isdigit() for f in other[:10]):
                print(f"      (Appears to be pre-processed/encoded features)")
        
        # Overall score
        score = 0
        reasons = []
        
        if api_calls:
            score += 5
            reasons.append("Has API calls (best for detection)")
        if dynamic_behavior:
            score += 5
            reasons.append("Has dynamic behavior features")
        if network_features:
            score += 3
            reasons.append("Has network indicators")
        if static_pe:
            score += 2
            reasons.append("Has static PE features")
        if len(columns) > 50:
            score += 1
            reasons.append("Rich feature set")
        
        print(f"\n   {'='*76}")
        print(f"   FEATURE QUALITY SCORE: {score}/10")
        if reasons:
            print(f"   Strengths: {', '.join(reasons)}")
        print(f"   {'='*76}")
        
        # Recommendation
        if score >= 8:
            print(f"\n   ✅ RECOMMENDED: Excellent features for FYP")
        elif score >= 5:
            print(f"\n   ⚠️  ACCEPTABLE: Good features but not ideal")
        else:
            print(f"\n   ❌ NOT RECOMMENDED: Limited feature quality")
        
        return score
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return 0

def main():
    print("="*80)
    print("DATASET FEATURE QUALITY ANALYSIS")
    print("="*80)
    print("\nComparing datasets based on feature types and quality...")
    print("Focus: Which features are best for malware detection research?\n")
    
    datasets = {
        'Kaggle (Amdjed)': 'Dataset/Kaggle (Amdjed) .csv',
        'MalBehavD-V1': 'Dataset/MalBehavD-V1-dataset.csv',
        'Zenodo': 'Dataset/Zenedo.csv',
        'UGRansome': 'Dataset/UGRansome.csv',
        'MLRan (RFE)': 'Dataset/MLran/MLRan_X_train_RFE.csv'
    }
    
    scores = {}
    for name, path in datasets.items():
        full_path = f'c:\\Users\\User\\OneDrive\\Test\\K\\{path}'
        score = analyze_feature_types(name, full_path)
        scores[name] = score
    
    # Final recommendation
    print(f"\n\n{'='*80}")
    print("FINAL RECOMMENDATION FOR FYP")
    print(f"{'='*80}\n")
    
    sorted_datasets = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    
    print("Ranking by Feature Quality:\n")
    for i, (name, score) in enumerate(sorted_datasets, 1):
        stars = "⭐" * (score // 2)
        print(f"  {i}. {name:<25} Score: {score}/10  {stars}")
    
    # Best pick
    best = sorted_datasets[0]
    print(f"\n{'='*80}")
    print(f"🏆 BEST DATASET FOR FYP: {best[0]}")
    print(f"{'='*80}")
    
    print(f"\nWhy?")
    if best[0] == 'MalBehavD-V1':
        print("  ✓ API call features - captures actual malware behavior")
        print("  ✓ Used in academic research papers")
        print("  ✓ Harder for malware to evade (must change behavior)")
    elif best[0] == 'Zenodo':
        print("  ✓ Hybrid approach (static + dynamic)")
        print("  ✓ Network behavior indicators")
        print("  ✓ Malware family labels included")
        print("  ✓ Already has dynamic analysis features!")
    
    print(f"\n💡 For your FYP objective #3 (hybrid approach):")
    print(f"   Use {best[0]} - it already has both static AND dynamic features!")
    print(f"   No need to run sandboxes yourself - features already extracted!")
    
    print(f"\n{'='*80}\n")

if __name__ == "__main__":
    main()
