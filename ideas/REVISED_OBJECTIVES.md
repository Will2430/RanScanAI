# Revised FYP Objectives

## Project Title
**Privacy-First Explainable Malware Detection System for SMEs Using Hybrid AI Analysis**

---

## Objective 1: Develop a Privacy-Preserving Malware Detection System Suitable for SMEs

**Original:**
> Develop a detection system using a lightweight AI model to eliminate the need for substantial investment in hardware setup, making it deployable within normal SMEs' technical and budget constraints.

**Revised & Enhanced:**
> Develop a privacy-preserving malware detection system using a lightweight AI model (<5MB) that operates locally without requiring cloud uploads, eliminating the need for substantial investment in hardware while maintaining data confidentiality - making it deployable within normal SMEs' technical, budget, and privacy constraints.

### Implementation Details:
- **Lightweight Model:** 3.2MB Random Forest model
- **Inference Speed:** <100ms per file
- **Hardware Requirements:** Runs on 10-year-old PCs (2GB RAM minimum)
- **Privacy:** Local-first architecture - no automatic uploads
- **Cost:** Free for local scanning, optional VT API (500 free requests/day)
- **Deployment:** Browser extension + localhost backend service

### Success Metrics:
✅ Model size: <5MB
✅ Inference time: <100ms
✅ Accuracy: >99%
✅ False positive rate: <1%
✅ Memory footprint: <500MB
✅ No mandatory cloud dependency

---

## Objective 2: Implement Adaptive Learning Framework with Threat Intelligence Integration

**Original:**
> Design a framework which allows for periodic model retraining and updates to tackle the nuance of evolving ransomware, which has become increasingly adept at bypassing AI detection through obfuscation techniques.

**Revised & Enhanced:**
> Implement an adaptive learning framework that leverages VirusTotal threat intelligence to create a continuous feedback loop, enabling periodic model retraining with validated samples to adapt to evolving malware variants and obfuscation techniques without manual intervention.

### Implementation Details:

#### 1. **Continuous Feedback Loop**
```
Detection → ML Prediction → VT Validation → Mismatch Detection
                                                    ↓
                                              Log to Queue
                                                    ↓
                                         Weekly Batch Retraining
                                                    ↓
                                            Deploy Updated Model
```

#### 2. **Intelligent Sample Collection**
- Automatically logs samples where ML disagrees with VirusTotal consensus
- Stores features, predictions, and VT results in `retraining_queue.csv`
- Queues samples for human review and labeling
- Triggers retraining when threshold met (e.g., 100+ new samples)

#### 3. **Automated Retraining Pipeline**
- **Schedule:** Weekly batch updates (Sunday 2 AM)
- **Process:**
  1. Load original training data (21,752 samples)
  2. Add validated samples from feedback queue
  3. Retrain model with combined dataset
  4. Validate on test set
  5. Deploy if accuracy maintained/improved
  6. Log version and performance metrics

#### 4. **Version Management**
- Track model versions (v1.0, v1.1, v1.2, etc.)
- Maintain accuracy history
- Record samples added per iteration
- Rollback capability if performance degrades

#### 5. **Threat Intelligence Integration**
- Use VT as ground truth for uncertain cases
- Fallback mechanism: VT consensus overrides ML when confidence <80%
- Enrichment: Extract malware family names for user feedback
- Learning: New variants automatically flagged for retraining

### Success Metrics:
✅ Automated mismatch detection working
✅ Retraining pipeline executes successfully
✅ Model accuracy improves or maintains over iterations
✅ Version tracking functional
✅ Demonstrate 3+ retraining cycles with logged improvements

### Expected Outcomes:
- Model adapts to new ransomware variants within 1 week
- Demonstrated improvement from v1.0 (99.33%) to v1.x
- Zero manual intervention required for retraining
- Documented detection of new malware families (e.g., Lockbit 3.0, BlackCat variants)

---

## Objective 3: Construct a Hybrid Explainable Detection Approach

**Original:**
> Utilize both static and dynamic analysis, considering signature-based detection in conjunction with real-time behavior analysis to create a robust detection system.

**Revised & Enhanced:**
> Construct a hybrid explainable detection approach combining static analysis (PE headers), dynamic analysis (behavioral features), and network indicators, integrated with VirusTotal signature-based intelligence to create a transparent, robust detection system that educates users on threat characteristics.

### Implementation Details:

#### 1. **Static Analysis Layer (11% importance)**
**Features Extracted:**
- PE header attributes (Machine type, Subsystem, DllCharacteristics)
- Entry point location
- Section characteristics (.text, .data, .rdata)
- File metadata (size, alignment, checksum)
- Import/Export tables

**Purpose:** Fast initial triage, works on non-executable files

#### 2. **Dynamic Analysis Layer (81% importance)**
**Features Extracted:**
- Registry operations (read/write/delete counts)
- Process creation (malicious/suspicious/monitored)
- File operations (created/modified/deleted files)
- DLL loading patterns
- API call sequences

**Purpose:** Behavioral fingerprinting - harder to evade

**Key Finding:** Dynamic features are 7x more important than static!

#### 3. **Network Indicators (8% importance)**
**Features Extracted:**
- DNS query patterns
- HTTP/HTTPS connections
- Network threat indicators
- C2 communication signatures
- Bitcoin addresses (ransomware payment)

**Purpose:** Detect command-and-control communication

#### 4. **Signature-Based Layer (VirusTotal)**
**Integration:**
- Query VT API for confirmed threats
- Multi-vendor consensus (70+ AV engines)
- Malware family identification
- Threat categorization

**Purpose:** Leverage collective intelligence, identify specific variants

#### 5. **Explainability Component**
**Features:**
- Display top 5 features that triggered detection
- Show percentage contribution of each feature
- Explain what each feature means (e.g., "registry_write: Attempted to modify 47 registry keys - typical ransomware behavior")
- Visual representation of feature importance
- Educational tooltips

**Example Output:**
```
⚠️ Malware Detected (94% confidence)

Top suspicious behaviors:
  🔥 processes_malicious: 5 processes created (36.9% weight)
     → Explanation: Created multiple suspicious child processes
  
  📁 files_malicious: Modified 23 system files (10.7% weight)
     → Explanation: Attempted to encrypt user documents
  
  🔧 registry_total: 87 registry operations (7.0% weight)
     → Explanation: Excessive registry modifications typical of persistence mechanisms
  
  🌐 network_dns: 12 suspicious DNS queries (3.6% weight)
     → Explanation: Connected to known malicious domains
  
  📊 Overall: Dynamic behavior (81%), Network (8%), Static (11%)

VirusTotal: 65/72 engines flagged as WannaCry ransomware
Recommendation: Quarantine and delete immediately
```

### Hybrid Decision Logic:
```python
if ml_confidence > 0.9:
    verdict = ml_prediction
elif ml_confidence > 0.7 and vt_available:
    verdict = vt_consensus  # Use VT as tiebreaker
elif ml_confidence > 0.5:
    verdict = "Suspicious - manual review recommended"
else:
    verdict = "Uncertain - scan with full antivirus"
```

### Success Metrics:
✅ All three feature types (static, dynamic, network) utilized
✅ Feature importance analysis demonstrates dynamic > static
✅ Explainability: Show top features for every detection
✅ VT integration provides family names for 80%+ of threats
✅ User testing shows improved understanding of threats

---

## Additional Objectives (Implicit)

### Objective 4: Cross-Platform Deployment via Browser Extension
- Chrome/Firefox/Edge extension
- Works on Windows, Mac, Linux
- Seamless integration into download workflow
- Right-click context menu for file scanning

### Objective 5: Educational Contribution
- Open-source codebase for learning
- Documentation of feature engineering process
- Empirical analysis of feature importance
- Case studies of malware detection

---

## Summary of Changes

| Aspect | Original | Enhanced |
|--------|----------|----------|
| **Objective 1** | Lightweight for SMEs | + Privacy-preserving, local-first |
| **Objective 2** | Periodic retraining | + Automated feedback loop with VT intelligence |
| **Objective 3** | Static + Dynamic | + Network features + Explainability + VT integration |
| **Scope** | Generic malware | Focused on educational/privacy use cases |
| **Positioning** | Competing with AV | Complementing AV, research contribution |

---

## Deliverables

1. ✅ **Hybrid ML Model**
   - Zenodo-based training (21,752 samples)
   - 99.33% accuracy, 0.19% FPR
   - Static + Dynamic + Network features

2. ✅ **Browser Extension**
   - Chrome/Firefox compatible
   - Right-click scan functionality
   - Results visualization

3. ✅ **Backend Service**
   - FastAPI localhost server
   - Feature extraction
   - ML inference
   - VT integration

4. ✅ **Adaptive Learning System**
   - Feedback collector
   - Automated retraining script
   - Version management
   - Performance tracking

5. ✅ **Documentation**
   - FYP report with empirical findings
   - User guide
   - Developer documentation
   - Feature importance analysis

6. ✅ **Demonstration**
   - Live scanning demo
   - Model evolution dashboard
   - Explainability showcase
   - Performance benchmarks
