# Behavioral Analysis Integration Guide

## Architecture Overview

The SecureGuard malware detection system uses a **hybrid approach** combining:
1. **Static PE analysis** - File headers, sections, imports (fast, always available)
2. **Behavioral analysis** - Runtime monitoring in sandbox (high accuracy, requires execution)
3. **ML model prediction** - CNN trained on Zenodo dataset with both static + behavioral features

---

## Production vs Demo Architecture

### **DEMO/TESTING MODE** (Current Implementation)
```
┌─────────────────┐
│   User's VM     │
│  (Safe Testing) │
└────────┬────────┘
         │ 1. Run ransomware simulator in VM
         ▼
  vm_behavioral_monitor.py
         │ Captures runtime behavior
         ▼
  behavioral_data.json
         │ 2. Copy JSON to host machine
         ▼
┌────────────────────┐
│   Model Service    │
│  /predict/staged   │
│  (Port 8001)       │
└────────┬───────────┘
         │ 3. Upload file + behavioral JSON
         ▼
    ML Prediction
  (Static + Behavioral)
```

**Demo Workflow:**
```bash
# Step 1: Run in VM (or locally for testing)
python vm_behavioral_monitor.py malware.exe C:/Test_Folder

# Step 2: Get behavioral_data.json output

# Step 3: Send to model service
curl -X POST http://localhost:8001/predict/staged \
  -F "file=@malware.exe" \
  -F "behavioral_data=@behavioral_data.json"
```

---

### **PRODUCTION MODE** (Recommended Deployment)

```
┌──────────────┐       ┌───────────────────┐       ┌─────────────┐
│ Web Frontend │──1──▶ │   Model Service   │──2──▶ │  Sandboxing │
│ (React/Vue)  │       │   (FastAPI)       │       │  Service    │
└──────────────┘       └─────────┬─────────┘       └──────┬──────┘
                                 │                         │
                                 │ 4. Merge features       │ 3. Execute
                                 │    & predict            │    in VM
                                 ▼                         ▼
                         ┌──────────────┐          ┌──────────────┐
                         │   CNN Model  │          │  Isolated VM │
                         │   (TF/Keras) │          │  (KVM/Docker)│
                         └──────────────┘          └──────────────┘
```

**Production Components:**

1. **Model Service** (This service - `model_service.py`)
   - Receives file uploads
   - Extracts static PE features
   - Calls sandboxing service API
   - Merges behavioral + static features
   - Runs CNN prediction

2. **Sandboxing Service** (To be implemented)
   - Endpoint: `POST /sandbox/analyze`
   - Receives: Executable file
   - Returns: `behavioral_data.json`
   - Technologies:
     - **Cuckoo Sandbox** (open-source, Python, VirtualBox/KVM backend)
     - **CAPE Sandbox** (Cuckoo fork, better malware config extraction)
     - **VirtualBox API** (custom VM orchestration, full control)
     - **KVM + QEMU** (Linux-based, better performance than VirtualBox)
     - **Hyper-V API** (Windows Server, native integration)
   - **NOT Docker containers** - Requires actual VMs for kernel isolation!

3. **Production Sandboxing Service Implementation:**

**⚠️ CRITICAL: Docker Containers Alone Are NOT Safe for Malware Analysis!**

**Why Docker is Insufficient:**
```
❌ Docker containers share the host kernel
   → Malware can exploit kernel vulnerabilities to escape
   
❌ Windows malware needs Windows environment
   → Linux containers can't execute .exe files properly
   
❌ Container breakouts are well-documented
   → Malware authors know how to escape Docker

✅ SOLUTION: Use actual Virtual Machines (hardware isolation)
   → Hypervisors: KVM, VirtualBox, Hyper-V, VMware
   → Each malware sample runs in disposable VM
   → VM snapshots allow instant revert to clean state
```

**Docker's Role in Production:**
- ✅ **Orchestration layer** - Manages VM lifecycle, not malware execution
- ✅ **API gateway** - Receives requests, queues VM jobs
- ✅ **Result processing** - Parses behavioral_data.json from VMs
- ❌ **NOT for malware execution** - Too risky!

**Realistic Production Architecture:**

```python
# sandboxing_service.py (VM orchestration, not execution)
from fastapi import FastAPI, UploadFile, BackgroundTasks
from typing import Dict
import subprocess
import json
import uuid

app = FastAPI()

# VM pool management
AVAILABLE_VMS = ["sandbox-vm-1", "sandbox-vm-2", "sandbox-vm-3"]
ANALYSIS_QUEUE = {}  # {job_id: {"status": "running", "vm": "sandbox-vm-1"}}

@app.post("/sandbox/analyze")
async def analyze_file(file: UploadFile, background_tasks: BackgroundTasks):
    """
    Queue malware analysis in actual VM (not container!)
    Uses VirtualBox/KVM/Hyper-V for proper isolation
    """
    job_id = str(uuid.uuid4())
    
    # Save file
    file_path = f"/tmp/{job_id}.exe"
    with open(file_path, "wb") as f:
        f.write(await file.read())
    
    # Queue VM analysis (non-blocking)
    background_tasks.add_task(run_vm_analysis, job_id, file_path)
    
    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Analysis will complete in ~60 seconds"
    }

def run_vm_analysis(job_id: str, malware_path: str):
    """
    Execute in REAL VM using VirtualBox API
    NOT in Docker container!
    """
    vm_name = get_available_vm()  # Get VM from pool
    
    try:
        # 1. Revert VM to clean snapshot
        subprocess.run([
            "VBoxManage", "snapshot", vm_name, "restore", "clean_state"
        ], check=True)
        
        # 2. Start VM
        subprocess.run([
            "VBoxManage", "startvm", vm_name, "--type", "headless"
        ], check=True)
        
        # 3. Copy malware to VM
        subprocess.run([
            "VBoxManage", "guestcontrol", vm_name, "copyto",
            malware_path, "C:\\malware\\sample.exe",
            "--username", "sandbox", "--password", "sandbox123"
        ], check=True)
        
        # 4. Execute vm_behavioral_monitor.py in VM
        subprocess.run([
            "VBoxManage", "guestcontrol", vm_name, "run",
            "--exe", "C:\\Python310\\python.exe",
            "--username", "sandbox", "--password", "sandbox123",
            "--", "C:\\monitor\\vm_behavioral_monitor.py",
            "C:\\malware\\sample.exe"
        ], timeout=60)
        
        # 5. Retrieve behavioral_data.json from VM
        subprocess.run([
            "VBoxManage", "guestcontrol", vm_name, "copyfrom",
            "C:\\behavioral_data.json", f"/results/{job_id}.json",
            "--username", "sandbox", "--password", "sandbox123"
        ], check=True)
        
        # 6. Power off VM
        subprocess.run([
            "VBoxManage", "controlvm", vm_name, "poweroff"
        ])
        
        # Mark job complete
        ANALYSIS_QUEUE[job_id]["status"] = "complete"
        
    except Exception as e:
        ANALYSIS_QUEUE[job_id]["status"] = "failed"
        ANALYSIS_QUEUE[job_id]["error"] = str(e)
    
    finally:
        release_vm(vm_name)  # Return VM to pool

@app.get("/sandbox/results/{job_id}")
async def get_results(job_id: str):
    """Retrieve analysis results"""
    if job_id not in ANALYSIS_QUEUE:
        raise HTTPException(404, "Job not found")
    
    job = ANALYSIS_QUEUE[job_id]
    if job["status"] != "complete":
        return {"status": job["status"]}
    
    # Load behavioral data
    with open(f"/results/{job_id}.json") as f:
        return json.load(f)
```

**Real-World Production Solutions:**

| Solution | Isolation | Complexity | Cost | Best For |
|----------|-----------|------------|------|----------|
| **Cuckoo Sandbox** | VirtualBox/KVM VMs | Medium | Free | Small-medium orgs |
| **CAPE Sandbox** | KVM VMs | Medium-High | Free | Advanced malware analysis |
| **VMRay** | Custom hypervisor | Low (SaaS) | $$$ | Enterprise, no infra |
| **Joe Sandbox** | VMs + cloud | Low (SaaS) | $$$ | Quick deployment |
| **Custom VirtualBox** | VMs | High | Free | Full control, custom needs |

**Recommended Approach for Your FYP:**

**Demo/Presentation:**
```
✅ Use vm_behavioral_monitor.py locally (show it works)
✅ Upload pre-captured behavioral_data.json to model service
✅ Explain: "This simulates what a sandboxing service would provide"
```

**Architecture Slides:**
```
✅ Diagram showing VM-based sandboxing (not Docker)
✅ Explain kernel-level isolation requirements
✅ Reference Cuckoo/CAPE as production alternatives
✅ Show cost comparison: VMs vs VT Premium API
```

**What You DON'T Need to Build:**
```
❌ Actual VM orchestration (too complex for FYP scope)
❌ Docker-based malware execution (unsafe, won't work)
❌ Full Cuckoo deployment (overkill)

✅ What you HAVE: Working behavioral monitor script
✅ What you SHOW: Integration architecture diagram
✅ What you SAY: "Production would use Cuckoo/VMs, 
                  demo uses pre-captured data"
```

---

## API Usage

### Endpoint: `POST /predict/staged`

**Demo Mode** (with pre-captured behavioral data):
```bash
curl -X POST "http://localhost:8001/predict/staged" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@suspicious.exe" \
  -F "behavioral_data={\"files\":{\"encrypted\":[...],\"deleted\":[...]},\"registry\":{\"write\":15},...}"
```

**Production Mode** (service calls sandboxing service automatically):
```bash
curl -X POST "http://localhost:8001/predict/staged" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@suspicious.exe"
# No behavioral_data needed - service calls sandbox API internally
```

**Response:**
```json
{
  "is_malicious": true,
  "confidence": 0.94,
  "prediction_label": "MALICIOUS",
  "raw_score": 0.94,
  "detection_method": "pe_vm_local_enriched",
  "scan_time_ms": 1247.5,
  "pe_features_extracted": true,
  "behavioral_enriched": true,
  "behavioral_source": "vm_local",  // or "sandbox_service" in production
  "suspicious_indicators": "high_entropy (7.45)"
}
```

---

## Why VMs Instead of Docker?

### Security Comparison

| Feature | Docker Container | Virtual Machine |
|---------|------------------|-----------------|
| **Kernel** | Shared with host ⚠️ | Isolated (separate kernel) ✓ |
| **Escape Risk** | HIGH - well-known exploits | LOW - hardware isolation |
| **Windows Malware** | Can't run (Linux kernel) | Native Windows execution ✓ |
| **Performance** | Fast (native) | Slower (virtualized) |
| **Setup** | Easy (docker run) | Complex (hypervisor config) |
| **Snapshotting** | Limited | Full state revert ✓ |
| **Production Ready** | ❌ For malware analysis | ✓ Industry standard |

### Real Malware Analysis Tools Use VMs:
- **Cuckoo Sandbox**: VirtualBox or KVM
- **CAPE**: KVM with custom agent
- **Joe Sandbox**: Custom hypervisor
- **Any.Run**: Cloud VMs
- **VirusTotal**: Multiple VM backends

### Docker CAN Be Used For:
- ✅ **Orchestration layer** - Managing VM lifecycle
- ✅ **API gateway** - Receiving upload requests
- ✅ **Result processing** - Parsing JSON outputs
- ✅ **Queue management** - RabbitMQ/Redis containers
- ❌ **NOT malware execution** - Use VMs!

---

## What You Need to Demo for FYP

### ✅ What You Already Have (Sufficient for Demonstration):

1. **Working Behavioral Monitor**
   - `vm_behavioral_monitor.py` captures runtime behavior
   - Tested locally with ransomware simulator
   - Outputs valid `behavioral_data.json`

2. **Model Service Integration**
   - `/predict/staged` endpoint accepts behavioral data
   - Feature fusion pipeline works (PE + behavioral)
   - ML prediction uses enriched features

3. **End-to-End Proof**
   - Demo: Upload file + behavioral JSON → Get prediction
   - Show feature comparison (PE-only vs enriched)
   - Prove behavioral data improves detection

### 📋 What to Present:

**Slide 1: Architecture Diagram**
```
User uploads file → Model Service → [VM Sandbox Service] → Behavioral data
                         ↓
                    Feature fusion
                         ↓
                    CNN prediction
```
*Note: VM Sandbox Service shown as architecture, not implemented*

**Slide 2: Demo Workflow**
```
1. Run vm_behavioral_monitor.py (show captures encryption)
2. Upload file + JSON to /predict/staged
3. Show prediction: "Files encrypted: 6 → 94% malicious"
4. Compare to PE-only: "No behavioral data → 54% confidence"
```

**Slide 3: Production Deployment**
```
"In production, vm_behavioral_monitor.py would run as:
 - Cuckoo Sandbox plugin (VirtualBox/KVM VMs)
 - API returns behavioral_data.json automatically
 - Current demo uses pre-captured data to show pipeline"
```

**Slide 4: Why VMs Not Docker**
```
Docker containers:
  ❌ Share host kernel (escape risk)
  ❌ Can't run Windows malware on Linux host
  ✅ Good for orchestration, not execution

Production uses VMs:
  ✓ Hardware isolation
  ✓ Snapshot/restore capability
  ✓ Industry standard (Cuckoo, CAPE)
```

### ❌ What You DON'T Need to Build:

- ❌ Actual VM orchestration system
- ❌ Docker-based malware execution
- ❌ Full Cuckoo deployment
- ❌ Hypervisor integration

### 💡 What to Say When Asked:

**Q: "Why didn't you implement the sandboxing service?"**
> "I focused on the ML model and feature fusion pipeline, which are the novel contributions. For behavioral data, I created a monitoring script that simulates what production sandboxing services like Cuckoo provide. This allowed me to validate the hybrid detection approach without the infrastructure complexity of VM orchestration."

**Q: "Could this work in production?"**
> "Yes, the architecture is designed for production. The model service would call Cuckoo Sandbox's API instead of accepting pre-captured JSON. Cuckoo handles VM management, malware execution, and behavioral reporting. The integration would be a simple REST API call."

**Q: "Why not use Docker for sandboxing?"**
> "Docker containers share the host kernel, making them unsafe for malware analysis. Production malware sandboxes use actual VMs with hardware isolation - VirtualBox, KVM, or Hyper-V. This prevents malware from escaping to the host system."

---

| Feature Source | Demo (vm_behavioral_monitor.py) | Production (Sandboxing Service) |
|----------------|----------------------------------|----------------------------------|
| **Deployment** | Manual script run in VM | Automated microservice |
| **Scalability** | 1 file at a time | Parallel analysis (Docker Swarm/K8s) |
| **Isolation** | Local VM (manual setup) | Container orchestration |
| **API Integration** | Upload pre-captured JSON | REST API call |
| **Cost** | Free (local resources) | Infrastructure costs (VMs/containers) |
| **Best For** | Testing, demos, research | Production, high-volume scanning |

---

## Migration Path: Demo → Production

### Phase 1: Current (Demo)
- ✅ `vm_behavioral_monitor.py` script
- ✅ Manual VM execution
- ✅ Pre-captured behavioral JSON
- ✅ Model service accepts optional `behavioral_data`

### Phase 2: Service Integration
- 🔄 Deploy `vm_behavioral_monitor.py` as Docker container
- 🔄 Create sandboxing service API wrapper
- 🔄 Model service calls sandbox API instead of VT
- 🔄 Queue system for analysis requests (RabbitMQ/Redis)

### Phase 3: Production Scaling
- ⏳ Container orchestration (Kubernetes)
- ⏳ Auto-scaling based on queue length
- ⏳ Distributed storage for analysis results (S3/MinIO)
- ⏳ Monitoring & alerting (Prometheus/Grafana)

---

## Fallback Strategy

The model service uses a **tiered approach** for behavioral enrichment:

1. **Primary:** VM behavioral data (highest accuracy)
   - If `behavioral_data` provided → use it
   
2. **Secondary:** Sandboxing service (production)
   - If no data provided AND production mode → call sandbox API
   
3. **Tertiary:** VirusTotal API (fallback)
   - If sandbox unavailable → call VT API
   - Free tier: heuristic estimation from detection ratio
   - Paid tier: actual behavioral features from VT sandbox

4. **Fallback:** PE static only
   - If all enrichment fails → use PE features alone

---

## Presentation Talking Points

When presenting this to your examiners/stakeholders:

### **1. Demonstrate Local Testing:**
> "For development and testing, I created `vm_behavioral_monitor.py` which captures runtime behavior locally. This allows me to validate the behavioral enrichment pipeline without infrastructure costs."

### **2. Explain Production Architecture:**
> "In a production environment, this would be deployed as a separate sandboxing microservice using container orchestration. The model service would call this API automatically, eliminating manual steps."

### **3. Highlight Scalability:**
> "The current demo uses local VMs, but the architecture is designed to scale horizontally. We could deploy this on Kubernetes with auto-scaling based on analysis queue length."

### **4. Show Cost-Benefit Analysis:**
> "VirusTotal Premium API costs $$$ per request. By running our own sandboxing service, we reduce costs while increasing control over the analysis environment."

### **5. Security Considerations:**
> "Production deployment would use network-isolated containers, resource limits, and timeout mechanisms to prevent malware from escaping or consuming excessive resources."

---

## Code Organization

```
migration_package/
├── model_service.py                    # Main FastAPI service (you're here)
│   └── /predict/staged                 # Accepts optional behavioral_data
├── model_code/
│   ├── pe_feature_extractor.py         # Extracts static PE features
│   └── vt_integration.py               # VirusTotal API (fallback)
├── Training Code/
│   ├── vm_behavioral_monitor.py        # VM monitoring script (demo)
│   └── host_analyze_vm_data.py         # Converts VM data to VT format
└── BEHAVIORAL_INTEGRATION_GUIDE.md     # This file
```

**Production would add:**
```
sandboxing_service/                     # New microservice
├── api/
│   └── sandbox_api.py                  # FastAPI endpoint
├── docker/
│   ├── Dockerfile                      # Sandbox container image
│   └── docker-compose.yml              # Local testing
├── monitoring/
│   ├── vm_behavioral_monitor.py        # From Testing_Code (reused)
│   └── result_collector.py             # Gather JSON outputs
└── k8s/
    ├── deployment.yaml                 # Kubernetes deployment
    └── service.yaml                     # Load balancer
```

---

## Quick Start

### Demo Testing (Current):
```bash
# Terminal 1: Start model service
cd migration_package
python model_service.py

# Terminal 2: Run behavioral monitor (in VM or locally)
cd Testing_Code
python vm_behavioral_monitor.py ransomware_simulator.py C:/Test_Folder

# Terminal 3: Test prediction with behavioral data
curl -X POST http://localhost:8001/predict/staged \
  -F "file=@dist/RansomwareSimulator.exe" \
  -F "behavioral_data=$(cat behavioral_data.json)"
```

### Production Testing (Future):
```bash
# Just upload the file - service handles the rest
curl -X POST http://localhost:8001/predict/staged \
  -F "file=@suspicious.exe"
```

---

## Further Reading

**Malware Sandboxing (VM-based):**
- **Cuckoo Sandbox Documentation**: https://cuckoosandbox.org/
- **CAPE Sandbox**: https://github.com/kevoreilly/CAPEv2
- **VirtualBox Python API**: https://www.virtualbox.org/sdkref/
- **Malware Analysis with VMs**: https://www.sans.org/white-papers/malware-analysis/

**Why Docker is Unsafe for Malware:**
- **Docker Breakout Techniques**: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
- **Container Security**: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- **Kernel Exploits in Containers**: https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=docker+escape

**Production Malware Analysis:**
- **Any.Run (Cloud Sandbox)**: https://any.run/
- **Hybrid Analysis**: https://www.hybrid-analysis.com/
- **Joe Sandbox**: https://www.joesandbox.com/

**VM Orchestration:**
- **Libvirt (KVM Management)**: https://libvirt.org/
- **Vagrant (VM Automation)**: https://www.vagrantup.com/
- **Packer (VM Image Building)**: https://www.packer.io/

---

**Last Updated:** February 9, 2026  
**Author:** SecureGuard Development Team  
**Status:** Demo mode operational, Production architecture designed

---

## TL;DR: Docker vs VMs for Malware Sandboxing

### ❌ NO - You Can't Just "Spin Up a Docker Container"

**Why Docker Fails:**
```bash
# This is UNSAFE and WON'T work properly:
docker run malware-sandbox:latest malware.exe
```

**Problems:**
1. ⚠️ **Shared kernel** - Malware can exploit kernel bugs to escape to host
2. ⚠️ **Wrong OS** - Windows .exe won't run on Linux container kernel
3. ⚠️ **Known exploits** - Docker breakouts are well-documented
4. ⚠️ **No snapshots** - Can't revert to clean state easily

### ✅ YES - Use Actual Virtual Machines

**Production Approach:**
```python
# VirtualBox API (proper isolation)
import virtualbox

vbox = virtualbox.VirtualBox()
vm = vbox.find_machine("malware-sandbox-1")
vm.launch_vm_process(session, "headless", [])
# Malware runs in ACTUAL Windows VM with separate kernel
```

**For Your FYP:**
- ✅ **Demo**: Show `vm_behavioral_monitor.py` works
- ✅ **Present**: Explain production would use Cuckoo/VMs
- ✅ **Don't build**: Full VM orchestration (out of scope)
- ✅ **Focus on**: ML model + feature fusion (your contribution)

**Key Message for Presentation:**
> "I built the behavioral monitoring script and ML integration pipeline. Production deployment would use Cuckoo Sandbox for VM management - a proven, industry-standard solution. This allowed me to focus on the novel contribution: combining static PE analysis with behavioral features for improved ransomware detection."
