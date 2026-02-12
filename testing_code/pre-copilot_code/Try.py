import json
import math 
from collections import Counter, defaultdict
from pprint import pprint


def load_report(path):
    with open(path, "r") as f:
        return json.load(f)
    
report = load_report(r"C:\Users\willi\Downloads\K\M_WannaCry_588cc3d662585f277904ee6afb5aa73143119ac663531ea4b6301eaccd9e4117.exe.json")

def extract_static_features(report):
    features = defaultdict(int)

    info = report.get("info",{})
    features['platform'] = info.get("platform","")
    features['duration'] = info.get("duration",0)


    static = report.get("static",{}).get("pe_sections",{})
    features["num_sections"] = len(static)


    for section in static:
        name = section.get("name","").lower()
        size = section.get("size_of_data",0)
        entropy = section.get("entropy",0)

        features[f"{name}_size"] = size 
        features[f"{name}_entropy"] = entropy
        if entropy >7.5:
            features['High_entropy_section'] += 1

   
    target_file = report.get("target", {}).get("file", {})
    features["hashes"] = {
        "name": target_file.get("name", ""),
        "md5": target_file.get("md5", ""),
        "sha1": target_file.get("sha1", ""),
        "sha256": target_file.get("sha256", "")
    }

    imports = report.get("static", {}).get("pe_imports", [])
    for imp in imports:
        dll = imp.get("dll","").lower()
        features[f"imports_dll_{dll}"] += 1

        for func in imp.get("imports",[]):
            funcname = func.get("name",[])
            features[f"import_func_{funcname}"] += 1
        
    features["num_total_imports"] = sum(v for k,v in features.items() if k.startswith("import_func_"))
    features["num_dlls"] = len(imports)
    
    return dict(features)

extract_static_features(report)

def extract_dynamic_features(report):
    features = defaultdict(int)

    unique_files = set()
    unique_dirs = set()

    # Memory region
    for proc in report.get("procmemory",[]):
        for region in proc.get("regions",[]):
            prot = region.get("protect","")
            features[f"mem_prot_{prot}"] += 1
            features["total_mem_regions"] += 1
            
    # API calls
    behavior = report.get("behavior",{}).get("processes",[])
    for proc in behavior:
        for call in proc.get("calls", []):
            apiname = call.get("api","").lower()
            features[f"api_{apiname}"] += 1
            features["total_api_calls"] += 1

    # Registry ops
    for proc in behavior:
        for call in proc.get("calls",[]):
            if "reg" in call.get("api","").lower():
                features["registry_ops"] += 1

    # Registry key categories 
    for proc in behavior:
        for call in proc.get("calls",[]):
            api = call.get("api","").lower()
            arg = call.get("arguments",{})

            if "reg" in api or "regkey" in arg:
                regkey = arg.get("regkey")
                if regkey:
                    key = regkey.lower()
                    if "run" in key or "runonce" in key:
                        features["registry_persistence"] += 1
                    if "shadow" in key or "vss" in key:
                        features["registry_shadowcopy"] += 1
                    if "disable" in key:
                        features["registry_disable_security"] += 1
                    
    # File system 
    for proc in behavior:
        for call in proc.get("calls",[]):
            api = call.get("api","").lower()
            if "createfile" in api: features["file_create"] += 1
            if "writefile" in api: features["file_write"] += 1
            if "delete" in api: features["file_delete"] += 1
            if "rename" in api or "move" in api: features["file_rename"] += 1 
            
            arg = call.get("arguments",{})
            if "filepath" in arg:
                path = arg["filepath"].lower()
                unique_files.add(path )
                unique_dirs.add("/".join(path.split("\\")[:-1]))

            # Crypt not in APIs
            if "crypt" in api:
                features["crypto_calls"] += 1

    features["unique_files"] = len(unique_files)
    features["unique_dirs"] = len(unique_dirs)

    # Network Activity

    network = report.get("network", {})

    dns = network.get("dns", [])
    http = network.get("http", [])
    tcp = network.get("tcp", [])
    udp = network.get("udp", [])

    features["dns_requests"] = len(dns)
    features["unique_domains"] = len(set([d.get("request") for d in dns]))
    features["http_requests"] = len(http)
    features["tcp_connections"] = len(tcp)
    features["udp_connections"] = len(udp)

    # Suspicious TLDs
    suspicious_tlds = [".onion", ".xyz", ".top"]
    for d in dns:
        req = d.get("request", "").lower()
        if any(req.endswith(tld) for tld in suspicious_tlds):
            features["dns_suspicious_tld"] += 1


    imports = report.get("static", {}).get("pe_imports", [])
    # 6. Hybrid Cross-check Features
    imported_apis = {f"{dll.get('dll','').lower()}_{func.get('name','').lower()}"
                     for dll in imports for func in dll.get("imports", [])}

    if "advapi32.dll_cryptencrypt" in imported_apis and features["crypto_calls"] > 0:
        features["import_and_used_crypto"] = 1
    if "kernel32.dll_createfilew" in imported_apis and features["file_create"] > 0:
        features["import_and_used_filecreate"] = 1

        
    return dict(features)

extract_dynamic_features(report)

def extract_api_sequence(report, max_len=2000):
    seq = []
    for proc in report.get("behavior", {}).get("processes", []):
        for call in proc.get("calls", []):
            api = call.get("api", "").lower()
            seq.append(api)
            if len(seq) >= max_len:
                break
    return seq[:max_len]

sequences = extract_api_sequence(report)

def build_vocab(sequences):
    vocab = {"<PAD>":0, "<UNK>":1}
    for api in sequences:
            if api not in vocab:    
                vocab[api] = len(vocab)
    for api, idx in vocab.items():
        print(f"{idx:3}  {api}")

    return vocab

vocab = build_vocab(sequences)

def encode_sequence(seq, vocab, max_len=2000):
    encoded = [vocab.get(api, vocab["<UNK>"]) for api in seq]
    # pad if shorter
    return encoded + [vocab["<PAD>"]] * (max_len - len(encoded))

encode_seq = encode_sequence(sequences,vocab,max_len=50)

print(vocab)
print(encode_seq[:2000])


