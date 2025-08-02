import dns.resolver
import socket
import ipaddress
import time
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from tabulate import tabulate
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score

# -------------------- [1] Load and Normalize Dataset -------------------- #
dataset_path = "/Users/christinageorge/Desktop/top_1000_domains.csv"
df = pd.read_csv(dataset_path)
df.columns = [col.strip().lower() for col in df.columns]

ground_truth = {
    row["domain"].strip().lower(): row["label"].strip().lower()
    for _, row in df.iterrows()
    if "domain" in row and "label" in row
}

# -------------------- [2] Key Generation for Digital Signature -------------------- #
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# -------------------- [3] Resolver Configuration -------------------- #
resolvers = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9"
}
TTL_VARIANCE_THRESHOLD_PERCENT = 60
MAX_SUBNET_MISMATCH_SAFE = 2  # Threshold for verdict classification

# -------------------- [4] DNS Resolver Functions -------------------- #
def resolve_dns(domain, nameserver):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        answer = resolver.resolve(domain, 'A')
        ips = [rdata.address for rdata in answer]
        ttl = answer.rrset.ttl
        return ips, ttl
    except Exception:
        return None, None

def resolve_local(domain):
    try:
        return [socket.gethostbyname(domain)]
    except Exception:
        return []

def ttl_consistency_check(ttls):
    valid_ttls = [ttl for ttl in ttls if ttl is not None]
    if len(valid_ttls) <= 1:
        return True
    min_ttl, max_ttl = min(valid_ttls), max(valid_ttls)
    if min_ttl == 0:
        return False
    variance = ((max_ttl - min_ttl) / min_ttl) * 100
    return variance <= TTL_VARIANCE_THRESHOLD_PERCENT

def same_subnet(ip1, ip2, mask=24):
    try:
        net1 = ipaddress.ip_network(f"{ip1}/{mask}", strict=False)
        net2 = ipaddress.ip_network(f"{ip2}/{mask}", strict=False)
        return net1.network_address == net2.network_address
    except Exception:
        return False

def compare_ips_and_ttl(results, ttl_consistent):
    all_ips = [ip for res_ips in results.values() if res_ips for ip in res_ips]
    unique_ips = list(set(all_ips))

    if not unique_ips:
        return "No Response"

    # Count how many unique IP pairs differ in subnet
    subnet_mismatch = 0
    for i in range(len(unique_ips)):
        for j in range(i + 1, len(unique_ips)):
            if not same_subnet(unique_ips[i], unique_ips[j]):
                subnet_mismatch += 1

    # Verdict Heuristics
    if ttl_consistent and subnet_mismatch == 0:
        return "Safe"
    elif ttl_consistent and subnet_mismatch <= MAX_SUBNET_MISMATCH_SAFE:
        return "Likely Safe"
    elif not ttl_consistent and subnet_mismatch <= MAX_SUBNET_MISMATCH_SAFE:
        return "Potential Poisoning"
    else:
        return "Malicious or Unsafe"

# -------------------- [5] Digital Signature Functions -------------------- #
def sign_data(data):
    return private_key.sign(
        data.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(data, signature):
    try:
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -------------------- [6] Main Execution Block -------------------- #
domains = input("Enter domains separated by commas: ").strip().split(",")
domains = [d.strip().lower() for d in domains]

all_true, all_pred = [], []

for domain in domains:
    print(f"\n--- DNS Check for: {domain} ---")
    results, ttls = {}, {}

    for name, ns in resolvers.items():
        ips, ttl = resolve_dns(domain, ns)
        results[name] = ips
        ttls[name] = ttl

    local_ips = resolve_local(domain)
    results["Local Resolver"] = local_ips
    ttls["Local Resolver"] = "-"  # No TTL from local

    ttl_values = [ttl for ttl in ttls.values() if isinstance(ttl, int)]
    ttl_consistent = ttl_consistency_check(ttl_values)

    verdict = compare_ips_and_ttl(results, ttl_consistent)

    table_data = []
    for res_name in results:
        ip_str = ", ".join(results[res_name]) if results[res_name] else "-"
        ttl_str = str(ttls[res_name]) if ttls[res_name] else "-"
        table_data.append([res_name, ip_str, ttl_str])

    print(tabulate(table_data, headers=["Resolver", "IPs", "TTL"], tablefmt="grid"))
    print(f"TTL Consistency: {'✔️' if ttl_consistent else '❌'}")
    print(f"Verdict: {verdict}")

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    signed_data = f"{timestamp} | {domain} | {verdict}"
    signature = sign_data(signed_data)
    verified = verify_signature(signed_data, signature)

    print(f"Digital Signature Verified: {'✔️' if verified else '❌'}")
    print(f"Signed Verdict String: {signed_data}")

    # Ground truth comparison
    if domain in ground_truth:
        expected = ground_truth[domain]
        predicted = verdict.lower()
        mapped_pred = "safe" if predicted in ["safe", "likely safe"] else predicted

        all_true.append(expected)
        all_pred.append(mapped_pred)

        correctness = "✅ Correct" if expected == mapped_pred else "❌ Incorrect"
        print(f"Ground Truth: {expected} → {correctness}")
    else:
        print("Ground truth not found for this domain.")

# -------------------- [7] Final Evaluation Metrics -------------------- #
if all_true and all_pred:
    acc = round(accuracy_score(all_true, all_pred) * 100, 2)
    rec = round(recall_score(all_true, all_pred, pos_label='safe', zero_division=0) * 100, 2)
    prec = round(precision_score(all_true, all_pred, pos_label='safe', zero_division=0) * 100, 2)
    f1 = round(f1_score(all_true, all_pred, pos_label='safe', zero_division=0) * 100, 2)

    print("\n--- Evaluation Metrics ---")
    print(f"Accuracy : {acc}%")
    print(f"Recall   : {rec}%")
    print(f"Precision: {prec}%")
    print(f"F1 Score : {f1}%")
else:
    print("\nNo matching ground truth to compute metrics.")
