# DNS Cache Poisoning Detection Tool

A Python-based tool to detect DNS cache poisoning attacks by querying multiple DNS resolvers, verifying TTL consistency, analyzing IP subnet mismatches, and comparing results with a trusted domain list. Built as part of a cybersecurity project with future IoT integration.

---

##  Features

- Queries multiple DNS resolvers: **Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9)**
- Detects suspicious mismatches using:
  - **Exact IP matching**
  - **Subnet range analysis** (counts mismatch pairs)
  - **TTL consistency checking**
- Compares against a trusted CSV (`top_1000_domains.csv`)
- Classifies each domain as:
  - ✅ Safe
  - ⚠️ Likely Safe
  - ❌ Potential Poisoning
  - 🚨 Malicious or Unsafe
- Generates digital signature and verifies it on verdict

---

##  Subnet and TTL Logic

- IPs are checked pairwise to see if they fall within the same `/16` subnet.
- A mismatch counter is compared to a threshold to reduce false positives.
- TTLs are compared across resolvers to detect anomalies in DNS caching behavior.

---

##  Files in This Repo

|         File          |            Description           |
|-----------------------|----------------------------------|
| `IOT1.py`             | Main detection script            |
| `top_1000_domains.csv`| Trusted domain–IP mapping        |    
| `README.md`           | Project overview and usage guide |
| `sample_output.txt`   | Sample results from a script run |

---

## ❗ Usage Terms

**This repository is for academic and demonstration purposes only.  
Reproduction, reuse, or redistribution of this work without permission is not allowed.**

##  How to Run the Tool

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/dns-cache-poisoning-detector.git
cd dns-cache-poisoning-detector
