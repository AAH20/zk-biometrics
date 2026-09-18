# ZK-Biometrics: Zero-Knowledge Cancelable Biometrics & Homomorphic Encrypted Search

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Compliance: BIPA / GDPR Art 9](https://img.shields.io/badge/Compliance-Illinois%20BIPA%20%7C%20GDPR%20Art%209-purple.svg)](https://a2zsoc.com)
[![Privacy: Zero-Knowledge](https://img.shields.io/badge/Privacy-Homomorphic%20Encrypted%20Search-brightgreen.svg)](https://a2zsoc.com)

> **Mathematically Irreversible, Revocable Facial & Iris Templates with Zero-Knowledge Watchlist Clearance and Encrypted RAM Vector Matching.**  
> Eliminates central plaintext biometric vector databases, solving catastrophic breach liabilities and statutory non-compliance (Illinois BIPA, Texas CUBI, EU AI Act Annex III).

---

## 🎯 The Biometric Data Liability Crisis

Mass facial recognition and surveillance systems store floating-point feature vectors (128D / 512D) in central cloud databases:
1. **Irrevocable Breaches**: Unlike passwords, a victim cannot change their face or iris if a database is compromised.
2. **Statutory Penalties**: Laws like Illinois BIPA penalize unauthorized biometric storage with \$1,000 to \$5,000 per violation.
3. **Surveillance Privacy Violations**: Conventional surveillance exposes raw identity metadata to human CCTV operators.

---

## ⚡ ZK-Biometrics Benchmarks & Legal Shields

| Feature | Legacy Biometric Databases | **ZK-Biometrics Engine** | Regulatory & Legal Advantage |
| :--- | :---: | :---: | :---: |
| **Biometric Invertibility** | High (Raw face reconstructible) | **Strictly One-Way (Orthogonal Bio-Hash)** | Irreversible mathematical projection |
| **Revocability / Renewal** | ❌ (Impossible) | **✅ (New seed yields orthogonal hash)** | Breached tokens can be cancelled instantly |
| **Vector Search Privacy** | Plaintext float cosine search | **Homomorphic Search over Encrypted RAM** | Zero plaintext vector storage |
| **Surveillance Clearance** | Operator sees subject identity | **Zero-Knowledge Mathematical Proof** | BIPA Safe Harbor & GDPR Article 9 exempt |

---

## 🛠️ Components

```
zk-biometrics/
├── zk_biometrics/
│   ├── cancelable/
│   │   └── bio_hash.py              # One-way orthogonal cancelable biometric hasher
│   ├── encrypted_search/
│   │   └── fhe_cosine.py            # Homomorphic encrypted RAM vector search index
│   └── zk_proofs/
│       └── watchlist_attestation.py # Zero-knowledge watchlist clearance proof generator
```

---

## 💻 Quick Start & CLI

```bash
# Run unit tests
python3 -m unittest discover -s tests

# 1. Transform Biometric Vector into Cancelable Bio-Hash
zk-biometrics hash-bio

# 2. Search Enrolled Identities in Encrypted RAM
zk-biometrics encrypted-search

# 3. Generate BIPA-Compliant Zero-Knowledge Clearance Proof
zk-biometrics zk-prove
```

---

## 📄 License & Biometric Security Retainers

Apache-2.0 License. Authored by [Ahmed Hassan](https://github.com/AAH20) (Founder, [A2Z SOC](https://a2zsoc.com)).  
For sovereign border control, biometric privacy compliance, and encrypted identity retainers, contact: `ahmed@a2zsoc.com`.
