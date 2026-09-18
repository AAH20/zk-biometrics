"""
Homomorphic Encrypted Vector Search Simulator.
Searches encrypted biometric hashes directly in RAM without decrypting identities.
"""
from typing import List, Dict, Any, Tuple
import math

class EncryptedVectorIndex:
    def __init__(self):
        # Stores: (encrypted_token_id, bio_hash, metadata_ciphertext)
        self._index: List[Dict[str, Any]] = []

    def insert(self, token_id: str, bio_hash: List[int], encrypted_metadata: str) -> None:
        self._index.append({
            "token_id": token_id,
            "bio_hash": bio_hash,
            "encrypted_metadata": encrypted_metadata
        })

    def search_top_k(self, query_hash: List[int], max_hamming_threshold: float = 0.25, k: int = 3) -> List[Dict[str, Any]]:
        matches = []
        for entry in self._index:
            diff = sum(a ^ b for a, b in zip(query_hash, entry["bio_hash"]))
            norm_dist = diff / float(len(query_hash))
            if norm_dist <= max_hamming_threshold:
                matches.append({
                    "token_id": entry["token_id"],
                    "hamming_distance": round(norm_dist, 4),
                    "confidence_pct": round((1.0 - norm_dist) * 100.0, 2),
                    "encrypted_metadata": entry["encrypted_metadata"]
                })

        matches.sort(key=lambda x: x["hamming_distance"])
        return matches[:k]

    def __len__(self) -> int:
        return len(self._index)
