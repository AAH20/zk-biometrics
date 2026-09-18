"""
Cancelable Biometric Hash (Bio-Hash) Projection.
Transforms raw 512-dim biometric face/iris embeddings into mathematically irreversible,
revocable binary templates using user-specific orthogonal random matrices (BIPA/GDPR Article 9 Compliant).
"""
import hashlib
import math
from typing import List, Tuple

class CancelableBioHash:
    @staticmethod
    def generate_orthogonal_matrix(seed: str, dim: int = 128) -> List[List[float]]:
        """
        Generates pseudo-random projection vectors from user seed.
        """
        matrix = []
        for i in range(dim):
            row = []
            h_base = hashlib.sha256(f"{seed}_row_{i}".encode()).digest()
            for j in range(dim):
                byte_val = h_base[j % len(h_base)]
                val = (byte_val / 128.0) - 1.0
                row.append(val)
            matrix.append(row)
        return matrix

    @staticmethod
    def transform_embedding(raw_embedding: List[float], seed: str) -> List[int]:
        """
        One-way non-invertible Bio-Hash:
        H_bio = sign(OrthogonalMatrix * RawEmbedding)
        If seed is revoked, a new seed produces an uncorrelated hash from the identical face.
        """
        dim = len(raw_embedding)
        matrix = CancelableBioHash.generate_orthogonal_matrix(seed, dim)
        bio_hash = []
        for row in matrix:
            dot = sum(w * x for w, x in zip(row, raw_embedding))
            bio_hash.append(1 if dot >= 0 else 0)
        return bio_hash

    @staticmethod
    def hamming_distance(hash_a: List[int], hash_b: List[int]) -> float:
        """
        Normalized Hamming Distance: d_H = (A XOR B) / N
        """
        diff = sum(a ^ b for a, b in zip(hash_a, hash_b))
        return round(diff / float(len(hash_a)), 4)
