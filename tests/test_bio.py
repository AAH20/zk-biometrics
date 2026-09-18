import unittest
from zk_biometrics.cancelable.bio_hash import CancelableBioHash
from zk_biometrics.encrypted_search.fhe_cosine import EncryptedVectorIndex
from zk_biometrics.zk_proofs.watchlist_attestation import ZKWatchlistAttestation

class TestZKBiometrics(unittest.TestCase):
    def test_cancelable_bio_hash_properties(self):
        emb1 = [0.1 * i for i in range(128)]
        # Same face, same seed -> identical hash
        h1 = CancelableBioHash.transform_embedding(emb1, "seed_a")
        h2 = CancelableBioHash.transform_embedding(emb1, "seed_a")
        self.assertEqual(h1, h2)
        self.assertEqual(CancelableBioHash.hamming_distance(h1, h2), 0.0)

        # Same face, revoked/new seed -> uncorrelated hash
        h3 = CancelableBioHash.transform_embedding(emb1, "seed_b")
        dist = CancelableBioHash.hamming_distance(h1, h3)
        self.assertTrue(0.35 <= dist <= 0.65) # Pseudo-orthogonal

    def test_encrypted_vector_search(self):
        index = EncryptedVectorIndex()
        emb = [0.2 for _ in range(128)]
        h = CancelableBioHash.transform_embedding(emb, "user_key")
        index.insert("ID_USER_42", h, "encrypted_payload_aes")

        # Query with exact match
        matches = index.search_top_k(h, max_hamming_threshold=0.05)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["token_id"], "ID_USER_42")
        self.assertEqual(matches[0]["hamming_distance"], 0.0)

    def test_zk_clearance_proof(self):
        target_hash = [1 if i % 2 == 0 else 0 for i in range(128)]
        authorized_hashes = [target_hash, [0]*128]

        proof = ZKWatchlistAttestation.generate_clearance_proof(target_hash, authorized_hashes)
        self.assertTrue(proof["clearance_granted"])
        self.assertFalse(proof["raw_biometric_exposed"])
        self.assertIn("ILLINOIS_BIPA_SAFE_HARBOR", proof["statutory_compliance"])

if __name__ == "__main__":
    unittest.main()
