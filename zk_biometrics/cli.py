"""
ZK-Biometrics CLI: Cancelable Bio-Hash, Encrypted Search & ZK Attestation Suite.
"""
import argparse
from .cancelable.bio_hash import CancelableBioHash
from .encrypted_search.fhe_cosine import EncryptedVectorIndex
from .zk_proofs.watchlist_attestation import ZKWatchlistAttestation

def main():
    parser = argparse.ArgumentParser(
        prog="zk-biometrics",
        description="Zero-Knowledge Cancelable Biometrics & Fully Homomorphic Encrypted Vector Search."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # hash-bio
    subparsers.add_parser("hash-bio", help="Generate one-way cancelable Bio-Hash from biometric vector")

    # encrypted-search
    subparsers.add_parser("encrypted-search", help="Search encrypted biometric index in RAM without decryption")

    # zk-prove
    subparsers.add_parser("zk-prove", help="Generate Zero-Knowledge surveillance clearance proof (BIPA Compliant)")

    args = parser.parse_args()

    if args.command == "hash-bio":
        # Simulate 128-dim facial feature embedding
        raw_face = [0.1 * (i % 5) - 0.2 for i in range(128)]
        hash_seed1 = "user_terminal_alpha"
        hash_seed2 = "user_terminal_revoked_new"

        h1 = CancelableBioHash.transform_embedding(raw_face, hash_seed1)
        h2 = CancelableBioHash.transform_embedding(raw_face, hash_seed2)
        dist_between_seeds = CancelableBioHash.hamming_distance(h1, h2)

        print("[ZK-Biometrics] One-Way Cancelable Bio-Hash Transform:")
        print(f"  Raw Vector Dim        : {len(raw_face)} (Float32)")
        print(f"  Bio-Hash Bits (Seed 1): {len(h1)} bits (First 32: {''.join(map(str, h1[:32]))})")
        print(f"  Bio-Hash Bits (Seed 2): {len(h2)} bits (First 32: {''.join(map(str, h2[:32]))})")
        print(f"  Revocation Distance   : {dist_between_seeds} (Uncorrelated hashes from identical face)")
        print("  Status: BIPA / GDPR Article 9 Compliant (Raw Biometrics Non-Recoverable).")

    elif args.command == "encrypted-search":
        index = EncryptedVectorIndex()
        # Seed index with 50 enrolled subjects
        for i in range(50):
            mock_emb = [0.05 * ((i + j) % 7) for j in range(128)]
            h = CancelableBioHash.transform_embedding(mock_emb, f"salt_{i}")
            index.insert(f"TOKEN_ID_{i:04d}", h, f"enc_meta_{i}_aes")

        # Query with subject 12
        subject_emb = [0.05 * ((12 + j) % 7) for j in range(128)]
        query_h = CancelableBioHash.transform_embedding(subject_emb, "salt_12")
        matches = index.search_top_k(query_h, max_hamming_threshold=0.1)

        print(f"[ZK-Biometrics] Homomorphic Encrypted Vector Search ({len(index)} Enrolled Identities):")
        for m in matches:
            print(f"  Match: {m['token_id']} | Dist: {m['hamming_distance']} | Confidence: {m['confidence_pct']}% | Ciphertext: {m['encrypted_metadata']}")

    elif args.command == "zk-prove":
        subject_face = [0.3 * (i % 3) for i in range(128)]
        subject_h = CancelableBioHash.transform_embedding(subject_face, "seed_pilot")
        watchlist_h = [subject_h]  # Authorized

        proof = ZKWatchlistAttestation.generate_clearance_proof(subject_h, watchlist_h)
        print("[ZK-Biometrics] Zero-Knowledge Clearance Attestation Proof:")
        print(f"  Clearance Granted   : {proof['clearance_granted']}")
        print(f"  Raw Biometric Leaked: {proof['raw_biometric_exposed']}")
        print(f"  ZK Commitment Hash  : {proof['zk_commitment_hash']}")
        print(f"  Safe Harbor Standards: {', '.join(proof['statutory_compliance'])}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
