Work in progress: Not production-ready.
TODO: Add documentation for signle term proof of existence

# Merkle-Poseidon-ECDSA signature Verification in Noir
This circuit creates a verifiable proof, that a ECDSA (secp256k1 curve) signature over a Poseidon-Merkle-root from an encoded RDF dataset is verified correctly.
Idea: Use this proof as a trust anchor for subsequent selective disclosure of RDF and SPARQL query proofs over a signed dataset.

Pre-processing of RDF dataset happens in Rust 
- canonicalization -> see zk_preprocessing_rust_canon_rdf
- transform quads into Field elements with SHA256 -> see zk_preprocessing_rdf_to_zk
- construct dataset merkle root with Poseidon and sign root with ECDSA  -> see zk_preprocessing_merkle_poseidon_root_ecdsa
Warning: Make sure to sign the raw root (do not hash the root before signing in Rust) sothat it matches Noir's verify_signature blackbox function.
- verification check and writing the Prover.toml file required for Noir circuit -> see zk_preprocessing_prover_preparation


# Flow
Issuer -> Holder/Prover -> Verifier

Issuer: Issues 
- pre-processed RDF dataset
- generates keypair for ecdsa curve
- ecdsa signature over computed dataset poseidon-merkle root

Issuer passes to Prover: 
- issuer Public Key (verifier can look up who the signature came from)
- Signature
- Merkle root
- Dataset "leaves" (pre-processed RDF encoded as Field elements)

Prover: 
- generates proof in-circuit: “There exists a signature σ and a canonicalized RDF dataset, D s. t.
- assertion 1: re-computes Merkle root (R') = Merkle root (R)
- assertion 2: root was signed by the issuers ECDSA key s. t. Verify(pk, m, σ) = true

Prover passes to Verifier:
- proof
- verification key
- public inputs

Verifier: Verifies proof with Barettenberg backend (Ultra-Honk)

### Circuit details

pub inputs:

(pk_x, pk_y) — Issuer public key both [u8; 32]
Merkle root R - Field

priv inputs:

ecdsa signature over root (r, s) - [u8; 64]
dataset D: leaves - [Field; 4]

circuit computes:   
- build tree with fixed depth 2 from dataset leaves with Poseidon over BN254 = R'
- assert  R' = R  
- assert   ECDSA verification (pk, R', signature) = true using Noir's blackbox function verify_signature

circuit output:
- proof
- verification key
- public inputs (Issuer public key, Merkle root)

# Limitations
- Tree size is fixed
- Ordered tree construction (RDF datasets are unordered)
- No selective disclosure yet

# How to run

```bash
nargo check
nargo execute
bb prove
bb verify
```
