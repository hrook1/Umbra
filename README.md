# Umbra Private Payments - User Guide

## What is this?

[TECHNICAL DOCS](https://hackmd.io/@htx1E5TpQb-mUP-Jw9430A/rkGLtcKz-l)

A privacy-preserving wallet for USDC on Ethereum. Send payments without revealing amounts or balances on-chain.

**Key Features:**
- Private balances - your balance is encrypted, only you can see it
- Private transfers - amounts are hidden using zero-knowledge proofs
- Gasless transactions - no ETH needed, relayer pays gas fees
- Non-custodial - only you control your funds

---

## Getting Started

### 1. Access the Wallet

**https://wallet-ui-self.vercel.app**

*(Request access if prompted)*

### 2. Get Sepolia ETH 

Visit Google's faucet to get free test ETH:
**https://cloud.google.com/application/web3/faucet/ethereum/sepolia**

- Enter your wallet address
- Request ETH (needed once for USDC approval)

### 3. Get Sepolia USDC

Visit Circle's faucet to get free test USDC:
**https://faucet.circle.com/**

- Connect your wallet
- Select "Sepolia" network
- Request USDC (you'll get 1 USDC to dont spend it all at once!)

### 4. Connect Wallet

- Click "Connect Wallet"
- Switch to **Sepolia** network if prompted
- Generate private credentials

---

## Core Actions

### Deposit USDC

1. Click **"Deposit"**
2. Enter amount (e.g., 0.01 USDC)
3. First time: Approve USDC spending (one-time)
4. Sign the Permit2 message (gasless approval)
5. Wait for confirmation
6. Your private balance updates

### Send Private Payment

1. Click **"Send"**
2. Enter recipient's **private address** (starts with `0x...`).
    2.1. Heres my private address if you need a fren to share $ `0x03855c29051a934ef7c15ce4750dce8f0c9997c8a5b12711cf796ed83af6194ee4`
3. Enter amount
4. Click "Send"
5. Wait for ZK proof generation (~1-2 minutes)
6. Transaction submitted automatically
7. Recipient sees funds in their private balance

*Requires ZK proof - amounts are hidden on-chain*

### Withdraw to Public Wallet

1. Click **"Withdraw"**
2. Enter your public ETH address
3. Enter amount
4. Wait for ZK proof generation (~1-2 minutes)
5. USDC sent to your public wallet

*Requires ZK proof - proves you own the funds without revealing balance*

---

## Understanding Your Wallet

| Term | Meaning |
|------|---------|
| **Private Balance** | Your encrypted USDC balance (only you can see) |
| **Private Address** | Address others use to send you private payments |
| **Public Address** | Your regular ETH address (for withdrawals) |

---

## How Privacy Works

- **Deposits**: USDC goes into a shared pool
- **Balances**: Stored as encrypted "notes" on-chain
- **Transfers**: ZK proofs verify validity without revealing amounts
- **Withdrawals**: Prove ownership, receive USDC publicly

Your activity is unlinkable - observers can't connect deposits to withdrawals.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Prover offline" | Wait 1-2 min for server to wake up, retry |
| Proof taking long | Normal - ZK proofs take 1-2 minutes |
| Transaction failed | Check you have sufficient private balance |
| Wrong network | Switch MetaMask to Sepolia |

# Umbra: Private UTXO Payment System

## Technical Overview

### Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Privacy Model](#privacy-model)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Zero-Knowledge Proofs](#zero-knowledge-proofs)
5. [Security Model](#security-model)

---

## Architecture Overview

Umbra is a privacy-preserving payment system built on Ethereum using a UTXO model with zero-knowledge proofs. It enables private transfers of USDC where transaction amounts and relationships between sender/receiver are hidden from observers.

### High-Level Architecture

```
                    ┌──────────────────────────────────────────────────────────┐
                    │              ETHEREUM - Source of Truth                  │
                    │  ┌────────────────────────────────────────────────────┐  │
                    │  │            PrivateUTXOLedger Contract              │  │
                    │  │  - SP1 Groth16 Verifier (proof verification)       │  │
                    │  │  - UTXO Merkle Tree State                          │  │
                    │  │  - Nullifier Registry (double-spend prevention)    │  │
                    │  │  - USDC Custody                                    │  │
                    │  └────────────────────────────────────────────────────┘  │
                    └──────────────────────────────────────────────────────────┘
                                              ▲
                                              │ Submit proven transactions
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    │                                                   │
                    ▼                                                   │
          ┌──────────────────┐                                          │
          │  Relayer Server  │                                          │
          │  - Gasless TX    │                                          │
          │  - Pays gas fees │                                          │
          └──────────────────┘                                          │
                    ▲                                                   │
                    │ Proof + encrypted notes                           │
                    │                                                   │
┌─────────────────────────────────────────────────────────────────┐     │
│                         Wallet UI                               │     │
│  - Key derivation from wallet signature                         │     │
│  - UTXO scanning and decryption                                 │─────┘
│  - Transaction construction                                     │  Read state
│  - All cryptography happens client-side                         │  (events, roots)
└─────────────────────────────────────────────────────────────────┘
                    │
                    │ Witness data
                    ▼
          ┌──────────────────┐
          │  Prover Server   │
          │  - SP1 Host      │
          └──────────────────┘
                    │
                    │ Proof request
                    ▼
          ┌──────────────────┐
          │ Succinct Prover  │
          │ Network          │
          │ - ZK Execution   │
          │ - Groth16 Proof  │
          └──────────────────┘
```

### Data Flow

1. **Wallet** reads contract state (events, Merkle root) from Ethereum
2. User constructs transaction, wallet sends witness to Prover Server
3. Prover Server submits to Succinct Network for proof generation
4. Wallet receives proof, sends to Relayer
5. Relayer submits proven transaction to Contract
6. **Contract verifies proof on-chain** and updates state (nullifiers, commitments)

### System Components

| Component | Role | Trust Level |
|-----------|------|-------------|
| **Smart Contract** | Source of truth. Verifies all proofs on-chain, manages UTXO state, prevents double-spends | Trustless (code is law) |
| **Wallet UI** | All client-side cryptography: key derivation, UTXO scanning, encryption, signing | Self-custody (keys never leave browser) |
| **Prover Server** | Orchestrates proof generation via Succinct Network | **Not trusted** - proofs verified on-chain |
| **Relayer** | Submits transactions, pays gas | Cannot steal funds or modify proofs |
| **Succinct Network** | Generates Groth16 proofs | **Not trusted** - proofs verified on-chain |

---

## Privacy Model

### What's Hidden vs. Public

| Data | On-Chain Visibility | Who Can Decrypt |
|------|---------------------|-----------------|
| Note commitment | Public | No one (hash) |
| Encrypted note data | Public | Only recipient |
| Nullifier | Public (when spent) | No one (hash) |
| Transaction amount | **Hidden** | Sender & Recipient |
| Sender identity | **Hidden** | Recipient only |
| Recipient identity | **Hidden** | Sender only |

### Key Privacy Properties

1. **Amount Privacy**: Transaction values are never revealed on-chain
2. **Sender Privacy**: Cannot determine who sent a payment from on-chain data
3. **Recipient Privacy**: Cannot determine who received a payment
4. **Unlinkability**: Cannot link inputs to outputs in a transaction

---

## Cryptographic Primitives

### Key Derivation

Users derive a deterministic keypair from their Ethereum wallet signature:

```
Wallet Signature → Blake3 Hash → secp256k1 Private Key → Public Key → Address
```

- User signs a fixed message with their Ethereum wallet
- Signature is hashed with Blake3 to produce a 32-byte seed
- Seed is used as a secp256k1 private key
- **Keys exist only in browser memory** - never transmitted

### Note Structure

A note represents a private UTXO:

```
Note = {
    amount: u64,           // Value in smallest unit (e.g., USDC micro-units)
    owner_pubkey: [u8; 32], // Recipient's compressed public key
    blinding: [u8; 32]      // Random factor for commitment uniqueness
}
```

### Note Commitment

Domain-separated Blake3 hash ensuring collision resistance:

```
Commitment = Blake3(DOMAIN_NOTE_COMMITMENT || amount || owner_pubkey || blinding)
```

- Commitment is stored on-chain
- Reveals nothing about the note contents (one-way hash)
- Blinding factor ensures two notes with same amount/owner have different commitments

### Nullifier Construction

Prevents double-spending while hiding which note is being spent:

```
Nullifier = Blake3(DOMAIN_NULLIFIER || owner_pubkey || commitment)
```

**Security Properties:**
- Only the owner can compute the nullifier (requires knowing which pubkey maps to their privkey)
- Cannot be computed from commitment alone (requires owner_pubkey)
- Reveals nothing about the note contents
- Deterministic: same note always produces same nullifier
- Published on-chain when note is spent → prevents double-spend

### ECIES Encryption

Notes are encrypted to the recipient's public key using ECIES (Elliptic Curve Integrated Encryption Scheme):

```
1. Generate ephemeral keypair (r, R = r*G)
2. Compute shared secret: S = r * recipient_pubkey
3. Derive encryption key: K = Blake3(S)
4. Encrypt note data with ChaCha20-Poly1305
5. Output: (R, ciphertext, tag)
```

- Only recipient can decrypt (using their private key)
- Ephemeral key provides forward secrecy
- Encrypted notes are stored on-chain in events

### Signature Scheme

ECDSA signatures over secp256k1 prove note ownership:

```
Message = Blake3(DOMAIN_SIGNATURE || commitment)
Signature = ECDSA_Sign(private_key, message)
```

- Signature is verified inside the ZK circuit
- Public key is recovered from signature
- Recovered pubkey must match note's owner_pubkey

---

## Zero-Knowledge Proofs

### SP1 zkVM

We use Succinct's SP1 zkVM which allows writing ZK circuits in Rust. The circuit is compiled to an ELF binary and executed in a zkVM that generates Groth16 proofs.

### Trustless Verification

**The prover is NOT trusted.** All proofs are cryptographically verified on-chain by the SP1 Groth16 Verifier contract:

1. **Malicious prover cannot steal funds** - Invalid proofs are rejected by the on-chain verifier
2. **Prover cannot forge transactions** - Without the owner's private key, no valid signature can be produced
3. **Prover learns nothing exploitable** - Even if prover sees witness data, they cannot use it
4. **Verification is deterministic** - Same proof always produces same verification result

**On-chain verifier checks:**
- Proof was generated by the correct SP1 program (vkey match)
- All cryptographic constraints in the circuit were satisfied
- Public outputs match the claimed values

### What the Circuit Proves

The ZK circuit proves the following statements **without revealing the underlying data**:

| Statement | What It Proves | Why It Matters |
|-----------|----------------|----------------|
| **Merkle Membership** | Input notes exist in the committed UTXO set | Cannot spend non-existent notes |
| **Ownership** | Spender knows the private key for each input note | Only owner can spend their notes |
| **Nullifier Correctness** | Nullifiers are correctly derived from notes | Enables double-spend prevention without revealing which note |
| **Commitment Validity** | Output commitments are correctly formed | New notes are properly structured |
| **Value Conservation** | Sum of inputs ≥ sum of outputs | Cannot create money from nothing |

**Key insight**: The contract only sees nullifiers, commitments, and the proof. It never sees amounts, sender/recipient identities, or note contents. The ZK proof guarantees these hidden values satisfy all constraints.

### Circuit Logic (Simplified)

```
VERIFY each input note:
    1. Commitment matches: Hash(note) == claimed_commitment
    2. Merkle proof valid: note exists in tree at claimed root
    3. Ownership proven: Recover(signature) == note.owner_pubkey
    4. Nullifier correct: Hash(owner_pubkey, commitment) == claimed_nullifier

VERIFY each output note:
    1. Commitment valid: Hash(note) == claimed_output_commitment

VERIFY value conservation:
    sum(input_amounts) >= sum(output_amounts)

OUTPUT (public):
    - nullifiers (to mark notes as spent)
    - output_commitments (new notes to add to tree)
    - withdrawal_amount (if withdrawing to public address)
```

### Proof Generation Pipeline

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Wallet    │────▶│   Prover    │────▶│  Succinct   │────▶│  Contract   │
│             │     │   Server    │     │  Network    │     │  (verify)   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │                   │
  Construct           Forward            Execute SP1          Verify proof
  witness             to network         Generate Groth16     on-chain
  (notes,             (~30-60 sec)       proof                (~200k gas)
  signatures,
  merkle proofs)
```

---

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Double-spend** | Nullifier registry on-chain - each nullifier can only be used once |
| **Forged ownership** | ECDSA signature verification inside ZK circuit |
| **Invalid amounts** | Value conservation check inside ZK circuit |
| **Malicious prover** | All proofs verified on-chain - invalid proofs rejected |
| **Front-running** | Nullifiers hide which specific note is being spent |
| **Key theft** | Keys derived from wallet signature, exist only in browser memory |
| **Replay attacks** | Nullifiers are one-time use |

### Trust Assumptions

| Component | Security Trust | Liveness Trust |
|-----------|---------------|----------------|
| **Smart Contract** | Full (verified on-chain) | Ethereum availability |
| **Succinct Network** | **None** (proofs verified on-chain) | Required for proof generation |
| **Relayer** | None (cannot modify proofs) | Required for tx submission |
| **Wallet UI** | Self-custody | User's device |

### Cryptographic Assumptions

- **secp256k1 ECDSA**: Discrete log hardness
- **Blake3**: Collision resistance, preimage resistance
- **Groth16**: Knowledge-of-exponent assumption, q-PKE
- **ChaCha20-Poly1305**: Standard symmetric encryption security

### Key Security Properties

1. **Soundness**: Cannot create valid proof without knowing private keys
2. **Zero-Knowledge**: Proof reveals nothing about transaction details
3. **Unlinkability**: Cannot link sender to recipient from on-chain data
4. **Non-Malleability**: Proofs cannot be modified without invalidation
5. **Forward Secrecy**: ECIES ephemeral keys protect past communications

---

## References

- [SP1 Documentation](https://docs.succinct.xyz/)
- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [ECIES Specification](https://www.secg.org/sec1-v2.pdf)
- [Blake3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
