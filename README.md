# Umbra Core

This repository contains the core logic for the Umbra Private Payment Protocol.
It includes the zero-knowledge circuits, smart contracts, and cryptographic primitives used to enable private transactions.

## Structure

- `core/`: Shared Rust cryptographic primitives and ledger logic.
- `zkvm/`: SP1 Zero-knowledge program (ZK Circuit).
- `contracts/`: Solidity Smart Contracts (`PrivateUTXOLedger` and `EncryptedContacts`).
- `client/`: Browser-compatible TypeScript crypto libraries.

## Security

This code is open-source for transparency.
The core protocol relies on:
1. **ZK Proofs (SP1):** Proving valid state transitions without revealing inputs.
2. **ECIES Encryption:** Protecting transaction details and contact info.
3. **ECDSA Signatures:** Authorizing spends.

## License

MIT
