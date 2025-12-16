// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

contract PrivateUTXOLedger {
    using SafeERC20 for IERC20;

    bytes32 public currentRoot;
    mapping(bytes32 => bool) public nullifierUsed;
    address public immutable secp256r1Precompile;

    /// @notice The ERC20 token used for deposits/withdrawals (address(0) for native ETH)
    address public immutable token;

    uint256 public totalDeposited;

    /// @notice SP1 Groth16 verifier contract address
    address public immutable sp1Verifier;

    /// @notice Verification key for the UTXO SP1 program
    /// Updated for dual-signature model with ECDSA recovery ID fix (2025-12-15)
    bytes32 public constant UTXO_PROGRAM_VKEY = 0x00560b7d05cf32ebca214440ad7a9735bab35f767605062702eb24e1c8708856;

    /// @notice Permit2 canonical address (same on all EVM chains)
    ISignatureTransfer public constant PERMIT2 = ISignatureTransfer(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    mapping(bytes32 => bytes) public commitmentMetadata;

    struct PublicOutputs {
        bytes32 oldRoot;
        bytes32 newRoot;
        bytes32[] nullifiers;
        bytes32[] outputCommitments;
    }

    struct OutputCiphertext {
        bytes32 commitment;
        uint8 keyType;
        bytes ephemeralPubkey;
        bytes12 nonce;
        bytes ciphertext;
    }

    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event OutputCommitted(
        bytes32 indexed commitment,
        uint8 keyType,
        bytes ephemeralPubkey,
        bytes12 nonce,
        bytes ciphertext
    );
    event Deposited(address indexed from, uint256 amount, bytes32 commitment);
    event Withdrawn(address indexed to, uint256 amount);
    event MetadataPosted(bytes32 indexed commitment, uint256 metadataSize);
    event DepositAndTransfer(address indexed from, bytes32 depositCommitment, bytes32[] outputCommitments, uint256 totalAmount);

    constructor(bytes32 initialRoot, address _secp256r1Precompile, address _sp1Verifier, address _token) {
        currentRoot = initialRoot;
        secp256r1Precompile = _secp256r1Precompile;
        sp1Verifier = _sp1Verifier;
        token = _token;
    }

    /// @notice Check if this ledger uses ERC20 tokens (vs native ETH)
    function isERC20() public view returns (bool) {
        return token != address(0);
    }

    function deposit(
        bytes32 commitment,
        OutputCiphertext calldata encrypted,
        bytes calldata metadata,
        uint256 amount
    ) external payable {
        require(encrypted.commitment == commitment, "Commitment mismatch");

        uint256 depositAmount;
        if (token == address(0)) {
            // Native ETH deposit
            require(msg.value > 0, "Must deposit ETH");
            depositAmount = msg.value;
        } else {
            // ERC20 token deposit
            require(amount > 0, "Must deposit tokens");
            require(msg.value == 0, "Cannot send ETH for token deposit");
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            depositAmount = amount;
        }

        bytes32 oldRoot = currentRoot;
        bytes32 newRoot = keccak256(abi.encodePacked(oldRoot, commitment));
        currentRoot = newRoot;

        totalDeposited += depositAmount;

        if (metadata.length > 0) {
            require(metadata.length < 100_000, "Metadata too large");
            commitmentMetadata[commitment] = metadata;
            emit MetadataPosted(commitment, metadata.length);
        }

        emit Deposited(msg.sender, depositAmount, commitment);
        emit OutputCommitted(
            encrypted.commitment,
            encrypted.keyType,
            encrypted.ephemeralPubkey,
            encrypted.nonce,
            encrypted.ciphertext
        );
        emit RootUpdated(oldRoot, newRoot);
    }

    function deposit(
        bytes32 commitment,
        OutputCiphertext calldata encrypted,
        uint256 amount
    ) external payable {
        require(encrypted.commitment == commitment, "Commitment mismatch");

        uint256 depositAmount;
        if (token == address(0)) {
            // Native ETH deposit
            require(msg.value > 0, "Must deposit ETH");
            depositAmount = msg.value;
        } else {
            // ERC20 token deposit
            require(amount > 0, "Must deposit tokens");
            require(msg.value == 0, "Cannot send ETH for token deposit");
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            depositAmount = amount;
        }

        bytes32 oldRoot = currentRoot;
        bytes32 newRoot = keccak256(abi.encodePacked(oldRoot, commitment));
        currentRoot = newRoot;

        totalDeposited += depositAmount;

        emit Deposited(msg.sender, depositAmount, commitment);
        emit OutputCommitted(
            encrypted.commitment,
            encrypted.keyType,
            encrypted.ephemeralPubkey,
            encrypted.nonce,
            encrypted.ciphertext
        );
        emit RootUpdated(oldRoot, newRoot);
    }

    /// @notice Deposit ERC20 tokens using Permit2 signature (gasless approval)
    /// @dev User must have approved Permit2 contract once for all future deposits
    /// @param commitment The UTXO commitment hash
    /// @param encrypted The encrypted note data
    /// @param amount The amount to deposit
    /// @param permit The Permit2 permit data signed by the depositor
    /// @param signature The EIP-712 signature from the depositor
    /// @param depositor The address of the token owner (signer)
    function depositWithPermit2(
        bytes32 commitment,
        OutputCiphertext calldata encrypted,
        uint256 amount,
        ISignatureTransfer.PermitTransferFrom calldata permit,
        bytes calldata signature,
        address depositor
    ) external {
        require(token != address(0), "Permit2 only for ERC20");
        require(encrypted.commitment == commitment, "Commitment mismatch");
        require(amount > 0, "Must deposit tokens");
        require(permit.permitted.token == token, "Wrong token");
        require(permit.permitted.amount >= amount, "Insufficient permit amount");

        // Transfer tokens via Permit2 (verifies signature internally)
        PERMIT2.permitTransferFrom(
            permit,
            ISignatureTransfer.SignatureTransferDetails({
                to: address(this),
                requestedAmount: amount
            }),
            depositor,
            signature
        );

        // Update merkle root
        bytes32 oldRoot = currentRoot;
        bytes32 newRoot = keccak256(abi.encodePacked(oldRoot, commitment));
        currentRoot = newRoot;
        totalDeposited += amount;

        emit Deposited(depositor, amount, commitment);
        emit OutputCommitted(
            encrypted.commitment,
            encrypted.keyType,
            encrypted.ephemeralPubkey,
            encrypted.nonce,
            encrypted.ciphertext
        );
        emit RootUpdated(oldRoot, newRoot);
    }

    /// @notice Submit a proven transaction (SECURITY: outputs decoded from publicValues)
    function submitTx(
        OutputCiphertext[] calldata encryptedOutputs,
        bytes calldata proof,
        bytes calldata publicValues  // ABI-encoded PublicOutputs from SP1 zkVM
    ) external {
        bytes[] memory emptyMetadata = new bytes[](0);
        _submitTxWithMetadata(encryptedOutputs, emptyMetadata, proof, publicValues);
    }

    /// @notice Submit a proven transaction with metadata (SECURITY: outputs decoded from publicValues)
    function submitTxWithMetadata(
        OutputCiphertext[] calldata encryptedOutputs,
        bytes[] calldata metadata,
        bytes calldata proof,
        bytes calldata publicValues  // ABI-encoded PublicOutputs from SP1 zkVM
    ) external {
        _submitTxWithMetadata(encryptedOutputs, metadata, proof, publicValues);
    }

    function _submitTxWithMetadata(
        OutputCiphertext[] calldata encryptedOutputs,
        bytes[] memory metadata,
        bytes calldata proof,
        bytes calldata publicValues  // ABI-encoded PublicOutputs from SP1 zkVM
    ) internal {
        // Always verify SP1 Groth16 proof
        require(sp1Verifier != address(0), "SP1 verifier not configured");

        // Verify the proof - this cryptographically binds publicValues to the proof
        ISP1Verifier(sp1Verifier).verifyProof(UTXO_PROGRAM_VKEY, publicValues, proof);

        // SECURITY FIX: Decode outputs directly from the proven publicValues
        // This ensures the values we use are exactly what was proven in the ZK circuit
        // Previously, outputs was a separate parameter that could be manipulated
        PublicOutputs memory outputs = abi.decode(publicValues, (PublicOutputs));

        require(outputs.oldRoot == currentRoot, "Invalid old root");
        require(metadata.length == 0 || metadata.length == encryptedOutputs.length, "Metadata length mismatch");

        for (uint i = 0; i < outputs.nullifiers.length; i++) {
            bytes32 nullifier = outputs.nullifiers[i];
            require(!nullifierUsed[nullifier], "Nullifier already used");
            nullifierUsed[nullifier] = true;
        }

        require(encryptedOutputs.length == outputs.outputCommitments.length, "Ciphertext count mismatch");

        for (uint i = 0; i < encryptedOutputs.length; i++) {
            require(encryptedOutputs[i].commitment == outputs.outputCommitments[i], "Commitment mismatch");

            if (encryptedOutputs[i].keyType == 1) {
                require(secp256r1Precompile != address(0), "secp256r1 not supported");
            } else if (encryptedOutputs[i].keyType != 0) {
                revert("Unsupported key type");
            }

            emit OutputCommitted(
                encryptedOutputs[i].commitment,
                encryptedOutputs[i].keyType,
                encryptedOutputs[i].ephemeralPubkey,
                encryptedOutputs[i].nonce,
                encryptedOutputs[i].ciphertext
            );

            if (metadata.length > 0 && metadata[i].length > 0) {
                require(metadata[i].length < 100_000, "Metadata too large");
                bytes32 commitment = outputs.outputCommitments[i];
                commitmentMetadata[commitment] = metadata[i];
                emit MetadataPosted(commitment, metadata[i].length);
            }
        }

        currentRoot = outputs.newRoot;
        emit RootUpdated(outputs.oldRoot, outputs.newRoot);
    }

    /// @notice Withdraw funds with optional change output (SECURITY: outputs decoded from publicValues)
    function withdraw(
        address recipient,
        uint256 amount,
        bytes calldata proof,
        bytes calldata publicValues,  // ABI-encoded PublicOutputs from SP1 zkVM
        OutputCiphertext[] calldata encryptedOutputs  // Change outputs (if any)
    ) external {
        // Always verify SP1 Groth16 proof
        require(sp1Verifier != address(0), "SP1 verifier not configured");

        // Verify the proof - this cryptographically binds publicValues to the proof
        ISP1Verifier(sp1Verifier).verifyProof(UTXO_PROGRAM_VKEY, publicValues, proof);

        // SECURITY FIX: Decode outputs directly from the proven publicValues
        PublicOutputs memory outputs = abi.decode(publicValues, (PublicOutputs));

        require(outputs.oldRoot == currentRoot, "Invalid old root");
        require(amount > 0, "Amount must be positive");
        require(amount <= totalDeposited, "Insufficient contract balance");

        // Verify encrypted outputs match proven commitments (for change notes)
        require(encryptedOutputs.length == outputs.outputCommitments.length, "Output count mismatch");
        for (uint i = 0; i < encryptedOutputs.length; i++) {
            require(encryptedOutputs[i].commitment == outputs.outputCommitments[i], "Commitment mismatch");
        }

        for (uint i = 0; i < outputs.nullifiers.length; i++) {
            bytes32 nullifier = outputs.nullifiers[i];
            require(!nullifierUsed[nullifier], "Nullifier already used");
            nullifierUsed[nullifier] = true;
        }

        currentRoot = outputs.newRoot;
        emit RootUpdated(outputs.oldRoot, outputs.newRoot);

        // Emit OutputCommitted for each change output (so scanner can find them)
        for (uint i = 0; i < encryptedOutputs.length; i++) {
            emit OutputCommitted(
                encryptedOutputs[i].commitment,
                encryptedOutputs[i].keyType,
                encryptedOutputs[i].ephemeralPubkey,
                encryptedOutputs[i].nonce,
                encryptedOutputs[i].ciphertext
            );
        }

        totalDeposited -= amount;

        // Transfer ETH or ERC20 tokens
        if (token == address(0)) {
            payable(recipient).transfer(amount);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit Withdrawn(recipient, amount);
    }

    /// @notice Deposit and transfer atomically (SECURITY: outputs decoded from publicValues)
    function depositAndTransfer(
        bytes32 depositCommitment,
        OutputCiphertext[] calldata encryptedOutputs,
        bytes calldata proof,
        bytes calldata publicValues,  // ABI-encoded PublicOutputs from SP1 zkVM
        uint256 amount
    ) external payable {
        require(depositCommitment != bytes32(0), "Invalid deposit commitment");

        // Always verify SP1 Groth16 proof for the transfer portion
        require(sp1Verifier != address(0), "SP1 verifier not configured");

        uint256 depositAmount;
        if (token == address(0)) {
            // Native ETH deposit
            require(msg.value > 0, "Must send ETH");
            depositAmount = msg.value;
        } else {
            // ERC20 token deposit
            require(amount > 0, "Must deposit tokens");
            require(msg.value == 0, "Cannot send ETH for token deposit");
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            depositAmount = amount;
        }

        bytes32 oldRoot = currentRoot;
        currentRoot = keccak256(abi.encodePacked(currentRoot, depositCommitment));
        totalDeposited += depositAmount;

        emit Deposited(msg.sender, depositAmount, depositCommitment);
        emit RootUpdated(oldRoot, currentRoot);

        // Verify SP1 Groth16 proof - this cryptographically binds publicValues to the proof
        ISP1Verifier(sp1Verifier).verifyProof(UTXO_PROGRAM_VKEY, publicValues, proof);

        // SECURITY FIX: Decode outputs directly from the proven publicValues
        PublicOutputs memory transferOutputs = abi.decode(publicValues, (PublicOutputs));

        require(transferOutputs.outputCommitments.length > 0, "Must have outputs");
        require(transferOutputs.oldRoot == currentRoot, "Transfer oldRoot mismatch");

        for (uint i = 0; i < transferOutputs.nullifiers.length; i++) {
            bytes32 nf = transferOutputs.nullifiers[i];
            require(!nullifierUsed[nf], "Nullifier already used");
            nullifierUsed[nf] = true;
        }

        bytes32 previousRoot = currentRoot;
        currentRoot = transferOutputs.newRoot;

        emit RootUpdated(previousRoot, transferOutputs.newRoot);
        emit DepositAndTransfer(msg.sender, depositCommitment, transferOutputs.outputCommitments, depositAmount);
    }

    function getMetadata(bytes32 commitment) external view returns (bytes memory) {
        return commitmentMetadata[commitment];
    }

    function supportsSecp256r1() external view returns (bool) {
        return secp256r1Precompile != address(0);
    }

    function getBalance() external view returns (uint256) {
        if (token == address(0)) {
            return address(this).balance;
        } else {
            return IERC20(token).balanceOf(address(this));
        }
    }
}