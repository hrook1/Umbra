import { createPublicClient, http, parseAbiItem, keccak256 } from 'viem'
import * as secp256k1 from '@noble/secp256k1'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { PRIVATE_UTXO_LEDGER, DEPLOYMENT_BLOCK, getCurrentChain, getRpcUrl } from './config'

// Configure HMAC for secp256k1 v3 (Required for synchronous signing)
secp256k1.hashes.hmacSha256 = (k: Uint8Array, ...msgs: Uint8Array[]) => {
  const data = secp256k1.etc.concatBytes(...msgs)
  return hmac(sha256, k, data)
}
secp256k1.hashes.sha256 = (...msgs: Uint8Array[]) => {
  const data = secp256k1.etc.concatBytes(...msgs)
  return sha256(data)
}


// New KDF using HKDF (for new UTXOs)
function kdfNew(sharedSecret: Uint8Array): Uint8Array {
  // Rust: Hkdf::<Sha256>::new(None, shared_secret).expand(b"utxo-prototype-v1-encryption", &mut key)
  // @noble/hashes/hkdf: hkdf(sha256, sharedSecret, salt, info, length)
  return hkdf(sha256, sharedSecret, undefined, new TextEncoder().encode('utxo-prototype-v1-encryption'), 32)
}

// Legacy KDF for backward compatibility with existing UTXOs
// Original: sha256(sharedSecret) with compression byte skipped
function kdfLegacy(sharedSecret: Uint8Array): Uint8Array {
  // Skip the compression byte (first byte) as the original code did
  return sha256(sharedSecret.slice(1))
}

/**
 * Derive private/public keys from a signature
 * This allows users to "login" with just a Metamask signature
 */
export async function deriveKeys(signature: string): Promise<{
  privateKey: Uint8Array
  publicKey: Uint8Array
  address: string
}> {
  // Hash the signature with domain separation to derive a private key
  // Domain separation ensures keys are unique to this application
  const domain = 'utxo-prototype-v1-key-derivation:'
  const privateKey = sha256(new TextEncoder().encode(domain + signature))

  // Derive public key from private key
  const publicKey = secp256k1.getPublicKey(privateKey, true)

  // Address (for display/sharing)
  // We use the hex string of the compressed public key as the "Private Address"
  const address = '0x' + Buffer.from(publicKey).toString('hex')

  return { privateKey, publicKey, address }
}

// Compute nullifier: Hash(signature)
// MUST match Rust prover implementation in core/src/note.rs:compute_nullifier
// signature: 65-byte hex string (r, s, v)
export function computeNullifier(signature: string): string {
  // Domain separator MUST match Rust: b"NULLIFIER_v1"
  const domain = new TextEncoder().encode('NULLIFIER_v1')

  // Clean inputs
  const sigClean = signature.startsWith('0x') ? signature.slice(2) : signature
  const sigBytes = Buffer.from(sigClean, 'hex')

  if (sigBytes.length !== 65) throw new Error(`Invalid signature length: ${sigBytes.length}`)

  const data = new Uint8Array(domain.length + sigBytes.length)
  data.set(domain)
  data.set(sigBytes, domain.length)

  // Use Blake3 to match the Rust prover
  return '0x' + Buffer.from(blake3(data)).toString('hex')
}

/**
 * Compute commitment: Hash(domain | amount_le | ownerX | blinding)
 * MUST match Rust prover implementation in core/src/note.rs:commit
 *
 * Rust uses:
 * - Blake3 hash
 * - Domain separator: b"NOTE_COMMITMENT_v1"
 * - Amount as 8-byte little-endian (u64)
 * - Owner pubkey X-coord:
 */
export function computeCommitment(amount: bigint, ownerX: string, blinding: string): string {
  // ownerX should be the X-coord only (32 bytes / 64 hex chars)
  // If passed with 0x prefix, strip it
  const ownerXClean = ownerX.startsWith('0x') ? ownerX.slice(2) : ownerX
  const blindingClean = blinding.startsWith('0x') ? blinding.slice(2) : blinding

  // Domain separator MUST match Rust: b"NOTE_COMMITMENT_v1"
  const domain = new TextEncoder().encode('NOTE_COMMITMENT_v1')

  // Amount as 8-byte little-endian (matching Rust's u64.to_le_bytes())
  const amountLE = new Uint8Array(8)
  let amt = amount
  for (let i = 0; i < 8; i++) {
    amountLE[i] = Number(amt & 0xffn)
    amt >>= 8n
  }

  // Owner X-coord (32 bytes)
  const ownerBytes = Buffer.from(ownerXClean.padStart(64, '0'), 'hex')

  // Blinding (32 bytes)
  const blindingBytes = Buffer.from(blindingClean.padStart(64, '0'), 'hex')

  // Concatenate: domain + amount(8 LE) + owner(32) + blinding(32)
  const data = new Uint8Array(domain.length + 8 + 32 + 32)
  data.set(domain, 0)
  data.set(amountLE, domain.length)
  data.set(ownerBytes, domain.length + 8)
  data.set(blindingBytes, domain.length + 8 + 32)

  // Use Blake3 to match the Rust prover
  return '0x' + Buffer.from(blake3(data)).toString('hex')
}

/**
 * Validate a compressed secp256k1 public key (M-2 fix)
 * Returns true if valid, false otherwise
 */
export function validatePublicKey(pubkeyHex: string): boolean {
  try {
    const hex = pubkeyHex.startsWith('0x') ? pubkeyHex.slice(2) : pubkeyHex
    // Compressed public keys are 33 bytes (66 hex chars)
    if (hex.length !== 66) return false
    // Must start with 02 or 03
    if (!hex.startsWith('02') && !hex.startsWith('03')) return false
    // Parse the public key bytes and attempt ECDH - will throw if invalid point
    const pubkeyBytes = new Uint8Array(Buffer.from(hex, 'hex'))
    // Generate a dummy private key for validation
    const dummyPriv = new Uint8Array(32)
    dummyPriv[0] = 1 // Valid private key (just 1)
    secp256k1.getSharedSecret(dummyPriv, pubkeyBytes, true)
    return true
  } catch {
    return false
  }
}

// AES-256-GCM decryption using Web Crypto API
async function decryptAES256GCM(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array | null> {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(key).buffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    )

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(nonce).buffer },
      cryptoKey,
      new Uint8Array(ciphertext).buffer
    )

    return new Uint8Array(decrypted)
  } catch (error) {
    return null
  }
}

// Decrypt a UTXO note - tries both legacy and new KDF for backward compatibility
async function decryptNote(
  ephemeralPubkey: string,
  nonce: string,
  ciphertext: string,
  privateKey: Uint8Array
): Promise<{ amount: bigint; owner: string; blinding: string; contactName?: string } | null> {
  try {
    const ephPubkey = ephemeralPubkey.startsWith('0x') ? ephemeralPubkey.slice(2) : ephemeralPubkey

    const ephemeralPubkeyBytes = new Uint8Array(Buffer.from(ephPubkey, 'hex'))
    const nonceBytes = new Uint8Array(Buffer.from(nonce.startsWith('0x') ? nonce.slice(2) : nonce, 'hex'))
    const ciphertextBytes = new Uint8Array(Buffer.from(ciphertext.startsWith('0x') ? ciphertext.slice(2) : ciphertext, 'hex'))

    // Perform ECDH
    const sharedSecret = secp256k1.getSharedSecret(privateKey, ephemeralPubkeyBytes, true)

    // Try legacy KDF first (for existing UTXOs), then new KDF
    const kdfs = [kdfLegacy, kdfNew]

    for (const kdf of kdfs) {
      const aesKey = kdf(sharedSecret)
      const plaintext = await decryptAES256GCM(aesKey, nonceBytes, ciphertextBytes)

      if (plaintext && plaintext.length >= 96) {
        // Parse: amount (32) + owner (32) + blinding (32) + [optional contactName]
        const amount = BigInt('0x' + Buffer.from(plaintext.slice(0, 32)).toString('hex'))
        const owner = '0x' + Buffer.from(plaintext.slice(32, 64)).toString('hex')
        const blinding = '0x' + Buffer.from(plaintext.slice(64, 96)).toString('hex')

        let contactName = undefined
        if (plaintext.length > 96) {
          const nameBytes = plaintext.slice(96)
          contactName = new TextDecoder().decode(nameBytes).replace(/\0/g, '')
        }

        return { amount, owner, blinding, contactName }
      }
    }

    return null
  } catch (error) {
    return null
  }
}

// Scan and decrypt UTXOs
export async function scanUTXOs(
  _userAddress: string, // ETH address
  privateKey: Uint8Array, // Derived private key
  derivedAddress: string, // The "Private Address"
  startBlock: bigint = DEPLOYMENT_BLOCK // Allow incremental scanning
): Promise<{
  utxos: Array<{
    commitment: string
    amount: bigint
    blockNumber: bigint
    blinding: string
    owner: string
    index: number
    contactName?: string
  }>
  totalBalance: bigint
  lastScannedBlock: bigint
}> {
  try {
    const { chain } = await getCurrentChain()

    const client = createPublicClient({
      chain,
      transport: http(getRpcUrl(chain.id))
    })

    const latestBlock = await client.getBlockNumber()

    // Safety check: if startBlock > latest, just return empty
    if (startBlock > latestBlock) {
      return { utxos: [], totalBalance: 0n, lastScannedBlock: latestBlock }
    }

    console.log(`[Scan] Fetching events from ${startBlock} to ${latestBlock}...`)

    const events = await client.getLogs({
      address: PRIVATE_UTXO_LEDGER,
      event: parseAbiItem('event OutputCommitted(bytes32 indexed commitment, uint8 keyType, bytes ephemeralPubkey, bytes12 nonce, bytes ciphertext)'),
      fromBlock: startBlock,
      toBlock: 'latest' // We use 'latest' to catch up to tip, but return explicit block number
    })

    console.log(`[Scan] Found ${events.length} events, attempting decryption...`)

    // 1. Parallel Decryption
    // We map events to promises of (DecryptedNote | null)
    const potentialNotes = await Promise.all(events.map(async (event, i) => {
      const { commitment, ephemeralPubkey, nonce, ciphertext } = event.args as any
      const decrypted = await decryptNote(ephemeralPubkey, nonce, ciphertext, privateKey)

      if (decrypted) {
        const myX = derivedAddress.slice(4).toLowerCase()
        const noteOwnerX = decrypted.owner.slice(2).toLowerCase()
        if (myX === noteOwnerX) {
          return {
            event,
            decrypted,
            commitment,
            originalIndex: i // Store the original index from the `events` array
          }
        }
      }
      return null
    }))

    const myNotes = potentialNotes.filter(n => n !== null) as NonNullable<typeof potentialNotes[0]>[]

    if (myNotes.length === 0) {
      return { utxos: [], totalBalance: 0n, lastScannedBlock: latestBlock }
    }

    // 2. Multicall Nullifier Checks
    console.log(`[Scan] Checking ${myNotes.length} potential notes for spent status...`)

    // derivedAddress 0x[02/03][X]
    const myX = derivedAddress.slice(4)

    // Prepare multicall - compute nullifiers using signature-based method
    // For each note: commitment → sign → nullifier = Hash(signature)
    const nullifierChecks = await Promise.all(myNotes.map(async note => {
      // Compute commitment from decrypted note data
      const commitment = computeCommitment(
        note.decrypted.amount,
        note.decrypted.owner.slice(2), // Strip 0x prefix, use X-coord only
        note.decrypted.blinding
      )
      // Sign the commitment (NullifierSig)
      const nullifierSig = await signCommitment(privateKey, commitment)
      // Derive nullifier from signature
      const nullifier = computeNullifier(nullifierSig)
      return {
        address: PRIVATE_UTXO_LEDGER,
        abi: [parseAbiItem('function nullifierUsed(bytes32) view returns (bool)')],
        functionName: 'nullifierUsed',
        args: [nullifier as `0x${string}`]
      }
    }))

    const results = await client.multicall({
      contracts: nullifierChecks
    })

    const finalUTXOs: Array<{
      commitment: string
      amount: bigint
      blockNumber: bigint
      blinding: string
      owner: string
      index: number
      contactName?: string
    }> = []
    let decryptedCount = 0

    for (let j = 0; j < myNotes.length; j++) {
      const noteWrapper = myNotes[j]
      const result = results[j]

      // Strict check: Must succeed and explicitly return false (not spent)
      if (result.status === 'success') {
        const isSpent = result.result

        if (!isSpent) {
          // Skip zero-amount UTXOs - they're useless for spending
          if (noteWrapper.decrypted.amount === 0n) {
            continue
          }
          decryptedCount++
          finalUTXOs.push({
            commitment: noteWrapper.commitment,
            amount: noteWrapper.decrypted.amount,
            blockNumber: noteWrapper.event.blockNumber,
            blinding: noteWrapper.decrypted.blinding,
            owner: noteWrapper.decrypted.owner,
            // The 'index' here refers to the global Merkle tree leaf index.
            // This is only accurate if `startBlock` was `DEPLOYMENT_BLOCK`.
            // If `startBlock` is different, `noteWrapper.originalIndex` is just the index within the fetched batch.
            // For now, we assume a full scan from DEPLOYMENT_BLOCK for `index` to be valid.
            // If incremental scanning is fully implemented, this `index` will need to be adjusted by an offset.
            index: noteWrapper.originalIndex,
            contactName: noteWrapper.decrypted.contactName
          })
        }
      }
    }


    const totalBalance = finalUTXOs.reduce((sum, u) => sum + u.amount, BigInt(0))

    console.log(`[Scan] Successfully decrypted ${decryptedCount} UNSPENT UTXOs`)
    if (finalUTXOs.length > 0) {
      console.log(`[Scan] UTXO amounts:`, finalUTXOs.map(u => u.amount.toString()))
      console.log(`[Scan] Total balance:`, totalBalance.toString())
    }

    return {
      utxos: finalUTXOs,
      totalBalance,
      lastScannedBlock: latestBlock
    }

  } catch (error) {
    console.error('[Scan] Error:', error)
    return { utxos: [], totalBalance: 0n, lastScannedBlock: 0n }
  }
}

// Activity type for UI
export interface Activity {
  id: string
  type: 'received' | 'sent' | 'deposit' | 'withdraw'
  counterparty: string
  amount: number  // In USDC units (not wei)
  timestamp: Date
  txHash?: string
  status?: 'spent' | 'unspent' // Track if the received note has been spent
}

// Scan blockchain for activity history (received payments, deposits, etc.)
export async function scanActivities(
  walletAddress: string,
  privateKey: Uint8Array,
  derivedAddress: string
): Promise<Activity[]> {
  try {
    const { chain } = await getCurrentChain()

    const client = createPublicClient({
      chain,
      transport: http(getRpcUrl(chain.id))
    })

    console.log('[Activities] Fetching events...')

    // Get OutputCommitted events (these are received notes)
    const outputEvents = await client.getLogs({
      address: PRIVATE_UTXO_LEDGER,
      event: parseAbiItem('event OutputCommitted(bytes32 indexed commitment, uint8 keyType, bytes ephemeralPubkey, bytes12 nonce, bytes ciphertext)'),
      fromBlock: DEPLOYMENT_BLOCK,
      toBlock: 'latest'
    })

    // Get Deposited events (from this wallet)
    const depositEvents = await client.getLogs({
      address: PRIVATE_UTXO_LEDGER,
      event: parseAbiItem('event Deposited(address indexed from, uint256 amount, bytes32 commitment)'),
      fromBlock: DEPLOYMENT_BLOCK,
      toBlock: 'latest'
    })

    // Get Withdrawn events (to this wallet)
    const withdrawEvents = await client.getLogs({
      address: PRIVATE_UTXO_LEDGER,
      event: parseAbiItem('event Withdrawn(address indexed to, uint256 amount)'),
      fromBlock: DEPLOYMENT_BLOCK,
      toBlock: 'latest'
    })

    const activities: Activity[] = []

    // Process deposits from this wallet
    for (const event of depositEvents) {
      const { from, amount } = event.args as { from: string; amount: bigint; commitment: string }
      if (from.toLowerCase() === walletAddress.toLowerCase()) {
        const block = await client.getBlock({ blockNumber: event.blockNumber })
        activities.push({
          id: `deposit-${event.transactionHash}`,
          type: 'deposit',
          counterparty: 'Public Wallet',
          amount: Number(amount) / 1e6, // USDC has 6 decimals
          timestamp: new Date(Number(block.timestamp) * 1000),
          txHash: event.transactionHash
        })
      }
    }

    // Process withdrawals to this wallet
    for (const event of withdrawEvents) {
      const { to, amount } = event.args as { to: string; amount: bigint }
      if (to.toLowerCase() === walletAddress.toLowerCase()) {
        const block = await client.getBlock({ blockNumber: event.blockNumber })
        activities.push({
          id: `withdraw-${event.transactionHash}`,
          type: 'withdraw',
          counterparty: 'Public Wallet',
          amount: Number(amount) / 1e6, // USDC has 6 decimals
          timestamp: new Date(Number(block.timestamp) * 1000),
          txHash: event.transactionHash
        })
      }
    }

    // Process received notes (try to decrypt each one)
    for (const event of outputEvents) {
      const { commitment, ephemeralPubkey, nonce, ciphertext } = event.args as any

      const decrypted = await decryptNote(
        ephemeralPubkey,
        nonce,
        ciphertext,
        privateKey
      )

      if (decrypted) {
        const myX = derivedAddress.slice(4).toLowerCase()
        const noteOwnerX = decrypted.owner.slice(2).toLowerCase()

        if (myX === noteOwnerX) {
          // Check if this is a deposit (already counted above) by looking for matching deposit event
          const isDeposit = depositEvents.some(d =>
            (d.args as any).commitment === commitment &&
            (d.args as any).from.toLowerCase() === walletAddress.toLowerCase()
          )

          if (!isDeposit) {
            // This is a received payment from someone else
            const block = await client.getBlock({ blockNumber: event.blockNumber })

            // Check if nullifier is spent to mark status
            // Compute commitment from decrypted data, sign it, derive nullifier
            const computedCommitment = computeCommitment(
              decrypted.amount,
              decrypted.owner.slice(2), // Strip 0x prefix
              decrypted.blinding
            )
            const nullifierSig = await signCommitment(privateKey, computedCommitment)
            const nullifier = computeNullifier(nullifierSig)
            const isSpent = await client.readContract({
              address: PRIVATE_UTXO_LEDGER,
              abi: [parseAbiItem('function nullifierUsed(bytes32) view returns (bool)')],
              functionName: 'nullifierUsed',
              args: [nullifier as `0x${string}`]
            })

            activities.push({
              id: `received-${commitment}`,
              type: 'received',
              counterparty: decrypted.contactName || 'Unknown',
              amount: Number(decrypted.amount) / 1e6, // USDC has 6 decimals
              timestamp: new Date(Number(block.timestamp) * 1000),
              txHash: event.transactionHash,
              status: isSpent ? 'spent' : 'unspent'
            })
          }
        }
      }
    }

    // Sort by timestamp descending (newest first)
    activities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())

    console.log(`[Activities] Found ${activities.length} activities`)
    return activities

  } catch (error) {
    console.error('[Activities] Failed:', error)
    return []
  }
}

// Sign a note commitment for delegated proving (Split Witness)
// Matches Rust: Keccak256("\x19Ethereum Signed Message:\n32" + Keccak256(commitment))
export async function signCommitment(privateKey: Uint8Array, commitment: string): Promise<string> {
  // 1. Hash the commitment (Keccak256)
  // commitment is 0x... hex string
  const commitBytes = Buffer.from(commitment.startsWith('0x') ? commitment.slice(2) : commitment, 'hex')
  const msgHash = keccak256(commitBytes) // Returns 0x hex string

  // 2. Ethereum Signed Message hashing
  // "\x19Ethereum Signed Message:\n32" + Keccak256(commitment)
  const prefix = new TextEncoder().encode('\x19Ethereum Signed Message:\n32')
  const msgHashBytes = Buffer.from(msgHash.slice(2), 'hex')

  const ethMsg = new Uint8Array(prefix.length + msgHashBytes.length)
  ethMsg.set(prefix)
  ethMsg.set(msgHashBytes, prefix.length)

  const ethMsgHash = keccak256(ethMsg) // 0x hex string
  const ethMsgHashBytes = Buffer.from(ethMsgHash.slice(2), 'hex')

  // 3. Sign using secp256k1 v3 API
  // format: 'recovered' returns 65 bytes: recovery(1) + r(32) + s(32)
  // NOTE: Recovery byte is FIRST in noble/secp256k1 v3!
  // prehash: false because we already hashed with keccak256
  const sigBytes = secp256k1.sign(ethMsgHashBytes, privateKey, {
    prehash: false,
    format: 'recovered'
  })

  // sigBytes is Uint8Array[65]: recovery(1) + r(32) + s(32)
  // Recovery byte is 0 or 1, Ethereum uses 27/28
  const recoveryId = sigBytes[0] // Recovery byte is at index 0
  const r = sigBytes.slice(1, 33)  // r is bytes 1-32
  const s = sigBytes.slice(33, 65) // s is bytes 33-64

  // Build final 65-byte signature in Ethereum format: r(32) + s(32) + v(1)
  const fullSig = new Uint8Array(65)
  fullSig.set(r, 0)   // r at offset 0
  fullSig.set(s, 32)  // s at offset 32
  fullSig[64] = recoveryId + 27 // v = 27 + recovery_id

  const sigHex = Buffer.from(fullSig).toString('hex')
  return '0x' + sigHex
}
