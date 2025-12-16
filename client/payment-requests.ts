import { createPublicClient, createWalletClient, http, custom, keccak256, toBytes } from 'viem'
import { sepolia } from 'viem/chains'
import * as secp256k1 from '@noble/secp256k1'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { PAYMENT_REQUESTS_ADDRESS, getRpcUrl } from './config'
import { computeOwnerTag } from './contacts'

// ABI for PrivatePaymentRequests contract
const PAYMENT_REQUESTS_ABI = [
  {
    inputs: [
      { name: '_recipientTag', type: 'bytes8' },
      { name: '_encryptedPayload', type: 'bytes' }
    ],
    name: 'createRequest',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'payable',
    type: 'function'
  },
  {
    inputs: [{ name: '_tag', type: 'bytes8' }],
    name: 'getRequestsByTag',
    outputs: [{ name: '', type: 'uint256[]' }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [{ name: '_requestId', type: 'uint256' }],
    name: 'getRequest',
    outputs: [{
      components: [
        { name: 'recipientTag', type: 'bytes8' },
        { name: 'encryptedPayload', type: 'bytes' },
        { name: 'timestamp', type: 'uint256' },
        { name: 'status', type: 'uint8' }
      ],
      name: '',
      type: 'tuple'
    }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    inputs: [
      { name: '_requestId', type: 'uint256' },
      { name: '_txHash', type: 'bytes32' }
    ],
    name: 'approveRequest',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [{ name: '_requestId', type: 'uint256' }],
    name: 'rejectRequest',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function'
  },
  {
    inputs: [{ name: '_requestId', type: 'uint256' }],
    name: 'isExpired',
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function'
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: 'requestId', type: 'uint256' },
      { indexed: true, name: 'recipientTag', type: 'bytes8' },
      { name: 'encryptedPayload', type: 'bytes' },
      { name: 'timestamp', type: 'uint256' }
    ],
    name: 'RequestCreated',
    type: 'event'
  }
] as const

// Request status enum (matches contract)
export enum RequestStatus {
  Pending = 0,
  Approved = 1,
  Rejected = 2,
  Expired = 3
}

export interface PaymentRequest {
  id: string
  requester: {
    name: string
    address: string
  }
  amount: string
  reference: string
  message?: string
  timestamp: Date
  status: 'pending' | 'approved' | 'rejected' | 'expired'
}

// Payload structure for encrypted data
interface RequestPayload {
  requesterName: string
  requesterAddress: string
  amount: string
  reference: string
  message?: string
}

// HKDF-SHA256 for key derivation
function kdf(sharedSecret: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, new TextEncoder().encode('utxo-requests-v1'), 32)
}

// Encrypt payment request using recipient's public key (ECIES)
async function encryptRequestPayload(
  payload: RequestPayload,
  recipientPublicKey: Uint8Array
): Promise<`0x${string}`> {
  // Serialize payload to JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(payload))

  // Generate ephemeral key for encryption
  const ephemeralPriv = new Uint8Array(32)
  crypto.getRandomValues(ephemeralPriv)
  const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true)

  // ECDH shared secret
  const sharedSecret = secp256k1.getSharedSecret(ephemeralPriv, recipientPublicKey, true)
  const aesKey = kdf(sharedSecret)

  // AES-256-GCM encryption
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(aesKey).buffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    cryptoKey,
    plaintext
  )

  // Pack: [ephemeralPub(33)] [nonce(12)] [ciphertext(variable)]
  const result = new Uint8Array(33 + 12 + ciphertext.byteLength)
  result.set(ephemeralPub, 0)
  result.set(nonce, 33)
  result.set(new Uint8Array(ciphertext), 45)

  return `0x${Buffer.from(result).toString('hex')}` as `0x${string}`
}

// Decrypt payment request using recipient's private key
async function decryptRequestPayload(
  encryptedData: `0x${string}`,
  recipientPrivateKey: Uint8Array
): Promise<RequestPayload | null> {
  try {
    const data = Buffer.from(encryptedData.slice(2), 'hex')

    if (data.length < 45) {
      console.error('[PaymentRequests] Encrypted data too short')
      return null
    }

    // Unpack: [ephemeralPub(33)] [nonce(12)] [ciphertext]
    const ephemeralPub = data.subarray(0, 33)
    const nonce = data.subarray(33, 45)
    const ciphertext = data.subarray(45)

    // ECDH shared secret
    const sharedSecret = secp256k1.getSharedSecret(recipientPrivateKey, ephemeralPub, true)
    const aesKey = kdf(sharedSecret)

    // AES-256-GCM decryption
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(aesKey).buffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    )
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      cryptoKey,
      ciphertext
    )
    const decrypted = new TextDecoder().decode(plaintext)

    return JSON.parse(decrypted) as RequestPayload
  } catch (error) {
    console.error('[PaymentRequests] Decryption failed:', error)
    return null
  }
}

// Relayer URL
const RELAYER_URL = process.env.NEXT_PUBLIC_RELAYER_URL || 'http://localhost:3002'

// Create a new payment request via relayer (gasless)
export async function createPaymentRequest(
  recipientPublicKeyHex: string,
  requesterName: string,
  requesterAddress: string,
  amount: string,
  reference: string,
  message: string | undefined,
  _walletAddress: string // Not needed anymore, kept for API compatibility
): Promise<{ txHash: string; requestId: number }> {
  console.log('[PaymentRequests] Creating request via relayer for:', recipientPublicKeyHex.slice(0, 20) + '...')

  // Parse recipient public key
  const cleanHex = recipientPublicKeyHex.startsWith('0x')
    ? recipientPublicKeyHex.slice(2)
    : recipientPublicKeyHex
  const recipientPubKey = new Uint8Array(Buffer.from(cleanHex, 'hex'))

  // Compute recipient tag for lookup
  const recipientTag = computeOwnerTag(recipientPublicKeyHex)
  console.log('[PaymentRequests] Recipient tag:', recipientTag)

  // Build and encrypt payload
  const payload: RequestPayload = {
    requesterName,
    requesterAddress,
    amount,
    reference,
    ...(message && { message })
  }

  const encryptedPayload = await encryptRequestPayload(payload, recipientPubKey)
  console.log('[PaymentRequests] Encrypted payload length:', encryptedPayload.length)

  // Send via relayer (gasless)
  const response = await fetch(`${RELAYER_URL}/api/create-payment-request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      recipientTag,
      encryptedPayload: '0x' + Buffer.from(encryptedPayload).toString('hex')
    })
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.error || 'Failed to create payment request')
  }

  const result = await response.json()
  console.log('[PaymentRequests] Request created via relayer:', result.txHash)

  // Request ID will be assigned by contract
  return { txHash: result.txHash, requestId: 0 }
}

// Load all payment requests for a recipient
export async function loadPaymentRequests(
  recipientPrivateKey: Uint8Array,
  recipientPublicKeyHex: string
): Promise<PaymentRequest[]> {
  console.log('[PaymentRequests] Loading requests...')

  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(getRpcUrl())
  })

  // Compute recipient tag
  const recipientTag = computeOwnerTag(recipientPublicKeyHex)
  console.log('[PaymentRequests] Loading requests for tag:', recipientTag)

  // Get request IDs for this recipient
  const requestIds = await publicClient.readContract({
    address: PAYMENT_REQUESTS_ADDRESS,
    abi: PAYMENT_REQUESTS_ABI,
    functionName: 'getRequestsByTag',
    args: [recipientTag as `0x${string}`]
  }) as bigint[]

  if (requestIds.length === 0) {
    console.log('[PaymentRequests] No requests found')
    return []
  }

  console.log('[PaymentRequests] Found', requestIds.length, 'request IDs')

  // Fetch and decrypt each request
  const requests: PaymentRequest[] = []
  for (const requestId of requestIds) {
    try {
      const encryptedRequest = await publicClient.readContract({
        address: PAYMENT_REQUESTS_ADDRESS,
        abi: PAYMENT_REQUESTS_ABI,
        functionName: 'getRequest',
        args: [requestId]
      }) as { recipientTag: `0x${string}`; encryptedPayload: `0x${string}`; timestamp: bigint; status: number }

      // Skip empty or deleted requests
      if (!encryptedRequest.encryptedPayload || encryptedRequest.encryptedPayload === '0x') {
        continue
      }

      const payload = await decryptRequestPayload(encryptedRequest.encryptedPayload, recipientPrivateKey)
      if (payload) {
        // Map status number to string
        let status: PaymentRequest['status'] = 'pending'
        switch (encryptedRequest.status) {
          case RequestStatus.Approved:
            status = 'approved'
            break
          case RequestStatus.Rejected:
            status = 'rejected'
            break
          case RequestStatus.Expired:
            status = 'expired'
            break
        }

        requests.push({
          id: requestId.toString(),
          requester: {
            name: payload.requesterName,
            address: payload.requesterAddress
          },
          amount: payload.amount,
          reference: payload.reference,
          message: payload.message,
          timestamp: new Date(Number(encryptedRequest.timestamp) * 1000),
          status
        })
      }
    } catch (error) {
      console.error('[PaymentRequests] Failed to load request', requestId.toString(), error)
    }
  }

  console.log('[PaymentRequests] Loaded', requests.length, 'requests')
  return requests
}

// Approve a payment request (mark as paid)
export async function approvePaymentRequest(
  requestId: string,
  paymentTxHash: string,
  walletAddress: string
): Promise<string> {
  if (!window.ethereum) throw new Error('MetaMask not found')

  console.log('[PaymentRequests] Approving request:', requestId)

  const walletClient = createWalletClient({
    chain: sepolia,
    transport: custom(window.ethereum),
    account: walletAddress as `0x${string}`
  })

  // Convert tx hash to bytes32
  const txHashBytes = paymentTxHash.startsWith('0x')
    ? paymentTxHash as `0x${string}`
    : `0x${paymentTxHash}` as `0x${string}`

  const txHash = await walletClient.writeContract({
    address: PAYMENT_REQUESTS_ADDRESS,
    abi: PAYMENT_REQUESTS_ABI,
    functionName: 'approveRequest',
    args: [BigInt(requestId), txHashBytes as `0x${string}`]
  })

  console.log('[PaymentRequests] Approve transaction:', txHash)

  // Wait for confirmation
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(getRpcUrl())
  })

  await publicClient.waitForTransactionReceipt({ hash: txHash })
  console.log('[PaymentRequests] Request approved')

  return txHash
}

// Reject a payment request
export async function rejectPaymentRequest(
  requestId: string,
  walletAddress: string
): Promise<string> {
  if (!window.ethereum) throw new Error('MetaMask not found')

  console.log('[PaymentRequests] Rejecting request:', requestId)

  const walletClient = createWalletClient({
    chain: sepolia,
    transport: custom(window.ethereum),
    account: walletAddress as `0x${string}`
  })

  const txHash = await walletClient.writeContract({
    address: PAYMENT_REQUESTS_ADDRESS,
    abi: PAYMENT_REQUESTS_ABI,
    functionName: 'rejectRequest',
    args: [BigInt(requestId)]
  })

  console.log('[PaymentRequests] Reject transaction:', txHash)

  // Wait for confirmation
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(getRpcUrl())
  })

  await publicClient.waitForTransactionReceipt({ hash: txHash })
  console.log('[PaymentRequests] Request rejected')

  return txHash
}
