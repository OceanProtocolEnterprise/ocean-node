import { ReadableString } from '../../P2P/handleProtocolCommands.js'
import { OceanNodeConfig, P2PCommandResponse } from '../../../@types/OceanNode.js'
import { ethers } from 'ethers'
import { GENERIC_EMOJIS, LOG_LEVELS_STR } from '../../../utils/logging/Logger.js'
import { CORE_LOGGER, DATABASE_LOGGER } from '../../../utils/logging/common.js'
import { AbstractNonceDatabase } from '../../database/BaseDatabase.js'
import { CoreHandlersRegistry } from '../handler/coreHandlersRegistry.js'
import { OceanNode } from '../../../OceanNode.js'
import { PROTOCOL_COMMANDS } from '../../../utils/constants.js'
import { NonceCommand } from '../../../@types/commands.js'
import { streamToString } from '../../../utils/util.js'
import { Readable } from 'node:stream'

export function getDefaultErrorResponse(errorMessage: string): P2PCommandResponse {
  return {
    stream: null,
    status: { httpStatus: 500, error: 'Unknown error: ' + errorMessage }
  }
}

export function getDefaultResponse(nonce: number): P2PCommandResponse {
  const streamResponse = new ReadableString(String(nonce))
  // set nonce here
  return {
    status: {
      httpStatus: 200,
      headers: {
        'Content-Type': 'text/plain'
      }
    },
    stream: streamResponse
  }
}

// returns true/false (+ error message if needed)
export type NonceResponse = {
  valid: boolean
  error?: string
}

// we are doing the nonce stream response transformation in a few places
// so we can use this shortcut function when we just want the final number
export async function getNonceAsNumber(address: string): Promise<number> {
  const command: NonceCommand = { command: PROTOCOL_COMMANDS.NONCE, address }
  const nonceResponse = await CoreHandlersRegistry.getInstance(OceanNode.getInstance())
    .getHandlerForTask(command)
    .handle(command)
  if (nonceResponse.stream) {
    return await Number(streamToString(nonceResponse.stream as Readable))
  }
  return 0
}
// get stored nonce for an address ( 0 if not found)
export async function getNonce(
  db: AbstractNonceDatabase,
  address: string
): Promise<P2PCommandResponse> {
  // get nonce from db
  try {
    const nonceResponse = await db.retrieve(address)
    if (nonceResponse && nonceResponse.nonce !== null) {
      return getDefaultResponse(nonceResponse.nonce)
    }
    // // did not found anything, try add it and return default
    const setFirst = await db.create(address, 0)
    if (setFirst) {
      return getDefaultResponse(0)
    }
    return getDefaultErrorResponse(
      `Unable to retrieve nonce neither set first default for: ${address}`
    )
  } catch (err) {
    // did not found anything, try add it and return default
    if (err.message.indexOf(address) > -1) {
      return getDefaultErrorResponse(err.message)
    } else {
      DATABASE_LOGGER.logMessageWithEmoji(
        'Failure executing nonce task: ' + err.message,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return getDefaultErrorResponse(err.message)
    }
  }
}

// update stored nonce for an address
async function updateNonce(
  db: AbstractNonceDatabase,
  address: string,
  nonce: number
): Promise<NonceResponse> {
  try {
    // update nonce on db
    // it will create if none exists yet
    const resp = await db.update(address, nonce)
    return {
      valid: resp != null,
      error: resp == null ? 'error updating nonce to: ' + nonce : null
    }
  } catch (err) {
    DATABASE_LOGGER.logMessageWithEmoji(
      'Failure executing nonce task: ' + err.message,
      true,
      GENERIC_EMOJIS.EMOJI_CROSS_MARK,
      LOG_LEVELS_STR.LEVEL_ERROR
    )
    return {
      valid: false,
      error: err.message
    }
  }
}

// get stored nonce for an address, update it on db, validate signature
export async function checkNonce(
  config: OceanNodeConfig,
  db: AbstractNonceDatabase,
  consumer: string,
  nonce: number,
  signature: string,
  command: string,
  chainId?: string | null
): Promise<NonceResponse> {
  try {
    // get nonce from db
    let previousNonce = 0 // if none exists
    const existingNonce = await db.retrieve(consumer)
    if (existingNonce && existingNonce.nonce !== null) {
      previousNonce = existingNonce.nonce
    }
    // check if bigger than previous stored one and validate signature
    const validate = await validateNonceAndSignature(
      nonce,
      previousNonce, // will return 0 if none exists
      consumer,
      signature,
      command,
      config,
      chainId
    )
    if (validate.valid) {
      const updateStatus = await updateNonce(db, consumer, nonce)
      return updateStatus
    } else {
      // log error level when validation failed
      CORE_LOGGER.logMessageWithEmoji(
        'Failure when validating nonce and signature: ' + validate.error,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        valid: false,
        error: validate.error
      }
    }
    // return validation status and possible error msg
  } catch (err) {
    DATABASE_LOGGER.logMessageWithEmoji(
      'Failure executing nonce task: ' + err.message,
      true,
      GENERIC_EMOJIS.EMOJI_CROSS_MARK,
      LOG_LEVELS_STR.LEVEL_ERROR
    )
    return {
      valid: false,
      error: err.message
    }
  }
}

/**
 *
 * @param nonce nonce
 * @param existingNonce store nonce
 * @param consumer address
 * @param signature sign(nonce)
 * @param message Use this message instead of default String(nonce)
 * @returns true or false + error message
 */
async function validateNonceAndSignature(
  nonce: number,
  existingNonce: number,
  consumer: string,
  signature: string,
  command: string = null,
  config: OceanNodeConfig,
  chainId?: string | null
): Promise<NonceResponse> {
  CORE_LOGGER.logMessage(
    `Validating nonce and signature: ${JSON.stringify({
      nonce,
      existingNonce,
      consumer,
      command,
      chainId: chainId || null,
      signaturePresent: Boolean(signature),
      signatureLength: signature?.length || 0,
      signaturePrefix: signature?.slice(0, 10) || null
    })}`,
    true
  )

  if (nonce <= existingNonce) {
    CORE_LOGGER.error(
      `Nonce validation failed: received nonce ${nonce} is not greater than existing nonce ${existingNonce} for consumer ${consumer}`
    )
    return {
      valid: false,
      error: 'nonce: ' + nonce + ' is not a valid nonce'
    }
  }
  const message = String(String(consumer) + String(nonce) + String(command))
  const consumerMessage = ethers.solidityPackedKeccak256(
    ['bytes'],
    [ethers.hexlify(ethers.toUtf8Bytes(message))]
  )
  const messageHashBytes = ethers.toBeArray(consumerMessage)
  CORE_LOGGER.logMessage(
    `Signature verification inputs: ${JSON.stringify({
      message,
      consumerMessage,
      messageHashBytesLength: messageHashBytes.length
    })}`,
    true
  )

  // Try EOA signature validation
  try {
    const addressFromHashSignature = ethers.verifyMessage(consumerMessage, signature)
    const addressFromBytesSignature = ethers.verifyMessage(messageHashBytes, signature)
    const normalizedConsumer = ethers.getAddress(consumer).toLowerCase()
    const hashSignatureMatches =
      ethers.getAddress(addressFromHashSignature).toLowerCase() === normalizedConsumer
    const bytesSignatureMatches =
      ethers.getAddress(addressFromBytesSignature).toLowerCase() === normalizedConsumer

    CORE_LOGGER.logMessage(
      `EOA signature verification result: ${JSON.stringify({
        normalizedConsumer,
        addressFromHashSignature,
        addressFromBytesSignature,
        hashSignatureMatches,
        bytesSignatureMatches
      })}`,
      true
    )

    if (hashSignatureMatches || bytesSignatureMatches) {
      return { valid: true }
    }
  } catch (error) {
    CORE_LOGGER.error(
      `EOA signature verification threw an error for consumer ${consumer}: ${error instanceof Error ? error.message : String(error)}`
    )
    // Continue to smart account check
  }

  // Try ERC-1271 (smart account) validation
  try {
    const targetChainId = chainId || Object.keys(config?.supportedNetworks || {})[0]
    CORE_LOGGER.logMessage(
      `Starting ERC-1271 signature verification: ${JSON.stringify({
        consumer,
        targetChainId: targetChainId || null,
        networkConfigured: Boolean(
          targetChainId && config?.supportedNetworks?.[targetChainId]
        )
      })}`,
      true
    )
    if (targetChainId && config?.supportedNetworks?.[targetChainId]) {
      const provider = new ethers.JsonRpcProvider(
        config.supportedNetworks[targetChainId].rpc
      )

      // Try custom hash format (for backward compatibility)
      const customHashValid = await isERC1271Valid(
        consumer,
        consumerMessage,
        signature,
        provider
      )
      CORE_LOGGER.logMessage(
        `ERC-1271 custom hash verification result: ${customHashValid}`,
        true
      )
      if (customHashValid) {
        return { valid: true }
      }

      // Try EIP-191 prefixed hash (standard for smart wallets)
      const eip191Hash = ethers.hashMessage(message)
      const eip191HashValid = await isERC1271Valid(
        consumer,
        eip191Hash,
        signature,
        provider
      )
      CORE_LOGGER.logMessage(
        `ERC-1271 EIP-191 hash verification result: ${JSON.stringify({
          eip191Hash,
          valid: eip191HashValid
        })}`,
        true
      )
      if (eip191HashValid) {
        return { valid: true }
      }
    }
  } catch (error) {
    CORE_LOGGER.error(
      `ERC-1271 signature verification threw an error for consumer ${consumer}: ${error instanceof Error ? error.message : String(error)}`
    )
    // Smart account validation failed
  }

  CORE_LOGGER.error(
    `All signature verification methods failed for consumer ${consumer}, nonce ${nonce}, command ${command}`
  )
  return {
    valid: false,
    error: 'consumer address and nonce signature mismatch'
  }
}

// Smart account validation
export async function isERC1271Valid(
  address: string,
  hash: string | Uint8Array,
  signature: string,
  provider: ethers.Provider
): Promise<boolean> {
  try {
    const contract = new ethers.Contract(
      address,
      ['function isValidSignature(bytes32, bytes) view returns (bytes4)'],
      provider
    )
    const hashToUse = typeof hash === 'string' ? hash : ethers.hexlify(hash)
    const result = await contract.isValidSignature(hashToUse, signature)
    return result === '0x1626ba7e' // ERC-1271 magic value
  } catch {
    return false
  }
}
