import { ReadableString } from '../../P2P/handleProtocolCommands.js'
import { P2PCommandResponse } from '../../../@types/OceanNode.js'
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
import { getConfiguration } from '../../../utils/config.js'

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
  db: AbstractNonceDatabase,
  consumer: string,
  nonce: number,
  signature: string,
  command: string,
  chainId?: string | null
): Promise<NonceResponse> {
  CORE_LOGGER.info(
    `checkNonce start for consumer ${consumer}, nonce ${nonce}, command ${command}`
  )
  try {
    // get nonce from db
    let previousNonce = 0 // if none exists
    const existingNonce = await db.retrieve(consumer)
    if (existingNonce && existingNonce.nonce !== null) {
      previousNonce = existingNonce.nonce
    }
    CORE_LOGGER.info(
      `checkNonce loaded previous nonce ${previousNonce} for consumer ${consumer}`
    )
    // check if bigger than previous stored one and validate signature
    const validate = await validateNonceAndSignature(
      nonce,
      previousNonce, // will return 0 if none exists
      consumer,
      signature,
      command,
      chainId
    )
    CORE_LOGGER.info(
      `checkNonce validation result for consumer ${consumer}: ${validate.valid}`
    )
    if (validate.valid) {
      const updateStatus = await updateNonce(db, consumer, nonce)
      CORE_LOGGER.info(
        `checkNonce update result for consumer ${consumer} and nonce ${nonce}: ${updateStatus.valid}`
      )
      return updateStatus
    } else {
      // log error level when validation failed
      CORE_LOGGER.info(
        `checkNonce rejected consumer ${consumer} with error ${validate.error}`
      )
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
    CORE_LOGGER.info(`checkNonce threw error for consumer ${consumer}: ${err.message}`)
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
  chainId?: string | null
): Promise<NonceResponse> {
  CORE_LOGGER.info(
    `validateNonceAndSignature start for consumer ${consumer}, nonce ${nonce}, existingNonce ${existingNonce}, command ${command}`
  )
  if (nonce <= existingNonce) {
    CORE_LOGGER.info(
      `validateNonceAndSignature rejected stale nonce ${nonce} for consumer ${consumer}`
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

  // Try EOA signature validation
  try {
    CORE_LOGGER.info(`validateNonceAndSignature trying EOA signature validation`)
    const addressFromHashSignature = ethers.verifyMessage(consumerMessage, signature)
    const addressFromBytesSignature = ethers.verifyMessage(messageHashBytes, signature)
    CORE_LOGGER.info(
      `validateNonceAndSignature EOA signature validation result for ${consumer} AND ${addressFromBytesSignature} AND ${addressFromHashSignature}: ${addressFromHashSignature === consumer || addressFromBytesSignature === consumer}`
    )
    if (
      ethers.getAddress(addressFromHashSignature)?.toLowerCase() ===
        ethers.getAddress(consumer)?.toLowerCase() ||
      ethers.getAddress(addressFromBytesSignature)?.toLowerCase() ===
        ethers.getAddress(consumer)?.toLowerCase()
    ) {
      CORE_LOGGER.info(`validateNonceAndSignature accepted EOA signature for ${consumer}`)
      return { valid: true }
    }
    CORE_LOGGER.info(
      `validateNonceAndSignature EOA signature did not match consumer ${consumer}`
    )
  } catch (error) {
    CORE_LOGGER.info(`validateNonceAndSignature EOA signature validation threw ${error}`)
    // Continue to smart account check
  }

  // Try ERC-1271 (smart account) validation
  try {
    CORE_LOGGER.info(`validateNonceAndSignature trying ERC-1271 validation`)
    const config = await getConfiguration()
    const targetChainId = chainId || Object.keys(config?.supportedNetworks || {})[0]
    if (targetChainId && config?.supportedNetworks?.[targetChainId]) {
      CORE_LOGGER.info(
        `validateNonceAndSignature using ERC-1271 chain ${targetChainId} for consumer ${consumer}`
      )
      const provider = new ethers.JsonRpcProvider(
        config.supportedNetworks[targetChainId].rpc
      )

      // Try custom hash format (for backward compatibility)
      if (await isERC1271Valid(consumer, consumerMessage, signature, provider)) {
        CORE_LOGGER.info(
          `validateNonceAndSignature accepted ERC-1271 custom hash for ${consumer}`
        )
        return { valid: true }
      }

      // Try EIP-191 prefixed hash (standard for smart wallets)
      const eip191Hash = ethers.hashMessage(message)
      if (await isERC1271Valid(consumer, eip191Hash, signature, provider)) {
        CORE_LOGGER.info(
          `validateNonceAndSignature accepted ERC-1271 EIP-191 hash for ${consumer}`
        )
        return { valid: true }
      }
      CORE_LOGGER.info(
        `validateNonceAndSignature ERC-1271 validation did not match consumer ${consumer}`
      )
    } else {
      CORE_LOGGER.info(
        `validateNonceAndSignature could not resolve supported network for ERC-1271 validation`
      )
    }
  } catch (error) {
    CORE_LOGGER.info(`validateNonceAndSignature ERC-1271 validation threw ${error}`)
    // Smart account validation failed
  }

  CORE_LOGGER.info(`validateNonceAndSignature failed for consumer ${consumer}`)
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
