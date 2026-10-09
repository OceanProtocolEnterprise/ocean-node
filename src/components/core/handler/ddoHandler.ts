import { CommandHandler } from './handler.js'
import { OceanNode } from '../../../OceanNode.js'
import { EVENTS, MetadataStates, PROTOCOL_COMMANDS } from '../../../utils/constants.js'
import { P2PCommandResponse, FindDDOResponse } from '../../../@types/index.js'
import { Readable } from 'stream'
import { create256Hash } from '../../../utils/crypt.js'
import {
  hasCachedDDO,
  sortFindDDOResults,
  findDDOLocally,
  formatService
} from '../utils/findDdoHandler.js'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import { GENERIC_EMOJIS, LOG_LEVELS_STR } from '../../../utils/logging/Logger.js'
import {
  readStream,
  streamToUint8Array,
  fetchEventFromTransaction
} from '../../../utils/util.js'
import { P2P_TIMEOUTS } from '../../P2P/timeouts.js'
import { CORE_LOGGER } from '../../../utils/logging/common.js'
import { ethers, isAddress } from 'ethers'
import ERC721Template from '@oceanprotocol/contracts/artifacts/contracts/templates/ERC721Template.sol/ERC721Template.json' with { type: 'json' }
// import lzma from 'lzma-native'
import lzmajs from 'lzma-purejs-requirejs'
import { isRemoteDDO } from '../utils/validateDdoHandler.js'
import { getConfiguration, isPolicyServerConfigured } from '../../../utils/config.js'
import { PolicyServer } from '../../policyServer/index.js'
import {
  GetDdoCommand,
  FindDDOCommand,
  DecryptDDOCommand,
  ValidateDDOCommand
} from '../../../@types/commands.js'
import { EncryptMethod } from '../../../@types/fileObject.js'
import {
  ValidateParams,
  buildInvalidRequestMessage,
  validateCommandParameters
} from '../../httpRoutes/validateCommands.js'
import {
  findEventByKey,
  getNetworkHeight,
  wasNFTDeployedByOurFactory
} from '../../Indexer/utils.js'
import { deleteIndexedMetadataIfExists, validateDDOHash } from '../../../utils/asset.js'
import { Asset, DDO, DDOManager } from '@oceanprotocol/ddo-js'
import { checkCredentialOnAccessList } from '../../../utils/credentials.js'
import { createHash } from 'crypto'
import { Storage } from '../../../components/storage/index.js'
import {
  DCATDataset,
  DCATDistribution,
  DCATQualifiedAttribution,
  DCATTemporal,
  DCATDocument,
  DCATAgent,
  DCATService,
  DCATDatatoken,
  DCATAccessDetails,
  DCATRightsStatement,
  ChecksumAlgorithm
} from '../../../@types/dcat.js'
import { OE_VOCABULARY, OE_OBJECT_SHAPES } from '../../../@types/oecVocabulary.js'

const MAX_NUM_PROVIDERS = 5
// byte cap on one provider's getDDO response. A DDO is comfortably under a MiB in practice,
// so this leaves room for an unusually large one while refusing a peer that answers with a
// gigabyte. The shared reader's default is 64 MiB, which is a heap ceiling for any
// accumulating read rather than a statement about this payload.
const MAX_DDO_RESPONSE_BYTES = 4 * 1024 * 1024

function oec(shortName: string): string {
  return OE_VOCABULARY[shortName] ? `oec:${shortName}` : shortName
}

function serializeWithVocabulary(
  raw: any,
  shapeKeys: readonly string[]
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  if (!raw || typeof raw !== 'object') return out
  for (const key of shapeKeys) {
    if (raw[key] !== undefined) {
      out[oec(key)] = raw[key]
    }
  }
  for (const [key, value] of Object.entries(raw)) {
    if (key.includes(':') && !key.startsWith('oec:')) {
      out[key] = value
    }
  }
  return out
}

function normalizeCredentialKeys(raw: any): any {
  if (!raw || typeof raw !== 'object') return raw
  return {
    ...raw,
    matchDeny: raw.match_deny ?? raw.matchDeny,
    requestCredentials: raw.request_credentials ?? raw.requestCredentials,
    vcPolicies: raw.vc_policies ?? raw.vcPolicies,
    vpPolicies: raw.vp_policies ?? raw.vpPolicies
  }
}

/**
 * DDO ids that a recent FindDDO could not locate anywhere - not locally, and not at any
 * provider the DHT returned.
 *
 * The ids callers ask for are frequently ids that do not exist: a stale link, a client polling
 * for an asset that was never published, a retry loop around a 404. Each of those costs a
 * provider walk plus a query to every provider it turns up, and it costs every peer asked the
 * same. One remembered answer collapses a hot loop into one lookup.
 *
 * Two properties make this safe rather than a source of phantom 404s. It is consulted **after**
 * the local database lookup, never before, so a DDO this node holds is always returned whatever
 * the cache says - the cache can only ever skip the *network* half of the search. And an entry
 * is only ever written when the search found nothing at all, so an id that was found locally
 * cannot have an entry in the first place.
 *
 * Module-level, like the P2P counters and the resolution cache, and for the same reason: one
 * node process, one instance of this handler, and a per-instance field would buy nothing.
 */
const notFoundDdos = new Map<string, number>()

/**
 * Ceiling on how many distinct missing ids are remembered at once. The ids callers ask for are
 * frequently ids that do not exist, and a caller can supply an unbounded number of *distinct*
 * non-existent ids - a scan, a retry loop over random dids - each of which would otherwise hold
 * a slot for the full TTL. Without this cap the cache grows without limit until each id happens
 * to be looked up again after it expired. At this size the map is a few hundred KB at most.
 */
const MAX_NOT_FOUND_DDOS = 50_000

/** Drops every entry whose TTL has already passed. */
function pruneExpiredNotFoundDdos(): void {
  const now = Date.now()
  for (const [id, expiresAt] of notFoundDdos) {
    if (expiresAt <= now) {
      notFoundDdos.delete(id)
    }
  }
}

/** True when `id` was searched for recently and found nowhere. Prunes as it reads. */
function isDdoKnownMissing(id: string): boolean {
  const expiresAt = notFoundDdos.get(id)
  if (expiresAt == null) {
    return false
  }
  if (expiresAt <= Date.now()) {
    notFoundDdos.delete(id)
    return false
  }
  return true
}

/**
 * Records that `id` was found nowhere.
 *
 * The lifetime is short on purpose: a DDO that genuinely appears becomes findable as soon as
 * its publisher has written a provider record, and an entry outliving that would make this
 * cache the reason a freshly published asset looked missing.
 */
function rememberDdoMissing(id: string): void {
  // Enforce the ceiling before adding a genuinely new id. Reclaim expired entries first, and if
  // that is not enough evict the oldest live ones - every entry shares the same TTL, so the
  // Map's insertion order is also expiry order, and the front is what is closest to expiring.
  if (notFoundDdos.size >= MAX_NOT_FOUND_DDOS && !notFoundDdos.has(id)) {
    pruneExpiredNotFoundDdos()
    while (notFoundDdos.size >= MAX_NOT_FOUND_DDOS) {
      const oldest = notFoundDdos.keys().next().value
      if (oldest === undefined) break
      notFoundDdos.delete(oldest)
    }
  }
  notFoundDdos.set(id, Date.now() + P2P_TIMEOUTS.ddoNotFoundCacheMs)
}

/** Test seam: only the unit tests clear this, a running node never does. */
export function resetDdoNotFoundCache(): void {
  notFoundDdos.clear()
}

// scans all receipt logs for a MetadataCreated/MetadataUpdated event emitted by the
// given data NFT. The metadata event is not necessarily the first log of the
// transaction (AA accounts, multisigs and relayers emit other events before it)
export function findMetadataEventInLogs(
  logs: readonly { address: string; topics: readonly string[]; data: string }[],
  dataNftAddress: string
): ethers.LogDescription | null {
  const abiInterface = new ethers.Interface(ERC721Template.abi)
  const nftLogs = logs.filter(
    (log) => log.address.toLowerCase() === dataNftAddress.toLowerCase()
  )
  for (const eventName of [EVENTS.METADATA_CREATED, EVENTS.METADATA_UPDATED]) {
    const events = fetchEventFromTransaction({ logs: nftLogs }, eventName, abiInterface)
    if (events && events.length > 0) {
      return events[0]
    }
  }
  return null
}

export class DecryptDdoHandler extends CommandHandler {
  validate(command: DecryptDDOCommand): ValidateParams {
    const validation = validateCommandParameters(command, [
      'decrypterAddress',
      'chainId',
      'nonce',
      'signature'
    ])
    if (validation.valid) {
      if (!isAddress(command.decrypterAddress)) {
        return buildInvalidRequestMessage(
          'Parameter : "decrypterAddress" is not a valid web3 address'
        )
      }
    }
    return validation
  }

  checkId(id: string, dataNftAddress: string, chainId: string): Boolean {
    const didV5 =
      'did:ope:' +
      createHash('sha256')
        .update(ethers.getAddress(dataNftAddress) + chainId)
        .digest('hex')

    const didV4 =
      'did:op:' +
      createHash('sha256')
        .update(ethers.getAddress(dataNftAddress) + chainId)
        .digest('hex')
    return id === didV4 || id === didV5
  }

  async handle(task: DecryptDDOCommand): Promise<P2PCommandResponse> {
    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }
    const chainId = String(task.chainId)
    const config = this.getOceanNode().getConfig()
    const supportedNetwork = config.supportedNetworks[chainId]

    // check if supported chainId
    if (!supportedNetwork) {
      CORE_LOGGER.logMessage(`Decrypt DDO: Unsupported chain id ${chainId}`, true)
      return {
        stream: null,
        status: {
          httpStatus: 400,
          error: `Decrypt DDO: Unsupported chain id`
        }
      }
    }
    const isAuthRequestValid = await this.validateTokenOrSignature(
      task.authorization,
      task.decrypterAddress,
      task.nonce,
      task.signature,
      task.command
    )
    if (isAuthRequestValid.status.httpStatus !== 200) {
      return isAuthRequestValid
    }

    try {
      let decrypterAddress: string
      try {
        decrypterAddress = ethers.getAddress(task.decrypterAddress)
      } catch (error) {
        CORE_LOGGER.logMessage(`Decrypt DDO: error ${error}`, true)
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: 'Decrypt DDO: invalid parameter decrypterAddress'
          }
        }
      }

      const ourEthAddress = this.getOceanNode().getKeyManager().getEthAddress()
      if (config.authorizedDecrypters.length > 0) {
        // allow if on authorized list or it is own node
        if (
          !config.authorizedDecrypters
            .map((address) => address?.toLowerCase())
            .includes(decrypterAddress?.toLowerCase()) &&
          decrypterAddress?.toLowerCase() !== ourEthAddress.toLowerCase()
        ) {
          return {
            stream: null,
            status: {
              httpStatus: 403,
              error: 'Decrypt DDO: Decrypter not authorized'
            }
          }
        }
      }
      const oceanNode = this.getOceanNode()
      const blockchain = oceanNode.getBlockchain(supportedNetwork.chainId)
      if (!blockchain) {
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: `Decrypt DDO: Blockchain instance not available for chain ${supportedNetwork.chainId}`
          }
        }
      }
      const { ready, error } = await blockchain.isNetworkReady()
      if (!ready) {
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: `Decrypt DDO: ${error}`
          }
        }
      }

      const provider = await blockchain.getProvider()
      const signer = await blockchain.getSigner()
      // note: "getOceanArtifactsAdresses()"" is broken for at least optimism sepolia
      // if we do: artifactsAddresses[supportedNetwork.network]
      // because on the contracts we have "optimism_sepolia" instead of "optimism-sepolia"
      // so its always safer to use the chain id to get the correct network and artifacts addresses

      const dataNftAddress = ethers.getAddress(task.dataNftAddress)
      const wasDeployedByUs = await wasNFTDeployedByOurFactory(
        supportedNetwork.chainId,
        signer,
        dataNftAddress
      )
      if (!wasDeployedByUs) {
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: 'Decrypt DDO: Asset not deployed by the data NFT factory'
          }
        }
      }

      // access list checks, needs blockchain connection
      const { authorizedDecryptersList } = config

      const isAllowed = await checkCredentialOnAccessList(
        authorizedDecryptersList,
        chainId,
        decrypterAddress,
        signer
      )
      if (!isAllowed) {
        return {
          stream: null,
          status: {
            httpStatus: 403,
            error: `Decrypt DDO: Decrypter ${decrypterAddress} not authorized per access list`
          }
        }
      }

      const transactionId = task.transactionId ? String(task.transactionId) : ''
      let encryptedDocument: Uint8Array
      let flags: number
      let documentHash: string
      if (transactionId) {
        try {
          const receipt = await provider.getTransactionReceipt(transactionId)
          if (!receipt || !receipt.logs.length) {
            throw new Error('receipt logs 0')
          }
          const eventData = findMetadataEventInLogs(receipt.logs, dataNftAddress)
          if (!eventData) {
            throw new Error(
              `transaction ${transactionId} does not contain a MetadataCreated or MetadataUpdated event emitted by ${dataNftAddress}`
            )
          }
          flags = parseInt(eventData.args[3], 16)
          encryptedDocument = ethers.getBytes(eventData.args[4])
          documentHash = eventData.args[5]
        } catch (error) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: 'Decrypt DDO: Failed to process transaction id'
            }
          }
        }
      } else {
        try {
          encryptedDocument = ethers.getBytes(task.encryptedDocument)
          flags = Number(task.flags)
          // eslint-disable-next-line prefer-destructuring
          documentHash = task.documentHash
        } catch (error) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: 'Decrypt DDO: Failed to convert input args to bytes'
            }
          }
        }
      }
      const templateContract = new ethers.Contract(
        dataNftAddress,
        ERC721Template.abi,
        signer
      )
      const metaData = await templateContract.getMetaData()
      const metaDataState = Number(metaData[2])
      if ([MetadataStates.DEPRECATED, MetadataStates.REVOKED].includes(metaDataState)) {
        CORE_LOGGER.logMessage(`Decrypt DDO: error metadata state ${metaDataState}`, true)
        return {
          stream: null,
          status: {
            httpStatus: 403,
            error: 'Decrypt DDO: invalid metadata state'
          }
        }
      }
      if (
        ![
          MetadataStates.ACTIVE,
          MetadataStates.END_OF_LIFE,
          MetadataStates.ORDERING_DISABLED,
          MetadataStates.UNLISTED
        ].includes(metaDataState)
      ) {
        CORE_LOGGER.logMessage(`Decrypt DDO: error metadata state ${metaDataState}`, true)
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: 'Decrypt DDO: invalid metadata state'
          }
        }
      }

      let decryptedDocument: Buffer
      // check if DDO is ECIES encrypted
      if ((flags & 2) !== 0) {
        try {
          decryptedDocument = await oceanNode
            .getKeyManager()
            .decrypt(encryptedDocument, EncryptMethod.ECIES)
        } catch (error) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: 'Decrypt DDO: Failed to decrypt'
            }
          }
        }
      } else {
        try {
          decryptedDocument = lzmajs.decompressFile(decryptedDocument)
          /*
          lzma.decompress(
            decryptedDocument,
            { synchronous: true },
            (decompressedResult: any) => {
              decryptedDocument = decompressedResult
            }
          )
          */
        } catch (error) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: 'Decrypt DDO: Failed to lzma decompress'
            }
          }
        }
      }

      // did matches
      const ddo = JSON.parse(decryptedDocument.toString())
      if (ddo.id && !this.checkId(ddo.id, dataNftAddress, chainId)) {
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: 'Decrypt DDO: did does not match'
          }
        }
      }
      const decryptedDocumentString = decryptedDocument.toString()
      const ddoObject = JSON.parse(decryptedDocumentString)

      let stream = Readable.from(decryptedDocumentString)
      if (isRemoteDDO(ddoObject)) {
        const storage = Storage.getStorageClass(ddoObject.remote, config)
        const result = await storage.getReadableStream()
        stream = result.stream as Readable
      } else {
        // checksum matches
        const decryptedDocumentHash = create256Hash(decryptedDocument.toString())
        if (documentHash && decryptedDocumentHash !== documentHash) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: 'Decrypt DDO: checksum does not match'
            }
          }
        }
      }

      return {
        stream,
        status: { httpStatus: 200 }
      }
    } catch (error) {
      CORE_LOGGER.info(`ERROR Decrypt DDO: ${JSON.stringify(error)}`) // should be logged by caller
      return {
        stream: null,
        status: { httpStatus: 500, error: `Decrypt DDO: Unknown error ${error}` }
      }
    }
  }
}

export class GetDdoHandler extends CommandHandler {
  validate(command: GetDdoCommand): ValidateParams {
    let validation = validateCommandParameters(command, ['id'])
    if (validation.valid) {
      validation = validateDDOIdentifier(command.id)
    }

    return validation
  }

  async handle(task: GetDdoCommand): Promise<P2PCommandResponse> {
    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }
    try {
      const database = await this.getOceanNode().getDatabase()
      if (!database || !database.ddo) {
        CORE_LOGGER.error('DDO database is not available')
        return {
          stream: null,
          status: { httpStatus: 503, error: 'DDO database is not available' }
        }
      }
      const ddo = await database.ddo.retrieve(task.id)
      if (!ddo) {
        return {
          stream: null,
          status: { httpStatus: 404, error: 'Not found' }
        }
      }
      return {
        stream: Readable.from(JSON.stringify(ddo)),
        status: { httpStatus: 200 }
      }
    } catch (error) {
      CORE_LOGGER.error(`Get DDO error: ${error}`)
      return {
        stream: null,
        status: { httpStatus: 500, error: 'Unknown error: ' + error.message }
      }
    }
  }
}

export class FindDdoHandler extends CommandHandler {
  validate(command: FindDDOCommand): ValidateParams {
    let validation = validateCommandParameters(command, ['id'])
    if (validation.valid) {
      validation = validateDDOIdentifier(command.id)
    }

    return validation
  }

  async handle(task: FindDDOCommand): Promise<P2PCommandResponse> {
    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }
    // assigned once the FindDDO deadline exists; the finally below runs it on
    // every exit path, including the outer-exception one
    let endFindDdo: () => void = () => {}
    try {
      const node = this.getOceanNode()
      const p2pNode = node.getP2PNode()

      // if not P2P node just look on local DB
      if (!node.hasP2PInterface || !p2pNode) {
        // Checking locally only...
        const ddoInf = await findDDOLocally(node, task.id)
        const result = ddoInf ? [ddoInf] : []
        return {
          stream: Readable.from(JSON.stringify(result, null, 4)),
          status: { httpStatus: 200 }
        }
      }

      let updatedCache = false
      // result list
      const resultList: FindDDOResponse[] = []
      // if we have the result cached recently we return that result
      if (hasCachedDDO(task, p2pNode)) {
        // 'found cached DDO'
        resultList.push(p2pNode.getDDOCache().dht.get(task.id))
        return {
          stream: Readable.from(JSON.stringify(resultList, null, 4)),
          status: { httpStatus: 200 }
        }
      }
      // otherwise we need to contact other providers and get DDO from them

      const configuration = node.getConfig()

      // Checking locally...
      const ddoInfo = await findDDOLocally(node, task.id)
      if (ddoInfo) {
        // node has ddo
        // add to the result list anyway
        resultList.push(ddoInfo)

        updatedCache = true
      }

      // Deliberately *after* the local lookup, so a DDO this node holds is always returned no
      // matter what a previous search concluded. All this entry can do is skip the network half
      // of the search for a short while, which is the half a hot loop of requests for a
      // non-existent id is repeatedly paying for.
      if (isDdoKnownMissing(task.id)) {
        CORE_LOGGER.logMessage(
          `Skipping the provider search for DDO id ${task.id}: a recent search found it nowhere`,
          true
        )
        return {
          stream: Readable.from(JSON.stringify(sortFindDDOResults(resultList), null, 4)),
          status: { httpStatus: 200 }
        }
      }

      /**
       * Validates one provider's answer and folds it into the result list.
       *
       * @returns whether the answer was a legitimate DDO. The concurrent provider queries race
       *   on this: a peer that returns HTTP 200 with something that does not verify has not
       *   answered the question, so it must not cancel the peers that still might.
       */
      const processDDOResponse = async (
        peer: string,
        data: Uint8Array
      ): Promise<boolean> => {
        try {
          const ddo: any = JSON.parse(uint8ArrayToString(data))
          const isResponseLegit = await checkIfDDOResponseIsLegit(ddo, node)

          if (isResponseLegit) {
            const ddoInfo: FindDDOResponse = {
              id: ddo.id,
              lastUpdateTx: ddo.indexedMetadata.event.txid,
              lastUpdateTime: ddo.metadata.updated,
              provider: peer
            }
            resultList.push(ddoInfo)

            CORE_LOGGER.logMessage(
              `Successfully processed DDO info, id: ${ddo.id} from remote peer: ${peer}`,
              true
            )

            // Update cache
            const ddoCache = p2pNode.getDDOCache()
            if (ddoCache.dht.has(ddo.id)) {
              const localValue: FindDDOResponse = ddoCache.dht.get(ddo.id)
              if (
                new Date(ddoInfo.lastUpdateTime) > new Date(localValue.lastUpdateTime)
              ) {
                // update cached version
                ddoCache.dht.set(ddo.id, ddoInfo)
              }
            } else {
              // just add it to the list
              ddoCache.dht.set(ddo.id, ddoInfo)
            }
            updatedCache = true

            // Store locally if indexer is enabled
            if (configuration.hasIndexer) {
              const database = await node.getDatabase()
              if (database && database.ddo) {
                const ddoExistsLocally = await database.ddo.retrieve(ddo.id)
                if (!ddoExistsLocally) {
                  p2pNode.storeAndAdvertiseDDOS([ddo])
                }
              }
            }
            return true
          }
          CORE_LOGGER.warn(
            `Cannot confirm validity of ${ddo.id} from remote node, skipping it...`
          )
        } catch (err) {
          CORE_LOGGER.logMessageWithEmoji(
            'FindDDO: Error on sink function: ' + err.message,
            true,
            GENERIC_EMOJIS.EMOJI_CROSS_MARK,
            LOG_LEVELS_STR.LEVEL_ERROR
          )
        }
        return false
      }

      // Overall FindDDO deadline. Read from the P2P budgets rather than from a local literal:
      // the budget and its environment override already existed, and this file re-declared the
      // same 60s next to it, so `P2P_FINDDDO_TIMEOUT_MS` was documented but reached nothing.
      // Destructured inside the handler, not at module scope: the budget object is a set of
      // getters, so reading it per call is what keeps an environment override effective.
      const { findDdoMs } = P2P_TIMEOUTS
      // this is a real AbortController for the whole FindDDO: the deadline is
      // propagated into the provider lookup and into every peer query, so it
      // actually stops the work instead of just firing a timer callback
      const findDdoController = new AbortController()
      // a plain timer, not AbortSignal.timeout(): that one cannot be cancelled, so it
      // would still fire - and log a spurious 'Timeout reached' - long after the
      // request returned. clearTimeout below really does cancel it
      const findDdoDeadline = setTimeout(() => {
        CORE_LOGGER.log(LOG_LEVELS_STR.LEVEL_DEBUG, 'FindDDO: Timeout reached: ', true)
        findDdoController.abort(
          new Error(
            `FindDDO aborted after ${findDdoMs}ms, returning whatever info we have available`
          )
        )
      }, findDdoMs)
      const findDdoSignal = findDdoController.signal
      // releases the deadline and cancels anything still in flight (idempotent)
      endFindDdo = () => {
        clearTimeout(findDdoDeadline)
        findDdoController.abort(new Error('FindDDO finished'))
      }
      // rejects as soon as the FindDDO deadline fires, for callees that cannot
      // (yet) take a signal of their own
      const withFindDdoDeadline = <T>(promise: Promise<T>): Promise<T> => {
        if (findDdoSignal.aborted) {
          return Promise.reject(findDdoSignal.reason)
        }
        let onAbort: () => void = () => {}
        const aborted = new Promise<never>((resolve, reject) => {
          onAbort = () => reject(findDdoSignal.reason)
          findDdoSignal.addEventListener('abort', onAbort, { once: true })
        })
        return Promise.race([promise, aborted]).finally(() => {
          findDdoSignal.removeEventListener('abort', onAbort)
        })
      }

      /**
       * The single exit for a search that actually *finished* - every provider that was going
       * to answer has answered, or there were none to ask.
       *
       * It is the only place a "found nowhere" answer is remembered, and the distinction it
       * draws is the one that matters: a search the deadline cut short establishes nothing about
       * whether the DDO exists, only that looking took too long, so those exits deliberately do
       * not go through here.
       */
      const finishCompletedSearch = (): P2PCommandResponse => {
        // Only a search that ran to completion may write a "found nowhere" entry. The concurrent
        // provider loop swallows each branch's abort, so this exit is still reached when the
        // deadline fired mid-query - and a deadline establishes nothing about whether the DDO
        // exists (see the comment on this block). Remembering it missing then would let a slow
        // lookup poison the cache against an id that is simply expensive to find.
        if (resultList.length === 0 && !findDdoSignal.aborted) {
          rememberDdoMissing(task.id)
        }
        endFindDdo()
        return {
          stream: Readable.from(JSON.stringify(sortFindDDOResults(resultList), null, 4)),
          status: { httpStatus: 200 }
        }
      }

      // check other providers for this ddo
      let providers: Array<{ id: string; multiaddrs: any[] }> = []
      try {
        providers = await withFindDdoDeadline(
          p2pNode.getProvidersForString(task.id, undefined, findDdoSignal)
        )
      } catch (findProvidersError) {
        // only the deadline may be swallowed into a 200. Anything else - notably a
        // malformed task.id rejected by cidFromRawString(), which sits outside
        // getProvidersForString's own try - must keep its 500
        if (!findDdoSignal.aborted) {
          throw findProvidersError
        }
        // deadline reached while looking for providers: return what we already have
        CORE_LOGGER.warn(
          `FindDDO: provider lookup ended early for id ${task.id}: ${findProvidersError.message}`
        )
        endFindDdo()
        return {
          stream: Readable.from(JSON.stringify(sortFindDDOResults(resultList), null, 4)),
          status: { httpStatus: 200 }
        }
      }
      // check if includes self and exclude from check list
      if (providers.length > 0) {
        // exclude this node from the providers list if present
        let filteredProviders = providers.filter((provider: any) => {
          return provider.id.toString() !== p2pNode.getPeerId()
        })

        // work with the filtered list only
        if (filteredProviders.length > 0) {
          // only process a maximum of 5 provider entries per DDO (might never be that much anyway??)
          if (filteredProviders.length > MAX_NUM_PROVIDERS) {
            filteredProviders = filteredProviders.slice(0, MAX_NUM_PROVIDERS)
          }

          /**
           * Providers are queried **concurrently**, each with its own budget, and the first
           * legitimate answer ends the search.
           *
           * What this replaces: the providers were queried one at a time, with a fixed 5 second
           * sleep after each, wrapped in a `do/while` that could re-run the whole pass. At the
           * provider maximum of 5 that is 5 x (one whole `sendTo` setup budget + 5s) =
           * 5 x 50s = 250 seconds of structure, before counting the response-body read - and the
           * only reason a request did not take that long was the overall deadline cutting it
           * off, which meant the later providers in the list were never actually asked. So the
           * sequential shape did not just cost latency, it silently reduced the number of
           * providers consulted to however many fitted in the deadline.
           *
           * Concurrency removes both problems: every provider is asked at once, so the answer
           * arrives in roughly one provider round trip rather than in list order, and no
           * provider is skipped because an earlier one was slow. Nothing sleeps between
           * providers - there was never a reason to pause between two independent peers - and
           * there is no re-query pass, because asking the same providers the same question again
           * cannot produce a different answer inside one deadline.
           *
           * The trade, stated plainly: the result list now holds the first legitimate answer
           * rather than every provider's answer, so `sortFindDDOResults` has one remote entry to
           * choose between instead of up to five. The sort exists to prefer the most recently
           * updated DDO, and collecting all five to do that costs the latency of the slowest
           * provider on every request, for a difference that only appears when providers
           * disagree about the same asset.
           */
          const perProviderMs = P2P_TIMEOUTS.findDdoProviderMs
          // Cancels the losers the moment one provider answers legitimately. A separate
          // controller from the overall deadline so that "we have our answer" and "we ran out
          // of time" stay distinguishable in the logs.
          const answered = new AbortController()
          let haveAnswer = false

          await Promise.all(
            filteredProviders.map(async (provider: any) => {
              const peer = provider.id.toString()
              const getCommand: GetDdoCommand = {
                id: task.id,
                command: PROTOCOL_COMMANDS.GET_DDO
              }
              // Three ways this branch can end early: the overall deadline, another provider
              // having answered, and this provider taking too long on its own. The per-provider
              // budget is what makes concurrency safe - without it one unresponsive provider
              // would hold a branch open for the whole FindDDO deadline.
              const providerSignal = AbortSignal.any([
                findDdoSignal,
                answered.signal,
                AbortSignal.timeout(perProviderMs)
              ])
              // A provider record from the DHT usually carries the provider's addresses. Passing
              // them through means this send skips address resolution altogether - the addresses
              // are already in hand, and re-deriving them would repeat the lookup that produced
              // this provider. Falling back to no addresses lets `sendTo` resolve normally.
              //
              // Pinned addresses are used verbatim and are not re-resolved on failure, so a
              // provider whose advertised address no longer works is lost for this request. That
              // is the right trade here and only here: four other providers are being asked the
              // same question at the same moment, so the cost of dropping one is nothing, while
              // a DHT walk per provider would reintroduce exactly the latency this loop removes.
              const providerAddrs: string[] = Array.isArray(provider.multiaddrs)
                ? provider.multiaddrs.map((ma: any) => ma.toString())
                : []

              try {
                const response = await p2pNode.sendTo(
                  peer,
                  JSON.stringify(getCommand),
                  providerAddrs.length > 0 ? providerAddrs : undefined,
                  undefined,
                  providerSignal
                )
                if (response.status.httpStatus !== 200 || !response.stream) {
                  return
                }
                // Capped: this is one DDO from an untrusted provider, and the shared
                // reader's 64 MiB default is a heap ceiling rather than a statement about
                // this payload. A DDO is well under a MiB in practice. Time is already
                // bounded - the send above carries providerSignal - so only the size was
                // unbounded.
                const data = await streamToUint8Array(
                  response.stream as Readable,
                  MAX_DDO_RESPONSE_BYTES
                )
                const accepted = await processDDOResponse(peer, data)
                if (accepted && !haveAnswer) {
                  haveAnswer = true
                  answered.abort(
                    new Error(`FindDDO for ${task.id} answered by provider ${peer}`)
                  )
                }
              } catch (innerException) {
                // One provider failing, timing out, or being cancelled because another
                // answered is not a FindDDO failure. The overall outcome is whatever the
                // result list holds when every branch has settled.
                CORE_LOGGER.debug(
                  `FindDDO: provider ${peer} did not answer for ${task.id}: ${innerException.message}`
                )
              }
            })
          )

          if (updatedCache) {
            p2pNode.getDDOCache().updated = new Date().getTime()
          }

          // house cleaning
          return finishCompletedSearch()
        } else {
          // could empty list
          return finishCompletedSearch()
        }
      } else {
        // could be empty list
        return finishCompletedSearch()
      }
    } catch (error) {
      // 'FindDDO big error: '
      CORE_LOGGER.logMessageWithEmoji(
        `Error: '${error.message}' was caught while getting DDO info for id: ${task.id}`,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: { httpStatus: 500, error: 'Unknown error: ' + error.message }
      }
    } finally {
      // every exit path releases the deadline listener/timer
      endFindDdo()
    }
  }

  // Function to use findDDO and get DDO in desired format
  async findAndFormatDdo(ddoId: string, force: boolean = false): Promise<DDO | null> {
    const node = this.getOceanNode()
    // First try to find the DDO Locally if findDDO is not enforced
    if (!force) {
      try {
        const database = await node.getDatabase()
        if (database && database.ddo) {
          const ddo = await database.ddo.retrieve(ddoId)
          return ddo as DDO
        } else {
          CORE_LOGGER.logMessage(
            `DDO database is not available. Proceeding to call findDDO`,
            true
          )
        }
      } catch (error) {
        CORE_LOGGER.logMessage(
          `Unable to find DDO locally. Proceeding to call findDDO`,
          true
        )
      }
    }
    try {
      const task: FindDDOCommand = {
        id: ddoId,
        command: PROTOCOL_COMMANDS.FIND_DDO,
        force
      }
      const response: P2PCommandResponse = await this.handle(task)

      if (response && response?.status?.httpStatus === 200 && response?.stream) {
        const streamData = await readStream(response.stream)
        const ddoList = JSON.parse(streamData)

        // Assuming the first DDO in the list is the one we want
        const ddoData = ddoList[0]
        if (!ddoData) {
          return null
        }

        // Format each service according to the Service interface
        const formattedServices = ddoData.services.map(formatService)

        // Map the DDO data to the DDO interface
        const ddo: Asset = {
          '@context': ddoData['@context'],
          id: ddoData.id,
          version: ddoData.version,
          nftAddress: ddoData.nftAddress,
          chainId: ddoData.chainId,
          metadata: ddoData.metadata,
          services: formattedServices,
          credentials: ddoData.credentials,
          indexedMetadata: {
            stats: ddoData.indexedMetadata.stats,
            event: ddoData.indexedMetadata.event,
            nft: ddoData.indexedMetadata.nft
          }
        }

        return ddo
      }

      return null
    } catch (error) {
      CORE_LOGGER.log(
        LOG_LEVELS_STR.LEVEL_ERROR,
        `Error finding DDO: ${error.message}`,
        true
      )
      return null
    }
  }

  private serviceIri(assetDid: string, serviceId: string): string {
    return assetDid ? `${assetDid}#service-${serviceId}` : `#service-${serviceId}`
  }

  private toAbsoluteUrl(value: unknown): string | undefined {
    if (typeof value !== 'string') return undefined
    const trimmed = value.trim()
    if (trimmed === '') return undefined
    try {
      const parsed = new URL(trimmed)
      return parsed.protocol === 'http:' || parsed.protocol === 'https:'
        ? trimmed
        : undefined
    } catch {
      return undefined
    }
  }

  private toRightsStatement(license: any): DCATRightsStatement | undefined {
    if (!license) return undefined
    const name =
      typeof license === 'string'
        ? license
        : typeof license.name === 'string'
          ? license.name
          : ''
    const trimmed = name.trim()
    const nameUrl = this.toAbsoluteUrl(trimmed)
    const url =
      nameUrl ??
      (typeof license === 'object'
        ? this.toAbsoluteUrl(license?.licenseDocuments?.[0]?.mirrors?.[0]?.url)
        : undefined)

    if (url) {
      const statement: DCATRightsStatement = {
        '@id': url,
        '@type': 'dct:RightsStatement'
      }
      if (trimmed !== '' && !nameUrl) {
        statement['dct:title'] = trimmed
      }
      return statement
    }
    if (trimmed !== '') {
      return { '@type': 'dct:RightsStatement', 'dct:title': trimmed }
    }
    return undefined
  }

  private issuerAgent(issuer: string): DCATAgent {
    return {
      '@id': issuer,
      '@type': 'foaf:Agent',
      'foaf:name': issuer
    }
  }

  private ownerAgent(owner: string, chainId?: unknown): DCATAgent {
    const agent: DCATAgent = {
      '@type': 'foaf:Agent',
      'foaf:name': `NFT Owner: ${owner}`
    }
    if (chainId !== undefined && chainId !== null && String(chainId) !== '') {
      agent['@id'] = `did:pkh:eip155:${chainId}:${owner}`
    }
    return agent
  }

  private formatDistributions(ddo: any, assetDid: string = ''): DCATDistribution[] {
    const distributions: DCATDistribution[] = []
    const credentialSubject = ddo?.credentialSubject || ddo || {}
    const services = Array.isArray(credentialSubject.services)
      ? credentialSubject.services
      : []

    if (services.length === 0) {
      return distributions
    }

    services.forEach((service: any) => {
      const distribution: DCATDistribution = {
        '@type': 'dcat:Distribution'
      }

      const endpoint =
        typeof service.serviceEndpoint === 'string'
          ? service.serviceEndpoint
          : service.serviceEndpoint?.['@id']

      if (endpoint) {
        distribution['dcat:accessURL'] = {
          '@id': endpoint,
          '@type': 'rdfs:Resource'
        }
      }

      const serviceId =
        typeof service.id === 'string' && service.id.trim() !== ''
          ? service.id.trim()
          : undefined

      if (serviceId) {
        distribution['dcat:accessService'] = {
          '@id': this.serviceIri(assetDid, serviceId)
        }
      }

      if (service.name) {
        distribution['dct:title'] = service.name
      }

      if (service.description) {
        if (typeof service.description === 'object' && service.description['@value']) {
          distribution['dct:description'] = service.description['@value']
        } else if (typeof service.description === 'string') {
          distribution['dct:description'] = service.description
        }
      }

      if (service.type === 'compute') {
        distribution['oec:distributionFormat'] = 'compute-service'

        if (service.compute) {
          distribution['oec:compute'] = {
            'oec:allowNetworkAccess': service.compute.allowNetworkAccess ?? false,
            'oec:allowRawAlgorithm': service.compute.allowRawAlgorithm ?? false,
            'oec:publisherTrustedAlgorithms': Array.isArray(
              service.compute.publisherTrustedAlgorithms
            )
              ? service.compute.publisherTrustedAlgorithms.map((algorithm: any) => ({
                  'oec:did': algorithm.did,
                  'oec:filesChecksum': algorithm.filesChecksum,
                  'oec:containerSectionChecksum': algorithm.containerSectionChecksum,
                  ...(algorithm.serviceId
                    ? {
                        'oec:serviceId': algorithm.serviceId
                      }
                    : {})
                }))
              : undefined,
            'oec:publisherTrustedAlgorithmPublishers': Array.isArray(
              service.compute.publisherTrustedAlgorithmPublishers
            )
              ? service.compute.publisherTrustedAlgorithmPublishers
              : undefined
          }
        }
      }

      if (service.files) {
        distribution['oec:distributionFormat'] =
          distribution['oec:distributionFormat'] || 'encrypted'
      }

      if (service.links && typeof service.links === 'object') {
        const links: DCATDocument[] = Object.values(service.links)
          .filter((value): value is string => typeof value === 'string')
          .map((url) => ({
            '@id': url,
            '@type': 'foaf:Document' as const
          }))

        if (links.length > 0) {
          distribution['rdfs:seeAlso'] = links
        }
      }

      distributions.push(distribution)
    })

    return distributions
  }

  private formatQualifiedAttribution(
    metadata: any,
    nftOwner?: string,
    issuer?: string,
    chainId?: unknown
  ): DCATQualifiedAttribution[] {
    const attributions: DCATQualifiedAttribution[] = []

    const authorValue = typeof metadata.author === 'string' ? metadata.author.trim() : ''

    if (authorValue !== '') {
      attributions.push({
        '@type': 'prov:Attribution',
        'prov:agent': {
          '@type': 'foaf:Agent',
          'foaf:name': authorValue
        },
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/author',
          '@type': 'dct:AgentRole'
        }
      })
    } else if (
      metadata.author &&
      typeof metadata.author === 'object' &&
      metadata.author['foaf:name']
    ) {
      attributions.push({
        '@type': 'prov:Attribution',
        'prov:agent': {
          '@type': 'foaf:Agent',
          'foaf:name': metadata.author['foaf:name']
        },
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/author',
          '@type': 'dct:AgentRole'
        }
      })
    } else if (issuer && issuer.trim() !== '') {
      attributions.push({
        '@type': 'prov:Attribution',
        'prov:agent': this.issuerAgent(issuer),
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/author',
          '@type': 'dct:AgentRole'
        }
      })
    } else if (nftOwner && nftOwner.trim() !== '') {
      attributions.push({
        '@type': 'prov:Attribution',
        'prov:agent': this.ownerAgent(nftOwner, chainId),
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/owner',
          '@type': 'dct:AgentRole'
        }
      })
    }

    if (metadata.publisher && metadata.publisher.trim() !== '') {
      attributions.push({
        '@type': 'prov:Attribution',
        'prov:agent': {
          '@type': 'foaf:Agent',
          'foaf:name': metadata.publisher
        },
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/publisher',
          '@type': 'dct:AgentRole'
        }
      })
    }

    return attributions
  }

  private getChecksumAlgorithm(algorithm?: string): ChecksumAlgorithm {
    const validAlgorithms: ChecksumAlgorithm[] = [
      'SHA-1',
      'SHA-256',
      'SHA-384',
      'SHA-512'
    ]
    if (algorithm && validAlgorithms.includes(algorithm as ChecksumAlgorithm)) {
      return algorithm as ChecksumAlgorithm
    }
    return 'SHA-256'
  }

  async transformToDCAT(ddo: any): Promise<DCATDataset> {
    CORE_LOGGER.debug(`[DCAT] Original DDO v5: ${JSON.stringify(ddo, null, 2)}`)

    const ddoCopy = JSON.parse(JSON.stringify(ddo || {}))

    const credentialSubject = ddoCopy.credentialSubject || {}
    const metadata = credentialSubject.metadata || ddoCopy.metadata || {}
    const services = Array.isArray(credentialSubject.services)
      ? credentialSubject.services
      : Array.isArray(ddoCopy.services)
        ? ddoCopy.services
        : []

    const indexedMetadata = ddoCopy.indexedMetadata || {}
    const nft = indexedMetadata.nft || credentialSubject.nft || ddoCopy.nft || {}
    const stats = Array.isArray(indexedMetadata.stats) ? indexedMetadata.stats : []
    const purgatory = indexedMetadata.purgatory ||
      credentialSubject.purgatory ||
      ddoCopy.purgatory || { state: false }

    const event = indexedMetadata.event || credentialSubject.event || ddoCopy.event || {}
    const issuer = typeof ddoCopy.issuer === 'string' ? ddoCopy.issuer.trim() : ''

    // The asset DID lives in credentialSubject.id; the root id may become the VC id
    const assetDid =
      typeof credentialSubject.id === 'string' && credentialSubject.id.trim() !== ''
        ? credentialSubject.id.trim()
        : typeof ddoCopy.id === 'string' && ddoCopy.id.trim() !== ''
          ? ddoCopy.id.trim()
          : ''

    // A DID is already a valid IRI, so it is used directly (no "urn:" prefix)
    const datasetId = assetDid
    const chainId = credentialSubject.chainId ?? ddoCopy.chainId
    const nftAddress = credentialSubject.nftAddress ?? ddoCopy.nftAddress
    const datatokens = Array.isArray(credentialSubject.datatokens)
      ? credentialSubject.datatokens
      : Array.isArray(ddoCopy.datatokens)
        ? ddoCopy.datatokens
        : []

    const additionalDdos = Array.isArray(ddoCopy.additionalDdos)
      ? ddoCopy.additionalDdos
      : Array.isArray(credentialSubject.additionalDdos)
        ? credentialSubject.additionalDdos
        : []

    const accessDetails = Array.isArray(ddoCopy.accessDetails)
      ? ddoCopy.accessDetails
      : Array.isArray(credentialSubject.accessDetails)
        ? credentialSubject.accessDetails
        : []

    const config = await getConfiguration()
    let baseUrl = ''
    const firstService = services[0]
    if (firstService?.serviceEndpoint) {
      const endpoint =
        typeof firstService.serviceEndpoint === 'string'
          ? firstService.serviceEndpoint
          : firstService.serviceEndpoint?.['@id']
      if (endpoint) {
        baseUrl = endpoint.replace(/\/$/, '')
      }
    }

    if (!baseUrl && config?.httpPort) {
      baseUrl = `http://localhost:${config.httpPort}`
    }

    const dcat: DCATDataset = {
      '@context': {
        '@vocab': 'https://oceanenterprise.io/vocab/',
        dcat: 'http://www.w3.org/ns/dcat#',
        dct: 'http://purl.org/dc/terms/',
        foaf: 'http://xmlns.com/foaf/0.1/',
        geo: 'http://www.opengis.net/ont/geosparql#',
        oec: 'https://oceanenterprise.io/vocab/',
        prov: 'http://www.w3.org/ns/prov#',
        rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
        skos: 'http://www.w3.org/2004/02/skos/core#',
        spdx: 'http://spdx.org/rdf/terms#',
        vcard: 'http://www.w3.org/2006/vcard/ns#',
        xsd: 'http://www.w3.org/2001/XMLSchema#'
      },
      '@id': datasetId,
      '@type': 'dcat:Dataset',
      'dct:title': typeof metadata.name === 'string' ? metadata.name : ''
    }

    if (metadata.description) {
      if (typeof metadata.description === 'object' && metadata.description['@value']) {
        dcat['dct:description'] = metadata.description['@value']
      } else if (typeof metadata.description === 'string') {
        dcat['dct:description'] = metadata.description
      }
    }

    // dct:description is mandatory in DCAT-AP: fall back to the title
    if (!dcat['dct:description'] && dcat['dct:title']) {
      dcat['dct:description'] = dcat['dct:title']
    }

    if (Array.isArray(metadata.tags) && metadata.tags.length > 0) {
      const seen = new Set<string>()
      const keywords: string[] = []

      for (const tag of metadata.tags) {
        if (typeof tag !== 'string') continue
        const trimmed = tag.trim()
        if (trimmed === '' || seen.has(trimmed)) continue
        seen.add(trimmed)
        keywords.push(trimmed)
      }

      if (keywords.length > 0) {
        dcat['dcat:keyword'] = keywords
      }
    } else if (services.length > 0) {
      const seen = new Set<string>()
      const serviceTypes: string[] = []

      for (const service of services) {
        const type = service?.type
        if (typeof type !== 'string') continue
        const trimmed = type.trim()
        if (trimmed === '' || seen.has(trimmed)) continue
        seen.add(trimmed)
        serviceTypes.push(trimmed)
      }

      if (serviceTypes.length > 0) {
        dcat['dcat:keyword'] = serviceTypes
      }
    }

    if (typeof metadata.author === 'string' && metadata.author.trim() !== '') {
      dcat['dct:creator'] = {
        '@type': 'foaf:Agent',
        'foaf:name': metadata.author.trim()
      }
    } else if (metadata.author && typeof metadata.author === 'object') {
      dcat['dct:creator'] = metadata.author as DCATAgent
    }

    if (typeof metadata.providedBy === 'string' && metadata.providedBy.trim() !== '') {
      dcat['dct:publisher'] = {
        '@type': 'foaf:Agent',
        'foaf:name': metadata.providedBy.trim()
      }
    } else if (issuer !== '') {
      dcat['dct:publisher'] = this.issuerAgent(issuer)
    } else if (typeof nft.owner === 'string' && nft.owner.trim() !== '') {
      dcat['dct:publisher'] = this.ownerAgent(nft.owner, chainId)
    }

    if (
      typeof metadata.copyrightHolder === 'string' &&
      metadata.copyrightHolder.trim() !== ''
    ) {
      dcat['dcat:contactPoint'] = {
        '@type': 'vcard:Kind',
        'vcard:fn': metadata.copyrightHolder.trim()
      }
    } else if (
      typeof metadata.providedBy === 'string' &&
      metadata.providedBy.trim() !== ''
    ) {
      dcat['dcat:contactPoint'] = {
        '@type': 'vcard:Kind',
        'vcard:fn': metadata.providedBy.trim()
      }
    } else if (issuer !== '') {
      dcat['dcat:contactPoint'] = {
        '@type': 'vcard:Kind',
        'vcard:fn': issuer
      }
    } else if (typeof nft.owner === 'string' && nft.owner.trim() !== '') {
      dcat['dcat:contactPoint'] = {
        '@type': 'vcard:Kind',
        'vcard:fn': `NFT Owner: ${nft.owner}`
      }
    }

    if (metadata.license) {
      const licenseStatement = this.toRightsStatement(metadata.license)
      if (licenseStatement) {
        dcat['dct:license'] = licenseStatement
      }
    }

    if (metadata.created) {
      dcat['dct:issued'] = {
        '@type': 'xsd:dateTime',
        '@value': metadata.created
      }
    }

    if (metadata.updated) {
      dcat['dct:modified'] = {
        '@type': 'xsd:dateTime',
        '@value': metadata.updated
      }
    }

    const additionalInformation =
      metadata.additionalInformation && typeof metadata.additionalInformation === 'object'
        ? metadata.additionalInformation
        : {}

    if (additionalInformation['dct:spatial']) {
      dcat['dct:spatial'] = additionalInformation['dct:spatial']

      const spatial = additionalInformation['dct:spatial']

      if (spatial && typeof spatial === 'object') {
        if (spatial['dcat:bbox']) {
          dcat['dcat:bbox'] = spatial['dcat:bbox']
        }

        if (spatial['dcat:centroid']) {
          dcat['dcat:centroid'] = spatial['dcat:centroid']
        }
      }
    }

    // dct:temporal is the period the DATA covers, so it is only taken from
    // additionalInformation (never derived from created/updated)
    if (additionalInformation['dct:temporal']) {
      dcat['dct:temporal'] = additionalInformation['dct:temporal'] as DCATTemporal
    }

    if (additionalInformation['dcat:theme']) {
      dcat['dcat:theme'] = additionalInformation['dcat:theme']
    }

    if (additionalInformation['dcat:spatialResolutionInMeters'] !== undefined) {
      dcat['dcat:spatialResolutionInMeters'] =
        additionalInformation['dcat:spatialResolutionInMeters']
    }

    if (additionalInformation['dcat:temporalResolution'] !== undefined) {
      dcat['dcat:temporalResolution'] = additionalInformation['dcat:temporalResolution']
    }

    if (additionalInformation['dct:accrualPeriodicity']) {
      dcat['dct:accrualPeriodicity'] = {
        '@type': 'dct:Frequency',
        '@id': additionalInformation['dct:accrualPeriodicity']
      }
    }

    for (const [key, value] of Object.entries(additionalInformation)) {
      if (
        value === undefined ||
        value === null ||
        key === 'dct:spatial' ||
        key === 'dcat:theme' ||
        key === 'dcat:spatialResolutionInMeters' ||
        key === 'dcat:temporalResolution' ||
        key === 'dct:accrualPeriodicity'
      ) {
        continue
      }

      if (!key.startsWith('dcat:') && !key.startsWith('dct:')) {
        continue
      }

      if (!(key in dcat)) {
        ;(dcat as any)[key] = value
      }
    }

    // Only emit dct:conformsTo when there is an actual conformance target.
    // The DCAT namespace itself (http://www.w3.org/ns/dcat#) is not a Standard,
    // and GeoDCAT-AP SHACL rejects it. Conformance is only meaningful for geo
    // assets (INSPIRE + GeoDCAT-AP) and for other explicitly declared standards
    // via additionalInformation['dct:conformsTo'].
    const conformsTo: string[] = []

    if (Array.isArray(additionalInformation['dct:conformsTo'])) {
      conformsTo.push(...additionalInformation['dct:conformsTo'])
    } else if (typeof additionalInformation['dct:conformsTo'] === 'string') {
      conformsTo.push(additionalInformation['dct:conformsTo'])
    }

    if (additionalInformation['dct:spatial']) {
      conformsTo.push(
        'http://inspire.ec.europa.eu/schemas/inspire_vs/1.0',
        'https://semiceu.github.io/GeoDCAT-AP/releases/3.0.0/'
      )
    }

    if (conformsTo.length > 0) {
      // DCAT-AP expects dct:conformsTo values to be dct:Standard nodes, not plain strings
      dcat['dct:conformsTo'] = Array.from(
        new Set(conformsTo.filter((uri) => typeof uri === 'string' && uri.trim() !== ''))
      ).map((uri) => ({
        '@id': uri,
        '@type': 'dct:Standard' as const
      }))
    }

    if (baseUrl && assetDid) {
      dcat['dcat:landingPage'] = {
        '@id': `${baseUrl}/api/aquarius/assets/ddo/${assetDid}`,
        '@type': 'foaf:Document'
      }
    }

    const distributions = this.formatDistributions(
      {
        ...ddoCopy,
        credentialSubject: {
          ...credentialSubject,
          services
        }
      },
      assetDid
    )

    if (distributions.length > 0) {
      dcat['dcat:distribution'] = distributions
    }

    const formattedServices = this.formatServicesForDCAT(services, assetDid)

    if (formattedServices.length > 0) {
      dcat['oec:services'] = formattedServices
    }

    const attributions = this.formatQualifiedAttribution(
      metadata,
      nft.owner,
      issuer,
      chainId
    )
    if (attributions.length > 0) {
      dcat['prov:qualifiedAttribution'] = attributions
    }

    const descriptionLanguage =
      metadata.description &&
      typeof metadata.description === 'object' &&
      typeof metadata.description['@language'] === 'string'
        ? metadata.description['@language']
        : undefined
    const metadataLanguage = metadata.language || descriptionLanguage

    if (metadataLanguage) {
      const languages = Array.isArray(metadataLanguage)
        ? metadataLanguage
        : [metadataLanguage]

      const languageMap: Record<string, string> = {
        en: 'http://publications.europa.eu/resource/authority/language/ENG',
        de: 'http://publications.europa.eu/resource/authority/language/DEU',
        fr: 'http://publications.europa.eu/resource/authority/language/FRA',
        es: 'http://publications.europa.eu/resource/authority/language/SPA',
        it: 'http://publications.europa.eu/resource/authority/language/ITA'
      }

      dcat['dct:language'] = languages
        .filter(
          (language: unknown): language is string =>
            typeof language === 'string' && language.trim() !== ''
        )
        .map((language: string) => ({
          '@id': languageMap[language.toLowerCase()] || language,
          '@type': 'dct:LinguisticSystem'
        }))
    } else {
      dcat['dct:language'] = [
        {
          '@id': 'http://publications.europa.eu/resource/authority/language/ENG',
          '@type': 'dct:LinguisticSystem'
        }
      ]
    }

    if (assetDid) {
      dcat['dct:identifier'] = [assetDid]
    }

    if (metadata.license) {
      const rightsStatement = this.toRightsStatement(metadata.license)
      if (rightsStatement) {
        dcat['dct:rights'] = rightsStatement
      }
    }

    if (metadata.accessRights) {
      dcat['dct:accessRights'] = metadata.accessRights
    } else {
      const allowList = credentialSubject.credentials?.allow || ddoCopy.credentials?.allow

      const hasRestrictions = Array.isArray(allowList) && allowList.length > 0
      dcat['dct:accessRights'] = {
        '@id': `http://publications.europa.eu/resource/authority/access-right/${
          hasRestrictions ? 'RESTRICTED' : 'PUBLIC'
        }`,
        '@type': 'dct:RightsStatement'
      }
    }

    if (metadata.type) {
      dcat['dct:type'] = metadata.type
    }

    if (metadata.algorithm) {
      dcat['oec:algorithm'] = {
        'oec:language': metadata.algorithm.language,
        'oec:version': metadata.algorithm.version,
        'oec:container': {
          'oec:entrypoint': metadata.algorithm.container.entrypoint,
          'oec:image': metadata.algorithm.container.image,
          'oec:tag': metadata.algorithm.container.tag,
          'oec:checksum': metadata.algorithm.container.checksum
        }
      }
    }

    if (issuer) {
      dcat['oec:issuer'] = issuer
    }

    if (chainId !== undefined && chainId !== null) {
      dcat['oec:chainId'] = Number(chainId)
    }

    if (nftAddress !== undefined && nftAddress !== null) {
      dcat['oec:nftAddress'] = nftAddress
    }

    if (datatokens.length > 0) {
      dcat['oec:datatokens'] = this.formatDatatokensForDCAT(datatokens)
    }

    dcat['oec:purgatory'] = {
      'oec:state': Boolean(purgatory.state)
    }

    // Dataset-level credentials (including vc_policies / vp_policies)
    const datasetCredentials = credentialSubject.credentials || ddoCopy.credentials
    if (datasetCredentials && typeof datasetCredentials === 'object') {
      dcat['oec:credentials'] = this.formatCredentialsForDCAT(datasetCredentials)
    }

    if (additionalDdos.length > 0) {
      dcat['oec:additionalDdos'] = additionalDdos
    }

    if (
      nft.owner &&
      !attributions.some((attribution) =>
        attribution['prov:hadRole']?.['@id']?.includes('owner')
      )
    ) {
      if (!dcat['prov:qualifiedAttribution']) {
        dcat['prov:qualifiedAttribution'] = []
      }
      dcat['prov:qualifiedAttribution'].push({
        '@type': 'prov:Attribution',
        'prov:agent': this.ownerAgent(nft.owner, chainId),
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/owner',
          '@type': 'dct:AgentRole'
        }
      })
    }

    const csStats = credentialSubject.stats || ddoCopy.stats

    if (csStats) {
      const statsOut: Record<string, unknown> = {}
      if (csStats.allocated !== undefined && csStats.allocated !== null) {
        statsOut['oec:allocated'] = csStats.allocated
      }
      if (csStats.orders !== undefined && csStats.orders !== null) {
        statsOut['oec:orders'] = csStats.orders
      }
      if (csStats.price) {
        statsOut['oec:price'] = {
          ...serializeWithVocabulary(csStats.price, ['tokenAddress', 'tokenSymbol']),
          'oec:value': String(csStats.price.value)
        }
      }
      dcat['oec:stats'] = statsOut as unknown as (typeof dcat)['oec:stats']
    } else if (stats.length > 0) {
      const totalOrders = stats.reduce(
        (sum: number, stat: any) => sum + (stat.orders || 0),
        0
      )
      // No invented values: only the real order total is emitted (no "allocated")
      const statsOut: Record<string, unknown> = {
        'oec:orders': totalOrders
      }

      // One price entry per service price, with the symbol resolved from accessDetails
      const priceEntries: Array<Record<string, unknown>> = []
      for (const stat of stats) {
        const statPrices = Array.isArray(stat?.prices) ? stat.prices : []
        for (const price of statPrices) {
          const tokenAddress = typeof price?.token === 'string' ? price.token : undefined
          const baseToken = tokenAddress
            ? accessDetails.find(
                (detail: any) =>
                  typeof detail?.baseToken?.address === 'string' &&
                  detail.baseToken.address.toLowerCase() === tokenAddress.toLowerCase()
              )?.baseToken
            : undefined
          priceEntries.push(
            serializeWithVocabulary(
              {
                tokenAddress,
                tokenSymbol: price.tokenSymbol || baseToken?.symbol,
                value:
                  price.price !== undefined && price.price !== null
                    ? String(price.price)
                    : undefined,
                serviceId: stat.serviceId
              },
              ['tokenAddress', 'tokenSymbol', 'value', 'serviceId']
            )
          )
        }
      }

      if (priceEntries.length > 0) {
        statsOut['oec:price'] = priceEntries
      }
      dcat['oec:stats'] = statsOut as unknown as (typeof dcat)['oec:stats']
    }

    if (Object.keys(nft).length > 0) {
      const nftOut: Record<string, unknown> = serializeWithVocabulary(nft, [
        'name',
        'symbol',
        'address',
        'owner',
        'state',
        'tokenURI'
      ])
      if (nft.name) nftOut['dct:title'] = nft.name
      delete nftOut['oec:name']
      if (nft.created) {
        nftOut['dct:issued'] = { '@type': 'xsd:dateTime', '@value': nft.created }
      }
      dcat['oec:nft'] = nftOut as unknown as (typeof dcat)['oec:nft']
    }

    if (event.txid || event.tx) {
      dcat['oec:event'] = {
        ...serializeWithVocabulary(event, ['block', 'contract', 'datetime', 'from']),
        'oec:tx': event.txid || event.tx
      } as unknown as (typeof dcat)['oec:event']
    }

    if (accessDetails.length > 0) {
      dcat['oec:accessDetails'] = accessDetails
        .map((detail: any) => this.formatAccessDetails(detail, services))
        .filter(Boolean)
    }

    CORE_LOGGER.debug(`[DCAT] Transformed DCAT: ${JSON.stringify(dcat, null, 2)}`)
    return dcat
  }

  private formatCredentialsForDCAT(credentials: any): Record<string, unknown> {
    return {
      ...serializeWithVocabulary(normalizeCredentialKeys(credentials), ['matchDeny']),
      ...(Array.isArray(credentials.allow)
        ? {
            'oec:allow': credentials.allow.map((rule: any) => ({
              ...serializeWithVocabulary(normalizeCredentialKeys(rule), [
                'type',
                'requestCredentials',
                'vcPolicies',
                'vpPolicies'
              ]),
              ...(Array.isArray(rule.values)
                ? {
                    'oec:values': rule.values.map((v: any) =>
                      v && typeof v === 'object'
                        ? serializeWithVocabulary(normalizeCredentialKeys(v), [
                            'address',
                            'requestCredentials',
                            'vcPolicies',
                            'vpPolicies'
                          ])
                        : { 'oec:value': v }
                    )
                  }
                : {})
            }))
          }
        : {}),
      ...(Array.isArray(credentials.deny)
        ? {
            'oec:deny': credentials.deny.map((rule: any) => ({
              ...serializeWithVocabulary(normalizeCredentialKeys(rule), [
                'type',
                'requestCredentials',
                'vcPolicies',
                'vpPolicies'
              ]),
              ...(Array.isArray(rule.values)
                ? {
                    'oec:values': rule.values.map((v: any) =>
                      v && typeof v === 'object'
                        ? serializeWithVocabulary(normalizeCredentialKeys(v), [
                            'address',
                            'requestCredentials',
                            'vcPolicies',
                            'vpPolicies'
                          ])
                        : { 'oec:value': v }
                    )
                  }
                : {})
            }))
          }
        : {})
    }
  }

  private formatServicesForDCAT(services: any[], datasetId?: string): DCATService[] {
    if (!Array.isArray(services)) {
      return []
    }

    // The dataset id is a DID (valid IRI), used as-is
    const normalizedDatasetId = datasetId || undefined

    return services
      .filter((service) => service && typeof service === 'object')
      .map((service) => {
        const serviceId =
          typeof service.id === 'string' && service.id.trim() !== ''
            ? service.id.trim()
            : undefined

        const formattedService: DCATService = {
          '@type': 'dcat:DataService'
        }

        if (serviceId) {
          formattedService['@id'] = this.serviceIri(datasetId || '', serviceId)
          formattedService['dct:identifier'] = serviceId
        }

        if (service.name) {
          formattedService['dct:title'] =
            typeof service.name === 'string' ? service.name : String(service.name)
        } else if (serviceId) {
          formattedService['dct:title'] = `Service ${serviceId}`
        }

        if (service.description) {
          const description =
            typeof service.description === 'object'
              ? service.description['@value']
              : service.description

          if (typeof description === 'string' && description.trim() !== '') {
            formattedService['dct:description'] = description
          }
        }

        if (service.serviceEndpoint) {
          const endpoint =
            typeof service.serviceEndpoint === 'string'
              ? service.serviceEndpoint
              : service.serviceEndpoint?.['@id']

          if (typeof endpoint === 'string' && endpoint.trim() !== '') {
            formattedService['dcat:endpointURL'] = {
              '@id': endpoint,
              '@type': 'rdfs:Resource'
            }
          }
        }

        if (normalizedDatasetId) {
          formattedService['dcat:servesDataset'] = {
            '@id': normalizedDatasetId
          }
        }

        if (service.type !== undefined && service.type !== null) {
          formattedService['oec:serviceType'] = String(service.type)
        }

        if (service.datatokenAddress !== undefined && service.datatokenAddress !== null) {
          formattedService['oec:datatokenAddress'] = service.datatokenAddress
        }

        if (service.files !== undefined && service.files !== null) {
          formattedService['oec:files'] = service.files
        }

        if (service.timeout !== undefined && service.timeout !== null) {
          formattedService['oec:timeout'] = Number(service.timeout)
        }

        if (service.state !== undefined && service.state !== null) {
          formattedService['oec:state'] = Number(service.state)
        }

        if (service.compute !== undefined && service.compute !== null) {
          formattedService['oec:compute'] = {
            ...serializeWithVocabulary(service.compute, [
              'allowNetworkAccess',
              'allowRawAlgorithm'
            ]),
            ...(Array.isArray(service.compute.publisherTrustedAlgorithms)
              ? {
                  'oec:publisherTrustedAlgorithms':
                    service.compute.publisherTrustedAlgorithms.map((algorithm: any) =>
                      serializeWithVocabulary(algorithm, [
                        'did',
                        'filesChecksum',
                        'containerSectionChecksum',
                        'serviceId'
                      ])
                    )
                }
              : {}),
            ...(Array.isArray(service.compute.publisherTrustedAlgorithmPublishers)
              ? {
                  'oec:publisherTrustedAlgorithmPublishers':
                    service.compute.publisherTrustedAlgorithmPublishers
                }
              : {})
          }
        }

        if (
          Array.isArray(service.consumerParameters) &&
          service.consumerParameters.length > 0
        ) {
          formattedService['oec:consumerParameters'] = service.consumerParameters.map(
            (p: any) => serializeWithVocabulary(p, OE_OBJECT_SHAPES.ConsumerParameter)
          )
        }

        if (service.credentials !== undefined && service.credentials !== null) {
          formattedService['oec:credentials'] = this.formatCredentialsForDCAT(
            service.credentials
          )
        }

        return formattedService
      })
  }

  private formatDatatokensForDCAT(datatokens: any[]): DCATDatatoken[] {
    if (!datatokens || !Array.isArray(datatokens)) {
      return []
    }

    return datatokens.map((token) =>
      serializeWithVocabulary(token, OE_OBJECT_SHAPES.Datatoken)
    ) as unknown as DCATDatatoken[]
  }

  private formatAccessDetails(
    accessDetails: any,
    services: any[] = []
  ): DCATAccessDetails {
    if (!accessDetails) {
      return undefined
    }

    const formatted: Record<string, unknown> = {
      '@type': accessDetails.type || 'oec:Fixed'
    }

    // Link this price entry to its service through the datatoken address
    const datatokenAddress = accessDetails.datatoken?.address
    if (typeof datatokenAddress === 'string' && Array.isArray(services)) {
      const matchingService = services.find(
        (service: any) =>
          typeof service?.datatokenAddress === 'string' &&
          service.datatokenAddress.toLowerCase() === datatokenAddress.toLowerCase()
      )
      if (matchingService?.id) {
        formatted['oec:serviceId'] = matchingService.id
      }
    }

    for (const key of [
      'addressOrId',
      'isOwned',
      'isPurchasable',
      'price',
      'publisherMarketOrderFee',
      'templateId',
      'validOrderTx',
      'paymentCollector'
    ]) {
      if (accessDetails[key] !== undefined) {
        formatted[`oec:${key}`] = accessDetails[key]
      }
    }

    if (accessDetails.baseToken) {
      formatted['oec:baseToken'] = {
        'dct:title': accessDetails.baseToken.name,
        ...serializeWithVocabulary(accessDetails.baseToken, [
          'address',
          'decimals',
          'symbol'
        ])
      }
    }

    if (accessDetails.datatoken) {
      formatted['oec:datatoken'] = {
        'dct:title': accessDetails.datatoken.name,
        ...serializeWithVocabulary(accessDetails.datatoken, [
          'address',
          'symbol',
          'decimals'
        ])
      }
    }

    return formatted as unknown as DCATAccessDetails
  }
}

export class ValidateDDOHandler extends CommandHandler {
  validate(command: ValidateDDOCommand): ValidateParams {
    let validation = validateCommandParameters(command, ['ddo'])
    if (validation.valid) {
      validation = validateDDOIdentifier(command.ddo.id)
    }

    return validation
  }

  async handle(task: ValidateDDOCommand): Promise<P2PCommandResponse> {
    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }
    if (!task.ddo || !task.ddo.version) {
      return {
        stream: null,
        status: { httpStatus: 400, error: 'Missing DDO version' }
      }
    }
    let shouldSign = false
    const configuration = this.getOceanNode().getConfig()
    if (configuration.validateUnsignedDDO) {
      shouldSign = true
    }
    if (task.authorization || task.signature || task.nonce || task.publisherAddress) {
      const validationResponse = await this.validateTokenOrSignature(
        task.authorization,
        task.publisherAddress,
        task.nonce,
        task.signature,
        task.command
      )
      if (validationResponse.status.httpStatus !== 200) {
        return validationResponse
      }
      shouldSign = true
    }

    try {
      const ddoInstance = DDOManager.getDDOClass(task.ddo)
      const validation = await ddoInstance.validate()
      if (validation[0] === false) {
        CORE_LOGGER.logMessageWithEmoji(
          `Validation failed with error: ${validation[1]}`,
          true,
          GENERIC_EMOJIS.EMOJI_CROSS_MARK,
          LOG_LEVELS_STR.LEVEL_ERROR
        )
        return {
          stream: null,
          status: { httpStatus: 400, error: `Validation error: ${validation[1]}` }
        }
      }
      if (isPolicyServerConfigured()) {
        const policyServer = new PolicyServer()
        const response = await policyServer.validateDDO(
          task.ddo,
          task.publisherAddress,
          task.policyServer
        )
        if (!response.success) {
          CORE_LOGGER.logMessage(
            `Error: Validation for ${task.publisherAddress} was denied`,
            true
          )
          return {
            stream: null,
            status: {
              httpStatus: 403,
              error: `Error: Validation for ${task.publisherAddress} was denied`
            }
          }
        }
      }
      return {
        stream: shouldSign
          ? Readable.from(
              JSON.stringify(
                await this.getOceanNode().getValidationSignature(JSON.stringify(task.ddo))
              )
            )
          : null,
        status: { httpStatus: 200 }
      }
    } catch (error) {
      CORE_LOGGER.logMessageWithEmoji(
        `Error occurred on validateDDO command: ${error}`,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: { httpStatus: 500, error: 'Unknown error: ' + error.message }
      }
    }
  }
}

export function validateDdoSignedByPublisher(
  ddo: DDO,
  nonce: string,
  signature: string,
  publisherAddress: string
): boolean {
  try {
    const message = ddo.id + nonce
    const messageHash = ethers.solidityPackedKeccak256(
      ['bytes'],
      [ethers.hexlify(ethers.toUtf8Bytes(message))]
    )
    const messageHashBytes = ethers.getBytes(messageHash)
    // Try both verification methods for backward compatibility
    const addressFromHashSignature = ethers.verifyMessage(messageHash, signature)
    const addressFromBytesSignature = ethers.verifyMessage(messageHashBytes, signature)
    return (
      addressFromHashSignature?.toLowerCase() === publisherAddress?.toLowerCase() ||
      addressFromBytesSignature?.toLowerCase() === publisherAddress?.toLowerCase()
    )
  } catch (error) {
    CORE_LOGGER.logMessage(`Error: ${error}`, true)
    return false
  }
}

export function validateDDOIdentifier(identifier: string): ValidateParams {
  const valid =
    !!identifier &&
    identifier.length > 0 &&
    (identifier.startsWith('did:op:') || identifier.startsWith('did:ope:'))
  if (!valid) {
    return {
      valid: false,
      status: 400,
      reason: 'Missing or invalid required parameter "id"'
    }
  }
  return {
    valid: true
  }
}

/**
 * Checks if the response is legit
 * @param ddo the DDO
 * @param oceanNode the OceanNode instance
 * @returns validation result
 */
async function checkIfDDOResponseIsLegit(
  ddo: any,
  oceanNode: OceanNode
): Promise<boolean> {
  const clonedDdo = structuredClone(ddo)
  const { indexedMetadata } = clonedDdo
  const updatedDdo = deleteIndexedMetadataIfExists(ddo)
  const { nftAddress, chainId } = updatedDdo
  let isValid = validateDDOHash(updatedDdo.id, nftAddress, chainId)
  // 1) check hash sha256(nftAddress + chainId)
  if (!isValid) {
    CORE_LOGGER.error(`Asset ${updatedDdo.id} does not have a valid hash`)
    return false
  }

  // 2) check event
  //
  // This tested a bare `event`, which is declared nowhere in this function - the only `event`
  // in the file is a `const` inside a `for` block further down, in a different scope. So the
  // check threw `ReferenceError: event is not defined` for every DDO that got past the hash
  // gate above, the caller's `try/catch` swallowed it as "Error on sink function", and the
  // answer was discarded. The effect was that **no** DDO fetched from a remote provider was
  // ever accepted: a FindDDO could only ever return what this node already held locally. It
  // was invisible because the failure looked identical to a provider that simply had nothing.
  //
  // TypeScript did not catch it because `target: ES2022` pulls in the default DOM library,
  // where `event` is a declared global.
  //
  // What the check is for is visible from step 5, which reads `indexedMetadata.event.block` and
  // `indexedMetadata.event.tx`: the DDO has to carry an indexed event before any of that can be
  // verified. Testing that also stops step 5 throwing on a DDO that has no `indexedMetadata`.
  if (!indexedMetadata?.event) {
    CORE_LOGGER.error(
      `Asset ${updatedDdo.id} carries no indexed event, cannot confirm validation.`
    )
    return false
  }

  // 3) check if we support this network
  const config = oceanNode.getConfig()
  const network = config.supportedNetworks[chainId.toString()]
  if (!network) {
    CORE_LOGGER.error(
      `We do not support the newtwork ${chainId}, cannot confirm validation.`
    )
    return false
  }
  // 4) check if was deployed by our factory
  const blockchain = oceanNode.getBlockchain(chainId as number)
  if (!blockchain) {
    CORE_LOGGER.error(
      `Blockchain instance not available for chain ${chainId}, cannot confirm validation.`
    )
    return false
  }
  const signer = await blockchain.getSigner()

  const wasDeployedByUs = await wasNFTDeployedByOurFactory(
    chainId as number,
    signer,
    ethers.getAddress(nftAddress)
  )

  if (!wasDeployedByUs) {
    CORE_LOGGER.error(`Asset ${updatedDdo.id} not deployed by the data NFT factory`)
    return false
  }

  // 5) check block & events
  const networkBlock = await getNetworkHeight(await blockchain.getProvider())
  if (
    !indexedMetadata.event.block ||
    indexedMetadata.event.block < 0 ||
    networkBlock < indexedMetadata.event.block
  ) {
    CORE_LOGGER.error(
      `Event block: ${indexedMetadata.event.block} is either missing or invalid`
    )
    return false
  }

  // check events on logs
  const txId: string = indexedMetadata.event.tx || indexedMetadata.event.txid // NOTE: DDO is txid, Asset is tx
  if (!txId) {
    CORE_LOGGER.error(`DDO event missing tx data, cannot confirm transaction`)
    return false
  }
  const provider = await blockchain.getProvider()
  const receipt = await provider.getTransactionReceipt(txId)
  let foundEvents = false
  if (receipt) {
    const { logs } = receipt
    for (const log of logs) {
      const event = findEventByKey(log.topics[0])
      if (event && Object.values(EVENTS).includes(event.type)) {
        if (
          event.type === EVENTS.METADATA_CREATED ||
          event.type === EVENTS.METADATA_UPDATED
        ) {
          foundEvents = true
          break
        }
      }
    }
    isValid = foundEvents
  } else {
    isValid = false
  }

  return isValid
}
