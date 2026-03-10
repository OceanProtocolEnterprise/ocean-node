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
import { sleep, readStream, streamToUint8Array } from '../../../utils/util.js'
import { CORE_LOGGER } from '../../../utils/logging/common.js'
import { ethers, isAddress } from 'ethers'
import ERC721Template from '@oceanprotocol/contracts/artifacts/contracts/templates/ERC721Template.sol/ERC721Template.json' with { type: 'json' }
// import lzma from 'lzma-native'
import lzmajs from 'lzma-purejs-requirejs'
import { getValidationSignature, isRemoteDDO } from '../utils/validateDdoHandler.js'
import {
  getConfiguration,
  hasP2PInterface,
  isPolicyServerConfigured
} from '../../../utils/config.js'
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
  DCATTemporal
} from '../../../@types/dcat.js'

const MAX_NUM_PROVIDERS = 5
// after 60 seconds it returns whatever info we have available
const MAX_RESPONSE_WAIT_TIME_SECONDS = 60
// wait time for reading the next getDDO command
const MAX_WAIT_TIME_SECONDS_GET_DDO = 5

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
    const config = await getConfiguration()
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
          if (!receipt.logs.length) {
            throw new Error('receipt logs 0')
          }
          const abiInterface = new ethers.Interface(ERC721Template.abi)
          const eventObject = {
            topics: receipt.logs[0].topics as string[],
            data: receipt.logs[0].data
          }
          const eventData = abiInterface.parseLog(eventObject)
          if (
            eventData.name !== EVENTS.METADATA_CREATED &&
            eventData.name !== EVENTS.METADATA_UPDATED
          ) {
            throw new Error(`event name ${eventData.name}`)
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
        if (decryptedDocumentHash !== documentHash) {
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
      const database = this.getOceanNode().getDatabase()
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
    try {
      const node = this.getOceanNode()
      const p2pNode = node.getP2PNode()

      // if not P2P node just look on local DB
      if (!hasP2PInterface || !p2pNode) {
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
      // ids of available providers
      let processed = 0
      let toProcess = 0

      const configuration = await getConfiguration()

      // Checking locally...
      const ddoInfo = await findDDOLocally(node, task.id)
      if (ddoInfo) {
        // node has ddo
        // add to the result list anyway
        resultList.push(ddoInfo)

        updatedCache = true
      }

      const processDDOResponse = async (peer: string, data: Uint8Array) => {
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
              const database = node.getDatabase()
              if (database && database.ddo) {
                const ddoExistsLocally = await database.ddo.retrieve(ddo.id)
                if (!ddoExistsLocally) {
                  p2pNode.storeAndAdvertiseDDOS([ddo])
                }
              }
            }
          } else {
            CORE_LOGGER.warn(
              `Cannot confirm validity of ${ddo.id} from remote node, skipping it...`
            )
          }
        } catch (err) {
          CORE_LOGGER.logMessageWithEmoji(
            'FindDDO: Error on sink function: ' + err.message,
            true,
            GENERIC_EMOJIS.EMOJI_CROSS_MARK,
            LOG_LEVELS_STR.LEVEL_ERROR
          )
        }
        processed++
      }

      // if something goes really bad then exit after 60 secs
      const fnTimeout = setTimeout(() => {
        CORE_LOGGER.log(LOG_LEVELS_STR.LEVEL_DEBUG, 'FindDDO: Timeout reached: ', true)
        return {
          stream: Readable.from(JSON.stringify(sortFindDDOResults(resultList), null, 4)),
          status: { httpStatus: 200 }
        }
      }, 1000 * MAX_RESPONSE_WAIT_TIME_SECONDS)

      // check other providers for this ddo
      const providers = await p2pNode.getProvidersForString(task.id)
      // check if includes self and exclude from check list
      if (providers.length > 0) {
        // exclude this node from the providers list if present
        const filteredProviders = providers.filter((provider: any) => {
          return provider.id.toString() !== p2pNode.getPeerId()
        })

        // work with the filtered list only
        if (filteredProviders.length > 0) {
          toProcess = filteredProviders.length
          // only process a maximum of 5 provider entries per DDO (might never be that much anyway??)
          if (toProcess > MAX_NUM_PROVIDERS) {
            filteredProviders.slice(0, MAX_NUM_PROVIDERS)
            toProcess = MAX_NUM_PROVIDERS
          }

          let doneLoop = 0
          do {
            // eslint-disable-next-line no-unmodified-loop-condition
            for (let i = 0; i < toProcess && doneLoop < toProcess; i++) {
              const provider = filteredProviders[i]
              const peer = provider.id.toString()
              const getCommand: GetDdoCommand = {
                id: task.id,
                command: PROTOCOL_COMMANDS.GET_DDO
              }

              try {
                const response = await p2pNode.sendTo(peer, JSON.stringify(getCommand))

                if (response.status.httpStatus === 200 && response.stream) {
                  // Convert stream to Uint8Array for processing
                  const data = await streamToUint8Array(response.stream as Readable)
                  await processDDOResponse(peer, data)
                } else {
                  processed++
                }
              } catch (innerException) {
                processed++
              }
              // 'sleep 5 seconds...'

              CORE_LOGGER.logMessage(
                `Sleeping for: ${MAX_WAIT_TIME_SECONDS_GET_DDO} seconds, while getting DDO info remote peer...`,
                true
              )
              await sleep(MAX_WAIT_TIME_SECONDS_GET_DDO * 1000) // await 5 seconds before proceeding to next one
              // if the ddo is not cached, the very 1st request will take a bit longer
              // cause it needs to get the response from all the other providers call getDDO()
              // otherwise is immediate as we just return the cached version, once the cache expires we
              // repeat the procedure and query the network again, updating cache at the end
            }
            doneLoop += 1
          } while (processed < toProcess)

          if (updatedCache) {
            p2pNode.getDDOCache().updated = new Date().getTime()
          }

          // house cleaning
          clearTimeout(fnTimeout)
          return {
            stream: Readable.from(
              JSON.stringify(sortFindDDOResults(resultList), null, 4)
            ),
            status: { httpStatus: 200 }
          }
        } else {
          // could empty list
          clearTimeout(fnTimeout)
          return {
            stream: Readable.from(
              JSON.stringify(sortFindDDOResults(resultList), null, 4)
            ),
            status: { httpStatus: 200 }
          }
        }
      } else {
        // could be empty list
        clearTimeout(fnTimeout)
        return {
          stream: Readable.from(JSON.stringify(sortFindDDOResults(resultList), null, 4)),
          status: { httpStatus: 200 }
        }
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
    }
  }

  // Function to use findDDO and get DDO in desired format
  async findAndFormatDdo(ddoId: string, force: boolean = false): Promise<DDO | null> {
    const node = this.getOceanNode()
    // First try to find the DDO Locally if findDDO is not enforced
    if (!force) {
      try {
        const database = node.getDatabase()
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

  private formatDistributions(ddo: any): DCATDistribution[] {
    const distributions: DCATDistribution[] = []
    const credentialSubject = ddo.credentialSubject || {}

    if (credentialSubject.services && Array.isArray(credentialSubject.services)) {
      credentialSubject.services.forEach((service: any) => {
        const distribution: DCATDistribution = {
          '@type': 'dcat:Distribution',
          'dcat:accessURL': {
            '@id': service.serviceEndpoint || ''
          }
        }

        if (service.name) {
          distribution['dct:title'] = service.name
        }

        if (service.type === 'compute') {
          distribution['dcat:mediaType'] = 'application/json'
          distribution['dcat:format'] = 'compute-service'

          if (service.compute) {
            distribution['oc:compute'] = {
              'oc:allowNetworkAccess': service.compute.allowNetworkAccess || false,
              'oc:allowRawAlgorithm': service.compute.allowRawAlgorithm || false,
              'oc:publisherTrustedAlgorithms':
                service.compute.publisherTrustedAlgorithms?.map((algo: any) => ({
                  'oc:did': algo.did,
                  'oc:filesChecksum': algo.filesChecksum,
                  'oc:containerSectionChecksum': algo.containerSectionChecksum,
                  'oc:serviceId': algo.serviceId
                })),
              'oc:publisherTrustedAlgorithmPublishers':
                service.compute.publisherTrustedAlgorithmPublishers || []
            }
          }
        } else if (service.type === 'access') {
          distribution['dcat:mediaType'] = 'application/octet-stream'
        }

        if (service.files) {
          distribution['dcat:format'] = distribution['dcat:format'] || 'encrypted'
        }

        if (service.files && service.files.length > 64) {
          distribution['dcat:checksum'] = {
            '@type': 'spdx:Checksum',
            'spdx:algorithm': 'SHA-256',
            'spdx:checksumValue': service.files.substring(0, 64)
          }
        }

        distributions.push(distribution)
      })
    }

    return distributions
  }

  private formatQualifiedAttribution(
    metadata: any,
    nftOwner?: string
  ): DCATQualifiedAttribution[] {
    const attributions: DCATQualifiedAttribution[] = []

    if (metadata.author && metadata.author.trim && metadata.author.trim() !== '') {
      const authorName =
        typeof metadata.author === 'string'
          ? metadata.author
          : metadata.author['foaf:name'] || ''

      if (authorName) {
        attributions.push({
          '@type': 'prov:Attribution',
          'prov:agent': {
            '@type': 'foaf:Agent',
            'foaf:name': authorName
          },
          'prov:hadRole': {
            '@id': 'http://inspire.ec.europa.eu/role/author',
            '@type': 'dct:AgentRole'
          }
        })
      }
    } else if (nftOwner) {
      attributions.push({
        '@type': 'prov:Attribution',
        'prov:agent': {
          '@type': 'foaf:Agent',
          'foaf:name': `NFT Owner: ${nftOwner}`
        },
        'prov:hadRole': {
          '@id': 'http://inspire.ec.europa.eu/role/owner',
          '@type': 'dct:AgentRole'
        }
      })
    }

    if (metadata.publisher) {
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

  private formatTemporalCoverage(metadata: any): DCATTemporal | undefined {
    if (!metadata.created && !metadata.updated) {
      return undefined
    }

    return {
      '@type': 'dct:PeriodOfTime',
      'dcat:startDate': metadata.created
        ? {
            '@type': 'xsd:dateTime',
            '@value': metadata.created
          }
        : undefined,
      'dcat:endDate': metadata.updated
        ? {
            '@type': 'xsd:dateTime',
            '@value': metadata.updated
          }
        : undefined
    }
  }

  transformToDCAT(ddo: any): DCATDataset {
    CORE_LOGGER.debug(`[DCAT] Original DDO v5: ${JSON.stringify(ddo, null, 2)}`)

    const ddoCopy = JSON.parse(JSON.stringify(ddo))

    const credentialSubject = ddoCopy.credentialSubject || {}
    const metadata = credentialSubject.metadata || {}
    const indexedMetadata = ddoCopy.indexedMetadata || {}
    const nft = indexedMetadata.nft || {}
    const stats = indexedMetadata.stats || []
    const purgatory = indexedMetadata.purgatory || { state: false }
    const event = indexedMetadata.event || {}

    const dcat: DCATDataset = {
      '@context': {
        dcat: 'http://www.w3.org/ns/dcat#',
        dct: 'http://purl.org/dc/terms/',
        foaf: 'http://xmlns.com/foaf/0.1/',
        geo: 'http://www.opengis.net/ont/geosparql#',
        oc: 'https://oceanprotocol.com/vocab/',
        prov: 'http://www.w3.org/ns/prov#',
        rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
        skos: 'http://www.w3.org/2004/02/skos/core#',
        spdx: 'http://spdx.org/rdf/terms#',
        xsd: 'http://www.w3.org/2001/XMLSchema#'
      },
      '@id': ddoCopy.id ? `urn:${ddoCopy.id}` : '',
      '@type': 'dcat:Dataset',
      'dcat:version': ddoCopy.version || '5.0.0',
      'dct:title': metadata.name || ''
    }

    if (metadata.description) {
      if (typeof metadata.description === 'object' && metadata.description['@value']) {
        dcat['dct:description'] = metadata.description['@value']
      } else if (typeof metadata.description === 'string') {
        dcat['dct:description'] = metadata.description
      }
    }

    if (metadata.tags && Array.isArray(metadata.tags) && metadata.tags.length > 0) {
      dcat['dcat:keyword'] = metadata.tags
    } else if (credentialSubject.services) {
      const serviceTypes = credentialSubject.services
        .map((s: any) => s.type)
        .filter((t: string) => t)

      if (serviceTypes.length > 0) {
        dcat['dcat:keyword'] = serviceTypes
      }
    }

    if (metadata.author && metadata.author.trim && metadata.author.trim() !== '') {
      if (typeof metadata.author === 'string') {
        dcat['dct:creator'] = {
          '@type': 'foaf:Agent',
          'foaf:name': metadata.author
        }
      } else if (typeof metadata.author === 'object') {
        dcat['dct:creator'] = metadata.author
      }
    }

    if (metadata.license) {
      if (typeof metadata.license === 'object') {
        dcat['dct:license'] = metadata.license.name || JSON.stringify(metadata.license)
      } else {
        dcat['dct:license'] = metadata.license
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

    if (metadata.additionalInformation?.['dct:spatial']) {
      dcat['dct:spatial'] = metadata.additionalInformation['dct:spatial']

      const spatial = metadata.additionalInformation['dct:spatial']
      if (spatial['dcat:bbox']) {
        dcat['dcat:bbox'] = spatial['dcat:bbox']
      }
      if (spatial['dcat:centroid']) {
        dcat['dcat:centroid'] = spatial['dcat:centroid']
      }
    }

    if (metadata.additionalInformation?.['dcat:theme']) {
      dcat['dcat:theme'] = metadata.additionalInformation['dcat:theme']
    }

    if (metadata.additionalInformation?.['dcat:spatialResolutionInMeters']) {
      dcat['dcat:spatialResolutionInMeters'] =
        metadata.additionalInformation['dcat:spatialResolutionInMeters']
    }

    if (metadata.additionalInformation?.['dcat:temporalResolution']) {
      dcat['dcat:temporalResolution'] =
        metadata.additionalInformation['dcat:temporalResolution']
    }

    if (metadata.additionalInformation?.['dct:accrualPeriodicity']) {
      dcat['dct:accrualPeriodicity'] = {
        '@type': 'dct:Frequency',
        '@id': metadata.additionalInformation['dct:accrualPeriodicity']
      }
    }

    const distributions = this.formatDistributions(ddoCopy)
    if (distributions.length > 0) {
      dcat['dcat:distribution'] = distributions
    }

    const temporal = this.formatTemporalCoverage(metadata)
    if (temporal) {
      dcat['dct:temporal'] = temporal
    }

    const attributions = this.formatQualifiedAttribution(metadata, nft.owner)
    if (attributions.length > 0) {
      dcat['prov:qualifiedAttribution'] = attributions
    }

    if (metadata.language) {
      dcat['dct:language'] = Array.isArray(metadata.language)
        ? metadata.language
        : [metadata.language]
    }

    if (ddoCopy.id) {
      dcat['dct:identifier'] = [ddoCopy.id]
    }

    if (metadata.license) {
      dcat['dct:rights'] =
        typeof metadata.license === 'string' ? metadata.license : metadata.license.name
    }

    if (metadata.accessRights) {
      dcat['dct:accessRights'] = metadata.accessRights
    }

    dcat['oc:chainId'] = credentialSubject.chainId
    dcat['oc:nftAddress'] = credentialSubject.nftAddress
    dcat['oc:datatokens'] = credentialSubject.datatokens || []
    dcat['oc:services'] = this.formatServicesForDCAT(credentialSubject.services || [])

    dcat['oc:purgatory'] = {
      'oc:state': purgatory.state
    }

    if (stats.length > 0) {
      const totalOrders = stats.reduce(
        (sum: number, stat: any) => sum + (stat.orders || 0),
        0
      )
      dcat['oc:stats'] = {
        'oc:allocated': totalOrders,
        'oc:orders': totalOrders
      }

      const firstPrice = stats[0]?.prices?.[0]
      if (firstPrice) {
        dcat['oc:stats']['oc:price'] = {
          'oc:tokenAddress': firstPrice.token,
          'oc:tokenSymbol': firstPrice.tokenSymbol || 'EURC',
          'oc:value': firstPrice.price
        }
      }
    }

    if (Object.keys(nft).length > 0) {
      dcat['oc:nft'] = {
        'dct:title': nft.name,
        'oc:address': nft.address,
        'oc:owner': nft.owner,
        'oc:state': nft.state,
        'oc:symbol': nft.symbol,
        'oc:tokenURI': nft.tokenURI
      }

      if (nft.created) {
        dcat['oc:nft']['dct:issued'] = {
          '@type': 'xsd:dateTime',
          '@value': nft.created
        }
      }
    }

    if (event.txid || event.tx) {
      dcat['oc:event'] = {
        'oc:block': event.block,
        'oc:contract': event.contract,
        'oc:datetime': event.datetime,
        'oc:from': event.from,
        'oc:tx': event.txid || event.tx
      }
    }

    if (
      ddoCopy.accessDetails &&
      Array.isArray(ddoCopy.accessDetails) &&
      ddoCopy.accessDetails.length > 0
    ) {
      dcat['oc:accessDetails'] = this.formatAccessDetails(ddoCopy.accessDetails[0])
    }

    CORE_LOGGER.debug(`[DCAT] Transformed DCAT: ${JSON.stringify(dcat, null, 2)}`)
    return dcat
  }

  private formatServicesForDCAT(services: any[]): any[] {
    if (!services || !Array.isArray(services)) {
      return []
    }

    return services.map((service) => {
      const formattedService: any = { ...service }

      if (service.serviceEndpoint && typeof service.serviceEndpoint === 'string') {
        formattedService['dct:title'] = service.serviceEndpoint
        formattedService.serviceEndpoint = {
          '@id': service.serviceEndpoint,
          '@type': 'rdfs:Resource'
        }
      }

      return formattedService
    })
  }

  private formatAccessDetails(accessDetails: any): any {
    if (!accessDetails) {
      return undefined
    }

    const formatted: any = {
      '@type': 'oc:Fixed',
      'oc:addressOrId': accessDetails.addressOrId,
      'oc:isOwned': accessDetails.isOwned || false,
      'oc:isPurchasable': accessDetails.isPurchasable || false,
      'oc:price': accessDetails.price,
      'oc:publisherMarketOrderFee': accessDetails.publisherMarketOrderFee || '0',
      'oc:templateId': accessDetails.templateId
    }

    if (accessDetails.validOrderTx) {
      formatted['oc:validOrderTx'] = accessDetails.validOrderTx
    }

    if (accessDetails.paymentCollector) {
      formatted['oc:paymentCollector'] = accessDetails.paymentCollector
    }

    if (accessDetails.baseToken) {
      formatted['oc:baseToken'] = {
        'dct:title': accessDetails.baseToken.name,
        'oc:address': accessDetails.baseToken.address,
        'oc:decimals': accessDetails.baseToken.decimals,
        'oc:symbol': accessDetails.baseToken.symbol
      }
    }

    if (accessDetails.datatoken) {
      formatted['oc:datatoken'] = {
        'dct:title': accessDetails.datatoken.name,
        'oc:address': accessDetails.datatoken.address,
        'oc:symbol': accessDetails.datatoken.symbol,
        'oc:decimals': accessDetails.datatoken.decimals
      }
    }

    return formatted
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
    const configuration = await getConfiguration()
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
        if (!response) {
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
              JSON.stringify(await getValidationSignature(JSON.stringify(task.ddo)))
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
  const valid = identifier && identifier.length > 0 && identifier.startsWith('did:op')
  if (!valid) {
    return {
      valid: false,
      status: 400,
      reason: ' Missing or invalid required parameter "id'
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
  if (!event) {
    return false
  }

  // 3) check if we support this network
  const config = await getConfiguration()
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
  const txId: string = indexedMetadata.event.txid || indexedMetadata.event.tx // NOTE: DDO is txid, Asset is tx
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
