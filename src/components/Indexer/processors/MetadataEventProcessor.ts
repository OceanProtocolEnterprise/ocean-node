import { DDOManager, DDO, VersionedDDO } from '@oceanprotocol/ddo-js'
import { ethers, Signer, FallbackProvider, getAddress } from 'ethers'
import {
  ENVIRONMENT_VARIABLES,
  EVENTS,
  MetadataStates
} from '../../../utils/constants.js'
import { deleteIndexedMetadataIfExists } from '../../../utils/asset.js'
import { getConfiguration } from '../../../utils/config.js'
import { checkCredentialOnAccessList } from '../../../utils/credentials.js'
import { getDatabase } from '../../../utils/database.js'
import { INDEXER_LOGGER } from '../../../utils/logging/common.js'
import { LOG_LEVELS_STR } from '../../../utils/logging/Logger.js'
import { asyncCallWithTimeout, streamToString } from '../../../utils/util.js'
import { PolicyServer } from '../../policyServer/index.js'
import { wasNFTDeployedByOurFactory, getPricingStatsForDddo, getDid } from '../utils.js'
import { BaseEventProcessor } from './BaseProcessor.js'
import ERC721Template from '@oceanprotocol/contracts/artifacts/contracts/templates/ERC721Template.sol/ERC721Template.json' with { type: 'json' }
import { Purgatory } from '../purgatory.js'
import { isRemoteDDO } from '../../core/utils/validateDdoHandler.js'
import { Storage } from '../../storage/index.js'
import { Readable } from 'stream'

export class MetadataEventProcessor extends BaseEventProcessor {
  async processEvent(
    event: ethers.Log,
    chainId: number,
    signer: Signer,
    provider: FallbackProvider,
    eventName: string
  ): Promise<any> {
    let did = 'did:op'
    let processingStage = 'start'
    try {
      INDEXER_LOGGER.logMessage(
        `MetadataEventProcessor started for tx ${event.transactionHash} on contract ${event.address}`,
        true
      )

      processingStage = 'load-database-and-validate-factory'
      const { ddo: ddoDatabase, ddoState } = await getDatabase()
      const wasDeployedByUs = await wasNFTDeployedByOurFactory(
        chainId,
        signer,
        getAddress(event.address)
      )
      INDEXER_LOGGER.logMessage(
        `Factory validation for ${event.address} returned ${wasDeployedByUs}`,
        true
      )

      if (!wasDeployedByUs) {
        INDEXER_LOGGER.log(
          LOG_LEVELS_STR.LEVEL_ERROR,
          `NFT not deployed by OPF factory`,
          true
        )
        return
      }
      processingStage = 'decode-event'
      const decodedEventData = await this.getEventData(
        provider,
        event.transactionHash,
        ERC721Template.abi,
        eventName
      )
      INDEXER_LOGGER.logMessage(
        `Decoded ${eventName} for tx ${event.transactionHash}`,
        true
      )

      const metadata = decodedEventData.args[4]
      const metadataHash = decodedEventData.args[5]
      const flag = decodedEventData.args[3]
      const owner = decodedEventData.args[0]

      const dataNftAddress = ethers.getAddress(event.address)

      did = getDid(event.address, chainId)

      processingStage = 'load-template-metadata'
      const templateContract = new ethers.Contract(
        dataNftAddress,
        ERC721Template.abi,
        signer
      )
      const metaData = await templateContract.getMetaData()
      const metadataState = Number(metaData[2])
      INDEXER_LOGGER.logMessage(
        `Fetched on-chain metadata state ${metadataState} for ${did}`,
        true
      )

      if ([MetadataStates.DEPRECATED, MetadataStates.REVOKED].includes(metadataState)) {
        INDEXER_LOGGER.logMessage(
          `Delete DDO because Metadata state is ${metadataState}`,
          true
        )
        const { ddo: ddoDatabase } = await getDatabase()
        const ddo = await ddoDatabase.retrieve(did)
        if (!ddo) {
          INDEXER_LOGGER.logMessage(
            `Detected MetadataState changed for ${did}, but it does not exists.`
          )
          return
        }

        const ddoInstance = DDOManager.getDDOClass(ddo)

        INDEXER_LOGGER.logMessage(
          `DDO became non-visible from ${
            ddoInstance.getAssetFields().indexedMetadata.nft.state
          } to ${metadataState}`
        )

        const shortDdoInstance = DDOManager.getDDOClass({
          id: ddo.id,
          version: 'deprecated',
          chainId,
          nftAddress: ddo.nftAddress,
          indexedMetadata: {
            nft: {
              state: metadataState
            }
          }
        })

        const savedDDO = await this.createOrUpdateDDO(
          shortDdoInstance,
          EVENTS.METADATA_STATE
        )
        INDEXER_LOGGER.logMessage(
          `Saved metadata state transition for ${did} with state ${metadataState}`,
          true
        )
        return savedDDO
      }

      processingStage = 'decrypt-and-process-ddo'
      INDEXER_LOGGER.logMessage(`Decrypting DDO payload for ${did}`, true)
      const decryptedDDO = await this.decryptDDO(
        decodedEventData.args[2],
        flag,
        owner,
        event.address,
        chainId,
        event.transactionHash,
        metadataHash,
        metadata
      )
      INDEXER_LOGGER.logMessage(`Decrypt finished for ${did}`, true)
      let ddo = await this.processDDO(decryptedDDO)
      INDEXER_LOGGER.logMessage(`DDO processing finished for ${did}`, true)
      if (
        !isRemoteDDO(decryptedDDO) &&
        parseInt(flag) !== 2 &&
        !this.checkDdoHash(ddo, metadataHash)
      ) {
        INDEXER_LOGGER.logMessage(
          `Aborting ${did} because processed DDO hash check failed`,
          true
        )
        return
      }
      if (ddo.encryptedData) {
        INDEXER_LOGGER.logMessage(`Encrypted data proof found for ${did}`, true)
        const proof = await this.decryptDDOIPFS(
          decodedEventData.args[2],
          owner,
          ddo.encryptedData
        )
        const data = this.getDataFromProof(proof)
        const ddoInstance = DDOManager.getDDOClass(data.ddoObj)
        ddo = ddoInstance.updateFields({
          proof: { signature: data.signature, header: data.header }
        })
        INDEXER_LOGGER.logMessage(`Updated proof fields for ${did}`, true)
      }
      const clonedDdo = structuredClone(ddo)
      const updatedDdo = deleteIndexedMetadataIfExists(clonedDdo)
      const ddoInstance = DDOManager.getDDOClass(updatedDdo)
      if (updatedDdo.id !== ddoInstance.makeDid(event.address, chainId.toString(10))) {
        INDEXER_LOGGER.logMessage(`Generated DID mismatch detected for ${did}`, true)
        INDEXER_LOGGER.error(
          `Decrypted DDO ID is not matching the generated hash for DID.`
        )
        await ddoState.update(
          this.networkId,
          did,
          event.address,
          event.transactionHash,
          false,
          'Decrypted DDO ID does not match generated DID.'
        )
        return
      }
      // for unencrypted DDOs
      if ((parseInt(flag) & 2) === 0 && !this.checkDdoHash(updatedDdo, metadataHash)) {
        INDEXER_LOGGER.logMessage(
          `Unencrypted metadata hash mismatch detected for ${did}`,
          true
        )
        INDEXER_LOGGER.error('Unencrypted DDO hash does not match metadata hash.')
        await ddoState.update(
          this.networkId,
          did,
          event.address,
          event.transactionHash,
          false,
          'Unencrypted DDO hash does not match metadata hash.'
        )
        return
      }

      // check authorized publishers
      processingStage = 'validate-authorized-publishers'
      const { authorizedPublishers, authorizedPublishersList } = await getConfiguration()
      INDEXER_LOGGER.logMessage(`Loaded publisher authorization config for ${did}`, true)
      if (authorizedPublishers.length > 0) {
        // if is not there, do not index
        const authorized: string[] = authorizedPublishers.filter((address) =>
          // do a case insensitive search
          address.toLowerCase().includes(owner.toLowerCase())
        )
        INDEXER_LOGGER.logMessage(
          `Authorized publisher list match count for ${owner}: ${authorized.length}`,
          true
        )
        if (!authorized.length) {
          INDEXER_LOGGER.error(
            `DDO owner ${owner} is NOT part of the ${ENVIRONMENT_VARIABLES.AUTHORIZED_PUBLISHERS.name} group.`
          )
          await ddoState.update(
            this.networkId,
            did,
            event.address,
            event.transactionHash,
            false,
            `DDO owner ${owner} is NOT part of the ${ENVIRONMENT_VARIABLES.AUTHORIZED_PUBLISHERS.name} group.`
          )
          return
        }
      }
      if (authorizedPublishersList) {
        // check accessList
        const isAuthorized = await checkCredentialOnAccessList(
          authorizedPublishersList,
          String(chainId),
          owner,
          signer
        )
        INDEXER_LOGGER.logMessage(
          `Access list authorization for ${owner}: ${isAuthorized}`,
          true
        )
        if (!isAuthorized) {
          INDEXER_LOGGER.error(
            `DDO owner ${owner} is NOT part of the ${ENVIRONMENT_VARIABLES.AUTHORIZED_PUBLISHERS_LIST.name} access group.`
          )
          await ddoState.update(
            this.networkId,
            did,
            event.address,
            event.transactionHash,
            false,
            `DDO owner ${owner} is NOT part of the ${ENVIRONMENT_VARIABLES.AUTHORIZED_PUBLISHERS_LIST.name} access group.`
          )
          return
        }
      }

      // stuff that we overwrite
      did = ddoInstance.getDid()
      const { services } = ddoInstance.getDDOFields()
      INDEXER_LOGGER.logMessage(
        `Updating datatokens for ${did} with ${services?.length || 0} services`,
        true
      )
      ddoInstance.updateFields({
        chainId,
        nftAddress: event.address,
        datatokens: await this.getTokenInfo(services, signer)
      })

      INDEXER_LOGGER.logMessage(
        `Processed new DDO data ${ddoInstance.getDid()} with txHash ${
          event.transactionHash
        } from block ${event.blockNumber}`,
        true
      )

      let previousDdoInstance
      const previousDdo = await ddoDatabase.retrieve(ddoInstance.getDid())
      INDEXER_LOGGER.logMessage(
        `Previous DDO lookup for ${ddoInstance.getDid()} returned ${Boolean(previousDdo)}`,
        true
      )
      if (previousDdo) {
        previousDdoInstance = DDOManager.getDDOClass(previousDdo)
      }
      if (eventName === EVENTS.METADATA_CREATED) {
        if (
          previousDdoInstance &&
          previousDdoInstance.getAssetFields().indexedMetadata.nft.state ===
            MetadataStates.ACTIVE
        ) {
          const previousTxId =
            previousDdoInstance.getAssetFields().indexedMetadata?.event?.txid
          // If it's the same transaction being reprocessed, just skip (idempotent)
          if (previousTxId === event.transactionHash) {
            INDEXER_LOGGER.logMessage(
              `DDO ${ddoInstance.getDid()} already indexed from same transaction ${
                event.transactionHash
              }. Skipping reprocessing.`,
              true
            )
            await ddoState.update(
              this.networkId,
              did,
              event.address,
              event.transactionHash,
              true,
              ' '
            )
            return
          }
          INDEXER_LOGGER.logMessage(
            `DDO ${ddoInstance.getDid()} is already registered as active from different transaction ${previousTxId}`,
            true
          )
          await ddoState.update(
            this.networkId,
            did,
            event.address,
            event.transactionHash,
            false,
            `DDO ${ddoInstance.getDid()} is already registered as active from transaction ${previousTxId}`
          )
          return
        }
      }

      if (eventName === EVENTS.METADATA_UPDATED) {
        if (!previousDdoInstance) {
          INDEXER_LOGGER.logMessage(
            `Previous DDO with did ${ddoInstance.getDid()} was not found the database`,
            true
          )
          return
        }
        const [isUpdateable, error] = this.isUpdateable(
          previousDdoInstance,
          event.transactionHash,
          event.blockNumber
        )
        INDEXER_LOGGER.logMessage(
          `Update eligibility for ${ddoInstance.getDid()}: ${isUpdateable}`,
          true
        )
        if (!isUpdateable) {
          INDEXER_LOGGER.error(
            `Error encountered when checking if the asset is eligiable for update: ${error}`
          )
          await ddoState.update(
            this.networkId,
            did,
            event.address,
            event.transactionHash,
            false,
            error
          )
          return
        }
      }
      const from = decodedEventData.args[0].toString()
      let ddoUpdatedWithPricing
      // we need to store the event data (either metadata created or update and is updatable)
      if (
        [EVENTS.METADATA_CREATED, EVENTS.METADATA_UPDATED].includes(eventName) &&
        this.isValidDtAddressFromServices(ddoInstance.getDDOFields().services)
      ) {
        processingStage = 'enrich-ddo-with-pricing-and-policy'
        INDEXER_LOGGER.logMessage(
          `Starting pricing and policy enrichment for ${ddoInstance.getDid()}`,
          true
        )
        const ddoWithPricing = await getPricingStatsForDddo(ddoInstance, signer)
        const nft = await this.getNFTInfo(
          ddoWithPricing.getDDOFields().nftAddress,
          signer,
          owner,
          parseInt(decodedEventData.args[6])
        )

        let block
        let datetime
        INDEXER_LOGGER.logMessage(`DDO ${ddoWithPricing.getDid()} is being indexed`)
        INDEXER_LOGGER.logMessage(`BLOCK ${event.blockNumber}`)
        if (event.blockNumber) {
          block = event.blockNumber
          // try get block & timestamp from block (only wait 2.5 secs maximum)
          const promiseFn = provider.getBlock(event.blockNumber)
          const result = await asyncCallWithTimeout(promiseFn, 2500)
          if (result.data !== null && !result.timeout) {
            datetime = new Date(result.data.timestamp * 1000).toJSON()
            INDEXER_LOGGER.logMessage(
              `Resolved block ${block} timestamp ${datetime} for ${ddoWithPricing.getDid()}`,
              true
            )
          } else {
            INDEXER_LOGGER.logMessage(
              `Block timestamp lookup timed out or returned empty for ${ddoWithPricing.getDid()}`,
              true
            )
          }
        }

        const fieldsToUpdate = {
          indexedMetadata: {
            nft,
            event: {
              txid: event.transactionHash,
              from,
              contract: event.address,
              block,
              datetime
            }
          }
        }
        ddoWithPricing.updateFields(fieldsToUpdate)

        // policyServer check
        const policyServer = new PolicyServer()
        let policyStatus
        if (eventName === EVENTS.METADATA_UPDATED)
          policyStatus = await policyServer.checkUpdateDDO(
            ddoWithPricing.getDDOData() as DDO,
            this.networkId,
            event.transactionHash,
            event
          )
        else
          policyStatus = await policyServer.checknewDDO(
            ddoWithPricing.getDDOData() as DDO,
            this.networkId,
            event.transactionHash,
            event
          )
        INDEXER_LOGGER.logMessage(`policyStatus: ${JSON.stringify(policyStatus)}`)

        if (!policyStatus.success) {
          INDEXER_LOGGER.logMessage(
            `Policy check failed for ${did}: ${policyStatus.message}`,
            true
          )
          await ddoState.update(
            this.networkId,
            did,
            event.address,
            event.transactionHash,
            false,
            policyStatus.message
          )
          return
        }
        ddoUpdatedWithPricing = ddoWithPricing
      } else {
        INDEXER_LOGGER.logMessage(
          `Skipping pricing enrichment for ${did} because event or datatoken services are not indexable`,
          true
        )
      }
      // always call, but only create instance once
      processingStage = 'check-purgatory-and-save'
      const purgatory = await Purgatory.getInstance()
      // if purgatory is disabled just return false
      const state = await this.getPurgatoryState(ddo, from, purgatory)
      INDEXER_LOGGER.logMessage(`Purgatory state for ${did}: ${state}`, true)

      ddoUpdatedWithPricing.updateFields({
        indexedMetadata: { purgatory: { state } }
      })
      if (state === false) {
        // TODO: insert in a different collection for purgatory DDOs
        INDEXER_LOGGER.logMessage(`saving DDO: ${JSON.stringify(ddoUpdatedWithPricing)}`)
        const saveDDO = await this.createOrUpdateDDO(ddoUpdatedWithPricing, eventName)
        INDEXER_LOGGER.logMessage(`saved DDO: ${JSON.stringify(saveDDO)}`)
        return saveDDO
      }
      INDEXER_LOGGER.logMessage(
        `Skipping save for ${did} because asset is in purgatory`,
        true
      )
    } catch (error) {
      const { ddoState } = await getDatabase()
      INDEXER_LOGGER.logMessage(
        `error processing DDO at stage ${processingStage}: ${did} and error: ${error}`
      )
      await ddoState.update(
        this.networkId,
        did,
        event.address,
        event.transactionHash,
        false,
        error.message
      )
      INDEXER_LOGGER.log(
        LOG_LEVELS_STR.LEVEL_ERROR,
        `Error processMetadataEvents for did: ${did}, txHash: ${event.transactionHash}, stage: ${processingStage} and error: ${error}`,
        true
      )
    }
  }

  async getPurgatoryState(
    ddo: any,
    owner: string,
    purgatory: Purgatory
  ): Promise<boolean> {
    if (purgatory.isEnabled()) {
      const state: boolean =
        (await purgatory.isBannedAsset(ddo.id)) ||
        (await purgatory.isBannedAccount(owner))
      return state
    }
    return false
  }

  async updatePurgatoryStateDdo(
    ddo: VersionedDDO,
    owner: string,
    purgatory: Purgatory
  ): Promise<Record<string, any>> {
    if (!purgatory.isEnabled()) {
      return ddo.updateFields({
        indexedMetadata: {
          purgatory: {
            state: false
          }
        }
      })
    }

    const state: boolean =
      (await purgatory.isBannedAsset(ddo.getDid())) ||
      (await purgatory.isBannedAccount(owner))
    return ddo.updateFields({
      indexedMetadata: {
        purgatory: {
          state
        }
      }
    })
  }

  isUpdateable(
    previousDdo: VersionedDDO,
    txHash: string,
    block: number
  ): [boolean, string] {
    let errorMsg: string
    const ddoTxId = previousDdo.getAssetFields().indexedMetadata?.event?.txid
    // do not update if we have the same txid
    if (txHash === ddoTxId) {
      errorMsg = `Previous DDO has the same tx id, no need to update: event-txid=${txHash} <> asset-event-txid=${ddoTxId}`
      INDEXER_LOGGER.log(LOG_LEVELS_STR.LEVEL_DEBUG, errorMsg, true)
      return [false, errorMsg]
    }
    const ddoBlock = previousDdo.getAssetFields().indexedMetadata?.event?.block
    // do not update if we have the same block
    if (block === ddoBlock) {
      errorMsg = `Asset was updated later (block: ${ddoBlock}) vs transaction block: ${block}`
      INDEXER_LOGGER.log(LOG_LEVELS_STR.LEVEL_DEBUG, errorMsg, true)
      return [false, errorMsg]
    }

    return [true, '']
  }

  async processDDO(ddo: any) {
    if (isRemoteDDO(ddo)) {
      INDEXER_LOGGER.logMessage('DDO is remote', true)

      const storage = Storage.getStorageClass(ddo.remote, await getConfiguration())
      const result = await storage.getReadableStream()
      const streamToStringDDO = await streamToString(result.stream as Readable)

      return JSON.parse(streamToStringDDO)
    }

    return ddo
  }
}
