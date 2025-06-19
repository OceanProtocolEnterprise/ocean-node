import { OceanNode } from '../../../OceanNode.js'
import { AlgoChecksums } from '../../../@types/C2D/C2D.js'
import {
  ArweaveFileObject,
  IpfsFileObject,
  UrlFileObject
} from '../../../@types/fileObject.js'
import { getFile } from '../../../utils/file.js'
import urlJoin from 'url-join'
import { fetchFileMetadata } from '../../../utils/asset.js'

import { CORE_LOGGER } from '../../../utils/logging/common.js'
import { createHash } from 'crypto'
import { FindDdoHandler } from '../../core/handler/ddoHandler.js'
import { DDOManager, VersionedDDO } from '@oceanprotocol/ddo-js'

export async function getAlgoChecksums(
  algoDID: string,
  algoServiceId: string,
  oceanNode: OceanNode
): Promise<AlgoChecksums> {
  const checksums: AlgoChecksums = {
    files: '',
    container: ''
  }
  try {
    const algoDDO = await new FindDdoHandler(oceanNode).findAndFormatDdo(algoDID)
    if (!algoDDO) {
      CORE_LOGGER.error(`Algorithm with id: ${algoDID} not found!`)
      return checksums
    }
    const fileArray = await getFile(algoDDO, algoServiceId, oceanNode)
    for (const file of fileArray) {
      const url =
        file.type === 'url'
          ? (file as UrlFileObject).url
          : file.type === 'arweave'
            ? urlJoin(
                process.env.ARWEAVE_GATEWAY,
                (file as ArweaveFileObject).transactionId
              )
            : file.type === 'ipfs'
              ? urlJoin(process.env.IPFS_GATEWAY, (file as IpfsFileObject).hash)
              : null

      const { contentChecksum } = await fetchFileMetadata(url, 'get', false)
      checksums.files = checksums.files.concat(contentChecksum)
    }

    const ddoInstance = DDOManager.getDDOClass(algoDDO)
    const { metadata } = ddoInstance.getDDOFields()
    checksums.container = createHash('sha256')
      .update(
        metadata.algorithm.container.entrypoint + metadata.algorithm.container.checksum
      )
      .digest('hex')
    return checksums
  } catch (error) {
    CORE_LOGGER.error(`Fetching algorithm checksums failed: ${error.message}`)
    return checksums
  }
}

export async function validateAlgoForDataset(
  algoDID: string,
  algoChecksums: {
    files: string
    container: string
  },
  ddoInstance: VersionedDDO,
  datasetServiceId: string,
  oceanNode: OceanNode
) {
  try {
    CORE_LOGGER.info(
      `validateAlgoForDataset params: ${JSON.stringify({
        algoDID,
        algoChecksums,
        datasetServiceId
      })}`
    )

    const { services } = ddoInstance.getDDOFields() as any
    CORE_LOGGER.info(
      `services: ${JSON.stringify({
        services
      })}`
    )
    const datasetService = services.find(
      (service: any) => service.id === datasetServiceId
    )
    CORE_LOGGER.info(
      `datasetService: ${JSON.stringify({
        datasetService
      })}`
    )
    if (!datasetService) {
      throw new Error('Dataset service not found')
    }
    const { compute } = datasetService
    CORE_LOGGER.info(
      `compute: ${JSON.stringify({
        compute
      })}`
    )
    if (datasetService.type !== 'compute' || !compute) {
      throw new Error('Service not compute')
    }

    if (algoDID) {
      if (
        // if not set deny them all
        (!Array.isArray(compute.publisherTrustedAlgorithms) ||
          compute.publisherTrustedAlgorithms.length === 0) &&
        (!Array.isArray(compute.publisherTrustedAlgorithmPublishers) ||
          compute.publisherTrustedAlgorithmPublishers.length === 0)
      ) {
        return false
      }

      if (
        compute.publisherTrustedAlgorithms.includes('*') &&
        compute.publisherTrustedAlgorithmPublishers.includes('*')
      ) {
        return true
      }

      if (
        Array.isArray(compute.publisherTrustedAlgorithms) &&
        compute.publisherTrustedAlgorithms.length > 0 &&
        !compute.publisherTrustedAlgorithms.includes('*')
      ) {
        const trustedAlgo = compute.publisherTrustedAlgorithms.find(
          (algo: any) => algo.did === algoDID
        )
        CORE_LOGGER.info(
          `trustedAlgo: ${JSON.stringify({
            trustedAlgo
          })}`
        )
        if (trustedAlgo) {
          return (
            trustedAlgo.filesChecksum === algoChecksums.files &&
            trustedAlgo.containerSectionChecksum === algoChecksums.container
          )
        }
        return false
      }
      if (
        Array.isArray(compute.publisherTrustedAlgorithmPublishers) &&
        compute.publisherTrustedAlgorithmPublishers.length > 0 &&
        !compute.publisherTrustedAlgorithmPublishers.includes('*')
      ) {
        const algoDDO = await new FindDdoHandler(oceanNode).findAndFormatDdo(algoDID)
        const algoInstance = DDOManager.getDDOClass(algoDDO)
        const { nftAddress } = algoInstance.getDDOFields()
        CORE_LOGGER.info(`nftAddress: ${nftAddress})}`)
        if (algoDDO) {
          return compute.publisherTrustedAlgorithmPublishers
            .map((address: string) => address?.toLowerCase())
            .includes(nftAddress?.toLowerCase())
        }
        return false
      }
      return true
    }

    return compute.allowRawAlgorithm
  } catch (error) {
    CORE_LOGGER.error(error.message)
    return false
  }
}
