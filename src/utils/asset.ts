import axios from 'axios'
import { DDO } from '../@types/DDO/DDO'
import { Service } from '../@types/DDO/Service'
import { DDO_IDENTIFIER_PREFIX } from './constants.js'
import { CORE_LOGGER } from './logging/common.js'
import { createHash } from 'crypto'
import { getAddress } from 'ethers'
import { DDOProcessorFactory } from '../components/core/utils/DDOFactory.js'

// Notes:
// Asset as per asset.py on provider, is a class there, while on ocean.Js we only have a type
// this is an utility to extract information from the Asset services
export const AssetUtils = {
  getServiceIndexById(asset: DDO, id: string): number | null {
    const processor = DDOProcessorFactory.createProcessor(asset)

    // Get the DDO identifier using the processor
    const { services } = processor.extractDDOFields(asset as any)

    for (let c = 0; c < services.length; c++) if (services[c].id === id) return c
    return null
  },
  getServiceByIndex(asset: DDO, index: number): Service | null {
    const processor = DDOProcessorFactory.createProcessor(asset)

    // Get the DDO identifier using the processor
    const { services } = processor.extractDDOFields(asset as any)
    if (index >= 0 && index < services.length) {
      return services[index]
    }
    return null
  },

  getServiceById(asset: DDO, id: string): Service | null {
    const processor = DDOProcessorFactory.createProcessor(asset)

    // Get the DDO identifier using the processor
    const { services: servicesToSearch } = processor.extractDDOFields(asset as any)
    const services = servicesToSearch.filter((service: Service) => service.id === id)
    return services.length ? services[0] : null
  }
}

export async function fetchFileMetadata(
  url: string,
  method: string,
  forceChecksum: boolean
): Promise<{ contentLength: string; contentType: string; contentChecksum: string }> {
  let contentType: string = ''
  let contentLength: number = 0
  const contentChecksum = createHash('sha256')
  const maxLengthInt = parseInt(process.env.MAX_CHECKSUM_LENGTH, 10)
  const maxLength = isNaN(maxLengthInt) ? 10 * 1024 * 1024 : maxLengthInt

  try {
    const response = await axios({
      url,
      method: method || 'get',
      responseType: 'stream'
    })
    contentType = response.headers['content-type']
    let totalSize = 0
    for await (const chunk of response.data) {
      totalSize += chunk.length
      contentChecksum.update(chunk)
      if (totalSize > maxLength && !forceChecksum) {
        contentLength = 0
        break
      }
    }
    contentLength = totalSize
  } catch (error) {
    CORE_LOGGER.error(error)
  }

  return {
    contentLength: contentLength.toString(),
    contentType,
    contentChecksum: contentChecksum.digest('hex')
  }
}

/**
 * Validates if a given DDO identifier matches the NFT address and the chain ID provided
 * @param ddoID the ID of the DDO
 * @param nftAddress the nft address
 * @param chainId the chain id
 * @returns validation result
 */
export function validateDDOHash(
  ddoID: string,
  nftAddress: string,
  chainId: number
): boolean {
  if (!ddoID || !nftAddress || !chainId) {
    CORE_LOGGER.error('Invalid or missing data for proper DDO id validation')
    return false
  }
  const hashAddressAndChain: string = generateDDOHash(nftAddress, chainId)
  return ddoID === hashAddressAndChain
}

/**
 * Generates DDO Id given the chain and nft address provided
 * @param nftAddress the nft address
 * @param chainId the chain id
 * @returns did
 */
export function generateDDOHash(nftAddress: string, chainId: number): string | null {
  if (!nftAddress || !chainId) {
    CORE_LOGGER.error('Invalid or missing data for proper DDO id hash generation')
    return null
  }
  const hashAddressAndChain: string = createHash('sha256')
    .update(getAddress(nftAddress) + chainId.toString(10))
    .digest('hex')

  return DDO_IDENTIFIER_PREFIX + hashAddressAndChain
}
