import express from 'express'
import { HTTP_LOGGER } from '../../utils/logging/common.js'
import { getAllServiceEndpoints } from './index.js'
import { getNodeOwnerInfo } from './utils.js'
import { getPackageVersion } from '../../utils/version.js'
export const rootEndpointRoutes = express.Router()

rootEndpointRoutes.get('/', (req, res) => {
  const config = req.oceanNode.getConfig()
  if (!config.supportedNetworks) {
    HTTP_LOGGER.warn(`Supported networks not defined`)
  }
  const keyManager = req.oceanNode.getKeyManager()
  const rootResponse: Record<string, unknown> = {
    nodeId: keyManager.getPeerId().toString(),
    chainIds: config.supportedNetworks ? Object.keys(config.supportedNetworks) : [],
    providerAddress: keyManager.getEthAddress(),
    nodePublicKey: keyManager.getPublicKey(),
    serviceEndpoints: getAllServiceEndpoints(),
    software: 'Ocean-Node',
    version: getPackageVersion()
  }

  const ownerInfo = getNodeOwnerInfo()
  if (ownerInfo) {
    rootResponse.ownerInfo = ownerInfo
  } else {
    HTTP_LOGGER.warn('NODE_OWNER_INFO not present or invalid')
  }

  res.json(rootResponse)
})
