import EnterpriseFeeCollectorJson from '@oceanprotocol/contracts/artifacts/contracts/communityFee/EnterpriseFeeCollector.sol/EnterpriseFeeCollector.json' with { type: 'json' }
import { Contract } from 'ethers'
import type { OceanNodeConfig } from '../@types/OceanNode.js'
import type { FeeTokens } from '../@types/Fees.js'
import type { Blockchain } from './blockchain.js'
import type { BlockchainRegistry } from '../components/BlockchainRegistry/index.js'
import { getOceanArtifactsAdressesByChainId } from './address.js'
import { CORE_LOGGER } from './logging/common.js'

export type UnsupportedFeeToken = {
  chain: string
  token: string
}

type BlockchainRegistryLike = Pick<BlockchainRegistry, 'getBlockchain'>

function formatFeeToken(token: UnsupportedFeeToken): string {
  return `chain=${token.chain}, token=${token.token}`
}

export async function validateFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<UnsupportedFeeToken[]> {
  const feeTokens = config?.feeStrategy?.feeTokens || []
  const unsupportedFeeTokens: UnsupportedFeeToken[] = []

  for (const feeToken of feeTokens) {
    const { chain, token } = feeToken as FeeTokens
    const chainId = Number(chain)

    try {
      const addresses = getOceanArtifactsAdressesByChainId(chainId)
      const enterpriseFeeCollectorAddress = addresses?.EnterpriseFeeCollector
      CORE_LOGGER.info(
        `Validating fee token ${token} on chain ${chainId} with EnterpriseFeeCollector ${enterpriseFeeCollectorAddress}`
      )

      const blockchain = blockchainRegistry.getBlockchain(chainId) as Blockchain | null
      if (!enterpriseFeeCollectorAddress || !blockchain) {
        throw new Error('Unable to initialize EnterpriseFeeCollector validation')
      }
      const signer = await blockchain.getSigner()
      const enterpriseFeeCollector = new Contract(
        enterpriseFeeCollectorAddress,
        EnterpriseFeeCollectorJson.abi,
        signer
      )
      const isAllowed = await enterpriseFeeCollector.isTokenAllowed(token)
      if (isAllowed !== true) {
        unsupportedFeeTokens.push({ chain, token })
      }
    } catch {
      unsupportedFeeTokens.push({ chain, token })
    }
  }

  return unsupportedFeeTokens
}

export async function assertFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<void> {
  const unsupportedFeeTokens = await validateFeeTokensSupportedByOec(
    config,
    blockchainRegistry
  )

  if (unsupportedFeeTokens.length > 0) {
    throw new Error(
      `Unsupported fee token(s) configured in FEE_TOKENS: ${unsupportedFeeTokens
        .map(formatFeeToken)
        .join('; ')}`
    )
  }
}
