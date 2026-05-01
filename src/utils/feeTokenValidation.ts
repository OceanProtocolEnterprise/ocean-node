import EnterpriseFeeCollectorJson from '@oceanprotocol/contracts/artifacts/contracts/communityFee/EnterpriseFeeCollector.sol/EnterpriseFeeCollector.json' with { type: 'json' }
import { Contract } from 'ethers'
import type { OceanNodeConfig } from '../@types/OceanNode.js'
import type { FeeTokens } from '../@types/Fees.js'
import type { Blockchain } from './blockchain.js'
import type { BlockchainRegistry } from '../components/BlockchainRegistry/index.js'
import type { ComputeEnvFeesStructure } from '../@types/C2D/C2D.js'
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

function dedupeFeeTokens(feeTokens: UnsupportedFeeToken[]): UnsupportedFeeToken[] {
  const seen = new Set<string>()
  const unique: UnsupportedFeeToken[] = []

  for (const feeToken of feeTokens) {
    const key = `${feeToken.chain}:${feeToken.token.toLowerCase()}`
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(feeToken)
    }
  }

  return unique
}

function addFeeTokensFromFees(
  fees: ComputeEnvFeesStructure,
  feeTokens: UnsupportedFeeToken[]
): void {
  if (!fees) return

  for (const [chain, chainFees] of Object.entries(fees)) {
    for (const fee of chainFees || []) {
      if (fee.feeToken) {
        feeTokens.push({ chain, token: fee.feeToken })
      }
    }
  }
}

export function getDockerComputeFeeTokens(
  config: OceanNodeConfig
): UnsupportedFeeToken[] {
  const feeTokens: UnsupportedFeeToken[] = []

  for (const dockerCompute of config?.dockerComputeEnvironments || []) {
    addFeeTokensFromFees(
      (dockerCompute as unknown as { fees?: ComputeEnvFeesStructure }).fees,
      feeTokens
    )

    for (const environment of dockerCompute.environments || []) {
      addFeeTokensFromFees(environment.fees as ComputeEnvFeesStructure, feeTokens)
    }
  }

  return dedupeFeeTokens(feeTokens)
}

async function validateTokensSupportedByOec(
  feeTokens: UnsupportedFeeToken[],
  blockchainRegistry: BlockchainRegistryLike
): Promise<UnsupportedFeeToken[]> {
  const unsupportedFeeTokens: UnsupportedFeeToken[] = []

  for (const feeToken of feeTokens) {
    const { chain, token } = feeToken
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
      } else {
        CORE_LOGGER.info(
          `Fee token ${token} on chain ${chainId} with EnterpriseFeeCollector ${enterpriseFeeCollectorAddress} validated`
        )
      }
    } catch {
      unsupportedFeeTokens.push({ chain, token })
    }
  }

  return unsupportedFeeTokens
}

export async function validateFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<UnsupportedFeeToken[]> {
  const feeTokens = config?.feeStrategy?.feeTokens || []
  return await validateTokensSupportedByOec(feeTokens as FeeTokens[], blockchainRegistry)
}

export async function validateDockerComputeFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<UnsupportedFeeToken[]> {
  const feeTokens = getDockerComputeFeeTokens(config)
  return await validateTokensSupportedByOec(feeTokens, blockchainRegistry)
}

export async function assertFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<void> {
  if (config.skipFeeTokenValidation) {
    CORE_LOGGER.warn(
      'Skipping fee token validation because skipFeeTokenValidation is enabled'
    )
    return
  }

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

export async function assertDockerComputeFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<void> {
  if (config.skipFeeTokenValidation) {
    CORE_LOGGER.warn(
      'Skipping fee token validation because skipFeeTokenValidation is enabled'
    )
    return
  }

  const feeTokens = getDockerComputeFeeTokens(config)
  if (feeTokens.length === 0) {
    CORE_LOGGER.info(
      'No fee tokens configured in DOCKER_COMPUTE_ENVIRONMENTS. Skipping Docker compute fee token validation.'
    )
    return
  }

  const unsupportedFeeTokens = await validateTokensSupportedByOec(
    feeTokens,
    blockchainRegistry
  )

  if (unsupportedFeeTokens.length > 0) {
    throw new Error(
      `Unsupported fee token(s) configured in DOCKER_COMPUTE_ENVIRONMENTS: ${unsupportedFeeTokens
        .map(formatFeeToken)
        .join('; ')}`
    )
  }
}

export async function assertConfiguredFeeTokensSupportedByOec(
  config: OceanNodeConfig,
  blockchainRegistry: BlockchainRegistryLike
): Promise<void> {
  if (config.skipFeeTokenValidation) {
    CORE_LOGGER.warn(
      'Skipping fee token validation because skipFeeTokenValidation is enabled'
    )
    return
  }

  await assertFeeTokensSupportedByOec(config, blockchainRegistry)
  await assertDockerComputeFeeTokensSupportedByOec(config, blockchainRegistry)
}
