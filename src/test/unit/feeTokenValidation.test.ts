import { expect } from 'chai'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { Interface } from 'ethers'
import EnterpriseFeeCollectorJson from '@oceanprotocol/contracts/artifacts/contracts/communityFee/EnterpriseFeeCollector.sol/EnterpriseFeeCollector.json' with { type: 'json' }
import { OceanNodeConfig } from '../../@types/OceanNode.js'
import {
  assertConfiguredFeeTokensSupportedByOec,
  getDockerComputeFeeTokens
} from '../../utils/feeTokenValidation.js'
import { getConfiguration } from '../../utils/config.js'
import { ENVIRONMENT_VARIABLES } from '../../utils/constants.js'
import {
  TEST_ENV_CONFIG_PATH,
  buildEnvOverrideConfig,
  setupEnvironment,
  tearDownEnvironment
} from '../utils/utils.js'

const CHAIN_WITH_COLLECTOR = 11155111
const CHAIN_WITHOUT_COLLECTOR = 8453
const COLLECTOR = '0x00000000000000000000000000000000000000c1'
const ALLOWED = '0x00000000000000000000000000000000000000a1'
const NOT_ALLOWED = '0x00000000000000000000000000000000000000b1'

const collectorInterface = new Interface(EnterpriseFeeCollectorJson.abi)

// A BlockchainRegistry whose signer answers EnterpriseFeeCollector.isTokenAllowed from
// `allowed`, so the check runs without an RPC node
function registryAllowing(allowed: string[]): any {
  const runner = {
    provider: null as any,
    call: (tx: { to: string; data: string }) => {
      const [token] = collectorInterface.decodeFunctionData('isTokenAllowed', tx.data)
      const isAllowed = allowed
        .map((address) => address.toLowerCase())
        .includes(String(token).toLowerCase())
      return Promise.resolve(
        collectorInterface.encodeFunctionResult('isTokenAllowed', [isAllowed])
      )
    }
  }
  return { getBlockchain: () => ({ getSigner: () => Promise.resolve(runner) }) }
}

function nodeConfig(
  feeTokens: { chain: string; token: string }[],
  computeFeeTokens: { chain: string; token: string }[] = [],
  skipFeeTokenValidation = false
): OceanNodeConfig {
  const fees: Record<string, any[]> = {}
  for (const { chain, token } of computeFeeTokens) {
    fees[chain] = [...(fees[chain] || []), { feeToken: token, prices: [] }]
  }
  return {
    feeStrategy: { feeTokens },
    dockerComputeEnvironments: [{ environments: [{ fees }] }],
    skipFeeTokenValidation
  } as unknown as OceanNodeConfig
}

describe('Fee token validation against the EnterpriseFeeCollector', () => {
  const previousAddressFile = process.env.ADDRESS_FILE
  let addressFile: string

  before(() => {
    addressFile = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'fee-token-validation-')),
      'address.json'
    )
    fs.writeFileSync(
      addressFile,
      JSON.stringify({
        sepolia: { chainId: CHAIN_WITH_COLLECTOR, EnterpriseFeeCollector: COLLECTOR },
        base: { chainId: CHAIN_WITHOUT_COLLECTOR }
      })
    )
    process.env.ADDRESS_FILE = addressFile
  })

  after(() => {
    if (previousAddressFile === undefined) delete process.env.ADDRESS_FILE
    else process.env.ADDRESS_FILE = previousAddressFile
    fs.rmSync(path.dirname(addressFile), { recursive: true, force: true })
  })

  it('passes when every FEE_TOKENS and compute environment token is allowed', async () => {
    const config = nodeConfig(
      [{ chain: String(CHAIN_WITH_COLLECTOR), token: ALLOWED }],
      [{ chain: String(CHAIN_WITH_COLLECTOR), token: ALLOWED }]
    )
    await assertConfiguredFeeTokensSupportedByOec(config, registryAllowing([ALLOWED]))
  })

  it('rejects a FEE_TOKENS token the collector does not allow', async () => {
    const config = nodeConfig([
      { chain: String(CHAIN_WITH_COLLECTOR), token: ALLOWED },
      { chain: String(CHAIN_WITH_COLLECTOR), token: NOT_ALLOWED }
    ])
    try {
      await assertConfiguredFeeTokensSupportedByOec(config, registryAllowing([ALLOWED]))
      expect.fail('expected the check to throw')
    } catch (error) {
      expect(error.message).to.contain('FEE_TOKENS')
      expect(error.message).to.contain(NOT_ALLOWED)
      expect(error.message).to.not.contain(ALLOWED)
    }
  })

  it('rejects a compute environment fee token the collector does not allow', async () => {
    const config = nodeConfig(
      [{ chain: String(CHAIN_WITH_COLLECTOR), token: ALLOWED }],
      [{ chain: String(CHAIN_WITH_COLLECTOR), token: NOT_ALLOWED }]
    )
    try {
      await assertConfiguredFeeTokensSupportedByOec(config, registryAllowing([ALLOWED]))
      expect.fail('expected the check to throw')
    } catch (error) {
      expect(error.message).to.contain('DOCKER_COMPUTE_ENVIRONMENTS')
      expect(error.message).to.contain(NOT_ALLOWED)
    }
  })

  it('rejects a token on a chain without an EnterpriseFeeCollector', async () => {
    const config = nodeConfig([
      { chain: String(CHAIN_WITHOUT_COLLECTOR), token: ALLOWED }
    ])
    try {
      await assertConfiguredFeeTokensSupportedByOec(config, registryAllowing([ALLOWED]))
      expect.fail('expected the check to throw')
    } catch (error) {
      expect(error.message).to.contain(`chain=${CHAIN_WITHOUT_COLLECTOR}`)
    }
  })

  it('skips the check when skipFeeTokenValidation is true', async () => {
    const config = nodeConfig(
      [{ chain: String(CHAIN_WITHOUT_COLLECTOR), token: NOT_ALLOWED }],
      [{ chain: String(CHAIN_WITH_COLLECTOR), token: NOT_ALLOWED }],
      true
    )
    await assertConfiguredFeeTokensSupportedByOec(config, registryAllowing([]))
  })

  it('collects compute environment fee tokens once per chain and token', () => {
    const config = nodeConfig(
      [],
      [
        { chain: String(CHAIN_WITH_COLLECTOR), token: ALLOWED },
        { chain: String(CHAIN_WITH_COLLECTOR), token: ALLOWED.toUpperCase() },
        { chain: String(CHAIN_WITHOUT_COLLECTOR), token: ALLOWED }
      ]
    )
    expect(getDockerComputeFeeTokens(config)).to.have.length(2)
  })
})

describe('SKIP_FEE_TOKEN_VALIDATION config parsing', () => {
  async function skipFlagFor(value: string): Promise<boolean> {
    const overrides = buildEnvOverrideConfig(
      [ENVIRONMENT_VARIABLES.SKIP_FEE_TOKEN_VALIDATION],
      [value]
    )
    try {
      await setupEnvironment(TEST_ENV_CONFIG_PATH, overrides)
      return (await getConfiguration(true)).skipFeeTokenValidation
    } finally {
      await tearDownEnvironment(overrides)
    }
  }

  it('enforces the check for SKIP_FEE_TOKEN_VALIDATION=false', async () => {
    // before the schema declared the field, the raw string "false" was truthy and skipped it
    expect(await skipFlagFor('false')).to.equal(false)
  })

  it('skips the check for SKIP_FEE_TOKEN_VALIDATION=true', async () => {
    expect(await skipFlagFor('true')).to.equal(true)
  })
})
