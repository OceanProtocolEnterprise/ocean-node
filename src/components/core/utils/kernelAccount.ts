import { createRequire } from 'module'
import { ethers } from 'ethers'

const moduleRequire = createRequire(import.meta.url)

export const DEFAULT_ZERODEV_RPC =
  'https://rpc.zerodev.app/api/v3/d09b9d4e-ce67-41e6-850a-a0f2eb772c37/chain/11155111'

export type KernelAccountContext = {
  address: string
  signerAddress: string
  isDeployed: boolean
  deployIfNeeded: () => Promise<{
    deployed: boolean
    userOperationHash?: string
    transactionHash?: string
  }>
  isValidSignature: (message: string, signature: string) => Promise<boolean>
  signMessage: (message: string) => Promise<string>
}

export type KernelAccountOptions = {
  bundlerRpc?: string
  log?: (message: string) => void
}

export async function createKernelAccountForNodeWallet(
  privateKey: string,
  options: KernelAccountOptions = {}
): Promise<KernelAccountContext> {
  const { createKernelAccount, createKernelAccountClient, constants } =
    moduleRequire('@zerodev/sdk')
  const { signerToEcdsaValidator } = moduleRequire('@zerodev/ecdsa-validator')
  const { createPublicClient, http } = moduleRequire('viem')
  const { privateKeyToAccount } = moduleRequire('viem/accounts')
  const { sepolia } = moduleRequire('viem/chains')

  const bundlerRpc = options.bundlerRpc || DEFAULT_ZERODEV_RPC
  const entryPoint = constants.getEntryPoint('0.7')
  const kernelVersion = constants.KERNEL_V3_1
  const signer = privateKeyToAccount(privateKey)
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(bundlerRpc)
  })

  const validator = await signerToEcdsaValidator(publicClient, {
    signer,
    entryPoint,
    kernelVersion
  })

  const account = await createKernelAccount(publicClient, {
    plugins: { sudo: validator },
    entryPoint,
    kernelVersion
  })

  const kernelClient = createKernelAccountClient({
    account,
    chain: sepolia,
    bundlerTransport: http(bundlerRpc),
    client: publicClient
  })

  const getIsDeployed = async () => {
    const bytecode = await publicClient.getBytecode({ address: account.address })
    return Boolean(bytecode && bytecode.length > 2)
  }

  const contract = new ethers.Contract(
    account.address,
    ['function isValidSignature(bytes32, bytes) view returns (bytes4)'],
    new ethers.JsonRpcProvider(bundlerRpc)
  )

  return {
    address: account.address,
    signerAddress: signer.address,
    isDeployed: await getIsDeployed(),
    deployIfNeeded: async () => {
      if (await getIsDeployed()) {
        return { deployed: false }
      }

      options.log?.(
        `Kernel account ${account.address} is not deployed; sending deployment user operation`
      )
      const userOperationHash = await kernelClient.sendTransaction({
        to: account.address,
        value: 0n,
        data: '0x'
      })
      const receipt = await kernelClient.waitForUserOperationReceipt({
        hash: userOperationHash
      })

      return {
        deployed: true,
        userOperationHash,
        transactionHash: receipt?.receipt?.transactionHash
      }
    },
    isValidSignature: async (message: string, signature: string) => {
      if (!(await getIsDeployed())) {
        return false
      }

      const result = await contract.isValidSignature(
        ethers.hashMessage(message),
        signature
      )
      return result === '0x1626ba7e'
    },
    signMessage: async (message: string) => {
      for (const useReplayableSignature of [false, true]) {
        const signature = await account.signMessage({
          message,
          useReplayableSignature
        })
        const result = await contract.isValidSignature(
          ethers.hashMessage(message),
          signature
        )
        if (result === '0x1626ba7e') {
          return signature
        }
      }

      throw new Error(
        `Kernel account ${account.address} did not accept the generated ERC-1271 signature`
      )
    }
  }
}
