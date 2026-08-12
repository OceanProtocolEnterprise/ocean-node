import { CommandHandler } from './handler.js'
import { GetFeesCommand } from '../../../@types/commands.js'
import { P2PCommandResponse } from '../../../@types/OceanNode.js'
import { ProviderFees } from '../utils/feesHandler.js'
import { Readable } from 'stream'
import { GENERIC_EMOJIS, LOG_LEVELS_STR } from '../../../utils/logging/Logger.js'
import { PROVIDER_LOGGER } from '../../../utils/logging/common.js'
import {
  ValidateParams,
  buildInvalidRequestMessage,
  validateCommandParameters
} from '../../httpRoutes/validateCommands.js'
import { FindDdoHandler, validateDDOIdentifier } from './ddoHandler.js'
import { isAddress } from 'ethers'
import { ProviderInitialize } from '../../../@types/Fees.js'
import { getNonce } from '../utils/nonceHandler.js'
import { streamToString } from '../../../utils/util.js'
import { isOrderingAllowedForAsset } from './downloadHandler.js'
import { Credentials, DDOManager } from '@oceanprotocol/ddo-js'
import { checkCredentials } from '../../../utils/credentials.js'
import { isPolicyServerConfigured } from '../../../utils/index.js'
import { PolicyServer } from '../../policyServer/index.js'

export class FeesHandler extends CommandHandler {
  validate(command: GetFeesCommand): ValidateParams {
    let validation = validateCommandParameters(command, ['ddoId', 'serviceId'])
    if (validation.valid) {
      validation = validateDDOIdentifier(command.ddoId)

      if (command.consumerAddress && !isAddress(command.consumerAddress)) {
        return buildInvalidRequestMessage(
          'Parameter : "consumerAddress" is not a valid web3 address'
        )
      }
    }
    return validation
  }

  async handle(task: GetFeesCommand): Promise<P2PCommandResponse> {
    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }
    PROVIDER_LOGGER.logMessage(
      `Try to calculate fees for DDO with id: ${task.ddoId} and serviceId: ${task.serviceId}`,
      true
    )
    let errorMsg: string = null
    const ddo = await new FindDdoHandler(this.getOceanNode()).findAndFormatDdo(task.ddoId)
    if (!ddo) {
      errorMsg = 'Cannot resolve DID'
    }

    const isOrdable = isOrderingAllowedForAsset(ddo)
    if (!isOrdable.isOrdable) {
      PROVIDER_LOGGER.error(isOrdable.reason)
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: isOrdable.reason
        }
      }
    }
    const ddoInstance = DDOManager.getDDOClass(ddo)
    const {
      chainId: ddoChainId,
      credentials,
      services
    } = ddoInstance.getDDOFields() as any
    const service = services.find((what: any) => what.id === task.serviceId)
    if (!service) {
      errorMsg = 'Invalid serviceId'
    }
    if (service?.type === 'compute') {
      errorMsg = 'Use the initializeCompute endpoint to initialize compute jobs'
    }

    if (errorMsg) {
      PROVIDER_LOGGER.logMessageWithEmoji(
        errorMsg,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: errorMsg
        }
      }
    }

    const policyServer = new PolicyServer()
    if (credentials || service.credentials) {
      if (!task.consumerAddress) {
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: 'consumerAddress is required to check credentials'
          }
        }
      }

      let signer
      if (!isPolicyServerConfigured()) {
        const oceanNode = this.getOceanNode()
        const supportedNetwork = oceanNode.getConfig().supportedNetworks?.[ddoChainId]
        if (!supportedNetwork) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: `Fees handler: Unsupported chain id ${ddoChainId}`
            }
          }
        }

        const blockchain = oceanNode.getBlockchain(supportedNetwork.chainId)
        if (!blockchain) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: `Fees handler: Blockchain instance not available for chain ${supportedNetwork.chainId}`
            }
          }
        }

        const { ready, error } = await blockchain.isNetworkReady()
        if (!ready) {
          return {
            stream: null,
            status: {
              httpStatus: 400,
              error: `Fees handler: ${error}`
            }
          }
        }
        signer = await blockchain.getSigner()
      }

      let accessGrantedDDOLevel = false
      if (credentials) {
        if (isPolicyServerConfigured()) {
          PROVIDER_LOGGER.info(
            `Checking credentials for consumer address on policy server: ${task.consumerAddress}`
          )
          const response = await policyServer.initializePSVerification(
            ddoInstance.getDid(),
            ddo,
            task.serviceId,
            task.consumerAddress,
            task.policyServer
          )
          accessGrantedDDOLevel = response.success
        } else {
          PROVIDER_LOGGER.info(
            `Checking credentials for consumer address: ${task.consumerAddress}`
          )
          accessGrantedDDOLevel = await checkCredentials(
            task.consumerAddress,
            credentials as Credentials,
            signer
          )
        }
      }

      PROVIDER_LOGGER.info(`credentials: ${JSON.stringify(credentials)}`)
      PROVIDER_LOGGER.info(`accessGrantedDDOLevel: ${accessGrantedDDOLevel}`)

      if (credentials && !accessGrantedDDOLevel) {
        const error = `Error: Access to asset ${ddoInstance.getDid()} was denied`
        PROVIDER_LOGGER.error(error)
        return {
          stream: null,
          status: { httpStatus: 403, error }
        }
      }

      if (service.credentials) {
        let accessGrantedServiceLevel: boolean
        if (isPolicyServerConfigured()) {
          const response = await policyServer.initializePSVerification(
            ddoInstance.getDid(),
            ddo,
            service.id,
            task.consumerAddress,
            task.policyServer
          )
          accessGrantedServiceLevel = accessGrantedDDOLevel || response.success
        } else {
          accessGrantedServiceLevel = await checkCredentials(
            task.consumerAddress,
            service.credentials,
            signer
          )
        }

        if (!accessGrantedServiceLevel) {
          const error = `Error: Access to service with id ${service.id} was denied`
          PROVIDER_LOGGER.error(error)
          return {
            stream: null,
            status: { httpStatus: 403, error }
          }
        }
      }
    }

    const now = new Date().getTime() / 1000
    let validUntil = service.timeout === 0 ? 0 : now + service.timeout // first, make it service default
    if (task.validUntil && !isNaN(task.validUntil)) {
      // so user input is a number
      if (service.timeout > 0 && task.validUntil > validUntil) {
        errorMsg = 'Required validUntil is higher than service timeout'
      }
      // eslint-disable-next-line prefer-destructuring
      validUntil = task.validUntil
    }

    if (errorMsg) {
      PROVIDER_LOGGER.logMessageWithEmoji(
        errorMsg,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: errorMsg
        }
      }
    }

    const nonceDB = (await this.getOceanNode().getDatabase()).nonce
    const nonceHandlerResponse = await getNonce(nonceDB, task.consumerAddress)
    const nonce = await streamToString(nonceHandlerResponse.stream as Readable)
    const feesClass = new ProviderFees(this.getOceanNode())
    try {
      const providerFee = await feesClass.createProviderFee(ddo, service, validUntil)
      if (providerFee) {
        const response: ProviderInitialize = {
          providerFee,
          datatoken: service?.datatokenAddress,
          nonce,
          computeAddress: task?.consumerAddress
        }
        return {
          stream: Readable.from(JSON.stringify(response, null, 4)),
          status: { httpStatus: 200 }
        }
      } else {
        const error = `Unable to calculate fees (null) for DDO with id: ${task.ddoId} and serviceId: ${task.serviceId}`
        PROVIDER_LOGGER.logMessageWithEmoji(
          error,
          true,
          GENERIC_EMOJIS.EMOJI_CROSS_MARK,
          LOG_LEVELS_STR.LEVEL_ERROR
        )
        return {
          stream: null,
          status: {
            httpStatus: 500,
            error
          }
        }
      }
    } catch (error) {
      PROVIDER_LOGGER.logMessageWithEmoji(
        error.message,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: error.message
        }
      }
    }
  }
}
