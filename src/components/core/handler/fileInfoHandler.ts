import { Readable } from 'stream'
import { P2PCommandResponse } from '../../../@types/index.js'
import { StorageObject } from '../../../@types/fileObject.js'
import { OceanNodeConfig } from '../../../@types/OceanNode.js'
import { FileInfoCommand } from '../../../@types/commands.js'
import { CORE_LOGGER } from '../../../utils/logging/common.js'
import { Storage } from '../../storage/index.js'
import { CommandHandler } from './handler.js'
import { validateDDOIdentifier } from './ddoHandler.js'
import {
  ValidateParams,
  buildInvalidRequestMessage,
  validateCommandParameters
} from '../../httpRoutes/validateCommands.js'
import { getFile } from '../../../utils/file.js'
import { getConfiguration } from '../../../utils/index.js'

async function formatMetadata(
  file: StorageObject,
  config: OceanNodeConfig
): Promise<{
  valid: boolean
  contentLength: string
  contentType: string
  checksum?: string
  name: string
  type: string
}> {
  CORE_LOGGER.logMessage(
    `[formatMetadata] Formatting metadata for file type: ${file.type}`,
    true
  )

  try {
    const storage = Storage.getStorageClass(file, config)
    CORE_LOGGER.logMessage(
      `[formatMetadata] Got storage class for type: ${file.type}`,
      true
    )

    const fileInfo = await storage.fetchSpecificFileMetadata(file, false)
    CORE_LOGGER.logMessage(
      `[formatMetadata] Metadata for file: ${fileInfo.contentLength} ${fileInfo.contentType}`,
      true
    )
    return fileInfo
  } catch (error) {
    CORE_LOGGER.error(`[formatMetadata] Error: ${error.message}`)
    if (error instanceof Error) {
      CORE_LOGGER.error(`[formatMetadata] Stack: ${error.stack}`)
    }
    throw error
  }
}

export class FileInfoHandler extends CommandHandler {
  validate(command: FileInfoCommand): ValidateParams {
    CORE_LOGGER.logMessage(`[FileInfoHandler] Validating command`, true)

    let validation = validateCommandParameters(command, []) // all optional? weird
    if (validation.valid) {
      if (command.did) {
        validation = validateDDOIdentifier(command.did)
        if (validation.valid && !command.serviceId) {
          validation.valid = false
          validation.reason = 'Invalid Request: matching "serviceId" not specified!'
        }
      } else if (
        !command.checksum &&
        !command.did &&
        !command.file &&
        !command.fileIndex &&
        !command.serviceId &&
        !command.type
      ) {
        return buildInvalidRequestMessage('Invalid Request: no fields are present!')
      }
    }
    return validation
  }

  async handle(task: FileInfoCommand): Promise<P2PCommandResponse> {
    CORE_LOGGER.logMessage(
      `[FileInfoHandler] Handling task: ${JSON.stringify(task, null, 2)}`,
      true
    )

    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }

    try {
      const oceanNode = this.getOceanNode()
      const config = await getConfiguration()
      let fileInfo = []

      if (task.file && task.type) {
        CORE_LOGGER.logMessage(
          `[FileInfoHandler] Processing file of type: ${task.type}`,
          true
        )
        CORE_LOGGER.logMessage(
          `[FileInfoHandler] File object: ${JSON.stringify(task.file, null, 2)}`,
          true
        )

        try {
          const storage = Storage.getStorageClass(task.file, config)
          CORE_LOGGER.logMessage(
            `[FileInfoHandler] Storage class created successfully`,
            true
          )

          fileInfo = await storage.getFileInfo({
            type: task.type,
            fileIndex: task.fileIndex
          })
          CORE_LOGGER.logMessage(
            `[FileInfoHandler] getFileInfo returned: ${JSON.stringify(fileInfo, null, 2)}`,
            true
          )
        } catch (storageError) {
          CORE_LOGGER.error(`[FileInfoHandler] Storage error: ${storageError.message}`)
          if (storageError instanceof Error) {
            CORE_LOGGER.error(
              `[FileInfoHandler] Storage error stack: ${storageError.stack}`
            )
          }
          throw storageError
        }
      } else if (task.did && task.serviceId) {
        CORE_LOGGER.logMessage(
          `[FileInfoHandler] Processing DID: ${task.did}, serviceId: ${task.serviceId}`,
          true
        )

        const fileArray = await getFile(task.did, task.serviceId, oceanNode)
        CORE_LOGGER.logMessage(
          `[FileInfoHandler] Got fileArray with ${fileArray.length} files`,
          true
        )

        if (task.fileIndex) {
          CORE_LOGGER.logMessage(
            `[FileInfoHandler] Getting metadata for file index: ${task.fileIndex}`,
            true
          )
          const fileMetadata = await formatMetadata(fileArray[task.fileIndex], config)
          fileInfo.push(fileMetadata)
        } else {
          for (let i = 0; i < fileArray.length; i++) {
            CORE_LOGGER.logMessage(
              `[FileInfoHandler] Getting metadata for file index: ${i}`,
              true
            )
            const fileMetadata = await formatMetadata(fileArray[i], config)
            fileInfo.push(fileMetadata)
          }
        }
      } else {
        const errorMessage =
          'Invalid arguments. Please provide either file && Type OR did && serviceId'
        CORE_LOGGER.error(`[FileInfoHandler] ${errorMessage}`)
        return {
          stream: null,
          status: {
            httpStatus: 400,
            error: errorMessage
          }
        }
      }

      CORE_LOGGER.logMessage(
        '[FileInfoHandler] File Info Response: ' + JSON.stringify(fileInfo, null, 2),
        true
      )

      return {
        stream: Readable.from(JSON.stringify(fileInfo)),
        status: {
          httpStatus: 200
        }
      }
    } catch (error) {
      CORE_LOGGER.error(`[FileInfoHandler] Error: ${error.message}`)
      if (error instanceof Error) {
        CORE_LOGGER.error(`[FileInfoHandler] Error stack: ${error.stack}`)
        CORE_LOGGER.error(`[FileInfoHandler] Error name: ${error.name}`)
      }
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: error.message || 'UnknownError'
        }
      }
    }
  }
}
