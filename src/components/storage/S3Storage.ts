import {
  FileInfoResponse,
  S3FileObject,
  StorageReadable
} from '../../@types/fileObject.js'
import { OceanNodeConfig } from '../../@types/OceanNode.js'
import { GetObjectCommand, HeadObjectCommand, S3Client } from '@aws-sdk/client-s3'
import { Upload } from '@aws-sdk/lib-storage'
import { Readable } from 'stream'
import { CORE_LOGGER } from '../../utils/logging/common.js'

import { Storage } from './Storage.js'

function createS3Client(s3Access: S3FileObject['s3Access']): S3Client {
  CORE_LOGGER.logMessage(
    `[S3Storage] Creating S3 client with endpoint: ${s3Access.endpoint}, region: ${s3Access.region || 'us-east-1'}, forcePathStyle: ${s3Access.forcePathStyle}`,
    true
  )

  return new S3Client({
    endpoint: s3Access.endpoint,
    region: s3Access.region ?? 'us-east-1',
    forcePathStyle: s3Access.forcePathStyle ?? false,
    credentials: {
      accessKeyId: s3Access.accessKeyId,
      secretAccessKey: s3Access.secretAccessKey
    },
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED'
  })
}

export class S3Storage extends Storage {
  public constructor(file: S3FileObject, config: OceanNodeConfig) {
    super(file, config, true)
    CORE_LOGGER.logMessage(
      `[S3Storage] Constructor called with file type: ${file.type}`,
      true
    )
    const [isValid, message] = this.validate()
    if (isValid === false) {
      CORE_LOGGER.error(`[S3Storage] Validation failed: ${message}`)
      throw new Error(`Error validating the S3 file: ${message}`)
    }
    CORE_LOGGER.logMessage(`[S3Storage] Validation successful`, true)
  }

  validate(): [boolean, string] {
    const file: S3FileObject = this.getFile() as S3FileObject
    CORE_LOGGER.logMessage(`[S3Storage] Validating S3 file...`, true)

    if (!file.s3Access) {
      CORE_LOGGER.error(`[S3Storage] Missing s3Access object`)
      return [false, 'Missing s3Access']
    }

    const {
      bucket,
      objectKey,
      endpoint,
      accessKeyId,
      secretAccessKey,
      region,
      forcePathStyle
    } = file.s3Access

    CORE_LOGGER.logMessage(
      `[S3Storage] Validating fields - bucket: ${bucket}, objectKey: ${objectKey}, endpoint: ${endpoint}, region: ${region}, forcePathStyle: ${forcePathStyle}`,
      true
    )

    if (!bucket?.trim()) {
      CORE_LOGGER.error(`[S3Storage] Missing bucket`)
      return [false, 'Missing bucket']
    }
    if (!objectKey?.trim()) {
      CORE_LOGGER.error(`[S3Storage] Missing objectKey`)
      return [false, 'Missing objectKey']
    }
    if (!endpoint?.trim()) {
      CORE_LOGGER.error(`[S3Storage] Missing endpoint`)
      return [false, 'Missing endpoint']
    }
    if (!accessKeyId?.trim()) {
      CORE_LOGGER.error(`[S3Storage] Missing accessKeyId`)
      return [false, 'Missing accessKeyId']
    }
    if (!secretAccessKey?.trim()) {
      CORE_LOGGER.error(`[S3Storage] Missing secretAccessKey`)
      return [false, 'Missing secretAccessKey']
    }

    CORE_LOGGER.logMessage(`[S3Storage] All fields validated successfully`, true)
    return [true, '']
  }

  override async getReadableStream(): Promise<StorageReadable> {
    const { s3Access } = this.getFile() as S3FileObject
    CORE_LOGGER.logMessage(
      `[S3Storage] Getting readable stream for bucket: ${s3Access.bucket}, key: ${s3Access.objectKey}`,
      true
    )

    const s3Client = createS3Client(s3Access)

    try {
      CORE_LOGGER.logMessage(`[S3Storage] Sending GetObjectCommand...`, true)
      const response = await s3Client.send(
        new GetObjectCommand({
          Bucket: s3Access.bucket,
          Key: s3Access.objectKey
        })
      )

      CORE_LOGGER.logMessage(
        `[S3Storage] GetObjectCommand successful, statusCode: ${response.$metadata.httpStatusCode}`,
        true
      )

      if (!response.Body) {
        CORE_LOGGER.error(`[S3Storage] GetObject returned no body`)
        throw new Error('S3 GetObject returned no body')
      }

      return {
        httpStatus: response.$metadata.httpStatusCode ?? 200,
        stream: response.Body as Readable,
        headers: response.ContentType
          ? { 'Content-Type': response.ContentType }
          : undefined
      }
    } catch (err) {
      CORE_LOGGER.error(`[S3Storage] Error fetching object from S3: ${err}`)
      if (err instanceof Error) {
        CORE_LOGGER.error(
          `[S3Storage] Error name: ${err.name}, message: ${err.message}, stack: ${err.stack}`
        )

        // Log specific AWS error details
        if ('$metadata' in err) {
          const awsError = err as any
          CORE_LOGGER.error(
            `[S3Storage] AWS Error metadata: ${JSON.stringify(awsError.$metadata)}`
          )
          CORE_LOGGER.error(
            `[S3Storage] AWS Error code: ${awsError.Code}, requestId: ${awsError.$metadata?.requestId}`
          )
        }
      }
      throw err
    }
  }

  /**
   * Upload a file via S3 multipart upload (streaming). If s3Access.objectKey ends with /, the key becomes objectKey + filename; otherwise objectKey is the target key.
   * Uses @aws-sdk/lib-storage Upload so large streams are sent in parts without buffering the entire file.
   */
  async upload(
    filename: string,
    stream: Readable
  ): Promise<{ httpStatus: number; headers?: Record<string, string | string[]> }> {
    const { s3Access } = this.getFile() as S3FileObject
    CORE_LOGGER.logMessage(
      `[S3Storage] Uploading file: ${filename} to bucket: ${s3Access.bucket}`,
      true
    )

    const s3Client = createS3Client(s3Access)
    let key = s3Access.objectKey
    if (key.endsWith('/')) {
      key = `${key.replace(/\/+$/, '')}/${filename}`
      CORE_LOGGER.logMessage(
        `[S3Storage] Key ends with '/', updated key to: ${key}`,
        true
      )
    }

    try {
      const upload = new Upload({
        client: s3Client,
        params: {
          Bucket: s3Access.bucket,
          Key: key,
          Body: stream,
          ContentType: 'application/octet-stream',
          ContentDisposition: `attachment; filename="${filename.replace(/"/g, '\\"')}"`
        },
        queueSize: 4,
        partSize: 5 * 1024 * 1024, // 5MB minimum for S3
        leavePartsOnError: false
      })

      CORE_LOGGER.logMessage(`[S3Storage] Starting upload...`, true)
      await upload.done()
      CORE_LOGGER.logMessage(`[S3Storage] Upload completed successfully`, true)

      return { httpStatus: 200, headers: {} }
    } catch (err) {
      CORE_LOGGER.error(`[S3Storage] Upload error: ${err}`)
      if (err instanceof Error) {
        CORE_LOGGER.error(
          `[S3Storage] Upload error name: ${err.name}, message: ${err.message}`
        )
      }
      throw err
    }
  }

  async fetchSpecificFileMetadata(
    fileObject: S3FileObject,
    _forceChecksum: boolean
  ): Promise<FileInfoResponse> {
    const { s3Access } = fileObject
    CORE_LOGGER.logMessage(
      `[S3Storage] Fetching metadata for bucket: ${s3Access.bucket}, key: ${s3Access.objectKey}`,
      true
    )

    const s3Client = createS3Client(s3Access)

    try {
      CORE_LOGGER.logMessage(`[S3Storage] Sending HeadObjectCommand...`, true)
      const data = await s3Client.send(
        new HeadObjectCommand({
          Bucket: s3Access.bucket,
          Key: s3Access.objectKey
        })
      )

      CORE_LOGGER.logMessage(
        `[S3Storage] HeadObjectCommand successful, statusCode: ${data.$metadata.httpStatusCode}`,
        true
      )
      CORE_LOGGER.logMessage(
        `[S3Storage] Metadata received - ContentLength: ${data.ContentLength}, ContentType: ${data.ContentType}, ETag: ${data.ETag}`,
        true
      )

      const contentLength = data.ContentLength != null ? String(data.ContentLength) : '0'
      const contentType = data.ContentType ?? 'application/octet-stream'
      const name = s3Access.objectKey.split('/').pop() ?? s3Access.objectKey

      CORE_LOGGER.logMessage(
        `[S3Storage] Returning file info - name: ${name}, type: ${contentType}, size: ${contentLength}`,
        true
      )

      return {
        valid: true,
        contentLength,
        contentType,
        checksum: data.ETag?.replace(/"/g, ''),
        name,
        type: 's3',
        encryptedBy: fileObject.encryptedBy,
        encryptMethod: fileObject.encryptMethod
      }
    } catch (err) {
      CORE_LOGGER.error(`[S3Storage] Error fetching metadata from S3: ${err}`)
      if (err instanceof Error) {
        CORE_LOGGER.error(
          `[S3Storage] Error name: ${err.name}, message: ${err.message}, stack: ${err.stack}`
        )

        // Log specific AWS error details
        if ('$metadata' in err) {
          const awsError = err as any
          CORE_LOGGER.error(
            `[S3Storage] AWS Error metadata: ${JSON.stringify(awsError.$metadata)}`
          )
          CORE_LOGGER.error(`[S3Storage] AWS Error code: ${awsError.Code}`)

          if (awsError.Code === 'NoSuchKey') {
            CORE_LOGGER.error(
              `[S3Storage] File not found: ${s3Access.bucket}/${s3Access.objectKey}`
            )
          } else if (awsError.Code === 'AccessDenied') {
            CORE_LOGGER.error(
              `[S3Storage] Access denied - check credentials and bucket permissions`
            )
          } else if (awsError.Code === 'NoSuchBucket') {
            CORE_LOGGER.error(`[S3Storage] Bucket does not exist: ${s3Access.bucket}`)
          } else if (awsError.Code === 'SignatureDoesNotMatch') {
            CORE_LOGGER.error(
              `[S3Storage] Signature does not match - check credentials and endpoint`
            )
          } else if (awsError.Code === 'InvalidAccessKeyId') {
            CORE_LOGGER.error(`[S3Storage] Invalid Access Key ID`)
          }
        }
      }
      throw err
    }
  }
}
