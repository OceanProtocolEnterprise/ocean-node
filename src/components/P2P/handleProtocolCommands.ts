import { pipe } from 'it-pipe'
import { Stream, Readable } from 'stream'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import StreamConcat from 'stream-concat'
// export function handleProtocolCommands (sourceStream:any,sinkStream:any) {

import * as fs from 'fs'
import { handleDownloadURLCommand } from './downloadHandler'
import { DownloadCommand, PROTOCOL_COMMANDS } from '../../utils/constants'
import { P2PCommandResponse } from '../../@types/OceanNode'

import { P2P_CONSOLE_LOGGER } from './index'

class ReadableString extends Readable {
  private sent = false

  constructor(private str: string) {
    super()
  }

  _read() {
    if (!this.sent) {
      this.push(Buffer.from(this.str))
      this.sent = true
    } else {
      this.push(null)
    }
  }
}

export async function handleProtocolCommands(connection: any) {
  P2P_CONSOLE_LOGGER.logMessage(
    'Incoming connection from peer ' + connection.connection.remotePeer,
    true
  )
  P2P_CONSOLE_LOGGER.logMessage('Using ' + connection.connection.remoteAddr, true)

  let status = null
  const isError = false
  let task
  let statusStream
  let sendStream = null
  /* eslint no-unreachable-loop: ["error", { "ignore": ["ForInStatement", "ForOfStatement"] }] */
  for await (const chunk of connection.stream.source) {
    try {
      const str = uint8ArrayToString(chunk.subarray())
      task = JSON.parse(str)
    } catch (e) {
      status = { httpStatus: 400, error: 'Invalid command' }
      statusStream = new ReadableString(JSON.stringify(status))
      pipe(statusStream, connection.stream.sink)
      return
    }
    break
  }
  P2P_CONSOLE_LOGGER.logMessage('Performing task: ' + JSON.stringify(task), true)

  let response: P2PCommandResponse = null
  try {
    switch (task.command) {
      case PROTOCOL_COMMANDS.ECHO:
        status = { httpStatus: 200 }
        break
      case PROTOCOL_COMMANDS.DOWNLOAD_URL:
        response = await handleDownloadURLCommand(task)
        // eslint-disable-next-line prefer-destructuring
        status = response.status
        sendStream = response.stream
        break
      default:
        status = { httpStatus: 501, error: 'Unknown command' }
        break
    }
    statusStream = new ReadableString(JSON.stringify(status))
    if (sendStream == null) pipe(statusStream, connection.stream.sink)
    else {
      const combinedStream = new StreamConcat([statusStream, sendStream])
      pipe(combinedStream, connection.stream.sink)
    }
  } catch (err) {
    console.log('error:')
    console.log(err)
  }
}
/**
 * Use this method to direct calls to the node as node cannot dial into itself
 * @param message command message
 * @param sink transform function
 */
export async function handleDirectProtocolCommand(message: string, sink: any) {
  P2P_CONSOLE_LOGGER.logMessage('Incoming direct command for peer self', true)
  let status = null
  const task = JSON.parse(message)
  // let statusStream
  let sendStream = null
  let response: P2PCommandResponse = null

  P2P_CONSOLE_LOGGER.logMessage('Performing task: ' + JSON.stringify(task), true)
  switch (task.command) {
    case PROTOCOL_COMMANDS.ECHO:
      status = { httpStatus: 200 }
      break
    case PROTOCOL_COMMANDS.DOWNLOAD_URL:
      response = await handleDownloadURLCommand(task)
      // eslint-disable-next-line prefer-destructuring
      status = response.status
      sendStream = response.stream
      break
    default:
      status = { httpStatus: 501, error: 'Unknown command' }
      break
  }

  const statusStream = new ReadableString(JSON.stringify(status))
  if (sendStream == null) {
    pipe(statusStream, sink)
  } else {
    const combinedStream = new StreamConcat([statusStream, sendStream])
    pipe(combinedStream, sink)
  }
}
