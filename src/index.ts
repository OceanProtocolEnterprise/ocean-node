import { OceanP2P } from './components/P2P/index.js'
import { OceanProvider } from './components/Provider/index.js'
import { OceanIndexer } from './components/Indexer/index.js'
import { Database } from './components/database/index.js'
import express, { Express } from 'express'
import { OceanNode } from './OceanNode.js'
import { KeyManager } from './components/KeyManager/index.js'
import { BlockchainRegistry } from './components/BlockchainRegistry/index.js'
import { httpRoutes } from './components/httpRoutes/index.js'
import {
  getConfiguration,
  computeCodebaseHash,
  ENVIRONMENT_VARIABLES
} from './utils/index.js'

import { GENERIC_EMOJIS, LOG_LEVELS_STR } from './utils/logging/Logger.js'
import fs from 'fs'
import https from 'https'
import { OCEAN_NODE_LOGGER } from './utils/logging/common.js'
import path from 'path'
import { fileURLToPath } from 'url'
import cors from 'cors'
import { scheduleCronJobs } from './utils/cronjobs/scheduleCronJobs.js'
import { requestValidator } from './components/httpRoutes/requestValidator.js'
import { hasValidDBConfiguration } from './utils/database.js'

const app: Express = express()

function removeExtraSlashes(req: any, res: any, next: any) {
  req.url = req.url.replace(/\/{2,}/g, '/')
  next()
}

function logStartupStep(step: string) {
  const message = `[startup] ${step}`
  console.error(message)
  OCEAN_NODE_LOGGER.info(`Startup step: ${step}`)
}

function logStartupFailure(step: string, err: unknown) {
  const errorMessage = err instanceof Error ? err.message : String(err)
  console.error(`[startup] failed during "${step}": ${errorMessage}`)
  if (err instanceof Error && err.stack) {
    console.error(err.stack)
  }
  OCEAN_NODE_LOGGER.error(`Startup failed during step "${step}": ${errorMessage}`)
  if (err instanceof Error && err.stack) {
    OCEAN_NODE_LOGGER.error(`Startup failure stack: ${err.stack}`)
  }
}

process.on('uncaughtException', (err) => {
  console.error(`[uncaughtException] ${err.message}`)
  if (err?.stack) {
    console.error(err.stack)
  }
  OCEAN_NODE_LOGGER.error(`Uncaught exception: ${err.message}`)
  if (err?.stack) {
    OCEAN_NODE_LOGGER.error(`Uncaught exception stack: ${err.stack}`)
  }
  process.exit(1)
})
process.on('unhandledRejection', (err) => {
  console.error(
    `[unhandledRejection] ${err instanceof Error ? err.message : String(err)}`
  )
  if (err instanceof Error && err.stack) {
    console.error(err.stack)
  }
  OCEAN_NODE_LOGGER.error(
    `Unhandled rejection: ${err instanceof Error ? err.message : String(err)}`
  )
  if (err instanceof Error && err.stack) {
    OCEAN_NODE_LOGGER.error(`Unhandled rejection stack: ${err.stack}`)
  }
  process.exit(1)
})

// const port = getRandomInt(6000,6500)

express.static.mime.define({ 'image/svg+xml': ['svg'] })

declare global {
  // eslint-disable-next-line no-unused-vars
  namespace Express {
    // eslint-disable-next-line no-unused-vars
    interface Request {
      oceanNode: OceanNode
      caller?: string | string[]
    }
  }
}

// (*) optional flag
const isStartup: boolean = true
// this is to avoid too much verbose logging, cause we're calling getConfig() from many parts
// and we are always running though the same process.env checks
// (we must start accessing the config from the OceanNode class only once we refactor)
OCEAN_NODE_LOGGER.logMessageWithEmoji(
  '[ Starting Ocean Node ]',
  true,
  GENERIC_EMOJIS.EMOJI_OCEAN_WAVE,
  LOG_LEVELS_STR.LEVEL_INFO
)

let startupStep = 'initializing'

try {
  startupStep = 'loading configuration'
  logStartupStep(startupStep)
  const config = await getConfiguration(true, isStartup)

  startupStep = 'computing codebase hash'
  logStartupStep(startupStep)
  const __filename = fileURLToPath(import.meta.url)
  const __dirname = path.dirname(__filename)
  config.codeHash = await computeCodebaseHash(__dirname)

  OCEAN_NODE_LOGGER.info(`Codebase hash: ${config.codeHash}`)
  OCEAN_NODE_LOGGER.info(
    `Startup config summary: hasHttp=${config.hasHttp}, hasP2P=${config.hasP2P}, hasIndexer=${config.hasIndexer}, httpPort=${config.httpPort}`
  )
  if (!config) {
    process.exit(1)
  }
  let node: OceanP2P = null
  let indexer = null
  let provider = null

  startupStep = 'initializing database'
  logStartupStep(startupStep)
  // If there is no DB URL only the nonce database will be available
  const dbconn: Database = await Database.init(config.dbConfig)
  if (!dbconn) {
    OCEAN_NODE_LOGGER.error('Database failed to initialize')
  } else {
    OCEAN_NODE_LOGGER.info('Database initialized')
  }

  if (!hasValidDBConfiguration(config.dbConfig)) {
    // once we create a database instance, we check the environment and possibly add the DB transport
    // after that, all loggers will eventually have it too (if in production/staging environments)
    // it creates dinamically DDO schemas
    config.hasIndexer = false
    OCEAN_NODE_LOGGER.warn(
      `Missing or invalid property: "${ENVIRONMENT_VARIABLES.DB_URL.name}". This means Indexer module will not be enabled.`
    )
  }

  startupStep = 'creating key manager'
  logStartupStep(startupStep)
  // Create KeyManager and BlockchainRegistry
  // KeyManager will determine provider type from config.keys.type and initialize in constructor
  const keyManager = new KeyManager(config)

  startupStep = 'creating blockchain registry'
  logStartupStep(startupStep)
  const blockchainRegistry = new BlockchainRegistry(keyManager, config)

  if (config.hasP2P) {
    startupStep = 'initializing p2p node'
    logStartupStep(startupStep)
    if (dbconn) {
      node = new OceanP2P(config, keyManager, dbconn)
    } else {
      node = new OceanP2P(config, keyManager)
    }

    startupStep = 'starting p2p node'
    logStartupStep(startupStep)
    await node.start()
    OCEAN_NODE_LOGGER.info('P2P node started')
  }

  if (config.hasIndexer && dbconn) {
    startupStep = 'creating indexer'
    logStartupStep(startupStep)
    indexer = new OceanIndexer(dbconn, config.indexingNetworks, blockchainRegistry)
    OCEAN_NODE_LOGGER.info('Indexer initialized')
  }
  if (dbconn) {
    startupStep = 'creating provider'
    logStartupStep(startupStep)
    provider = new OceanProvider(dbconn)
    OCEAN_NODE_LOGGER.info('Provider initialized')
  }

  startupStep = 'creating ocean node singleton'
  logStartupStep(startupStep)
  // Singleton instance across application
  const oceanNode = OceanNode.getInstance(
    config,

    dbconn,
    node,
    provider,
    indexer,
    keyManager,
    blockchainRegistry
  )

  startupStep = 'adding c2d engines'
  logStartupStep(startupStep)
  oceanNode.addC2DEngines()

  if (config.hasHttp) {
    startupStep = 'configuring http server'
    logStartupStep(startupStep)
    // allow up to 25Mb file upload
    app.use(express.raw({ limit: '25mb' }))
    app.use(cors())
    app.use(requestValidator, (req, res, next) => {
      req.caller = req.headers['x-forwarded-for'] || req.socket.remoteAddress
      req.oceanNode = oceanNode
      next()
    })

    // Integrate static file serving middleware
    app.use(removeExtraSlashes)
    app.use('/', httpRoutes)

    if (config.httpCertPath && config.httpKeyPath) {
      try {
        startupStep = 'starting https server'
        logStartupStep(startupStep)
        const options = {
          cert: fs.readFileSync(config.httpCertPath),
          key: fs.readFileSync(config.httpKeyPath)
        }
        https.createServer(options, app).listen(config.httpPort, () => {
          OCEAN_NODE_LOGGER.logMessage(`HTTPS port: ${config.httpPort}`, true)
        })
      } catch (err) {
        OCEAN_NODE_LOGGER.error(`Error starting HTTPS server: ${err.message}`)
        OCEAN_NODE_LOGGER.logMessage(`Falling back to HTTP`, true)
        startupStep = 'starting http server after https fallback'
        logStartupStep(startupStep)
        app.listen(config.httpPort, () => {
          OCEAN_NODE_LOGGER.logMessage(`HTTP port: ${config.httpPort}`, true)
        })
      }
    } else {
      startupStep = 'starting http server'
      logStartupStep(startupStep)
      app.listen(config.httpPort, () => {
        OCEAN_NODE_LOGGER.logMessage(`HTTP port: ${config.httpPort}`, true)
      })
    }

    startupStep = 'scheduling cron jobs'
    logStartupStep(startupStep)
    // Call the function to schedule the cron job to delete old logs
    scheduleCronJobs(oceanNode)
  }
} catch (err) {
  logStartupFailure(startupStep, err)
  process.exit(1)
}
