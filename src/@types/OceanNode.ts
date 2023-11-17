import { OceanP2P } from '../components/P2P/index'
import { OceanProvider } from '../components/Provider/index'
import { OceanIndexer } from '../components/Indexer/index'
import type { PeerId } from '@libp2p/interface/peer-id'
import { Stream } from 'stream'
import { TypesenseConfigOptions } from './Typesense'
import { Blockchain } from '../utils/blockchain'
import { RPCS } from './blockchain'

export interface OceanNodeDBConfig {
  url: string
}

export interface OceanNodeKeys {
  peerId: PeerId
  publicKey: any
  privateKey: any
}

export interface OceanNodeP2PConfig {
  ipV4BindAddress: string | null
  ipV4BindTcpPort: number | null
  ipV4BindWsPort: number | null
  ipV6BindAddress: string | null
  ipV6BindTcpPort: number | null
  ipV6BindWsPort: number | null
  pubsubPeerDiscoveryInterval: number
  dhtMaxInboundStreams: number
  dhtMaxOutboundStreams: number
  mDNSInterval: number
  connectionsMaxParallelDials: number
  connectionsDialTimeout: number
}

export interface OceanNodeConfig {
  keys: OceanNodeKeys
  hasP2P: boolean
  p2pConfig: OceanNodeP2PConfig | null
  hasIndexer: boolean
  hasProvider: boolean
  hasHttp: boolean
  dbConfig: OceanNodeDBConfig
  httpPort: number
  supportedNetworks: RPCS
}

export interface OceanNode {
  node: OceanP2P | null
  indexer: OceanIndexer | null
  provider: OceanProvider | null
}

export interface P2PCommandResponse {
  status: any
  stream: Stream | null
}
