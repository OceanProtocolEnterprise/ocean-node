/**
 * Ocean Enterprise (OE) vocabulary.
 *
 * Single source of truth for all custom terms used in the DCAT output that are
 * NOT covered by the standard DCAT/DCAT-AP/GeoDCAT-AP vocabularies.
 *
 * Every term here corresponds to a JSON-LD property of the form `oec:<name>`,
 * where `<name>` is the key in the OE_VOCABULARY map below.
 *
 * To add a new OE term:
 *   1. Add an entry to OE_VOCABULARY with the term name as the key.
 *   2. Use the term in transformToDCAT via the `oec()` helper.
 *   3. If the term belongs to an existing nested object, add it to the
 *      appropriate `properties` list in OE_OBJECT_SHAPES.
 *
 * The vocabulary URI is expected to be published at
 * https://oceanenterprise.io/vocab/ once the OE infrastructure serves it.
 * Until then, the URI is used as a namespace placeholder for the JSON-LD context.
 */

export type OECTerm = {
  name: string
  label: string
  description: string
  range?: string
  domain?: string
}

export const OE_VOCABULARY: Record<string, OECTerm> = {
  chainId: {
    name: 'chainId',
    label: 'Chain ID',
    description: 'Blockchain chain ID where the asset NFT is registered.',
    range: 'xsd:integer'
  },
  nftAddress: {
    name: 'nftAddress',
    label: 'NFT Address',
    description: 'Contract address of the data NFT representing the asset.',
    range: 'xsd:string'
  },
  issuer: {
    name: 'issuer',
    label: 'Issuer',
    description: 'DID of the entity that issued the Verifiable Credential.',
    range: 'xsd:string'
  },
  datatokens: {
    name: 'datatokens',
    label: 'Datatokens',
    description:
      'Array of access tokens (datatokens) attached to the asset, one per service.',
    range: 'oec:Datatoken'
  },
  algorithm: {
    name: 'algorithm',
    label: 'Algorithm',
    description: 'Container and language metadata for algorithm assets.',
    range: 'oec:Algorithm'
  },
  event: {
    name: 'event',
    label: 'Blockchain Event',
    description: 'On-chain event that created or updated the asset metadata.',
    range: 'oec:Event'
  },
  nft: {
    name: 'nft',
    label: 'NFT Metadata',
    description: 'Metadata of the data NFT (name, symbol, owner, state).',
    range: 'oec:NFT'
  },
  stats: {
    name: 'stats',
    label: 'Stats',
    description: 'Aggregated order/price statistics for the asset.',
    range: 'oec:Stats'
  },
  purgatory: {
    name: 'purgatory',
    label: 'Purgatory',
    description: 'Purgatory state of the asset.',
    range: 'oec:Purgatory'
  },
  accessDetails: {
    name: 'accessDetails',
    label: 'Access Details',
    description: 'Pricing and access configuration derived from the DDO.',
    range: 'oec:AccessDetails'
  },
  services: {
    name: 'services',
    label: 'Services',
    description:
      'Array of data services exposed by the asset, each typed as dcat:DataService.',
    range: 'dcat:DataService'
  },
  additionalDdos: {
    name: 'additionalDdos',
    label: 'Additional DDOs',
    description: 'Additional DDO entries attached to the asset (extensions).',
    range: 'oec:AdditionalDdo'
  },

  // ── Service-level OE metadata ────────────────────────────────────────
  serviceType: {
    name: 'serviceType',
    label: 'Service Type',
    description: 'Type of the service: "access" or "compute".',
    range: 'xsd:string'
  },
  datatokenAddress: {
    name: 'datatokenAddress',
    label: 'Datatoken Address',
    description: 'Contract address of the datatoken for this service.',
    range: 'xsd:string'
  },
  files: {
    name: 'files',
    label: 'Files',
    description: 'Encrypted file descriptor (0x-prefixed hex).',
    range: 'xsd:string'
  },
  timeout: {
    name: 'timeout',
    label: 'Timeout',
    description: 'Service timeout in seconds.',
    range: 'xsd:integer'
  },
  state: {
    name: 'state',
    label: 'State',
    description: 'Service state code (0 = active).',
    range: 'xsd:integer'
  },
  compute: {
    name: 'compute',
    label: 'Compute Configuration',
    description: 'Trusted algorithm and network policies for compute services.',
    range: 'oec:Compute'
  },
  consumerParameters: {
    name: 'consumerParameters',
    label: 'Consumer Parameters',
    description: 'Parameters the consumer supplies when ordering the service.',
    range: 'oec:ConsumerParameter'
  },
  credentials: {
    name: 'credentials',
    label: 'Credentials',
    description:
      'SSI credential and address allow/deny lists required to access the service.',
    range: 'oec:Credentials'
  },

  // ── Datatoken object fields ──────────────────────────────────────────
  address: {
    name: 'address',
    label: 'Address',
    description: 'Blockchain address.',
    range: 'xsd:string'
  },
  name: {
    name: 'name',
    label: 'Name',
    description: 'Human-readable name.',
    range: 'xsd:string'
  },
  symbol: {
    name: 'symbol',
    label: 'Symbol',
    description: 'Token symbol.',
    range: 'xsd:string'
  },
  serviceId: {
    name: 'serviceId',
    label: 'Service ID',
    description: 'Identifier of the service this datatoken grants access to.',
    range: 'xsd:string'
  },
  decimals: {
    name: 'decimals',
    label: 'Decimals',
    description: 'Number of decimals for a token amount.',
    range: 'xsd:integer'
  },

  // ── Compute object fields ────────────────────────────────────────────
  allowNetworkAccess: {
    name: 'allowNetworkAccess',
    label: 'Allow Network Access',
    description: 'Whether compute jobs on this service can access the network.',
    range: 'xsd:boolean'
  },
  allowRawAlgorithm: {
    name: 'allowRawAlgorithm',
    label: 'Allow Raw Algorithm',
    description: 'Whether raw (unpublished) algorithms may be run.',
    range: 'xsd:boolean'
  },
  publisherTrustedAlgorithms: {
    name: 'publisherTrustedAlgorithms',
    label: 'Publisher Trusted Algorithms',
    description:
      'List of algorithm DIDs the publisher has pre-approved for this compute service.',
    range: 'oec:TrustedAlgorithm'
  },
  publisherTrustedAlgorithmPublishers: {
    name: 'publisherTrustedAlgorithmPublishers',
    label: 'Publisher Trusted Algorithm Publishers',
    description: 'List of publisher addresses whose algorithms are trusted.',
    range: 'xsd:string'
  },

  // ── TrustedAlgorithm object fields ───────────────────────────────────
  did: {
    name: 'did',
    label: 'DID',
    description: 'Decentralized identifier.',
    range: 'xsd:string'
  },
  filesChecksum: {
    name: 'filesChecksum',
    label: 'Files Checksum',
    description: 'SHA-256 checksum of the algorithm files.',
    range: 'xsd:string'
  },
  containerSectionChecksum: {
    name: 'containerSectionChecksum',
    label: 'Container Section Checksum',
    description: 'SHA-256 checksum of the algorithm container section.',
    range: 'xsd:string'
  },

  // ── Credentials object fields ────────────────────────────────────────
  allow: {
    name: 'allow',
    label: 'Allow',
    description: 'Allow list of credential/address policies.',
    range: 'oec:CredentialRule'
  },
  deny: {
    name: 'deny',
    label: 'Deny',
    description: 'Deny list of credential/address policies.',
    range: 'oec:CredentialRule'
  },
  matchDeny: {
    name: 'matchDeny',
    label: 'Match Deny',
    description: 'How allow/deny matches are combined ("any" | "all").',
    range: 'xsd:string'
  },
  type: {
    name: 'type',
    label: 'Type',
    description: 'Type discriminator for a policy or parameter entry.',
    range: 'xsd:string'
  },
  values: {
    name: 'values',
    label: 'Values',
    description: 'Values carried by this policy entry.',
    range: 'xsd:string'
  },
  requestCredentials: {
    name: 'requestCredentials',
    label: 'Request Credentials',
    description: 'Credentials the consumer must present.',
    range: 'oec:RequestCredential'
  },
  format: {
    name: 'format',
    label: 'Format',
    description: 'Credential format (e.g. jwt_vc_json).',
    range: 'xsd:string'
  },
  policies: {
    name: 'policies',
    label: 'Policies',
    description: 'Credential policies (arrays or JSON-encoded strings).',
    range: 'xsd:string'
  },
  vcPolicies: {
    name: 'vcPolicies',
    label: 'VC Policies',
    description: 'Policies applied to the Verifiable Credential.',
    range: 'xsd:string'
  },
  vpPolicies: {
    name: 'vpPolicies',
    label: 'VP Policies',
    description: 'Policies applied to the Verifiable Presentation.',
    range: 'xsd:string'
  },

  // ── ConsumerParameter object fields ──────────────────────────────────
  label: {
    name: 'label',
    label: 'Label',
    description: 'Human-readable label for the parameter.',
    range: 'xsd:string'
  },
  description: {
    name: 'description',
    label: 'Description',
    description: 'Human-readable description.',
    range: 'xsd:string'
  },
  default: {
    name: 'default',
    label: 'Default',
    description: 'Default value for the parameter.',
    range: 'xsd:string'
  },
  required: {
    name: 'required',
    label: 'Required',
    description: 'Whether the consumer must supply the parameter.',
    range: 'xsd:boolean'
  },
  options: {
    name: 'options',
    label: 'Options',
    description: 'Selectable options for a `select`-type parameter.',
    range: 'xsd:string'
  },

  // ── NFT object fields ────────────────────────────────────────────────
  owner: {
    name: 'owner',
    label: 'Owner',
    description: 'Blockchain address of the current owner.',
    range: 'xsd:string'
  },
  tokenURI: {
    name: 'tokenURI',
    label: 'Token URI',
    description: 'URI of the token metadata (image, description).',
    range: 'xsd:string'
  },

  // ── Event object fields ──────────────────────────────────────────────
  block: {
    name: 'block',
    label: 'Block',
    description: 'Block number of the event.',
    range: 'xsd:integer'
  },
  contract: {
    name: 'contract',
    label: 'Contract',
    description: 'Contract address that emitted the event.',
    range: 'xsd:string'
  },
  datetime: {
    name: 'datetime',
    label: 'Datetime',
    description: 'Timestamp of the event.',
    range: 'xsd:dateTime'
  },
  from: {
    name: 'from',
    label: 'From',
    description: 'Address that initiated the event.',
    range: 'xsd:string'
  },
  tx: {
    name: 'tx',
    label: 'Transaction',
    description: 'Transaction hash of the event.',
    range: 'xsd:string'
  },

  // ── Stats object fields ──────────────────────────────────────────────
  allocated: {
    name: 'allocated',
    label: 'Allocated',
    description: 'Total number of allocated orders.',
    range: 'xsd:integer'
  },
  orders: {
    name: 'orders',
    label: 'Orders',
    description: 'Total number of orders.',
    range: 'xsd:integer'
  },
  price: {
    name: 'price',
    label: 'Price',
    description: 'Price information for the asset.',
    range: 'oec:Price'
  },
  tokenAddress: {
    name: 'tokenAddress',
    label: 'Token Address',
    description: 'Address of the payment token.',
    range: 'xsd:string'
  },
  tokenSymbol: {
    name: 'tokenSymbol',
    label: 'Token Symbol',
    description: 'Symbol of the payment token (e.g. EURC).',
    range: 'xsd:string'
  },
  value: {
    name: 'value',
    label: 'Value',
    description: 'Numeric or string value.',
    range: 'xsd:string'
  },

  // ── Access details fields ────────────────────────────────────────────
  addressOrId: {
    name: 'addressOrId',
    label: 'Address or ID',
    description: 'Address or identifier used to look up the price.',
    range: 'xsd:string'
  },
  isOwned: {
    name: 'isOwned',
    label: 'Is Owned',
    description: 'Whether the caller already owns the asset.',
    range: 'xsd:boolean'
  },
  isPurchasable: {
    name: 'isPurchasable',
    label: 'Is Purchasable',
    description: 'Whether the asset is currently purchasable.',
    range: 'xsd:boolean'
  },
  publisherMarketOrderFee: {
    name: 'publisherMarketOrderFee',
    label: 'Publisher Market Order Fee',
    description: 'Fee charged by the publisher per order.',
    range: 'xsd:string'
  },
  templateId: {
    name: 'templateId',
    label: 'Template ID',
    description: 'ID of the datatoken template used.',
    range: 'xsd:integer'
  },
  validOrderTx: {
    name: 'validOrderTx',
    label: 'Valid Order Transaction',
    description: 'Transaction hash of a valid order, if any.',
    range: 'xsd:string'
  },
  paymentCollector: {
    name: 'paymentCollector',
    label: 'Payment Collector',
    description: 'Address that collects payments for this asset.',
    range: 'xsd:string'
  },
  baseToken: {
    name: 'baseToken',
    label: 'Base Token',
    description: 'Base token used to price the asset.',
    range: 'oec:Token'
  },
  datatoken: {
    name: 'datatoken',
    label: 'Datatoken',
    description: 'Datatoken granting access to the asset.',
    range: 'oec:Token'
  },

  // ── Algorithm container fields ───────────────────────────────────────
  language: {
    name: 'language',
    label: 'Language',
    description: 'Programming language of the algorithm (e.g. py, js).',
    range: 'xsd:string'
  },
  version: {
    name: 'version',
    label: 'Version',
    description: 'Version of the algorithm or container.',
    range: 'xsd:string'
  },
  container: {
    name: 'container',
    label: 'Container',
    description: 'Container information for the algorithm.',
    range: 'oec:AlgorithmContainer'
  },
  entrypoint: {
    name: 'entrypoint',
    label: 'Entrypoint',
    description: 'Container entrypoint command.',
    range: 'xsd:string'
  },
  image: {
    name: 'image',
    label: 'Image',
    description: 'Container image name.',
    range: 'xsd:string'
  },
  tag: {
    name: 'tag',
    label: 'Tag',
    description: 'Container image tag.',
    range: 'xsd:string'
  },
  checksum: {
    name: 'checksum',
    label: 'Checksum',
    description: 'Container checksum.',
    range: 'xsd:string'
  }
}

export const OE_OBJECT_SHAPES = {
  Datatoken: ['address', 'name', 'symbol', 'serviceId', 'decimals'],
  ConsumerParameter: [
    'name',
    'label',
    'description',
    'type',
    'default',
    'required',
    'options'
  ],
  CredentialRule: ['type', 'values', 'requestCredentials', 'vcPolicies', 'vpPolicies'],
  RequestCredential: ['format', 'policies', 'type'],
  Compute: [
    'allowNetworkAccess',
    'allowRawAlgorithm',
    'publisherTrustedAlgorithms',
    'publisherTrustedAlgorithmPublishers'
  ],
  TrustedAlgorithm: ['did', 'filesChecksum', 'containerSectionChecksum', 'serviceId'],
  NFT: ['name', 'symbol', 'address', 'owner', 'state', 'tokenURI'],
  Event: ['block', 'contract', 'datetime', 'from', 'tx'],
  Price: ['tokenAddress', 'tokenSymbol', 'value'],
  AccessDetails: [
    'type',
    'addressOrId',
    'isOwned',
    'isPurchasable',
    'price',
    'publisherMarketOrderFee',
    'templateId',
    'validOrderTx',
    'paymentCollector'
  ],
  Token: ['name', 'address', 'symbol', 'decimals'],
  Algorithm: ['language', 'version', 'container'],
  AlgorithmContainer: ['entrypoint', 'image', 'tag', 'checksum']
} as const

export function oecVocabularyToRdf(
  baseUri = 'https://oceanenterprise.io/vocab/'
): string {
  const lines: string[] = []
  lines.push('@prefix oec: <' + baseUri + '> .')
  lines.push('@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .')
  lines.push('@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .')
  lines.push('@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .')
  lines.push('')
  for (const term of Object.values(OE_VOCABULARY)) {
    lines.push(`oec:${term.name} a rdf:Property ;`)
    lines.push(`  rdfs:label "${term.label}" ;`)
    lines.push(`  rdfs:comment "${term.description}"${term.range ? ' ;' : ' .'}`)
    if (term.range) {
      lines.push(`  rdfs:range ${term.range} .`)
    }
    lines.push('')
  }
  return lines.join('\n')
}

export function oecVocabularyToContext(
  baseUri = 'https://oceanenterprise.io/vocab/'
): Record<string, unknown> {
  const context: Record<string, unknown> = { oec: baseUri }
  for (const term of Object.values(OE_VOCABULARY)) {
    context[term.name] = `oec:${term.name}`
  }
  return context
}
