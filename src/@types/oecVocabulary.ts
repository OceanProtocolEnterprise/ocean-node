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
 *      appropriate list in OE_OBJECT_SHAPES.
 *   4. If its range is a new `oec:<Class>`, declare that class in OE_CLASSES.
 *   5. Bump OE_VOCABULARY_INFO.version / modified and regenerate the published
 *      files with `npm run vocab:build`.
 *
 * The vocabulary is published at https://oceanenterprise.io/vocab/ as
 * index.html (docs), vocab.ttl (Turtle), vocab.jsonld (JSON-LD) and
 * context.jsonld (JSON-LD context), all generated from this file.
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
  data: {
    name: 'data',
    label: 'Data',
    description: 'Free-form data attached to an additional DDO entry.',
    range: 'xsd:string'
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
    description: 'Values carried by this policy entry.'
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
    description: 'Selectable options for a `select`-type parameter.'
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
  AlgorithmContainer: ['entrypoint', 'image', 'tag', 'checksum'],
  AdditionalDdo: ['data', 'type']
} as const

export type OECClass = {
  name: string
  label: string
  description: string
}

export const OE_CLASSES: Record<string, OECClass> = {
  Datatoken: {
    name: 'Datatoken',
    label: 'Datatoken',
    description: 'ERC-20 access token granting access to one service of an asset.'
  },
  Token: {
    name: 'Token',
    label: 'Token',
    description: 'ERC-20 token (base token or datatoken) used in pricing.'
  },
  Algorithm: {
    name: 'Algorithm',
    label: 'Algorithm',
    description: 'Language, version and container metadata of an algorithm asset.'
  },
  AlgorithmContainer: {
    name: 'AlgorithmContainer',
    label: 'Algorithm Container',
    description:
      'Docker container (image, tag, entrypoint, checksum) that runs an algorithm.'
  },
  Compute: {
    name: 'Compute',
    label: 'Compute Configuration',
    description:
      'Compute-to-Data policy of a compute service: trusted algorithms and network access.'
  },
  TrustedAlgorithm: {
    name: 'TrustedAlgorithm',
    label: 'Trusted Algorithm',
    description: 'Algorithm the publisher has approved to run on a compute service.'
  },
  ConsumerParameter: {
    name: 'ConsumerParameter',
    label: 'Consumer Parameter',
    description: 'Input the consumer supplies when ordering a service.'
  },
  Credentials: {
    name: 'Credentials',
    label: 'Credentials',
    description: 'Allow and deny lists that control who may access an asset or service.'
  },
  CredentialRule: {
    name: 'CredentialRule',
    label: 'Credential Rule',
    description: 'One allow or deny entry: an address list or an SSI policy.'
  },
  RequestCredential: {
    name: 'RequestCredential',
    label: 'Request Credential',
    description:
      'Verifiable Credential (type, format, policies) the consumer must present.'
  },
  NFT: {
    name: 'NFT',
    label: 'Data NFT',
    description: 'ERC-721 data NFT that represents ownership of the asset on-chain.'
  },
  Event: {
    name: 'Event',
    label: 'Blockchain Event',
    description: 'On-chain event that created or last updated the asset metadata.'
  },
  Stats: {
    name: 'Stats',
    label: 'Stats',
    description: 'Order and price statistics for one service of the asset.'
  },
  Price: {
    name: 'Price',
    label: 'Price',
    description: 'Price of a service: payment token and amount.'
  },
  Purgatory: {
    name: 'Purgatory',
    label: 'Purgatory',
    description: 'Whether the asset has been flagged and placed in purgatory.'
  },
  AccessDetails: {
    name: 'AccessDetails',
    label: 'Access Details',
    description: 'Pricing and access configuration derived from the DDO.'
  },
  AdditionalDdo: {
    name: 'AdditionalDdo',
    label: 'Additional DDO',
    description: 'Extension entry attached to the DDO outside the credential subject.'
  }
}

// ── Publication metadata ─────────────────────────────────────────────────

export const OE_VOCABULARY_BASE_URI = 'https://oceanenterprise.io/vocab/'

export const OE_VOCABULARY_INFO = {
  title: 'Ocean Enterprise Vocabulary',
  description:
    'Terms used in the DCAT representation of Ocean Enterprise assets that are not covered by DCAT-AP or GeoDCAT-AP: blockchain, datatoken, compute-to-data, access-policy and pricing metadata.',
  version: '1.0.0',
  issued: '2026-10-13',
  modified: '2026-10-13',
  publisher: 'Ocean Enterprise',
  publisherUrl: 'https://oceanenterprise.io',
  license: 'https://creativecommons.org/licenses/by/4.0/',
  preferredPrefix: 'oec'
}

const STANDARD_PREFIXES: Record<string, string> = {
  rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
  rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
  owl: 'http://www.w3.org/2002/07/owl#',
  xsd: 'http://www.w3.org/2001/XMLSchema#',
  dct: 'http://purl.org/dc/terms/',
  dcat: 'http://www.w3.org/ns/dcat#',
  vann: 'http://purl.org/vocab/vann/'
}

// ── Helpers ──────────────────────────────────────────────────────────────

function turtleString(value: string): string {
  return (
    '"' +
    value
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r') +
    '"'
  )
}

function expandCurie(curie: string, baseUri: string): string {
  const index = curie.indexOf(':')
  if (index === -1) return curie
  const prefix = curie.substring(0, index)
  const local = curie.substring(index + 1)
  if (prefix === 'oec') return baseUri + local
  const namespace = STANDARD_PREFIXES[prefix]
  return namespace ? namespace + local : curie
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// ── Turtle (vocab.ttl) ───────────────────────────────────────────────────

export function oecVocabularyToRdf(baseUri = OE_VOCABULARY_BASE_URI): string {
  const info = OE_VOCABULARY_INFO
  const lines: string[] = []

  lines.push('@prefix oec: <' + baseUri + '> .')
  for (const [prefix, namespace] of Object.entries(STANDARD_PREFIXES)) {
    lines.push(`@prefix ${prefix}: <${namespace}> .`)
  }
  lines.push('')

  lines.push(`<${baseUri}> a owl:Ontology ;`)
  lines.push(`  dct:title ${turtleString(info.title)}@en ;`)
  lines.push(`  dct:description ${turtleString(info.description)}@en ;`)
  lines.push(`  owl:versionInfo ${turtleString(info.version)} ;`)
  lines.push(`  dct:issued ${turtleString(info.issued)}^^xsd:date ;`)
  lines.push(`  dct:modified ${turtleString(info.modified)}^^xsd:date ;`)
  lines.push(`  dct:publisher <${info.publisherUrl}> ;`)
  lines.push(`  dct:license <${info.license}> ;`)
  lines.push(`  vann:preferredNamespacePrefix ${turtleString(info.preferredPrefix)} ;`)
  lines.push(`  vann:preferredNamespaceUri ${turtleString(baseUri)} .`)
  lines.push('')

  lines.push('# ── Classes ──')
  lines.push('')
  for (const cls of Object.values(OE_CLASSES)) {
    lines.push(`oec:${cls.name} a rdfs:Class, owl:Class ;`)
    lines.push(`  rdfs:label ${turtleString(cls.label)}@en ;`)
    lines.push(`  rdfs:comment ${turtleString(cls.description)}@en ;`)
    lines.push(`  rdfs:isDefinedBy <${baseUri}> .`)
    lines.push('')
  }

  lines.push('# ── Properties ──')
  lines.push('')
  for (const term of Object.values(OE_VOCABULARY)) {
    lines.push(`oec:${term.name} a rdf:Property ;`)
    lines.push(`  rdfs:label ${turtleString(term.label)}@en ;`)
    lines.push(`  rdfs:comment ${turtleString(term.description)}@en ;`)
    if (term.domain) {
      lines.push(`  rdfs:domain ${term.domain} ;`)
    }
    if (term.range) {
      lines.push(`  rdfs:range ${term.range} ;`)
    }
    lines.push(`  rdfs:isDefinedBy <${baseUri}> .`)
    lines.push('')
  }

  return lines.join('\n')
}

// ── JSON-LD context (context.jsonld) ─────────────────────────────────────

export function oecVocabularyToContext(
  baseUri = OE_VOCABULARY_BASE_URI
): Record<string, unknown> {
  const context: Record<string, unknown> = { oec: baseUri }
  for (const term of Object.values(OE_VOCABULARY)) {
    context[term.name] = `oec:${term.name}`
  }
  return context
}

// ── JSON-LD vocabulary (vocab.jsonld) ────────────────────────────────────

export function oecVocabularyToJsonLd(
  baseUri = OE_VOCABULARY_BASE_URI
): Record<string, unknown> {
  const info = OE_VOCABULARY_INFO
  const en = (value: string) => ({ '@value': value, '@language': 'en' })

  const graph: Record<string, unknown>[] = [
    {
      '@id': baseUri,
      '@type': 'owl:Ontology',
      'dct:title': en(info.title),
      'dct:description': en(info.description),
      'owl:versionInfo': info.version,
      'dct:issued': { '@value': info.issued, '@type': 'xsd:date' },
      'dct:modified': { '@value': info.modified, '@type': 'xsd:date' },
      'dct:publisher': { '@id': info.publisherUrl },
      'dct:license': { '@id': info.license },
      'vann:preferredNamespacePrefix': info.preferredPrefix,
      'vann:preferredNamespaceUri': baseUri
    }
  ]

  for (const cls of Object.values(OE_CLASSES)) {
    graph.push({
      '@id': `oec:${cls.name}`,
      '@type': ['rdfs:Class', 'owl:Class'],
      'rdfs:label': en(cls.label),
      'rdfs:comment': en(cls.description),
      'rdfs:isDefinedBy': { '@id': baseUri }
    })
  }

  for (const term of Object.values(OE_VOCABULARY)) {
    const node: Record<string, unknown> = {
      '@id': `oec:${term.name}`,
      '@type': 'rdf:Property',
      'rdfs:label': en(term.label),
      'rdfs:comment': en(term.description),
      'rdfs:isDefinedBy': { '@id': baseUri }
    }
    if (term.domain) node['rdfs:domain'] = { '@id': term.domain }
    if (term.range) node['rdfs:range'] = { '@id': term.range }
    graph.push(node)
  }

  return {
    '@context': { oec: baseUri, ...STANDARD_PREFIXES },
    '@graph': graph
  }
}

// ── HTML documentation (index.html) ──────────────────────────────────────

export function oecVocabularyToHtml(baseUri = OE_VOCABULARY_BASE_URI): string {
  const info = OE_VOCABULARY_INFO

  const usedIn = new Map<string, string[]>()
  for (const [className, properties] of Object.entries(OE_OBJECT_SHAPES)) {
    for (const property of properties) {
      const list = usedIn.get(property) || []
      list.push(className)
      usedIn.set(property, list)
    }
  }

  const rangeHtml = (range?: string): string => {
    if (!range) return '<span class="muted">any</span>'
    if (range.startsWith('oec:')) {
      const local = range.substring(4)
      return `<a href="#${local}"><code>${escapeHtml(range)}</code></a>`
    }
    return `<a href="${escapeHtml(expandCurie(range, baseUri))}"><code>${escapeHtml(range)}</code></a>`
  }

  const classRows = Object.values(OE_CLASSES)
    .map((cls) => {
      const shape = (OE_OBJECT_SHAPES as Record<string, readonly string[]>)[cls.name]
      const props = shape
        ? shape.map((p) => `<a href="#${p}"><code>oec:${p}</code></a>`).join(', ')
        : '<span class="muted">—</span>'
      return `      <section class="term" id="${cls.name}">
        <h3><a href="#${cls.name}">oec:${cls.name}</a> <span class="kind">Class</span></h3>
        <p class="label">${escapeHtml(cls.label)}</p>
        <p>${escapeHtml(cls.description)}</p>
        <dl>
          <dt>IRI</dt><dd><code>${escapeHtml(baseUri + cls.name)}</code></dd>
          <dt>Properties</dt><dd>${props}</dd>
        </dl>
      </section>`
    })
    .join('\n')

  const propertyRows = Object.values(OE_VOCABULARY)
    .map((term) => {
      const classes = usedIn.get(term.name)
      const usedInHtml = classes
        ? classes.map((c) => `<a href="#${c}"><code>oec:${c}</code></a>`).join(', ')
        : '<code>dcat:Dataset</code> / <code>dcat:DataService</code>'
      return `      <section class="term" id="${term.name}">
        <h3><a href="#${term.name}">oec:${term.name}</a> <span class="kind">Property</span></h3>
        <p class="label">${escapeHtml(term.label)}</p>
        <p>${escapeHtml(term.description)}</p>
        <dl>
          <dt>IRI</dt><dd><code>${escapeHtml(baseUri + term.name)}</code></dd>
          <dt>Range</dt><dd>${rangeHtml(term.range)}</dd>
          <dt>Used in</dt><dd>${usedInHtml}</dd>
        </dl>
      </section>`
    })
    .join('\n')

  const classIndex = Object.values(OE_CLASSES)
    .map((cls) => `<a href="#${cls.name}">${cls.name}</a>`)
    .join(' · ')
  const propertyIndex = Object.values(OE_VOCABULARY)
    .map((term) => `<a href="#${term.name}">${term.name}</a>`)
    .join(' · ')

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(info.title)}</title>
  <link rel="alternate" type="text/turtle" href="vocab.ttl">
  <link rel="alternate" type="application/ld+json" href="vocab.jsonld">
  <style>
    :root { --bg: #ffffff; --fg: #1a1f2b; --muted: #5b6475; --line: #e3e7ee; --accent: #0b5cad; --code: #f3f5f9; }
    @media (prefers-color-scheme: dark) {
      :root { --bg: #0f131a; --fg: #e6e9ef; --muted: #9aa3b2; --line: #263040; --accent: #6fb1ff; --code: #1a212c; }
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
    main { max-width: 900px; margin: 0 auto; padding: 32px 16px 64px; }
    h1 { font-size: 2rem; margin: 0 0 8px; }
    h2 { margin-top: 48px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
    h3 { margin: 0 0 4px; font-size: 1.1rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code, pre { background: var(--code); border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
    code { padding: 1px 5px; overflow-wrap: anywhere; }
    pre { padding: 12px 14px; overflow-x: auto; }
    .muted, .label { color: var(--muted); }
    .label { margin: 0 0 6px; }
    .kind { font-size: 0.75rem; font-weight: 500; color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 1px 8px; margin-left: 6px; vertical-align: middle; }
    .meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 20px 0; }
    .meta dt { color: var(--muted); }
    .meta dd { margin: 0; }
    .index { line-height: 1.9; }
    .term { padding: 18px 0; border-bottom: 1px solid var(--line); scroll-margin-top: 16px; }
    .term:target { background: var(--code); margin: 0 -12px; padding: 18px 12px; border-radius: 6px; }
    .term dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 8px 0 0; font-size: 0.92rem; }
    .term dt { color: var(--muted); }
    .term dd { margin: 0; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(info.title)}</h1>
    <p>${escapeHtml(info.description)}</p>
    <dl class="meta">
      <dt>Namespace</dt><dd><code>${escapeHtml(baseUri)}</code></dd>
      <dt>Preferred prefix</dt><dd><code>${info.preferredPrefix}</code></dd>
      <dt>Version</dt><dd>${escapeHtml(info.version)}</dd>
      <dt>Issued</dt><dd>${escapeHtml(info.issued)}</dd>
      <dt>Last modified</dt><dd>${escapeHtml(info.modified)}</dd>
      <dt>Publisher</dt><dd><a href="${escapeHtml(info.publisherUrl)}">${escapeHtml(info.publisher)}</a></dd>
      <dt>License</dt><dd><a href="${escapeHtml(info.license)}">CC BY 4.0</a></dd>
      <dt>Downloads</dt><dd><a href="vocab.ttl">Turtle</a> · <a href="vocab.jsonld">JSON-LD</a> · <a href="context.jsonld">JSON-LD context</a></dd>
    </dl>

    <h2>Usage</h2>
    <p>Ocean Enterprise nodes publish asset metadata as DCAT-AP / GeoDCAT-AP JSON-LD at
      <code>/api/aquarius/assets/dcat/&lt;did&gt;</code>. Standard DCAT terms are used wherever they exist;
      this vocabulary covers the remaining Ocean Enterprise specific fields. Declare the prefix in your
      JSON-LD context:</p>
<pre>{
  "@context": {
    "oec": "${escapeHtml(baseUri)}"
  }
}</pre>

    <h2>Classes</h2>
    <p class="index">${classIndex}</p>
${classRows}

    <h2>Properties</h2>
    <p class="index">${propertyIndex}</p>
${propertyRows}
  </main>
</body>
</html>
`
}
