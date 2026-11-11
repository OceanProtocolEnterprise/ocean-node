export type ChecksumAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'

export interface DCATContext {
  '@context': {
    '@vocab'?: string
    dcat: string
    dct: string
    foaf: string
    geo: string
    oec: string
    prov: string
    rdfs: string
    skos: string
    spdx: string
    vcard: string
    xsd: string
  }
}

export interface DCATThemeConcept {
  '@id': string
  '@type': 'skos:Concept'
  'skos:prefLabel': {
    '@language': string
    '@value': string
  }
}

export interface DCATSpatial {
  '@type': string[]
  'dcat:bbox'?: {
    '@type': 'geo:wktLiteral'
    '@value': string
  }
  'dcat:centroid'?: {
    '@type': 'geo:wktLiteral'
    '@value': string
  }
  'skos:prefLabel'?: string
}

export interface DCATTemporal {
  '@type': 'dct:PeriodOfTime'
  'dcat:startDate'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'dcat:endDate'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
}

export interface DCATCompute {
  'oec:allowNetworkAccess': boolean
  'oec:allowRawAlgorithm': boolean
  'oec:publisherTrustedAlgorithms'?: Array<{
    'oec:did': string
    'oec:filesChecksum': string
    'oec:containerSectionChecksum': string
    'oec:serviceId'?: string
  }>
  'oec:publisherTrustedAlgorithmPublishers'?: string[]
}

export interface DCATAgent {
  '@type': 'foaf:Agent'
  'foaf:name': string
  'foaf:mbox'?: string
  'foaf:homepage'?: string
}

export interface DCATContactPoint {
  '@type': 'vcard:Kind'
  'vcard:fn': string
}

export interface DCATRightsStatement {
  '@id': string
  '@type': 'dct:RightsStatement'
}

export interface DCATLanguage {
  '@id': string
  '@type': 'dct:LinguisticSystem'
}

export interface DCATMediaType {
  '@id': string
  '@type': 'dct:MediaType'
}

export interface DCATResource {
  '@id': string
  '@type': 'rdfs:Resource'
}

export interface DCATChecksumAlgorithm {
  '@id': string
  '@type': 'spdx:ChecksumAlgorithm'
}

export interface DCATChecksum {
  '@type': 'spdx:Checksum'
  'spdx:algorithm': DCATChecksumAlgorithm
  'spdx:checksumValue': {
    '@type': 'xsd:hexBinary'
    '@value': string
  }
}

export interface DCATDocument {
  '@id': string
  '@type': 'foaf:Document'
}

export interface DCATDistribution {
  '@type': 'dcat:Distribution'
  'dcat:accessURL'?: DCATResource
  'dcat:downloadURL'?: DCATResource
  'dct:title'?: string
  'dct:description'?: string
  'dcat:mediaType'?: DCATMediaType
  'dcat:format'?: string
  'dcat:byteSize'?: number
  'dcat:checksum'?: DCATChecksum
  'dcat:landingPage'?: DCATDocument[]
  'oec:compute'?: DCATCompute
}

export interface DCATQualifiedAttribution {
  '@type': 'prov:Attribution'
  'prov:agent': DCATAgent
  'prov:hadRole': {
    '@id': string
    '@type': 'dct:AgentRole'
  }
}

export interface DCATEvent {
  'oec:block'?: number
  'oec:contract'?: string
  'oec:datetime'?: string
  'oec:from'?: string
  'oec:tx'?: string
}

export interface DCATNFT {
  'dct:title'?: string
  'dct:issued'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'oec:address'?: string
  'oec:owner'?: string
  'oec:state'?: number
  'oec:symbol'?: string
  'oec:tokenURI'?: string
}

export interface DCATStats {
  'oec:allocated'?: number
  'oec:orders'?: number
  'oec:price'?: {
    'oec:tokenAddress': string
    'oec:tokenSymbol': string
    'oec:value': string
  }
}

export interface DCATDatatoken {
  'oec:address'?: string
  'oec:name'?: string
  'oec:symbol'?: string
  'oec:serviceId'?: string
  'oec:decimals'?: number
}

export interface DCATAlgorithmContainer {
  'oec:entrypoint': string
  'oec:image': string
  'oec:tag': string
  'oec:checksum': string
}

export interface DCATAlgorithm {
  'oec:language': string
  'oec:version': string
  'oec:container': DCATAlgorithmContainer
}

export interface DCATAdditionalDdo {
  'oec:data'?: string
  'oec:type'?: string
  data?: string
  type?: string
}

export interface DCATService {
  '@type': 'dcat:DataService'
  '@id'?: string
  'dct:identifier'?: string
  'dct:title'?: string
  'dct:description'?: string
  'dcat:endpointURL'?: DCATResource
  'dcat:servesDataset'?: { '@id': string }
  'oec:serviceType'?: string
  'oec:datatokenAddress'?: string
  'oec:files'?: string
  'oec:timeout'?: number
  'oec:state'?: number
  'oec:compute'?: Record<string, unknown>
  'oec:consumerParameters'?: Array<Record<string, unknown>>
  'oec:credentials'?: Record<string, unknown>
}

export interface DCATAccessDetails {
  '@type': string
  'oec:addressOrId'?: string
  'oec:baseToken'?: {
    'dct:title'?: string
    'oec:address'?: string
    'oec:decimals'?: number
    'oec:symbol'?: string
  }
  'oec:datatoken'?: {
    'dct:title'?: string
    'oec:address'?: string
    'oec:symbol'?: string
    'oec:decimals'?: number
  }
  'oec:isOwned'?: boolean
  'oec:isPurchasable'?: boolean
  'oec:price'?: string
  'oec:publisherMarketOrderFee'?: string
  'oec:templateId'?: number
  'oec:validOrderTx'?: string
  'oec:paymentCollector'?: string
}

export interface DCATDataset {
  '@context': DCATContext['@context']
  '@id': string
  '@type': 'dcat:Dataset'
  'dct:title': string
  'dct:description'?: string
  'dcat:keyword'?: string[]
  'dcat:theme'?: DCATThemeConcept[]
  'dcat:version'?: string
  'dcat:distribution'?: DCATDistribution[]
  //   'dcat:service'?: DCATService[]
  'dcat:bbox'?: {
    '@type': 'geo:wktLiteral'
    '@value': string
  }
  'dcat:centroid'?: {
    '@type': 'geo:wktLiteral'
    '@value': string
  }
  'dcat:spatialResolutionInMeters'?: number
  'dcat:temporalResolution'?: string
  'dcat:landingPage'?: DCATDocument
  'dcat:contactPoint'?: DCATContactPoint
  'dct:creator'?: DCATAgent
  'dct:publisher'?: DCATAgent
  'dct:issued'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'dct:modified'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'dct:license'?: DCATRightsStatement
  'dct:spatial'?: DCATSpatial
  'dct:temporal'?: DCATTemporal
  'dct:accrualPeriodicity'?: {
    '@type': 'dct:Frequency'
    '@id': string
  }
  'dct:identifier'?: string[]
  'dct:language'?: DCATLanguage[]
  'dct:conformsTo'?: string[]
  'oec:issuer'?: string
  'dct:rights'?: DCATRightsStatement
  'dct:accessRights'?: DCATRightsStatement
  'dct:type'?: string
  'prov:qualifiedAttribution'?: DCATQualifiedAttribution[]
  'oec:accessDetails'?: DCATAccessDetails
  'oec:algorithm'?: DCATAlgorithm
  'oec:additionalDdos'?: DCATAdditionalDdo[]
  'oec:chainId'?: number
  'oec:datatokens'?: DCATDatatoken[]
  'oec:event'?: DCATEvent
  'oec:nft'?: DCATNFT
  'oec:nftAddress'?: string
  'oec:purgatory'?: {
    'oec:state': boolean
  }
  'oec:services'?: DCATService[]
  'oec:stats'?: DCATStats | Array<Record<string, unknown>>
}
