// @types/dcat.ts
export interface DCATContext {
  '@context': {
    dcat: string
    dct: string
    foaf: string
    geo: string
    oec: string
    prov: string
    rdfs: string
    skos: string
    spdx: string
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
  '@type': ['dct:Location', 'skos:Concept']
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

export interface DCATDistribution {
  '@type': 'dcat:Distribution'
  'dcat:accessURL': {
    '@id': string
  }
  'dct:title'?: string
  'dcat:mediaType'?: string
  'dcat:format'?: string
  'dcat:byteSize'?: number
  'dcat:checksum'?: {
    '@type': 'spdx:Checksum'
    'spdx:algorithm': string
    'spdx:checksumValue': string
  }
  'oec:compute'?: DCATCompute
}

export interface DCATQualifiedAttribution {
  '@type': 'prov:Attribution'
  'prov:agent': {
    '@type': 'foaf:Agent'
    'foaf:name': string
    'foaf:mbox'?: string
    'foaf:homepage'?: string
  }
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

export interface DCATAccessDetails {
  '@type': 'oec:Fixed'
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
  'dcat:keyword'?: string[]
  'dcat:theme'?: DCATThemeConcept[]
  'dcat:version'?: string
  'dcat:distribution'?: DCATDistribution[]
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
  'dct:creator'?: {
    '@type': 'foaf:Agent'
    'foaf:name': string
    'foaf:mbox'?: string
    'foaf:homepage'?: string
  }
  'dct:description'?: string
  'dct:issued'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'dct:license'?: string
  'dct:modified'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'dct:spatial'?: DCATSpatial
  'dct:temporal'?: DCATTemporal
  'dct:accrualPeriodicity'?: {
    '@type': 'dct:Frequency'
    '@id': string
  }
  'dct:title'?: string
  'dct:identifier'?: string[]
  'dct:language'?: string[]
  'dct:conformsTo'?: string[]
  'dct:rights'?: string
  'dct:accessRights'?: string
  'prov:qualifiedAttribution'?: DCATQualifiedAttribution[]
  'oec:accessDetails'?: DCATAccessDetails
  'oec:chainId'?: number
  'oec:datatokens'?: any[]
  'oec:event'?: DCATEvent
  'oec:nft'?: DCATNFT
  'oec:nftAddress'?: string
  'oec:purgatory'?: {
    'oec:state': boolean
  }
  'oec:services'?: any[]
  'oec:stats'?: DCATStats
}
