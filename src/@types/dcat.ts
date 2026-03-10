// @types/dcat.ts
export interface DCATContext {
  '@context': {
    dcat: string
    dct: string
    foaf: string
    geo: string
    oc: string
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
  'oc:allowNetworkAccess': boolean
  'oc:allowRawAlgorithm': boolean
  'oc:publisherTrustedAlgorithms'?: Array<{
    'oc:did': string
    'oc:filesChecksum': string
    'oc:containerSectionChecksum': string
    'oc:serviceId'?: string
  }>
  'oc:publisherTrustedAlgorithmPublishers'?: string[]
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
  'oc:compute'?: DCATCompute
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
  'oc:block'?: number
  'oc:contract'?: string
  'oc:datetime'?: string
  'oc:from'?: string
  'oc:tx'?: string
}

export interface DCATNFT {
  'dct:title'?: string
  'dct:issued'?: {
    '@type': 'xsd:dateTime'
    '@value': string
  }
  'oc:address'?: string
  'oc:owner'?: string
  'oc:state'?: number
  'oc:symbol'?: string
  'oc:tokenURI'?: string
}

export interface DCATStats {
  'oc:allocated'?: number
  'oc:orders'?: number
  'oc:price'?: {
    'oc:tokenAddress': string
    'oc:tokenSymbol': string
    'oc:value': string
  }
}

export interface DCATAccessDetails {
  '@type': 'oc:Fixed'
  'oc:addressOrId'?: string
  'oc:baseToken'?: {
    'dct:title'?: string
    'oc:address'?: string
    'oc:decimals'?: number
    'oc:symbol'?: string
  }
  'oc:datatoken'?: {
    'dct:title'?: string
    'oc:address'?: string
    'oc:symbol'?: string
    'oc:decimals'?: number
  }
  'oc:isOwned'?: boolean
  'oc:isPurchasable'?: boolean
  'oc:price'?: string
  'oc:publisherMarketOrderFee'?: string
  'oc:templateId'?: number
  'oc:validOrderTx'?: string
  'oc:paymentCollector'?: string
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
  'oc:accessDetails'?: DCATAccessDetails
  'oc:chainId'?: number
  'oc:datatokens'?: any[]
  'oc:event'?: DCATEvent
  'oc:nft'?: DCATNFT
  'oc:nftAddress'?: string
  'oc:purgatory'?: {
    'oc:state': boolean
  }
  'oc:services'?: any[]
  'oc:stats'?: DCATStats
}
