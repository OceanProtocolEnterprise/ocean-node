// @types/dcat.ts
export interface DCATContext {
  '@context': {
    dcat: string
    dct: string
    foaf: string
    geo: string
    oc: string
    rdfs: string
    skos: string
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
  'skos:prefLabel'?: string
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
  }
  'oc:isOwned'?: boolean
  'oc:isPurchasable'?: boolean
  'oc:price'?: string
  'oc:publisherMarketOrderFee'?: string
  'oc:templateId'?: number
  'oc:validOrderTx'?: string
}

export interface DCATDataset {
  '@context': DCATContext['@context']
  '@id': string
  '@type': 'dcat:Dataset'
  'dcat:keyword'?: string[]
  'dcat:theme'?: DCATThemeConcept[]
  'dcat:version'?: string
  'dct:creator'?: {
    '@type': 'foaf:Agent'
    'foaf:name': string
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
  'dct:title'?: string
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
