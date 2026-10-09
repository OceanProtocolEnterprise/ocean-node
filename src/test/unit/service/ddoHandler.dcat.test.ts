import { expect } from 'chai'
import { FindDdoHandler } from '../../../components/core/handler/ddoHandler.js'
import { DCATDataset } from '../../../@types/dcat.js'
import {
  simpleDatasetDdo,
  computeDatasetDdo,
  algorithmAssetDdo,
  multiServiceDatasetDdo,
  geospatialDatasetDdo
} from '../../data/dcatFixtures.js'

// The asset DID is read from credentialSubject.id first, then the root id
const expectedDid = (ddo: any): string => ddo?.credentialSubject?.id || ddo.id
const clone = (ddo: any): any => JSON.parse(JSON.stringify(ddo))

describe('********** FindDdoHandler DCAT transformation Unit Tests', () => {
  let handler: any

  before(() => {
    handler = Object.create(FindDdoHandler.prototype)
  })

  describe('transformToDCAT - basic structure', () => {
    let dcat: DCATDataset

    before(async () => {
      dcat = await handler.transformToDCAT(simpleDatasetDdo)
    })

    it('sets @type to dcat:Dataset', () => {
      expect(dcat['@type']).to.equal('dcat:Dataset')
    })

    it('uses the asset DID directly as @id (no urn: prefix, no /VC/ suffix)', () => {
      expect(dcat['@id']).to.equal(expectedDid(simpleDatasetDdo))
      expect(dcat['@id']).to.not.match(/^urn:/)
      expect(dcat['@id']).to.not.contain('/VC/')
    })

    it('uses the asset DID as dct:identifier', () => {
      expect(dcat['dct:identifier']).to.deep.equal([expectedDid(simpleDatasetDdo)])
    })

    it('sets dct:title from metadata.name', () => {
      expect(dcat['dct:title']).to.equal('Simple Dataset')
    })

    it('sets dct:description from metadata.description.@value', () => {
      expect(dcat['dct:description']).to.equal('A simple access-only dataset')
    })

    it('sets dcat:keyword from metadata.tags', () => {
      expect(dcat['dcat:keyword']).to.deep.equal(['simple', 'dataset'])
    })

    it('does not fabricate dcat:theme from tags', () => {
      expect(dcat['dcat:theme']).to.equal(undefined)
    })

    it('sets dct:creator from metadata.author', () => {
      expect(dcat['dct:creator']).to.deep.equal({
        '@type': 'foaf:Agent',
        'foaf:name': 'Alice'
      })
    })

    it('sets dct:publisher from metadata.providedBy', () => {
      expect(dcat['dct:publisher']).to.deep.equal({
        '@type': 'foaf:Agent',
        'foaf:name': 'did:web:example.com'
      })
    })

    it('sets dcat:contactPoint as vcard:Kind', () => {
      expect(dcat['dcat:contactPoint']).to.deep.equal({
        '@type': 'vcard:Kind',
        'vcard:fn': 'Example Org'
      })
    })

    it('sets dct:issued and dct:modified with xsd:dateTime type', () => {
      expect(dcat['dct:issued']).to.deep.equal({
        '@type': 'xsd:dateTime',
        '@value': '2026-01-01T10:00:00Z'
      })
      expect(dcat['dct:modified']).to.deep.equal({
        '@type': 'xsd:dateTime',
        '@value': '2026-01-01T10:00:00Z'
      })
    })

    it('does NOT derive dct:temporal from created/updated', () => {
      expect(dcat['dct:temporal']).to.equal(undefined)
    })
  })

  describe('transformToDCAT - asset DID resolution', () => {
    it('prefers credentialSubject.id over the root (VC) id', async () => {
      const ddo = clone(simpleDatasetDdo)
      const assetDid = 'did:ope:assetdid1234'
      ddo.id = `${assetDid}/VC/2026-02-18T23:26:19.800+01:00`
      ddo.credentialSubject.id = assetDid
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['@id']).to.equal(assetDid)
      expect(dcat['dct:identifier']).to.deep.equal([assetDid])
      expect(dcat['dcat:landingPage']['@id']).to.contain(assetDid)
      expect(dcat['dcat:landingPage']['@id']).to.not.contain('/VC/')
      expect(dcat['oec:services'][0]['dcat:servesDataset']['@id']).to.equal(assetDid)
    })

    it('falls back to the root id when credentialSubject.id is absent', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.id
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['@id']).to.equal(ddo.id)
    })
  })

  describe('transformToDCAT - SHACL-compliant shapes', () => {
    let dcat: DCATDataset

    before(async () => {
      dcat = await handler.transformToDCAT(simpleDatasetDdo)
    })

    it('dct:license is a dct:RightsStatement node', () => {
      expect(dcat['dct:license']).to.deep.equal({
        '@id': 'https://example.com/license.pdf',
        '@type': 'dct:RightsStatement'
      })
    })

    it('dct:rights is a dct:RightsStatement node', () => {
      expect(dcat['dct:rights']).to.deep.equal({
        '@id': 'https://example.com/license.pdf',
        '@type': 'dct:RightsStatement'
      })
    })

    it('dct:language is a dct:LinguisticSystem node', () => {
      expect(dcat['dct:language']).to.deep.equal([
        {
          '@id': 'http://publications.europa.eu/resource/authority/language/ENG',
          '@type': 'dct:LinguisticSystem'
        }
      ])
    })

    it('dct:accessRights is a dct:RightsStatement node', () => {
      expect(dcat['dct:accessRights']).to.have.property('@type', 'dct:RightsStatement')
      expect(dcat['dct:accessRights']).to.have.property('@id')
    })

    it('dcat:landingPage is a foaf:Document', () => {
      expect(dcat['dcat:landingPage']).to.have.property('@type', 'foaf:Document')
      expect(dcat['dcat:landingPage']).to.have.property('@id')
      expect(dcat['dcat:landingPage']['@id']).to.contain(expectedDid(simpleDatasetDdo))
    })

    it('does NOT emit dct:conformsTo when there is no geo metadata', () => {
      expect(dcat['dct:conformsTo']).to.equal(undefined)
    })
  })

  describe('transformToDCAT - license handling', () => {
    it('uses a non-URL license name as dct:title instead of a relative @id', async () => {
      const ddo = clone(simpleDatasetDdo)
      ddo.credentialSubject.metadata.license = { name: 'CC BY 4.0' }
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:license']).to.deep.equal({
        '@type': 'dct:RightsStatement',
        'dct:title': 'CC BY 4.0'
      })
      expect(dcat['dct:rights']).to.deep.equal({
        '@type': 'dct:RightsStatement',
        'dct:title': 'CC BY 4.0'
      })
    })

    it('takes the @id from the first licenseDocuments mirror when the name is not a URL', async () => {
      const ddo = clone(simpleDatasetDdo)
      ddo.credentialSubject.metadata.license = {
        name: 'My License',
        licenseDocuments: [
          { mirrors: [{ type: 'url', method: 'get', url: 'https://example.com/my.pdf' }] }
        ]
      }
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:license']).to.deep.equal({
        '@id': 'https://example.com/my.pdf',
        '@type': 'dct:RightsStatement',
        'dct:title': 'My License'
      })
    })
  })

  describe('transformToDCAT - mandatory / fallback fields', () => {
    it('falls back to the title when there is no description', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.metadata.description
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:description']).to.equal(dcat['dct:title'])
    })

    it('derives dct:language from description @language when metadata.language is absent', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.metadata.language
      ddo.credentialSubject.metadata.description = {
        '@value': 'Beschreibung',
        '@language': 'de'
      }
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:language']).to.deep.equal([
        {
          '@id': 'http://publications.europa.eu/resource/authority/language/DEU',
          '@type': 'dct:LinguisticSystem'
        }
      ])
    })

    it('only emits dct:temporal when provided in additionalInformation', async () => {
      const ddo = clone(simpleDatasetDdo)
      const temporal = {
        '@type': 'dct:PeriodOfTime',
        'dcat:startDate': { '@type': 'xsd:dateTime', '@value': '2020-01-01T00:00:00Z' },
        'dcat:endDate': { '@type': 'xsd:dateTime', '@value': '2020-12-31T23:59:59Z' }
      }
      ddo.credentialSubject.metadata.additionalInformation = {
        ...(ddo.credentialSubject.metadata.additionalInformation || {}),
        'dct:temporal': temporal
      }
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:temporal']).to.deep.equal(temporal)
    })
  })

  describe('transformToDCAT - agents', () => {
    it('uses the issuer DID as @id of the publisher when providedBy is absent', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.metadata.providedBy
      ddo.issuer = 'did:jwk:issuerkey'
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:publisher']).to.deep.equal({
        '@id': 'did:jwk:issuerkey',
        '@type': 'foaf:Agent',
        'foaf:name': 'did:jwk:issuerkey'
      })
      expect(dcat['oec:issuer']).to.equal('did:jwk:issuerkey')
    })

    it('uses a did:pkh identifier for the NFT owner when there is no issuer or providedBy', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.metadata.providedBy
      delete ddo.issuer
      ddo.credentialSubject.chainId = 11155111
      ddo.indexedMetadata = {
        nft: { owner: '0xabc0000000000000000000000000000000000001' }
      }
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:publisher']['@id']).to.equal(
        'did:pkh:eip155:11155111:0xabc0000000000000000000000000000000000001'
      )
      const ownerAttribution = dcat['prov:qualifiedAttribution'].find((a: any) =>
        a['prov:hadRole']['@id'].includes('owner')
      )
      expect(ownerAttribution['prov:agent']['@id']).to.equal(
        'did:pkh:eip155:11155111:0xabc0000000000000000000000000000000000001'
      )
    })
  })

  describe('transformToDCAT - distributions', () => {
    it('creates one dcat:Distribution per service', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['dcat:distribution']).to.have.lengthOf(1)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['@type']).to.equal('dcat:Distribution')
    })

    it('access service gets dcat:accessURL as rdfs:Resource and no downloadURL', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:accessURL']).to.deep.equal({
        '@id': 'https://ocean-node.example.io',
        '@type': 'rdfs:Resource'
      })
      expect(dist['dcat:downloadURL']).to.equal(undefined)
    })

    it('does not emit a guessed dcat:mediaType', async () => {
      const access = await handler.transformToDCAT(simpleDatasetDdo)
      expect(access['dcat:distribution'][0]['dcat:mediaType']).to.equal(undefined)
      const compute = await handler.transformToDCAT(computeDatasetDdo)
      expect(compute['dcat:distribution'][0]['dcat:mediaType']).to.equal(undefined)
    })

    it('links the distribution to its DataService via dcat:accessService', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      const svc = dcat['oec:services'][0]
      expect(dist['dcat:accessService']).to.deep.equal({ '@id': svc['@id'] })
    })

    it('compute service exposes oec:distributionFormat compute-service', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['oec:distributionFormat']).to.equal('compute-service')
      expect(dist['dcat:format']).to.equal(undefined)
    })

    it('access service with files exposes oec:distributionFormat encrypted', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['oec:distributionFormat']).to.equal('encrypted')
    })

    it('compute service exposes oec:compute with trusted algorithms', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['oec:compute']).to.have.property('oec:allowNetworkAccess', true)
      expect(dist['oec:compute']).to.have.property('oec:allowRawAlgorithm', false)
      expect(dist['oec:compute']['oec:publisherTrustedAlgorithms']).to.be.an('array')
      expect(
        dist['oec:compute']['oec:publisherTrustedAlgorithmPublishers']
      ).to.deep.equal(['*'])
    })

    it('does NOT fabricate a dcat:checksum from the encrypted files blob', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:checksum']).to.equal(undefined)
    })

    it('moves service.links to rdfs:seeAlso and never to dcat:landingPage', async () => {
      const ddo = clone(simpleDatasetDdo)
      ddo.credentialSubject.services[0].links = { link_1: 'https://example.com/ref' }
      const dcat = await handler.transformToDCAT(ddo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['rdfs:seeAlso']).to.deep.equal([
        { '@id': 'https://example.com/ref', '@type': 'foaf:Document' }
      ])
      expect(dist['dcat:landingPage']).to.equal(undefined)
    })

    it('multi-service asset yields one Distribution per service', async () => {
      const dcat = await handler.transformToDCAT(multiServiceDatasetDdo)
      expect(dcat['dcat:distribution']).to.have.lengthOf(2)
    })
  })

  describe('transformToDCAT - data services', () => {
    it('creates one dcat:DataService per service', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['oec:services']).to.have.lengthOf(1)
    })

    it('DataService has a stable @id of the form <did>#service-<id>', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const svc = dcat['oec:services'][0]
      const serviceId = 'a'.repeat(64)
      expect(svc['@id']).to.equal(`${expectedDid(simpleDatasetDdo)}#service-${serviceId}`)
      expect(svc['dct:identifier']).to.equal(serviceId)
    })

    it('DataService dcat:endpointURL is rdfs:Resource', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const svc = dcat['oec:services'][0]
      expect(svc['dcat:endpointURL']).to.deep.equal({
        '@id': 'https://ocean-node.example.io',
        '@type': 'rdfs:Resource'
      })
    })

    it('DataService dcat:servesDataset matches the Dataset @id', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const svc = dcat['oec:services'][0]
      expect(svc['dcat:servesDataset']).to.deep.equal({
        '@id': dcat['@id']
      })
    })

    it('DataService preserves oec:credentials, oec:consumerParameters when present', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const svc = dcat['oec:services'][0]
      expect(svc).to.have.property('oec:credentials')
      expect(svc).to.have.property('oec:consumerParameters')
    })

    it('oec:services contains the formatted DataService objects, not the raw DDO services', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['oec:services']).to.have.lengthOf(1)
      const svc = dcat['oec:services'][0]
      expect(svc['@type']).to.equal('dcat:DataService')
      expect(svc).to.have.property('dct:title', 'Access Service')
      expect(svc).to.have.property('oec:serviceType', 'access')
    })

    it('formatDatatokensForDCAT emits oec-prefixed datatoken fields', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['oec:datatokens'][0]).to.deep.equal({
        'oec:address': '0x1111111111111111111111111111111111111111',
        'oec:name': 'Access Token',
        'oec:symbol': 'OEAT',
        'oec:serviceId':
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      })
    })

    it('oec:services preserves consumerParameters with oec-prefixed fields', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const svc = dcat['oec:services'][0]
      const param = svc['oec:consumerParameters'][0]
      expect(param).to.have.property('oec:name', 'param1')
      expect(param).to.have.property('oec:label', 'Param 1')
      expect(param).to.have.property('oec:type', 'text')
      expect(param).to.have.property('oec:required', false)
    })

    it('oec:services preserves credentials with oec-prefixed fields', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const svc = dcat['oec:services'][0]
      expect(svc['oec:credentials']).to.have.property('oec:allow')
      expect(svc['oec:credentials']).to.have.property('oec:matchDeny', 'any')
    })

    it('oec:credentials allow rule carries oec:requestCredentials with camelCase normalization', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const svc = dcat['oec:services'][0]
      const firstRule = svc['oec:credentials']['oec:allow'][0]
      expect(firstRule).to.have.property('oec:type', 'SSIpolicy')
      expect(firstRule).to.have.property('oec:values')
      expect(firstRule['oec:values']).to.be.an('array')
      const firstValue = firstRule['oec:values'][0]
      expect(firstValue).to.have.property('oec:requestCredentials')
      expect(firstValue['oec:requestCredentials']).to.be.an('array')
    })

    it('oec:compute nested trusted algorithms are oec-prefixed', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const svc = dcat['oec:services'][0]
      const algo = svc['oec:compute']['oec:publisherTrustedAlgorithms'][0]
      expect(algo).to.have.property('oec:did', '*')
      expect(algo).to.have.property('oec:filesChecksum', '*')
      expect(algo).to.have.property('oec:containerSectionChecksum', '*')
      expect(algo).to.have.property('oec:serviceId', '*')
    })
  })

  describe('transformToDCAT - dataset-level credentials', () => {
    it('emits oec:credentials including vc/vp policies from the root credentials', async () => {
      const ddo = clone(simpleDatasetDdo)
      ddo.credentialSubject.credentials = {
        allow: [
          {
            type: 'SSIpolicy',
            values: [
              {
                request_credentials: [{ format: 'jwt_vc_json', type: 'gx:LegalPerson' }],
                vc_policies: ['not-before', 'signature'],
                vp_policies: [{ policy: 'holder-binding' }]
              }
            ]
          }
        ],
        deny: [],
        match_deny: 'any'
      }
      const dcat = await handler.transformToDCAT(ddo)
      const creds = dcat['oec:credentials']
      expect(creds).to.have.property('oec:matchDeny', 'any')
      const value = creds['oec:allow'][0]['oec:values'][0]
      expect(value['oec:vcPolicies']).to.deep.equal(['not-before', 'signature'])
      expect(value['oec:vpPolicies']).to.deep.equal([{ policy: 'holder-binding' }])
      expect(value['oec:requestCredentials']).to.be.an('array')
    })
  })

  describe('transformToDCAT - algorithm asset', () => {
    it('sets dct:type to algorithm', async () => {
      const dcat = await handler.transformToDCAT(algorithmAssetDdo)
      expect(dcat['dct:type']).to.equal('algorithm')
    })

    it('emits oec:algorithm with container details', async () => {
      const dcat = await handler.transformToDCAT(algorithmAssetDdo)
      expect(dcat['oec:algorithm']).to.deep.equal({
        'oec:language': 'py',
        'oec:version': '0.1',
        'oec:container': {
          'oec:entrypoint': 'python3 $ALGO',
          'oec:image': 'example/algo',
          'oec:tag': 'v1.0',
          'oec:checksum': 'sha256:abc123'
        }
      })
    })
  })

  describe('transformToDCAT - geo metadata', () => {
    it('promotes dct:spatial from additionalInformation', async () => {
      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      expect(dcat['dct:spatial']).to.deep.equal(
        geospatialDatasetDdo.credentialSubject.metadata.additionalInformation[
          'dct:spatial'
        ]
      )
    })

    it('promotes dcat:bbox and dcat:centroid from dct:spatial', async () => {
      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      expect(dcat['dcat:bbox']).to.deep.equal({
        '@type': 'geo:wktLiteral',
        '@value': 'POLYGON((0 0, 10 0, 10 10, 0 10, 0 0))'
      })
      expect(dcat['dcat:centroid']).to.deep.equal({
        '@type': 'geo:wktLiteral',
        '@value': 'POINT(5 5)'
      })
    })

    it('promotes dcat:theme from additionalInformation (real AGROVOC URI)', async () => {
      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      expect(dcat['dcat:theme']).to.deep.equal(
        geospatialDatasetDdo.credentialSubject.metadata.additionalInformation[
          'dcat:theme'
        ]
      )
    })

    it('emits dct:conformsTo as dct:Standard nodes with INSPIRE + GeoDCAT-AP when geo metadata present', async () => {
      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      expect(dcat['dct:conformsTo']).to.deep.include({
        '@id': 'http://inspire.ec.europa.eu/schemas/inspire_vs/1.0',
        '@type': 'dct:Standard'
      })
      expect(dcat['dct:conformsTo']).to.deep.include({
        '@id': 'https://semiceu.github.io/GeoDCAT-AP/releases/3.0.0/',
        '@type': 'dct:Standard'
      })
    })

    it('does not emit duplicate dct:conformsTo entries', async () => {
      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      const ids = dcat['dct:conformsTo'].map((s: any) => s['@id'])
      expect(new Set(ids).size).to.equal(ids.length)
    })
  })

  describe('transformToDCAT - access rights derivation', () => {
    it('RESTRICTED when credentials.allow contains SSIpolicy entries', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      expect(dcat['dct:accessRights']).to.deep.equal({
        '@id': 'http://publications.europa.eu/resource/authority/access-right/RESTRICTED',
        '@type': 'dct:RightsStatement'
      })
    })

    it('accessRights is a dct:RightsStatement node when present', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['dct:accessRights']).to.have.property('@type', 'dct:RightsStatement')
      expect(dcat['dct:accessRights']).to.have.property('@id')
    })
  })

  describe('transformToDCAT - stats source preference', () => {
    it('uses credentialSubject.stats when present, without inventing values', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const source: any = (computeDatasetDdo as any).credentialSubject.stats
      const stats: any = dcat['oec:stats']
      expect(stats['oec:price']).to.deep.equal({
        'oec:tokenAddress': '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4',
        'oec:tokenSymbol': 'EURC',
        'oec:value': '2'
      })
      if (source.orders !== undefined) {
        expect(stats['oec:orders']).to.equal(source.orders)
      } else {
        expect(stats['oec:orders']).to.equal(undefined)
      }
      if (source.allocated !== undefined) {
        expect(stats['oec:allocated']).to.equal(source.allocated)
      } else {
        expect(stats['oec:allocated']).to.equal(undefined)
      }
    })

    it('falls back to indexedMetadata.stats and never emits an invented oec:allocated', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['oec:stats']).to.have.property('oec:orders', 0)
      expect(dcat['oec:stats']).to.not.have.property('oec:allocated')
    })

    it('emits one oec:price per service price, resolving the symbol from accessDetails', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.stats
      const svc = ddo.credentialSubject.services[0]
      ddo.indexedMetadata = {
        ...(ddo.indexedMetadata || {}),
        stats: [
          {
            datatokenAddress: svc.datatokenAddress,
            serviceId: svc.id,
            orders: 3,
            prices: [
              {
                type: 'fixedrate',
                price: '1.0',
                token: '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4'
              }
            ]
          },
          {
            datatokenAddress: '0x2222222222222222222222222222222222222222',
            serviceId: 'other-service',
            orders: 1,
            prices: [
              {
                type: 'fixedrate',
                price: '2.0',
                token: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'
              }
            ]
          }
        ]
      }
      ddo.accessDetails = [
        {
          type: 'fixed',
          price: '1.0',
          baseToken: {
            address: '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4',
            name: 'EURC',
            symbol: 'EURC',
            decimals: 6
          },
          datatoken: {
            address: svc.datatokenAddress,
            name: 'Access Token',
            symbol: 'OEAT'
          }
        },
        {
          type: 'fixed',
          price: '2.0',
          baseToken: {
            address: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',
            name: 'USDC',
            symbol: 'USDC',
            decimals: 6
          },
          datatoken: {
            address: '0x2222222222222222222222222222222222222222',
            name: 'Access Token',
            symbol: 'OEAT'
          }
        }
      ]
      const dcat = await handler.transformToDCAT(ddo)
      const stats: any = dcat['oec:stats']
      expect(stats['oec:orders']).to.equal(4)
      expect(stats['oec:price']).to.be.an('array').with.lengthOf(2)
      expect(stats['oec:price'][0]).to.include({
        'oec:tokenSymbol': 'EURC',
        'oec:value': '1.0',
        'oec:serviceId': svc.id
      })
      expect(stats['oec:price'][1]).to.include({
        'oec:tokenSymbol': 'USDC',
        'oec:value': '2.0'
      })
    })
  })

  describe('transformToDCAT - access details', () => {
    it('emits one oec:accessDetails entry per access detail, linked to its service', async () => {
      const ddo = clone(simpleDatasetDdo)
      const svc = ddo.credentialSubject.services[0]
      ddo.accessDetails = [
        {
          type: 'fixed',
          price: '1.0',
          addressOrId: '0xabc',
          isPurchasable: true,
          baseToken: { address: '0x01', name: 'EURC', symbol: 'EURC', decimals: 6 },
          datatoken: {
            address: svc.datatokenAddress,
            name: 'Access Token',
            symbol: 'OEAT'
          }
        },
        {
          type: 'fixed',
          price: '2.0',
          addressOrId: '0xdef',
          isPurchasable: true,
          baseToken: { address: '0x02', name: 'USDC', symbol: 'USDC', decimals: 6 },
          datatoken: { address: '0xdeadbeef', name: 'Access Token', symbol: 'OEAT' }
        }
      ]
      const dcat = await handler.transformToDCAT(ddo)
      const details: any[] = dcat['oec:accessDetails']
      expect(details).to.be.an('array').with.lengthOf(2)
      expect(details[0]).to.have.property('oec:serviceId', svc.id)
      expect(details[0]).to.have.property('oec:price', '1.0')
      expect(details[1]).to.not.have.property('oec:serviceId')
      expect(details[1]['oec:baseToken']).to.have.property('oec:symbol', 'USDC')
    })

    it('omits oec:accessDetails when the DDO has none', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.accessDetails
      delete ddo.credentialSubject.accessDetails
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['oec:accessDetails']).to.equal(undefined)
    })
  })

  describe('transformToDCAT - edge cases', () => {
    it('handles missing metadata.additionalInformation', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.metadata.additionalInformation
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['@id']).to.equal(expectedDid(simpleDatasetDdo))
      expect(dcat['dct:conformsTo']).to.equal(undefined)
    })

    it('handles empty tags array', async () => {
      const ddo = clone(simpleDatasetDdo)
      ddo.credentialSubject.metadata.tags = []
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dcat:keyword']).to.deep.equal(['access'])
    })

    it('handles missing metadata.license', async () => {
      const ddo = clone(simpleDatasetDdo)
      delete ddo.credentialSubject.metadata.license
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:license']).to.equal(undefined)
      expect(dcat['dct:rights']).to.equal(undefined)
    })

    it('handles empty services array', async () => {
      const ddo = clone(simpleDatasetDdo)
      ddo.credentialSubject.services = []
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dcat:distribution']).to.equal(undefined)
      expect(dcat['oec:services']).to.equal(undefined)
    })

    it('handles DDO with no credentialSubject (flat shape)', async () => {
      const flatDdo = {
        id: 'did:ope:flat',
        metadata: {
          name: 'Flat',
          description: 'Flat DDO',
          type: 'dataset',
          tags: ['flat']
        },
        services: [] as any[],
        chainId: 11155111,
        nftAddress: '0xflat'
      }
      const dcat = await handler.transformToDCAT(flatDdo)
      expect(dcat['@id']).to.equal('did:ope:flat')
      expect(dcat['dct:title']).to.equal('Flat')
    })
  })

  describe('transformToDCAT - required SHACL fields always present', () => {
    const requiredFields = [
      'dct:title',
      'dct:description',
      'dct:publisher',
      'dcat:contactPoint',
      'dct:language',
      'dct:accessRights'
    ]

    for (const fixture of [
      { name: 'simpleDataset', ddo: simpleDatasetDdo },
      { name: 'computeDataset', ddo: computeDatasetDdo },
      { name: 'algorithmAsset', ddo: algorithmAssetDdo }
    ]) {
      it(`${fixture.name}: all required fields present`, async () => {
        const dcat = await handler.transformToDCAT(fixture.ddo)
        for (const field of requiredFields) {
          expect(dcat[field], `${field} missing for ${fixture.name}`).to.not.equal(
            undefined
          )
        }
      })
    }
  })
})
