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

    it('uses the asset DID as @id (no /VC/ suffix)', () => {
      expect(dcat['@id']).to.equal(`urn:${simpleDatasetDdo.id}`)
      expect(dcat['@id']).to.not.contain('/VC/')
    })

    it('uses the asset DID as dct:identifier', () => {
      expect(dcat['dct:identifier']).to.deep.equal([simpleDatasetDdo.id])
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
      expect(dcat['dcat:landingPage']['@id']).to.contain(simpleDatasetDdo.id)
    })

    it('does NOT emit dct:conformsTo when there is no geo metadata', () => {
      expect(dcat['dct:conformsTo']).to.equal(undefined)
    })
  })

  describe('transformToDCAT - distributions', () => {
    it('creates one dcat:Distribution per service', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['dcat:distribution']).to.have.lengthOf(1)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['@type']).to.equal('dcat:Distribution')
    })

    it('access service gets dcat:accessURL and dcat:downloadURL as rdfs:Resource', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:accessURL']).to.deep.equal({
        '@id': 'https://ocean-node.example.io',
        '@type': 'rdfs:Resource'
      })
      expect(dist['dcat:downloadURL']).to.deep.equal({
        '@id': 'https://ocean-node.example.io',
        '@type': 'rdfs:Resource'
      })
    })

    it('access service uses application/octet-stream media type', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:mediaType']).to.deep.equal({
        '@id': 'https://www.iana.org/assignments/media-types/application/octet-stream',
        '@type': 'dct:MediaType'
      })
    })

    it('compute service uses application/json media type and compute-service format', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:mediaType']).to.deep.equal({
        '@id': 'https://www.iana.org/assignments/media-types/application/json',
        '@type': 'dct:MediaType'
      })
      expect(dist['dcat:format']).to.equal('compute-service')
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

    it('dcat:checksum uses SPDX URI + xsd:hexBinary value', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:checksum']).to.deep.equal({
        '@type': 'spdx:Checksum',
        'spdx:algorithm': {
          '@id': 'http://spdx.org/rdf/terms#checksumAlgorithm_sha256',
          '@type': 'spdx:ChecksumAlgorithm'
        },
        'spdx:checksumValue': {
          '@type': 'xsd:hexBinary',
          '@value': '04' + 'a'.repeat(62)
        }
      })
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

    it('DataService has stable @id derived from service id', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      const svc = dcat['oec:services'][0]
      expect(svc['@id']).to.equal(
        'urn:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      )
      expect(svc['dct:identifier']).to.equal(
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      )
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

    it('emits dct:conformsTo with INSPIRE + GeoDCAT-AP when geo metadata present', async () => {
      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      expect(dcat['dct:conformsTo']).to.include(
        'http://inspire.ec.europa.eu/schemas/inspire_vs/1.0'
      )
      expect(dcat['dct:conformsTo']).to.include(
        'https://semiceu.github.io/GeoDCAT-AP/releases/3.0.0/'
      )
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
    it('uses credentialSubject.stats when present', async () => {
      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      expect(dcat['oec:stats']).to.deep.equal({
        'oec:allocated': 0,
        'oec:orders': 0,
        'oec:price': {
          'oec:tokenAddress': '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4',
          'oec:tokenSymbol': 'EURC',
          'oec:value': '2'
        }
      })
    })

    it('falls back to indexedMetadata.stats when credentialSubject.stats missing', async () => {
      const dcat = await handler.transformToDCAT(simpleDatasetDdo)
      expect(dcat['oec:stats']).to.have.property('oec:allocated', 0)
      expect(dcat['oec:stats']).to.have.property('oec:orders', 0)
    })
  })

  describe('transformToDCAT - edge cases', () => {
    it('handles missing metadata.additionalInformation', async () => {
      const ddo = JSON.parse(JSON.stringify(simpleDatasetDdo))
      delete ddo.credentialSubject.metadata.additionalInformation
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['@id']).to.equal(`urn:${simpleDatasetDdo.id}`)
      expect(dcat['dct:conformsTo']).to.equal(undefined)
    })

    it('handles empty tags array', async () => {
      const ddo = JSON.parse(JSON.stringify(simpleDatasetDdo))
      ddo.credentialSubject.metadata.tags = []
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dcat:keyword']).to.deep.equal(['access'])
    })

    it('handles missing metadata.license', async () => {
      const ddo = JSON.parse(JSON.stringify(simpleDatasetDdo))
      delete ddo.credentialSubject.metadata.license
      const dcat = await handler.transformToDCAT(ddo)
      expect(dcat['dct:license']).to.equal(undefined)
      expect(dcat['dct:rights']).to.equal(undefined)
    })

    it('handles empty services array', async () => {
      const ddo = JSON.parse(JSON.stringify(simpleDatasetDdo))
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
      expect(dcat['@id']).to.equal('urn:did:ope:flat')
      expect(dcat['dct:title']).to.equal('Flat')
    })
  })

  describe('transformToDCAT - required SHACL fields always present', () => {
    const requiredFields = [
      'dct:title',
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
