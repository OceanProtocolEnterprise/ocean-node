import { expect } from 'chai'
import { JsonRpcProvider, Signer } from 'ethers'
import { Database } from '../../components/database/index.js'
import { getConfiguration } from '../../utils/index.js'
import {
  DEFAULT_TEST_TIMEOUT,
  OverrideEnvConfig,
  TEST_ENV_CONFIG_FILE,
  buildEnvOverrideConfig,
  setupEnvironment,
  tearDownEnvironment,
  getMockSupportedNetworks
} from '../utils/utils.js'
import { ENVIRONMENT_VARIABLES } from '../../utils/constants.js'
import { OceanNodeConfig } from '../../@types/OceanNode.js'
import { RPCS } from '../../@types/blockchain.js'
import { OceanNode } from '../../OceanNode.js'
import { FindDdoHandler } from '../../components/core/handler/ddoHandler.js'
import { DCATDataset } from '../../@types/dcat.js'
import {
  simpleDatasetDdo,
  computeDatasetDdo,
  algorithmAssetDdo,
  multiServiceDatasetDdo,
  geospatialDatasetDdo
} from '../data/dcatFixtures.js'
import sinon from 'sinon'

describe('********** DCAT Integration Tests', () => {
  let config: OceanNodeConfig
  let database: Database
  let provider: JsonRpcProvider
  let previousConfiguration: OverrideEnvConfig[]
  let oceanNode: OceanNode
  let handler: FindDdoHandler

  const mockSupportedNetworks: RPCS = getMockSupportedNetworks()

  before(async () => {
    previousConfiguration = await setupEnvironment(
      TEST_ENV_CONFIG_FILE,
      buildEnvOverrideConfig(
        [
          ENVIRONMENT_VARIABLES.RPCS,
          ENVIRONMENT_VARIABLES.INDEXER_NETWORKS,
          ENVIRONMENT_VARIABLES.VALIDATE_UNSIGNED_DDO
        ],
        [JSON.stringify(mockSupportedNetworks), JSON.stringify([8996]), 'false']
      )
    )

    config = await getConfiguration(true)
    database = await Database.init(config.dbConfig)
    oceanNode = await OceanNode.getInstance(
      config,
      database,
      null,
      null,
      null,
      null,
      null,
      true
    )

    provider = new JsonRpcProvider(mockSupportedNetworks['8996'].rpc)
    handler = new FindDdoHandler(oceanNode)
  })

  after(async () => {
    await oceanNode.tearDownAll()
    await tearDownEnvironment(previousConfiguration)
  })

  describe('transformToDCAT end-to-end via handler', () => {
    it('produces a DCATDataset for a simple dataset DDO', async function () {
      this.timeout(DEFAULT_TEST_TIMEOUT)

      const dcat = await handler.transformToDCAT(simpleDatasetDdo)

      expect(dcat['@type']).to.equal('dcat:Dataset')
      expect(dcat['@id']).to.equal(`urn:${simpleDatasetDdo.id}`)
      expect(dcat['dct:title']).to.equal('Simple Dataset')

      expect(dcat['dct:publisher']).to.not.equal(undefined)
      expect(dcat['dcat:contactPoint']).to.not.equal(undefined)
      expect(dcat['dct:language']).to.not.equal(undefined)
      expect(dcat['dct:accessRights']).to.not.equal(undefined)

      expect(dcat['dcat:distribution']).to.be.an('array').with.lengthOf(1)
      expect(dcat['dcat:service']).to.be.an('array').with.lengthOf(1)

      const svc = dcat['dcat:service'][0]
      expect(svc['dcat:servesDataset']['@id']).to.equal(dcat['@id'])
    })

    it('produces a DCATDataset for a compute dataset DDO', async function () {
      this.timeout(DEFAULT_TEST_TIMEOUT)

      const dcat = await handler.transformToDCAT(computeDatasetDdo)
      expect(dcat['@id']).to.equal(`urn:${computeDatasetDdo.id}`)

      const dist = dcat['dcat:distribution'][0]
      expect(dist['dcat:format']).to.equal('compute-service')
      expect(dist['oec:compute']).to.not.equal(undefined)

      const svc = dcat['dcat:service'][0]
      expect(svc['oec:serviceType']).to.equal('compute')
      expect(svc['oec:compute']).to.not.equal(undefined)
      expect(svc['oec:consumerParameters']).to.be.an('array')
    })

    it('produces a DCATDataset for an algorithm asset DDO', async function () {
      this.timeout(DEFAULT_TEST_TIMEOUT)

      const dcat = await handler.transformToDCAT(algorithmAssetDdo)
      expect(dcat['dct:type']).to.equal('algorithm')
      expect(dcat['oec:algorithm']).to.not.equal(undefined)
      expect(dcat['oec:algorithm']['oec:language']).to.equal('py')
      expect(dcat['oec:algorithm']['oec:container']['oec:image']).to.equal('example/algo')
    })

    it('handles multi-service assets (access + compute)', async function () {
      this.timeout(DEFAULT_TEST_TIMEOUT)

      const dcat = await handler.transformToDCAT(multiServiceDatasetDdo)
      expect(dcat['dcat:distribution']).to.have.lengthOf(2)
      expect(dcat['dcat:service']).to.have.lengthOf(2)

      const types = dcat['dcat:service'].map((s: any) => s['oec:serviceType'])
      expect(types).to.include('access')
      expect(types).to.include('compute')

      for (const svc of dcat['dcat:service']) {
        expect(svc['dcat:servesDataset']['@id']).to.equal(dcat['@id'])
      }
    })

    it('handles geo metadata: promotes dct:spatial and adds conformsTo', async function () {
      this.timeout(DEFAULT_TEST_TIMEOUT)

      const dcat = await handler.transformToDCAT(geospatialDatasetDdo)
      expect(dcat['dct:spatial']).to.not.equal(undefined)
      expect(dcat['dcat:bbox']).to.not.equal(undefined)
      expect(dcat['dcat:centroid']).to.not.equal(undefined)
      expect(dcat['dcat:theme']).to.be.an('array').with.length.greaterThan(0)
      expect(dcat['dct:conformsTo']).to.include(
        'http://inspire.ec.europa.eu/schemas/inspire_vs/1.0'
      )
    })
  })

  describe('DCAT output conforms to expected SHACL-shape invariants', () => {

    it('every dcat:mediaType is typed dct:MediaType', async () => {
      for (const ddo of [simpleDatasetDdo, computeDatasetDdo, algorithmAssetDdo]) {
        const dcat = await handler.transformToDCAT(ddo)
        for (const dist of dcat['dcat:distribution'] || []) {
          if (dist['dcat:mediaType']) {
            expect(dist['dcat:mediaType']).to.have.property('@type', 'dct:MediaType')
          }
        }
      }
    })

    it('every dcat:accessURL / downloadURL / endpointURL is rdfs:Resource', async () => {
      for (const ddo of [simpleDatasetDdo, computeDatasetDdo, algorithmAssetDdo]) {
        const dcat = await handler.transformToDCAT(ddo)
        for (const dist of dcat['dcat:distribution'] || []) {
          if (dist['dcat:accessURL']) {
            expect(dist['dcat:accessURL']).to.have.property('@type', 'rdfs:Resource')
          }
          if (dist['dcat:downloadURL']) {
            expect(dist['dcat:downloadURL']).to.have.property('@type', 'rdfs:Resource')
          }
        }
        for (const svc of dcat['dcat:service'] || []) {
          if (svc['dcat:endpointURL']) {
            expect(svc['dcat:endpointURL']).to.have.property('@type', 'rdfs:Resource')
          }
        }
      }
    })

    it('every spdx:algorithm is typed spdx:ChecksumAlgorithm', async () => {
      for (const ddo of [simpleDatasetDdo, computeDatasetDdo, algorithmAssetDdo]) {
        const dcat = await handler.transformToDCAT(ddo)
        for (const dist of dcat['dcat:distribution'] || []) {
          if (dist['dcat:checksum']?.['spdx:algorithm']) {
            expect(dist['dcat:checksum']['spdx:algorithm']).to.have.property(
              '@type',
              'spdx:ChecksumAlgorithm'
            )
          }
        }
      }
    })

    it('every dct:language entry is typed dct:LinguisticSystem', async () => {
      for (const ddo of [simpleDatasetDdo, computeDatasetDdo, algorithmAssetDdo]) {
        const dcat = await handler.transformToDCAT(ddo)
        for (const lang of dcat['dct:language'] || []) {
          expect(lang).to.have.property('@type', 'dct:LinguisticSystem')
        }
      }
    })

    it('dct:license and dct:rights are dct:RightsStatement when present', async () => {
      for (const ddo of [simpleDatasetDdo, computeDatasetDdo, algorithmAssetDdo]) {
        const dcat = await handler.transformToDCAT(ddo)
        if (dcat['dct:license']) {
          expect(dcat['dct:license']).to.have.property('@type', 'dct:RightsStatement')
        }
        if (dcat['dct:rights']) {
          expect(dcat['dct:rights']).to.have.property('@type', 'dct:RightsStatement')
        }
      }
    })

    it('dct:conformsTo never contains the bare dcat namespace URI', async () => {
      for (const ddo of [
        simpleDatasetDdo,
        computeDatasetDdo,
        algorithmAssetDdo,
        multiServiceDatasetDdo
      ]) {
        const dcat = await handler.transformToDCAT(ddo)
        if (dcat['dct:conformsTo']) {
          expect(dcat['dct:conformsTo']).to.not.include('http://www.w3.org/ns/dcat#')
        }
      }
    })

    it('dcat:contactPoint is always vcard:Kind', async () => {
      for (const ddo of [simpleDatasetDdo, computeDatasetDdo, algorithmAssetDdo]) {
        const dcat = await handler.transformToDCAT(ddo)
        expect(dcat['dcat:contactPoint']).to.have.property('@type', 'vcard:Kind')
        expect(dcat['dcat:contactPoint']).to.have.property('vcard:fn')
      }
    })
  })

  describe('DCAT transformation does not mutate the source DDO', () => {
    it('leaves the input DDO unchanged after transformToDCAT', async function () {
      this.timeout(DEFAULT_TEST_TIMEOUT)

      const original = JSON.parse(JSON.stringify(simpleDatasetDdo))
      await handler.transformToDCAT(simpleDatasetDdo)
      expect(simpleDatasetDdo).to.deep.equal(original)
    })

    it('handles repeated transformation calls deterministically (except timestamps)', async () => {
      const dcat1 = await handler.transformToDCAT(simpleDatasetDdo)
      const dcat2 = await handler.transformToDCAT(simpleDatasetDdo)

      expect(dcat1['@id']).to.equal(dcat2['@id'])
      expect(dcat1['dct:title']).to.equal(dcat2['dct:title'])
      expect(dcat1['dcat:distribution']).to.deep.equal(dcat2['dcat:distribution'])
      expect(dcat1['dcat:service']).to.deep.equal(dcat2['dcat:service'])
    })
  })
})
