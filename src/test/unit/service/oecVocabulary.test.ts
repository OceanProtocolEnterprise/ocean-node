import { expect } from 'chai'
import {
  OE_VOCABULARY,
  OE_OBJECT_SHAPES,
  oecVocabularyToRdf,
  oecVocabularyToContext
} from '../../../@types/oecVocabulary.js'

describe('********** OE Vocabulary Unit Tests', () => {
  describe('OE_VOCABULARY', () => {
    it('every term has name, label, and description', () => {
      for (const [key, term] of Object.entries(OE_VOCABULARY)) {
        expect(term.name, `${key} missing name`).to.be.a('string').and.not.empty
        expect(term.label, `${key} missing label`).to.be.a('string').and.not.empty
        expect(term.description, `${key} missing description`).to.be.a('string').and.not
          .empty
      }
    })

    it('every term key matches its own name field', () => {
      for (const [key, term] of Object.entries(OE_VOCABULARY)) {
        expect(
          term.name,
          `key "${key}" does not match term.name "${term.name}"`
        ).to.equal(key)
      }
    })

    it('contains the terms used by the DCAT transformer', () => {
      const required = [
        'chainId',
        'nftAddress',
        'issuer',
        'datatokens',
        'algorithm',
        'event',
        'nft',
        'stats',
        'purgatory',
        'accessDetails',
        'services',
        'additionalDdos',
        'serviceType',
        'datatokenAddress',
        'files',
        'timeout',
        'state',
        'compute',
        'consumerParameters',
        'credentials',
        'address',
        'name',
        'symbol',
        'serviceId',
        'allowNetworkAccess',
        'allowRawAlgorithm',
        'publisherTrustedAlgorithms',
        'publisherTrustedAlgorithmPublishers',
        'did',
        'filesChecksum',
        'containerSectionChecksum',
        'allow',
        'deny',
        'matchDeny',
        'type',
        'values',
        'requestCredentials',
        'format',
        'policies',
        'vcPolicies',
        'vpPolicies',
        'label',
        'description',
        'default',
        'required',
        'owner',
        'tokenURI',
        'block',
        'contract',
        'datetime',
        'from',
        'tx',
        'allocated',
        'orders',
        'price',
        'tokenAddress',
        'tokenSymbol',
        'value',
        'addressOrId',
        'isOwned',
        'isPurchasable',
        'publisherMarketOrderFee',
        'templateId',
        'validOrderTx',
        'paymentCollector',
        'baseToken',
        'datatoken',
        'language',
        'version',
        'container',
        'entrypoint',
        'image',
        'tag',
        'checksum'
      ]
      for (const term of required) {
        expect(OE_VOCABULARY[term], `missing OE term: ${term}`).to.not.equal(undefined)
      }
    })
  })

  describe('OE_OBJECT_SHAPES', () => {
    it('every shape key is a term in OE_VOCABULARY or a DCAT term', () => {
      const knownShapeKeys = [
        ...Object.keys(OE_VOCABULARY),
        'matchDeny',
        'requestCredentials',
        'vcPolicies',
        'vpPolicies'
      ]
      for (const [shapeName, keys] of Object.entries(OE_OBJECT_SHAPES)) {
        for (const key of keys) {
          expect(
            knownShapeKeys.includes(key),
            `shape "${shapeName}" references unknown key: ${key}`
          ).to.equal(true)
        }
      }
    })

    it('Datatoken shape includes the fields the transformer emits', () => {
      expect(OE_OBJECT_SHAPES.Datatoken).to.include.members([
        'address',
        'name',
        'symbol',
        'serviceId'
      ])
    })

    it('ConsumerParameter shape includes the fields the transformer emits', () => {
      expect(OE_OBJECT_SHAPES.ConsumerParameter).to.include.members([
        'name',
        'label',
        'description',
        'type',
        'default',
        'required',
        'options'
      ])
    })

    it('TrustedAlgorithm shape includes the fields the transformer emits', () => {
      expect(OE_OBJECT_SHAPES.TrustedAlgorithm).to.include.members([
        'did',
        'filesChecksum',
        'containerSectionChecksum',
        'serviceId'
      ])
    })

    it('Compute shape includes allowNetworkAccess and allowRawAlgorithm', () => {
      expect(OE_OBJECT_SHAPES.Compute).to.include.members([
        'allowNetworkAccess',
        'allowRawAlgorithm'
      ])
    })
  })

  describe('oecVocabularyToRdf', () => {
    it('produces valid Turtle with @prefix declarations', () => {
      const rdf = oecVocabularyToRdf()
      expect(rdf).to.include('@prefix oec:')
      expect(rdf).to.include('@prefix rdfs:')
      expect(rdf).to.include('@prefix rdf:')
      expect(rdf).to.include('@prefix xsd:')
    })

    it('emits every term in OE_VOCABULARY', () => {
      const rdf = oecVocabularyToRdf()
      for (const term of Object.values(OE_VOCABULARY)) {
        expect(rdf, `missing oec:${term.name} in RDF output`).to.include(
          `oec:${term.name} `
        )
      }
    })

    it('uses rdf:Property as type', () => {
      const rdf = oecVocabularyToRdf()
      expect(rdf).to.include('a rdf:Property')
    })

    it('accepts a custom base URI', () => {
      const rdf = oecVocabularyToRdf('https://example.com/vocab/')
      expect(rdf).to.include('@prefix oec: <https://example.com/vocab/>')
    })
  })

  describe('oecVocabularyToContext', () => {
    it('sets the oec prefix to the base URI', () => {
      const ctx = oecVocabularyToContext()
      expect(ctx).to.have.property('oec', 'https://oceanenterprise.io/vocab/')
    })

    it('maps every term name to oec:<name>', () => {
      const ctx = oecVocabularyToContext()
      for (const term of Object.values(OE_VOCABULARY)) {
        expect(ctx, `missing ${term.name} in context`).to.have.property(
          term.name,
          `oec:${term.name}`
        )
      }
    })

    it('accepts a custom base URI', () => {
      const ctx = oecVocabularyToContext('https://example.com/vocab/')
      expect(ctx).to.have.property('oec', 'https://example.com/vocab/')
    })
  })
})
