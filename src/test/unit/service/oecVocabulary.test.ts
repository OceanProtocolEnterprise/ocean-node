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
        expect(term.name, `${key} missing name`).to.be.a('string')
        expect(term.name, `${key} missing name`).to.not.equal('')
        expect(term.label, `${key} missing label`).to.be.a('string')
        expect(term.label, `${key} missing label`).to.not.equal('')
        expect(term.description, `${key} missing description`).to.be.a('string')
        expect(term.description, `${key} missing description`).to.not.equal('')
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
        'distributionFormat',
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

    it('distributionFormat is a string-ranged term', () => {
      expect(OE_VOCABULARY.distributionFormat.range).to.equal('xsd:string')
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

    it('escapes double quotes inside labels and comments', () => {
      const rdf = oecVocabularyToRdf()
      // serviceType description contains "access" or "compute"
      expect(rdf).to.include('Type of the service: \\"access\\" or \\"compute\\".')
      // every label/comment literal must contain only escaped quotes
      const literal = /^ {2}rdfs:(label|comment) "((?:[^"\\]|\\.)*)"( ;| \.)$/
      for (const line of rdf.split('\n')) {
        if (/^ {2}rdfs:(label|comment) /.test(line)) {
          expect(line, `unparseable Turtle literal: ${line}`).to.match(literal)
        }
      }
    })

    it('declares every oec: class used as a range', () => {
      const rdf = oecVocabularyToRdf()
      const classes = new Set<string>()
      for (const term of Object.values(OE_VOCABULARY)) {
        if (term.range?.startsWith('oec:')) {
          classes.add(term.range.substring('oec:'.length))
        }
      }
      expect(classes.size).to.be.greaterThan(0)
      for (const cls of classes) {
        expect(rdf, `class oec:${cls} not declared`).to.include(
          `oec:${cls} a rdfs:Class .`
        )
      }
    })

    it('emits the distributionFormat term', () => {
      const rdf = oecVocabularyToRdf()
      expect(rdf).to.include('oec:distributionFormat a rdf:Property')
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
