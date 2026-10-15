type DdoFixture = {
  id: string
  credentialSubject: {
    services: any[]
    datatokens: any[]
    metadata: any
    [key: string]: any
  }
  [key: string]: any
}

export const simpleDatasetDdo: DdoFixture = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'did:ope:1111111111111111111111111111111111111111111111111111111111111111',
  version: '5.0.0',
  credentialSubject: {
    chainId: 11155111,
    metadata: {
      created: '2026-01-01T10:00:00Z',
      updated: '2026-01-01T10:00:00Z',
      type: 'dataset',
      name: 'Simple Dataset',
      description: {
        '@value': 'A simple access-only dataset',
        '@direction': 'ltr',
        '@language': 'en'
      },
      tags: ['simple', 'dataset'],
      author: 'Alice',
      links: {},
      license: {
        name: 'https://example.com/license.pdf'
      },
      additionalInformation: {
        termsAndConditions: true
      },
      copyrightHolder: 'Example Org',
      providedBy: 'did:web:example.com'
    },
    services: [
      {
        id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        type: 'access',
        name: 'Access Service',
        description: {
          '@value': 'Simple access service',
          '@direction': 'ltr',
          '@language': 'en'
        },
        files: '0x04' + 'a'.repeat(128),
        datatokenAddress: '0x1111111111111111111111111111111111111111',
        serviceEndpoint: 'https://ocean-node.example.io',
        timeout: 86400,
        state: 0,
        credentials: {
          allow: [{ type: 'address', values: [{ address: '*' }] }],
          deny: [],
          match_deny: 'any'
        }
      }
    ] as any[],
    nftAddress: '0x2222222222222222222222222222222222222222',
    credentials: {
      allow: [{ type: 'address', values: [{ address: '*' }] }],
      deny: [],
      match_deny: 'any'
    },
    datatokens: [
      {
        address: '0x1111111111111111111111111111111111111111',
        name: 'Access Token',
        symbol: 'OEAT',
        serviceId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      }
    ] as any[]
  },
  additionalDdos: [],
  type: ['VerifiableCredential'],
  issuer: 'did:web:issuer.example.com',
  indexedMetadata: {
    stats: [
      {
        datatokenAddress: '0x1111111111111111111111111111111111111111',
        name: 'Access Token',
        symbol: 'OEAT',
        serviceId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        orders: 0,
        prices: [
          {
            type: 'fixedrate',
            price: '1.0',
            token: '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4',
            contract: '0xfa48673a7C36A2A768f89AC1ee8C355D5c367B02',
            exchangeId: '0xdeadbeef'
          }
        ]
      }
    ],
    nft: {
      state: 0,
      address: '0x2222222222222222222222222222222222222222',
      name: 'Data NFT',
      symbol: 'OEC-NFT',
      owner: '0x3333333333333333333333333333333333333333',
      created: '2026-01-01T10:05:00Z',
      tokenURI: ''
    },
    event: {
      txid: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      from: '0x3333333333333333333333333333333333333333',
      contract: '0x2222222222222222222222222222222222222222',
      block: 10000000,
      datetime: '2026-01-01T10:05:00.000Z'
    },
    purgatory: { state: false }
  }
}

export const computeDatasetDdo: DdoFixture = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'did:ope:2222222222222222222222222222222222222222222222222222222222222222',
  version: '5.0.0',
  credentialSubject: {
    chainId: 11155111,
    metadata: {
      created: '2026-02-01T10:00:00Z',
      updated: '2026-02-01T10:00:00Z',
      type: 'dataset',
      name: 'Compute Dataset',
      description: {
        '@value': 'A compute-enabled dataset',
        '@direction': 'ltr',
        '@language': 'en'
      },
      tags: ['compute'],
      author: 'Bob',
      links: {},
      license: { name: 'https://example.com/license.pdf' },
      additionalInformation: { termsAndConditions: true },
      copyrightHolder: '',
      providedBy: ''
    },
    services: [
      {
        id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        type: 'compute',
        name: 'Compute Service',
        description: {
          '@value': 'Compute service',
          '@direction': 'ltr',
          '@language': 'en'
        },
        files: '0x04' + 'b'.repeat(128),
        datatokenAddress: '0x4444444444444444444444444444444444444444',
        serviceEndpoint: 'https://ocean-node.example.io',
        timeout: 86400,
        state: 0,
        compute: {
          allowRawAlgorithm: false,
          allowNetworkAccess: true,
          publisherTrustedAlgorithmPublishers: ['*'],
          publisherTrustedAlgorithms: [
            {
              did: '*',
              containerSectionChecksum: '*',
              filesChecksum: '*',
              serviceId: '*'
            }
          ]
        },
        consumerParameters: [
          {
            name: 'param1',
            label: 'Param 1',
            description: 'First parameter',
            type: 'text',
            default: 'value1',
            required: false
          }
        ],
        credentials: {
          allow: [
            {
              type: 'SSIpolicy',
              values: [
                {
                  request_credentials: [
                    { format: 'jwt_vc_json', policies: [], type: 'gx:LegalPerson' }
                  ]
                }
              ]
            }
          ],
          deny: [],
          match_deny: 'any'
        }
      }
    ] as any[],
    nftAddress: '0x5555555555555555555555555555555555555555',
    credentials: {
      allow: [
        {
          type: 'SSIpolicy',
          values: [
            {
              request_credentials: [
                { format: 'jwt_vc_json', policies: [], type: 'gx:LegalPerson' }
              ]
            }
          ]
        }
      ],
      deny: [],
      match_deny: 'any'
    },
    stats: {
      allocated: 0,
      orders: 0,
      price: {
        value: 2,
        tokenSymbol: 'EURC',
        tokenAddress: '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4'
      }
    },
    datatokens: [
      {
        address: '0x4444444444444444444444444444444444444444',
        name: 'Access Token',
        symbol: 'OEAT',
        serviceId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
      }
    ] as any[]
  },
  additionalDdos: [],
  type: ['VerifiableCredential'],
  issuer: 'did:web:issuer.example.com',
  indexedMetadata: {
    stats: [],
    nft: {
      state: 0,
      address: '0x5555555555555555555555555555555555555555',
      name: 'Data NFT',
      symbol: 'OEC-NFT',
      owner: '0x6666666666666666666666666666666666666666',
      created: '2026-02-01T10:05:00Z',
      tokenURI: ''
    },
    event: {
      txid: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      from: '0x6666666666666666666666666666666666666666',
      contract: '0x5555555555555555555555555555555555555555',
      block: 11000000,
      datetime: '2026-02-01T10:05:00.000Z'
    },
    purgatory: { state: false }
  }
}

export const algorithmAssetDdo: DdoFixture = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'did:ope:3333333333333333333333333333333333333333333333333333333333333333',
  version: '5.0.0',
  credentialSubject: {
    chainId: 11155111,
    metadata: {
      created: '2026-03-01T10:00:00Z',
      updated: '2026-03-01T10:00:00Z',
      type: 'algorithm',
      name: 'Test Algorithm',
      description: {
        '@value': 'An algorithm asset',
        '@direction': 'ltr',
        '@language': 'en'
      },
      tags: ['algorithm', 'yolo'],
      author: 'Carol',
      links: {},
      license: { name: 'https://example.com/license.pdf' },
      additionalInformation: { termsAndConditions: true },
      algorithm: {
        language: 'py',
        version: '0.1',
        container: {
          entrypoint: 'python3 $ALGO',
          image: 'example/algo',
          tag: 'v1.0',
          checksum: 'sha256:abc123'
        }
      },
      copyrightHolder: 'Example Org',
      providedBy: 'did:web:example.com'
    },
    services: [
      {
        id: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        type: 'compute',
        name: 'Algo Service',
        description: {
          '@value': 'Algorithm compute service',
          '@direction': 'ltr',
          '@language': 'en'
        },
        files: '0x04' + 'c'.repeat(128),
        datatokenAddress: '0x7777777777777777777777777777777777777777',
        serviceEndpoint: 'https://ocean-node.example.io',
        timeout: 86400,
        state: 0,
        compute: {
          allowRawAlgorithm: false,
          allowNetworkAccess: true,
          publisherTrustedAlgorithmPublishers: [],
          publisherTrustedAlgorithms: []
        },
        credentials: {
          allow: [{ type: 'address', values: [{ address: '*' }] }],
          deny: [],
          match_deny: 'any'
        }
      }
    ] as any[],
    nftAddress: '0x8888888888888888888888888888888888888888',
    credentials: {
      allow: [
        {
          type: 'SSIpolicy',
          values: [
            {
              request_credentials: [
                { format: 'jwt_vc_json', policies: [], type: 'gx:LegalPerson' }
              ]
            }
          ]
        }
      ],
      deny: [],
      match_deny: 'any'
    },
    datatokens: [
      {
        address: '0x7777777777777777777777777777777777777777',
        name: 'Access Token',
        symbol: 'OEAT',
        serviceId: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
      }
    ] as any[]
  },
  additionalDdos: [],
  type: ['VerifiableCredential'],
  issuer: 'did:web:issuer.example.com',
  indexedMetadata: {
    stats: [],
    nft: {
      state: 0,
      address: '0x8888888888888888888888888888888888888888',
      name: 'Data NFT',
      symbol: 'OEC-NFT',
      owner: '0x9999999999999999999999999999999999999999',
      created: '2026-03-01T10:05:00Z',
      tokenURI: ''
    },
    event: {
      txid: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      from: '0x9999999999999999999999999999999999999999',
      contract: '0x8888888888888888888888888888888888888888',
      block: 12000000,
      datetime: '2026-03-01T10:05:00.000Z'
    },
    purgatory: { state: false }
  }
}

// Extract sub-arrays with explicit types BEFORE building the derived fixtures.
// This forces TypeScript to type them as any[] rather than trying to infer the
// element type from the spread, which was producing `undefined[]` and triggering
// ts(7018) on the nested `services` / `datatokens` properties.
const simpleServices: any[] = simpleDatasetDdo.credentialSubject.services
const computeServices: any[] = computeDatasetDdo.credentialSubject.services
const simpleDatatokens: any[] = simpleDatasetDdo.credentialSubject.datatokens

export const multiServiceDatasetDdo: DdoFixture = {
  ...simpleDatasetDdo,
  id: 'did:ope:4444444444444444444444444444444444444444444444444444444444444444',
  credentialSubject: {
    ...simpleDatasetDdo.credentialSubject,
    services: [
      simpleServices[0],
      {
        ...computeServices[0],
        id: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        datatokenAddress: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        name: 'Compute Service 2'
      }
    ] as any[],
    datatokens: [
      ...simpleDatatokens,
      {
        address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        name: 'Access Token',
        symbol: 'OEAT',
        serviceId: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
      }
    ] as any[]
  }
}

export const geospatialDatasetDdo: DdoFixture = {
  ...simpleDatasetDdo,
  id: 'did:ope:5555555555555555555555555555555555555555555555555555555555555555',
  credentialSubject: {
    ...simpleDatasetDdo.credentialSubject,
    metadata: {
      ...simpleDatasetDdo.credentialSubject.metadata,
      additionalInformation: {
        termsAndConditions: true,
        'dct:spatial': {
          '@type': ['dct:Location', 'skos:Concept'],
          'dcat:bbox': {
            '@type': 'geo:wktLiteral',
            '@value': 'POLYGON((0 0, 10 0, 10 10, 0 10, 0 0))'
          },
          'dcat:centroid': {
            '@type': 'geo:wktLiteral',
            '@value': 'POINT(5 5)'
          }
        },
        'dcat:theme': [
          {
            '@id': 'http://aims.fao.org/aos/agrovoc/c_203',
            '@type': 'skos:Concept',
            'skos:prefLabel': { '@language': 'en', '@value': 'agriculture' }
          }
        ]
      }
    }
  }
}
