import { Credentials, Service } from 'aws-sdk'
import { Metadata } from 'aws-sdk/clients/appstream'
import { Nft } from './Nft'

export interface CredentialSubject {
  /**
   * NFT contract address
   * @type {string}
   */
  nftAddress: string

  /**
   * ChainId of the network the DDO was published to.
   * @type {number}
   */
  chainId: number

  /**
   * Stores an object describing the asset.
   * @type {Metadata}
   */
  metadata: Metadata

  /**
   * Stores an array of services defining access to the asset.
   * @type {Service[]}
   */
  services: Service[]

  /**
   * Describes the credentials needed to access a dataset
   * in addition to the services definition.
   * @type {Credentials}
   */
  credentials?: Credentials

  /**
   * Describes the event of last metadata event
   * @type {Event}
   */
  event?: Event

  nft?: Nft
}
