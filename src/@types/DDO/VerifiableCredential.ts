import { CredentialSubject } from './CredentialSubject'

export interface AdditionalVerifiableCredentials {
  type: string
  data: any
}

export interface VerifiableCredential {
  /**
   * Contexts used for validation.
   * @type {string[]}
   */
  '@context': string[]

  /**
   * id optional for verifiable credential
   * @type {string}
   */
  id?: string

  /**
   * @type {CredentialSubject}
   */
  credentialSubject: CredentialSubject

  /**
   * Id of issuer
   * @type {string}
   */
  issuer: string

  /**
   * Additional ddos
   * @type {AdditionalVerifiableCredentials[]}
   */
  additionalDdos?: AdditionalVerifiableCredentials[]

  /**
   * Version information in SemVer notation
   * referring to the DDO spec version
   * @type {string}
   */
  version: string
}
