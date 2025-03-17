export const KNOWN_CREDENTIALS_TYPES = ['address', 'accessList']

export interface Address {
  address: string
}
export interface Credential {
  type?: string
  values?: Address[]
}
export interface Credentials {
  allow?: Credential[]
  deny?: Credential[]
}
