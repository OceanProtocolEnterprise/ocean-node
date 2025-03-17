export const KNOWN_CREDENTIALS_TYPES = ['address', 'accessList']

export interface Credential {
  type?: string
  values?: any
}
export interface Credentials {
  allow?: Credential[]
  deny?: Credential[]
}
