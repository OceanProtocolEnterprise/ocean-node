import { Credential, Credentials } from '../@types/DDO/Credentials'

export function findCredential(
  credentials: Credential[],
  consumerCredentials: Credential,
  type?: string
) {
  return credentials.find((credential) => {
    if (Array.isArray(credential?.values)) {
      if (credential.values.length > 0) {
        const credentialType = String(credential.type ?? '').toLowerCase()
        if (credentialType !== 'address') {
          return false
        }
        const credentialValues = credential.values.map((v) =>
          typeof v === 'object' && 'address' in v ? v.address : v
        )
        if (credentialValues.includes('*')) {
          return true
        }
        return (
          credentialType === consumerCredentials.type &&
          credentialValues
            .map((address) => address.toLowerCase())
            .includes(consumerCredentials.values[0].address)
        )
      }
    }
    if (type === 'service') return true
    return false
  })
}
/**
 * This method checks credentials
 * @param credentials credentials
 * @param consumerAddress consumer address
 */
export function checkCredentials(
  credentials: Credentials,
  consumerAddress: string,
  type?: string
) {
  const consumerCredentials = {
    type: 'address',
    values: [{ address: String(consumerAddress)?.toLowerCase() }]
  }
  // check deny access
  if (Array.isArray(credentials?.deny) && credentials.deny.length > 0) {
    const accessDeny = findCredential(credentials.deny, consumerCredentials, type)
    if (accessDeny) {
      return false
    }
  }
  // check allow access
  if (Array.isArray(credentials?.allow) && credentials.allow.length > 0) {
    const accessAllow = findCredential(credentials.allow, consumerCredentials, type)
    if (!accessAllow) {
      return false
    }
  }
  return true
}
