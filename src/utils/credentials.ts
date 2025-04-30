import {
  Credential,
  Credentials,
  KNOWN_CREDENTIALS_TYPES
} from '../@types/DDO/Credentials'
import { isDefined } from './util'

export function findCredential(
  credentials: Credential[],
  consumerCredentials: Credential,
  type?: string
) {
  const hasAddressType = credentials.some((credential) => {
    const type = String(credential.type ?? '').toLowerCase()
    return type === 'address'
  })
  if (type === 'service' && !hasAddressType) return true

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

export function areKnownCredentialTypes(credentials: Credentials): boolean {
  if (isDefined(credentials)) {
    if (isDefined(credentials.allow) && credentials.allow.length > 0) {
      for (const credential of credentials.allow) {
        if (!isKnownCredentialType(credential.type)) {
          return false
        }
      }
    }

    if (isDefined(credentials.deny) && credentials.deny.length > 0) {
      for (const credential of credentials.deny) {
        if (!isKnownCredentialType(credential.type)) {
          return false
        }
      }
    }
  }
  return true
}

export function isKnownCredentialType(credentialType: string): boolean {
  return (
    isDefined(credentialType) &&
    KNOWN_CREDENTIALS_TYPES.findIndex((type) => {
      return type.toLowerCase() === credentialType.toLowerCase()
    }) > -1
  )
}
