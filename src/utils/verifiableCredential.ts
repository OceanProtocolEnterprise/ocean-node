export const isVerifiableCredential = (ddo: any): boolean => {
  return ddo.type && Array.isArray(ddo.type) && ddo.type.includes('VerifiableCredential')
}
