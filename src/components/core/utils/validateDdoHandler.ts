export function isRemoteDDO(ddo: any): boolean {
  let keys
  try {
    keys = Object.keys(ddo)
  } catch (e) {
    return false
  }

  if (keys.length === 1 && keys[0] === 'remote') {
    return true
  }

  return false
}
