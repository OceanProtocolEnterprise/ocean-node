export type NodeOwnerInfoSection = {
  url: string
  [key: string]: any
}

export type NodeOwnerInfo = {
  imprint?: NodeOwnerInfoSection & {
    legalName: string
    email: string
  }
  termsAndConditions?: NodeOwnerInfoSection
  privacyPolicy?: NodeOwnerInfoSection
  [key: string]: NodeOwnerInfoSection | undefined
}

const OWNER_INFO_ENV_KEY = 'NODE_OWNER_INFO'

function parseObj(envValue: string): Record<string, any> | null {
  if (!envValue) {
    return null
  }

  try {
    const parsedValue = JSON.parse(envValue)
    if (
      typeof parsedValue === 'object' &&
      parsedValue !== null &&
      !Array.isArray(parsedValue)
    ) {
      return parsedValue as Record<string, any>
    }
  } catch {
    return null
  }

  return null
}

function isObjectRecord(value: any): value is Record<string, any> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function isImprint(value: any): value is NonNullable<NodeOwnerInfo['imprint']> {
  if (!isObjectRecord(value)) {
    return false
  }
  return (
    typeof value.legalName === 'string' &&
    typeof value.email === 'string' &&
    typeof value.url === 'string'
  )
}

function isUrlContainer(value: any): value is NodeOwnerInfoSection {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  return typeof (value as Record<string, any>).url === 'string'
}

export function getNodeOwnerInfo(): NodeOwnerInfo | null {
  const rawValue = process.env[OWNER_INFO_ENV_KEY]
  if (!rawValue) {
    return null
  }

  const parsedOwnerInfo = parseObj(rawValue)
  if (!parsedOwnerInfo) {
    return null
  }

  const result: NodeOwnerInfo = {}
  if (isImprint(parsedOwnerInfo.imprint)) {
    result.imprint = parsedOwnerInfo.imprint
  }
  if (isUrlContainer(parsedOwnerInfo.termsAndConditions)) {
    result.termsAndConditions = parsedOwnerInfo.termsAndConditions
  }
  if (isUrlContainer(parsedOwnerInfo.privacyPolicy)) {
    result.privacyPolicy = parsedOwnerInfo.privacyPolicy
  }
  Object.entries(parsedOwnerInfo).forEach(([key, value]) => {
    if (
      !['imprint', 'termsAndConditions', 'privacyPolicy'].includes(key) &&
      isUrlContainer(value)
    ) {
      result[key] = value
    }
  })

  return Object.keys(result).length > 0 ? result : null
}
