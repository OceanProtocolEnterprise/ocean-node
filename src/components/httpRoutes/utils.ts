export type NodeInfoType = 'text' | 'url'

export type NodeInfoEntry = {
  type: NodeInfoType
  value: string
}

export type NodeOwnerInfo = {
  NODE_IMPRINT?: NodeInfoEntry
  NODE_TC?: NodeInfoEntry
  NODE_PRIVACY_POLICY?: NodeInfoEntry
  NODE_PROOF_OF_IDENTITY?: NodeInfoEntry
}

const OWNER_INFO_ENV_KEY = 'NODE_OWNER_INFO'
const OWNER_INFO_KEYS: (keyof NodeOwnerInfo)[] = [
  'NODE_IMPRINT',
  'NODE_TC',
  'NODE_PRIVACY_POLICY',
  'NODE_PROOF_OF_IDENTITY'
]

function parseObj(envValue: string): Record<string, unknown> | null {
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
      return parsedValue as Record<string, unknown>
    }
  } catch {
    return null
  }

  return null
}

function isNodeInfoEntry(value: unknown): value is NodeInfoEntry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }

  const candidate = value as Record<string, unknown>
  return (
    (candidate.type === 'text' || candidate.type === 'url') &&
    typeof candidate.value === 'string'
  )
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
  OWNER_INFO_KEYS.forEach((key) => {
    const value = parsedOwnerInfo[key]
    if (isNodeInfoEntry(value)) {
      result[key] = value
    }
  })

  return Object.keys(result).length > 0 ? result : null
}
