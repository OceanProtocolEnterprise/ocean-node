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

export function getNodeOwnerInfo(): Record<string, any> | null {
  return parseObj(process.env[OWNER_INFO_ENV_KEY])
}
