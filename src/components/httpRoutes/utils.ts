function parseObj(envKey: string): Record<string, unknown> | null {
  const rawValue = process.env[envKey]
  if (!rawValue) {
    return null
  }

  try {
    const parsedValue = JSON.parse(rawValue)
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

export function getProviderIdentityAndTC(): {
  license: Record<string, unknown> | null
  proofOfIdentity: Record<string, unknown> | null
} {
  return {
    license: parseObj('LICENSE'),
    proofOfIdentity: parseObj('PROOF_OF_IDENTITY')
  }
}
