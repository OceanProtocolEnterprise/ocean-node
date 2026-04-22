import { z } from 'zod'
import { CONFIG_LOGGER } from '../logging/common.js'

export const booleanFromString = z.union([z.boolean(), z.string()]).transform((v) => {
  if (typeof v === 'string') {
    return v === 'true' || v === '1' || v.toLowerCase() === 'yes'
  }
  return v
})

export const jsonFromString = <T>(schema: z.ZodType<T>, fieldName?: string) =>
  z.union([schema, z.string(), z.undefined()]).transform((v) => {
    if (v === undefined || v === 'undefined') {
      return undefined
    }
    if (typeof v === 'string') {
      try {
        return JSON.parse(v)
      } catch (error) {
        const trimmed = v.trim()
        const fieldContext = fieldName ? ` for "${fieldName}"` : ''
        const valueDetails =
          trimmed.length === 0
            ? 'empty/whitespace-only string'
            : `string length=${v.length}, startsWith=${JSON.stringify(trimmed.slice(0, 16))}`
        CONFIG_LOGGER.warn(
          `Failed to parse JSON${fieldContext}: ${error.message} (${valueDetails})`
        )
        return v
      }
    }
    return v
  })
