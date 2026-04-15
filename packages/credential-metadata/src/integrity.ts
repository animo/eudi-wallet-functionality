import { createHash } from 'node:crypto'

/** Compute the W3C SRI integrity value of a signed credential metadata JWT (Section 3.7.1). */
export function computeMetadataIntegrity(compactJwt: string): string {
  const hash = createHash('sha256').update(compactJwt, 'utf8').digest('base64')
  return `sha256-${hash}`
}
