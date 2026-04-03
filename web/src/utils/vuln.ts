import type { Vulnerability } from '@/types'

export function parseEvidenceTokens(evidence?: string) {
  const tokens: Record<string, string> = {}
  if (!evidence) {
    return tokens
  }

  const matches = evidence.matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+)/g)
  for (const match of matches) {
    const [, key, value] = match
    tokens[key] = value
  }
  return tokens
}

export function extractVersionContext(vuln: Vulnerability) {
  const tokens = parseEvidenceTokens(vuln.evidence)
  return {
    currentVersion: tokens.current_version,
    fixedVersion: tokens.fixed_version,
    hasLocalPoCRule: tokens.local_poc_rule === 'available',
  }
}
