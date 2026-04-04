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

function isOpenClawVulnerability(vuln: Vulnerability) {
  return vuln.agent_type?.toLowerCase() === 'openclaw' || vuln.title.toLowerCase().includes('openclaw')
}

export function buildCnnvdUrl(cnnvdID: string) {
  return `https://www.cnnvd.org.cn/home/globalSearch?keyword=${encodeURIComponent(cnnvdID)}`
}

export function buildGhsaUrl(vuln: Vulnerability) {
  if (!vuln.ghsa_id) {
    return ''
  }

  if (isOpenClawVulnerability(vuln)) {
    return `https://github.com/openclaw/openclaw/security/advisories/${vuln.ghsa_id}`
  }

  return `https://github.com/advisories/${vuln.ghsa_id}`
}

export function listVulnerabilityIdentifiers(vuln: Vulnerability) {
  return [
    vuln.cve_id
      ? { key: `cve:${vuln.cve_id}`, label: vuln.cve_id, href: `https://nvd.nist.gov/vuln/detail/${vuln.cve_id}` }
      : null,
    vuln.cnnvd_id
      ? { key: `cnnvd:${vuln.cnnvd_id}`, label: vuln.cnnvd_id, href: buildCnnvdUrl(vuln.cnnvd_id) }
      : null,
    vuln.ghsa_id
      ? { key: `ghsa:${vuln.ghsa_id}`, label: vuln.ghsa_id, href: buildGhsaUrl(vuln) }
      : null,
  ].filter((item): item is { key: string; label: string; href: string } => Boolean(item))
}

export function getPreferredDescription(vuln: Vulnerability) {
  return vuln.description_zh || vuln.description || ''
}
