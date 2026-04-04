import type { RuleCatalogEntry, Vulnerability } from '@/types'

type WithIdentifiers = Pick<Vulnerability, 'cve_id' | 'cnnvd_id' | 'check_type'>

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

export function buildCnnvdUrl(cnnvdID: string) {
  return `https://www.cnnvd.org.cn/home/globalSearch?keyword=${encodeURIComponent(cnnvdID)}`
}

export function buildCveUrl(cveID: string) {
  return `https://www.cve.org/CVERecord?id=${encodeURIComponent(cveID)}`
}

export function listVulnerabilityIdentifiers(vuln: WithIdentifiers | RuleCatalogEntry) {
  return [
    vuln.cve_id
      ? { key: `cve:${vuln.cve_id}`, label: vuln.cve_id, href: buildCveUrl(vuln.cve_id) }
      : null,
    vuln.cnnvd_id
      ? { key: `cnnvd:${vuln.cnnvd_id}`, label: vuln.cnnvd_id, href: buildCnnvdUrl(vuln.cnnvd_id) }
      : null,
  ].filter((item): item is { key: string; label: string; href: string } => Boolean(item))
}

export function describeIdentifierState(vuln: WithIdentifiers) {
  if (vuln.cve_id || vuln.cnnvd_id) {
    return ''
  }
  if (vuln.check_type === 'auth_check' || vuln.check_type === 'skills_check') {
    return '内置暴露检查，无对应CVE'
  }
  if (vuln.check_type === 'poc_verify') {
    return 'PoC已命中，但未提供外部编号'
  }
  return '暂无漏洞编号'
}

export function getPreferredDescription(vuln: Vulnerability) {
  return vuln.description_zh || vuln.description || ''
}
