import { describe, expect, it } from 'vitest'
import { makeVulnerability } from '@/test-utils/fixtures'
import { buildCnnvdUrl, buildGhsaUrl, listVulnerabilityIdentifiers } from './vuln'

describe('vulnerability link helpers', () => {
  it('builds official CNNVD global search links for CNNVD identifiers', () => {
    expect(buildCnnvdUrl('CNNVD-202603-5854')).toBe(
      'https://www.cnnvd.org.cn/home/globalSearch?keyword=CNNVD-202603-5854',
    )
  })

  it('prefers OpenClaw repository GHSA links for OpenClaw vulnerabilities', () => {
    const vuln = makeVulnerability({
      agent_type: 'openclaw',
      ghsa_id: 'GHSA-2qrv-rc5x-2g2h',
      title: 'OpenClaw 安全漏洞',
    })

    expect(buildGhsaUrl(vuln)).toBe('https://github.com/openclaw/openclaw/security/advisories/GHSA-2qrv-rc5x-2g2h')
  })

  it('renders all identifiers with corrected external links', () => {
    const vuln = makeVulnerability({
      agent_type: 'openclaw',
      cve_id: 'CVE-2026-32987',
      cnnvd_id: 'CNNVD-202603-5854',
      ghsa_id: 'GHSA-2qrv-rc5x-2g2h',
      title: 'OpenClaw 安全漏洞',
    })

    expect(listVulnerabilityIdentifiers(vuln)).toEqual([
      {
        key: 'cve:CVE-2026-32987',
        label: 'CVE-2026-32987',
        href: 'https://nvd.nist.gov/vuln/detail/CVE-2026-32987',
      },
      {
        key: 'cnnvd:CNNVD-202603-5854',
        label: 'CNNVD-202603-5854',
        href: 'https://www.cnnvd.org.cn/home/globalSearch?keyword=CNNVD-202603-5854',
      },
      {
        key: 'ghsa:GHSA-2qrv-rc5x-2g2h',
        label: 'GHSA-2qrv-rc5x-2g2h',
        href: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-2qrv-rc5x-2g2h',
      },
    ])
  })
})
