import { describe, expect, it } from 'vitest'
import { makeVulnerability } from '@/test-utils/fixtures'
import { buildCnnvdUrl, describeIdentifierState, listVulnerabilityIdentifiers } from './vuln'

describe('vulnerability link helpers', () => {
  it('builds official CNNVD global search links for CNNVD identifiers', () => {
    expect(buildCnnvdUrl('CNNVD-202603-5854')).toBe(
      'https://www.cnnvd.org.cn/home/globalSearch?keyword=CNNVD-202603-5854',
    )
  })

  it('renders all identifiers with corrected external links', () => {
    const vuln = makeVulnerability({
      agent_type: 'openclaw',
      cve_id: 'CVE-2026-32987',
      cnnvd_id: 'CNNVD-202603-5854',
      title: 'OpenClaw 安全漏洞',
    })

    expect(listVulnerabilityIdentifiers(vuln)).toEqual([
      {
        key: 'cve:CVE-2026-32987',
        label: 'CVE-2026-32987',
        href: 'https://www.cve.org/CVERecord?id=CVE-2026-32987',
      },
      {
        key: 'cnnvd:CNNVD-202603-5854',
        label: 'CNNVD-202603-5854',
        href: 'https://www.cnnvd.org.cn/home/globalSearch?keyword=CNNVD-202603-5854',
      },
    ])
  })

  it('labels internal exposure findings without external identifiers', () => {
    expect(
      describeIdentifierState(
        makeVulnerability({
          cve_id: '',
          cnnvd_id: '',
          check_type: 'auth_check',
        }),
      ),
    ).toBe('内置暴露检查，无对应CVE')
  })
})
