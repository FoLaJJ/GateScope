package l3

import (
	"fmt"
	"strings"

	"github.com/AutoScan/agentscan/internal/models"
)

func LocalizeVulnerability(vuln models.Vulnerability) models.Vulnerability {
	if strings.TrimSpace(vuln.DescriptionZH) != "" {
		return vuln
	}

	if rule, ok := findOpenClawRuleByIdentifiers(vuln.CVEID, vuln.CNNVDID, vuln.GHSAID); ok && strings.TrimSpace(rule.DescriptionZH) != "" {
		vuln.DescriptionZH = rule.DescriptionZH
		return vuln
	}

	vuln.DescriptionZH = fallbackDescriptionZH(vuln)
	return vuln
}

func findOpenClawRuleByIdentifiers(cveID, cnnvdID, ghsaID string) (CVEEntry, bool) {
	rules := getOpenClawCVEs()

	if rule, ok := findRuleByAlias(cveID, loadedCVEAliases); ok {
		return rule, true
	}
	if rule, ok := findRuleByAlias(cnnvdID, loadedCNNVDAliases); ok {
		return rule, true
	}
	if rule, ok := findRuleByAlias(ghsaID, loadedGHSAAliases); ok {
		return rule, true
	}

	for _, rule := range rules {
		switch {
		case cveID != "" && (rule.CVEID == cveID || rule.ID == cveID):
			return rule, true
		case cnnvdID != "" && rule.CNNVDID == cnnvdID:
			return rule, true
		case ghsaID != "" && (rule.GHSAID == ghsaID || rule.ID == ghsaID):
			return rule, true
		}
	}
	return CVEEntry{}, false
}

func findRuleByAlias(identifier string, aliases map[string]string) (CVEEntry, bool) {
	id := strings.TrimSpace(identifier)
	if id == "" || len(aliases) == 0 {
		return CVEEntry{}, false
	}
	ruleID, ok := aliases[id]
	if !ok {
		return CVEEntry{}, false
	}
	for _, rule := range getOpenClawCVEs() {
		if rule.ID == ruleID {
			return rule, true
		}
	}
	return CVEEntry{}, false
}

func ensureRuleChineseDescriptions() {
	for i := range loadedOpenClawCVEs {
		rule := &loadedOpenClawCVEs[i]
		if strings.TrimSpace(rule.DescriptionZH) != "" {
			continue
		}
		rule.DescriptionZH = buildRuleDescriptionZH(*rule)
	}
}

func buildRuleDescriptionZH(rule CVEEntry) string {
	title := strings.TrimSpace(rule.Title)
	versionScope := ""
	if strings.TrimSpace(rule.AffectedBefore) != "" {
		versionScope = fmt.Sprintf("受影响版本为 %s 之前。", strings.TrimSpace(rule.AffectedBefore))
	}

	return strings.TrimSpace(fmt.Sprintf("该漏洞与“%s”相关。%s%s", fallbackRuleTitle(title), versionScope, inferChineseImpact(rule)))
}

func fallbackRuleTitle(title string) string {
	if title == "" {
		return "OpenClaw 漏洞"
	}
	return title
}

func fallbackDescriptionZH(vuln models.Vulnerability) string {
	switch vuln.CheckType {
	case "auth_check":
		switch {
		case strings.Contains(strings.ToLower(vuln.Title), "no authentication") || strings.Contains(strings.ToLower(vuln.Description), "no authentication"):
			return "目标未启用认证，攻击者可直接访问接口与能力，风险较高。"
		case strings.Contains(strings.ToLower(vuln.Description), "unknown authentication mode"):
			return "目标返回了无法识别的认证模式，建议核实当前认证配置与访问控制策略。"
		default:
			return "检测过程中发现认证配置存在异常或强度不足，建议尽快核查。"
		}
	case "skills_check":
		switch {
		case strings.HasPrefix(vuln.Title, "Skills Enumeration:"):
			return "目标公开暴露了技能列表，攻击者可据此分析已安装能力并扩大攻击面。"
		case strings.HasPrefix(vuln.Title, "Malicious Skill Detected:"):
			return "检测到命中恶意规则的技能，建议立即下线并排查主机受控迹象。"
		case strings.HasPrefix(vuln.Title, "Suspicious Skill:"):
			return "检测到存在可疑特征的技能，建议人工复核其来源、代码与权限。"
		}
	case "poc_verify":
		return "已通过本地 PoC 对该漏洞进行实证验证，说明目标存在可被利用的真实风险。"
	}

	return strings.TrimSpace(fmt.Sprintf("该漏洞与“%s”相关。%s", fallbackRuleTitle(strings.TrimSpace(vuln.Title)), inferChineseImpact(CVEEntry{
		Title:       vuln.Title,
		Description: vuln.Description,
	})))
}

func inferChineseImpact(rule CVEEntry) string {
	text := strings.ToLower(strings.Join([]string{rule.Title, rule.Description}, " "))

	switch {
	case containsAny(text, "command injection", "remote code execution", "code execution", "code injection", "shell", "exec ", "exec-", "arbitrary code"):
		return "成功利用后可能导致命令注入或任意代码执行。"
	case containsAny(text, "path traversal", "directory traversal", "symlink", "workspace escape", "sandbox escape", "sandbox boundary", "local root"):
		return "成功利用后可能导致目录遍历、越权读写或沙箱边界突破。"
	case containsAny(text, "authentication bypass", "authorization bypass", "access control", "privilege escalation", "scope validation", "allowlist bypass", "policy bypass"):
		return "成功利用后可能导致未授权访问、权限提升或安全策略绕过。"
	case containsAny(text, "xss", "cross-site scripting", "prompt injection"):
		return "成功利用后可能导致跨站脚本、提示注入或界面上下文被劫持。"
	case containsAny(text, "ssrf", "server-side request forgery", "proxy", "fetch internal"):
		return "成功利用后可能导致服务端请求伪造并访问内网或云元数据资源。"
	case containsAny(text, "information disclosure", "info disclosure", "leak", "disclosure", "transcript", "timing", "credential"):
		return "成功利用后可能导致敏感信息、凭证或内部状态泄露。"
	case containsAny(text, "dos", "denial of service", "memory", "resource exhaustion", "buffered", "unbounded"):
		return "成功利用后可能导致拒绝服务、资源耗尽或稳定性下降。"
	case containsAny(text, "spoof", "forged", "replay", "brute force", "token prediction", "forgery"):
		return "成功利用后可能导致身份伪造、请求重放或认证被暴力猜解。"
	default:
		return "成功利用后会对 OpenClaw 的认证、授权、沙箱隔离或运行安全造成影响。"
	}
}

func containsAny(text string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}
