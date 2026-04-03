# GateScope

[English](README.en.md)

独立维护的 AI Agent 暴露面发现与漏洞审计项目，基于 `AutoScan/agentscan` 做了面向实战落地的一轮增强，而不是简单换名。

当前维护仓库：
- `https://github.com/FoLaJJ/GateScope`

上游原仓库：
- `https://github.com/AutoScan/agentscan`

许可证：
- `MIT`

归属和衍生说明：
- 见 [NOTICE](NOTICE)

## 这次 fork 主要改了什么

- 增加一站式控制脚本 `./agentscanctl`，统一安装、构建、启动、停止、重启、状态、日志、环境检查、数据库备份、清理、重置。
- 保留 `./gatescopectl` 作为别名包装，但文档默认以 `agentscanctl` 为主。
- 修复前端 `/index.html` 持续 `301` 跳转的问题。
- 登录页默认回填账号密码，网页端可直接一键登录。
- 扫描任务事件改为可持久化和历史回放，任务结束后不再出现“事件为 0”的空白体验。
- 网页端任务详情和漏洞页补充 IP、端口、Agent 类型、版本、认证方式、证据详情，直接能看到“哪个 IP 有哪个漏洞”。
- Excel 导出补全漏洞与资产归属，并保留更完整的证据字段。
- OpenClaw 漏洞库改为 YAML 外置维护，便于后续持续新增。
- 相同资产下同一 CVE 命中时，PoC 实证结果优先于纯版本命中。
- 页面中增加规则库元数据，能直接看到漏洞库截止日期和规则规模。

## OpenClaw 规则库状态

- 当前规则更新时间：`2026-04-03`
- 上游核对截止：`2026-04-02`
- 当前 OpenClaw CVE 规则：`36`
- 当前本地 PoC 规则：`4`
- 相比上游当前内置的 `7` 条 OpenClaw CVE，当前 fork 已扩展到 `36` 条，净增 `29` 条

当前 CVE 严重等级分布：
- `critical`: `8`
- `high`: `18`
- `medium`: `9`
- `low`: `1`

规则文件位置：
- `configs/rules/openclaw-cves.yaml`
- `configs/rules/pocs.yaml`
- `configs/rules/skills.yaml`

规则判断原则：
- 优先使用 PoC 实证结果，保证更客观
- 其次才使用版本号命中
- PoC 规则带 `cve_id` 时，会继承对应 CVE 的严重等级、CVSS 和修复建议，避免同一漏洞多套口径

## 页面展示

登录页：

![GateScope Login](docs/screenshots/login.png)

扫描任务页：

![GateScope Tasks](docs/screenshots/tasks.png)

漏洞列表页：

![GateScope Vulnerabilities](docs/screenshots/vulnerabilities.png)

## 一键运行

1. 克隆仓库

```bash
git clone https://github.com/FoLaJJ/GateScope.git
cd GateScope
```

2. 准备配置

```bash
cp configs/config.yaml.example _data/config.yaml
```

3. 一站式控制

```bash
./agentscanctl install
./agentscanctl start
./agentscanctl status
./agentscanctl logs --lines 200
./agentscanctl stop
```

常用附加动作：

```bash
./agentscanctl restart
./agentscanctl backup-db
./agentscanctl cleanup-db
./agentscanctl reset-db
./agentscanctl doctor
./agentscanctl env
```

别名入口：

```bash
./gatescopectl start
```

默认登录信息：
- 用户名：`admin`
- 密码：`agentscan`

## 目录重点

- `agentscanctl`: 一站式运维入口
- `gatescopectl`: 对外别名入口
- `configs/rules/`: OpenClaw 规则库
- `internal/`: 后端核心逻辑
- `web/`: 前端页面
- `docs/screenshots/`: README 展示图

## 兼容性说明

- 当前版本内部 Go module/import path 仍保留 `github.com/AutoScan/agentscan`
- 这是有意保留的兼容策略，用来避免一次性大改带来的额外风险
- 对外发布名、README、界面文案和交付方式已经按独立项目维护
