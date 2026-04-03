# GateScope

[English](README.md)

**独立发布的 AI Agent 暴露面发现与安全审计平台**

> 检测、识别和评估网络中暴露的 AI Agent 实例 —— 从内网到公网。

---

## 为什么需要 GateScope？

2026 年初，以 OpenClaw 为代表的开源 AI Agent 平台爆发式增长，大量非技术用户在主力电脑上以高权限、默认配置部署，导致严重的安全危机：

- **4.29 万+** OpenClaw 实例暴露在公网，93% 存在认证绕过
- **默认绑定 `0.0.0.0:18789`**，85% 部署直接暴露至公网
- **341+ 恶意技能包**投毒官方市场
- **150 万 API Token 泄露**，3.5 万用户邮箱曝光
- 工信部发布安全预警，银行/国企/券商全面禁用

与此同时，clawhive、GoGogot、Hermes Agent、Pincer 等同类平台层出不穷，安全隐患更加隐蔽。

GateScope 为组织提供一站式 AI Agent 暴露面发现、漏洞检测与合规审计能力。

## 核心特性

- **分层扫描** —— L1 端口发现 → L2 指纹识别 → L3 漏洞验证
- **多平台支持** —— OpenClaw（全版本）+ clawhive + GoGogot + Hermes + Pincer
- **CVE 检测** —— OpenClaw CVE 规则集、认证绕过检查、Skills 枚举、PoC 验证
- **实时大屏** —— React + ECharts，WebSocket 实时更新
- **任务管理** —— 单次/定时/周期扫描任务，Cron 调度
- **告警引擎** —— 可配规则 + Webhook 通知 + 历史记录持久化
- **Excel 报告** —— 4 张工作表导出（概况/资产/漏洞/修复清单）
- **威胁情报** —— FOFA 集成，支持互联网规模发现
- **GeoIP 就绪** —— MaxMind GeoLite2 接口，支持按区域扫描

## Fork 变更声明

本 fork 保留了上游项目的总体结构、主要模块划分和基本使用方式。下面记录的是面向实际运维和落地使用所做的增量修改，而不是对上游项目的大规模重构。

### 本 fork 已增加的内容

- 新增统一控制入口 `./agentscanctl`，整合安装、构建、启动、停止、重启、状态查看、日志查看、环境检查、数据库备份、清理和重置。
- 新增 `./gatescopectl` 作为更贴合新项目名称的包装入口，同时保留 `agentscanctl` 兼容旧习惯。
- 在 `scripts/` 下保留兼容型转发脚本，方便老习惯继续使用，但推荐统一用 `agentscanctl`。
- 修复前端静态资源路由问题，避免 `/index.html` 持续 `301` 跳转。
- 登录页增加默认账号密码回填，网页端可一键登录。
- 新增任务事件持久化与历史回放，已完成任务不再只能依赖实时 WebSocket 才能看到事件。
- 网页端任务详情页和漏洞页补充资产上下文，可直接看到对应 IP、端口、Agent 类型、版本、认证方式及证据详情。
- Excel 报告导出补充漏洞对应资产归属，避免必须额外推断受影响主机。
- 新扫描结果与新导出报告保留完整证据字符串，不再在扫描阶段截断。
- 将 OpenClaw 规则数据外置到 `configs/rules/` 下，便于后续维护。
- 新增规则库元数据展示，包括规则更新时间、上游核对截止时间、规则数量和一致性检查结果。
- 对带 `cve_id` 的 PoC 条目加入归一化逻辑，优先继承对应 CVE 的严重等级、CVSS 和修复建议，减少规则漂移。
- 对相同资产、相同 CVE 的重复结果做优先级处理，PoC 实证优先于纯版本命中。

### 当前 OpenClaw 规则说明

- 当前分支会在界面和 API 中展示规则库元数据。
- 当前规则元数据为：
  - 规则更新时间：`2026-04-03`
  - 上游核对截止：`2026-04-02`
  - OpenClaw CVE 规则数：`36`
  - PoC 规则数：`4`
- 版本命中证据中的 `local_poc_rule=available` 仅表示本地规则库存在对应的 PoC 规则，不表示一定存在已独立验证的公开利用代码。

### 文档范围说明

- 本 README 主要补充 fork 版本新增的运维能力、规则管理方式和界面改动说明。
- 上游原有架构、模块布局和主流程保持原样，不做改写。

## 快速开始

### 环境要求

- Go 1.23+（需启用 CGO 以支持 SQLite）
- Node.js 18+（前端）

### 1. 克隆仓库

```bash
git clone <你的仓库地址> GateScope
cd GateScope
```

### 2. 配置

```bash
cp configs/config.yaml.example _data/config.yaml
# 根据需要编辑 _data/config.yaml
```

### 3. 启动后端

```bash
go run cmd/agentscan/main.go server
```

### 4. 启动前端（开发模式）

```bash
cd web && npm install && npm run dev
```

### 5. 登录

打开 `http://localhost:5173`，使用默认账号登录：
- 用户名：`admin`
- 密码：`agentscan`

### 一站式运行控制

对于长期运行或打包部署，建议优先使用统一控制脚本：

```bash
./gatescopectl install
./gatescopectl start
./gatescopectl status
./gatescopectl logs --lines 200
./gatescopectl stop
```

当前支持的主要动作包括：

- `install`
- `build`
- `start`
- `stop`
- `restart`
- `status`
- `logs`
- `env`
- `doctor`
- `backup-db`
- `cleanup-db`
- `reset-db`

### Docker 快速启动

```bash
docker run -d --name agentscan -p 8080:8080 \
  -v agentscan-data:/data \
  -e AGENTSCAN_AUTH_JWT_SECRET=my-secret \
  ghcr.io/autoscan/agentscan:latest
```

或使用 Docker Compose：

```bash
curl -O <你发布后的仓库地址>/docker-compose.yml
docker compose up -d
```

打开 `http://localhost:8080` 即可访问。

### 命令行扫描

```bash
go run cmd/agentscan/main.go scan --targets 192.168.1.0/24
```

## 架构概览

```
┌─────────────┐     ┌──────────────────────────────────────────┐
│  React SPA  │────▶│  Gin REST API + WebSocket                │
│  Ant Design │◀────│  JWT 认证 · CORS · RequestID · 访问日志   │
│  ECharts    │     └──────────┬───────────────────────────────┘
└─────────────┘                │
                    ┌──────────▼───────────────┐
                    │      扫描流水线引擎       │
                    │  L1 端口 → L2 指纹 → L3 漏洞│
                    └──────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌───────────┐   ┌──────────────┐
        │  事件总线  │   │  数据存储  │   │   告警引擎   │
        │ (发布/订阅)│   │(GORM/SQL) │   │  (Webhook)   │
        └──────────┘   └───────────┘   └──────────────┘
```

### 扫描层级

| 层级 | 功能 | 实现方式 |
|------|------|----------|
| **L1** | 端口发现 | TCP CONNECT 扫描，可配并发数 |
| **L2** | 指纹识别 | HTTP/WebSocket/mDNS 探针，Agent 类型识别 |
| **L3** | 漏洞验证 | CVE 匹配、认证绕过检测、Skills 枚举、PoC 验证 |

## 技术栈

| 组件 | 技术方案 |
|------|----------|
| 后端 | Go 1.23 · Gin · GORM · Cobra · Viper · zap |
| 前端 | React 18 · TypeScript · Ant Design · ECharts · Zustand · TanStack Query |
| 数据库 | SQLite（开发）/ PostgreSQL（生产） |
| 构建 | `go build`（后端）· Vite（前端） |

## 目录结构

```
GateScope/
├── cmd/agentscan/          # CLI 入口（server/scan/migrate/version）
├── cmd/mock-openclaw/      # 测试用模拟目标服务器
├── configs/                # 配置模板（config.yaml.example）
├── _data/                  # 运行时数据 — 数据库和配置（已 gitignore）
├── internal/
│   ├── core/               # 基础设施（配置、事件总线、日志）
│   ├── utils/              # 纯工具函数（IP 解析、版本比较）
│   ├── models/             # GORM 数据模型
│   ├── store/              # 持久化层（SQLite/PostgreSQL）
│   ├── scanner/l1/         # TCP 端口扫描器
│   ├── scanner/l2/         # HTTP/WS/mDNS 指纹识别
│   ├── scanner/l3/         # CVE/认证/Skills/PoC 检测
│   ├── engine/             # L1→L2→L3 流水线编排
│   ├── api/                # REST API + WebSocket
│   ├── auth/               # JWT 认证
│   ├── task/               # 任务管理 + Cron 调度
│   ├── alert/              # 告警引擎
│   ├── report/             # Excel 报告生成
│   ├── intel/              # FOFA 威胁情报
│   └── geoip/              # GeoIP 服务
├── web/                    # React 前端
├── AGENTS.md               # AI 编码助手指南
└── scripts/                # 实用脚本
```

## 配置说明

GateScope 使用 [Viper](https://github.com/spf13/viper) 进行配置管理，优先级如下：

1. CLI 参数（`--config path/to/config.yaml`）
2. 环境变量（`AGENTSCAN_SERVER_PORT=9090`）
3. 配置文件（搜索路径：`./` → `./configs/` → `./_data/` → `/etc/agentscan/`）
4. 内置默认值

完整配置项参见 `configs/config.yaml.example`。

## 规则数据说明

本 fork 中 OpenClaw 规则数据主要以 YAML 形式存储，并在运行时加载：

- `configs/rules/openclaw-cves.yaml`
- `configs/rules/pocs.yaml`
- `configs/rules/skills.yaml`

运行逻辑说明：

- 当能识别到版本号时，CVE 检测以版本命中为主。
- PoC 验证独立执行，并可在相同资产/相同 CVE 下覆盖纯版本命中结果。
- 规则元数据会通过 API 和界面展示，方便直接看到当前规则生效日期和上游核对截止时间。

## 开发指南

```bash
make build        # 构建前端 + 后端（单二进制 → bin/agentscan）
make dev          # 启动后端（go run 或 air 热重载）
make dev-web      # 启动前端 Vite 开发服务器
make dev-all      # 同时启动前后端
make test         # go test ./...
make lint         # go vet ./...
make docker       # 本地构建 Docker 镜像
make help         # 显示所有可用命令
```

### Docker

```bash
# 本地构建
make docker

# 使用 docker-compose 启动
docker compose up -d

# 停止
docker compose down
```

Docker 镜像采用多阶段构建，最终产出约 30 MB 的 Alpine 镜像，前端已静态嵌入。
数据存储在 `/data` 卷中，通过环境变量（`AGENTSCAN_*`）进行配置。

## 路线图

| 阶段 | 重点方向 | 状态 |
|------|---------|------|
| **P1** | L1/L2/L3 扫描流水线、REST API、React 大屏、JWT 认证、任务管理、告警引擎、Excel 报告 | 已完成 |
| **P2** | SYN 扫描、并发 L2、YAML 指纹/CVE 数据库、RBAC 权限、限流、Prometheus 指标、健康检查 | 计划中 |
| **P3** | Redis 事件总线、ClickHouse 时序存储、PDF/Word 报告、Swagger/OpenAPI 文档 | 计划中 |
| **P4** | 分布式 Worker（gRPC）、多租户、SSO（LDAP/OAuth2）、资产分组、合规模板、国际化 | 远期 |

## 参与贡献

欢迎提交贡献，请遵循以下流程：

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feature/amazing-feature`）
3. 提交前运行 `go build ./...` 和 `go test ./...`
4. 使用清晰的提交信息（`模块: 操作描述`）
5. 提交 Pull Request

## 许可证

[MIT](LICENSE)

## 干净发布说明

当需要导出、压缩或归档本 fork 时，建议排除以下运行时和依赖产物：

- `.git/`
- `_data/`
- `bin/`
- `web/node_modules/`
- `web/dist/`
- `*.bak.*`
- `*.backup`

这样打出的包只包含源码、配置模板、脚本和文档，更适合分发和备份。

## 独立项目说明

本目录现在是一个可独立发布的新项目，而不是等待合并回上游的分支。

- 对外项目名：`GateScope`
- 上游基础项目：`AutoScan/agentscan`
- 许可证基础：`MIT`
- 上游归属与衍生说明：见 [NOTICE](NOTICE)

兼容性说明：

- 当前版本内部 Go 模块导入路径仍保留 `github.com/AutoScan/agentscan`
- 这是为了降低不必要的大范围重构风险，同时保证该版本可以独立发布和继续维护
