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

## 本次更改

- 增加一站式控制脚本 `./agentscanctl`，统一安装、构建、启动、停止、重启、状态、日志、环境检查、数据库备份、清理、重置。
- 保留 `./gatescopectl` 作为别名包装，但文档默认以 `agentscanctl` 为主。
- 修复前端 `/index.html` 持续 `301` 跳转的问题。
- 登录页默认回填账号密码，网页端可直接一键登录。
- 扫描任务事件改为可持久化和历史回放，任务结束后不再出现“事件为 0”的空白体验。
- 网页端任务详情和漏洞页补充 IP、端口、Agent 类型、版本、认证方式、证据详情，直接能看到“哪个 IP 有哪个漏洞”。
- Excel 导出补全漏洞与资产归属，并保留更完整的证据字段。
- OpenClaw 漏洞库改为纯 YAML 外置维护，程序仅负责加载、校验和展示，便于后续持续新增。
- 相同资产下同一 CVE 会先跑 PoC 实证，再用版本规则补充未被 PoC 命中的条目。
- 页面中增加规则库元数据，能直接看到漏洞库截止日期和规则规模。
- 版本规则补充 `GHSA/CNNVD` 外部编号字段，漏洞详情、任务详情和 Excel 导出可直接看到关联编号。
- 版本规则与漏洞结果补充 `description_zh` 中文描述字段，页面与导出同时展示中英文说明。
- 漏洞规则从“代码内置兜底”改成“YAML 唯一事实源”，避免以后每次补规则都改程序。
- 新增 131 条基于 NVD OpenClaw 记录生成的版本规则，并补齐 1 条遗漏的官方 GHSA，当前规则库总量提升到 `177` 条。
- `configs/rules/openclaw-id-mappings.yaml` 已合并 `155` 条 CNNVD 批量映射，页面和导出可直接渲染多编号。
- 规则 schema 扩展出 `CNNVD/GHSA` 字段，PoC 命中时也会继承对应外部编号。
- `177` 条 OpenClaw 版本规则已全部补齐 `description_zh`，漏洞详情页、任务详情页和 Excel 报告会同时展示中英文描述。
- 新增 `scripts/verify_openclaw_ghsa.py`，可直接对照 OpenClaw GitHub 官方 advisories 校验本地 GHSA-only 规则编号和标题是否失真。
- 新增 `scripts/verify_openclaw_poc_mappings.py`，可直接对照 NVD 在线元数据校验本地 `4` 条 PoC 规则关联的 `CVE/GHSA/严重等级/CVSS/修复版本` 是否一致。
- 新增 `scripts/repair_vulnerability_catalog.py`，可按当前 YAML 规则库批量修复数据库内历史漏洞记录的 `CVE/CNNVD/GHSA/标题/等级/中文描述`。
- 漏洞列表、任务详情、Dashboard 最近漏洞、Excel 报告都能展示 `CVE/CNNVD/GHSA`。
- 规则元数据新增总规则数、`CVE/CNNVD/GHSA/PoC` 分项统计。
- 漏洞页新增编号类型选择，可按 `CVE/CNNVD/GHSA` 精确筛选。
- 修复 SQLite 并发写入导致的“任务统计有 Agent，但 `assets` 表少记录”问题；SQLite 模式现在强制单连接、`busy_timeout` 和 `WAL`。
- 新增资产持久化保护：`UpsertAsset` 命中旧资产时会回写真实资产 ID，漏洞入库前会同步重映射，避免产生孤儿漏洞。
- 新增 `007` 数据修复迁移：会从 `task_events` 的 `agent.identified` 事件里自动回填历史漏写资产，并把原来失联的漏洞重新挂回资产。
- 前端导航收敛为 `态势大屏 / 扫描任务 / 资产管理 / 漏洞清单` 四个主视图，移除告警中心和情报中心，页面结构更直接。
- 新增 `web/public/favicon.svg`，浏览器标签页会显示 GateScope 的站点图标。
- `agentscanctl` 的 `status/start/stop/reset-db` 不再只信任当前目录的 PID 文件；会额外识别目标端口上的 `agentscan server` 进程，能区分“本 checkout 管理实例”和“其他 checkout 启动的实例”。
- 后端启动时会先执行中断任务恢复和历史资产风险回算；异常退出留下的运行中任务会被自动标记为中断取消，旧资产风险会按“认证暴露基线 + 该资产最高漏洞等级取最大值”重新修正。
- 前端 API 增加 `X-GateScope-Instance` 运行实例标识联动；后端实例变化时会主动 `resetQueries`，WebSocket 重连后会统一 `invalidateQueries`，减少 `reset-db` 或服务重启后页面残留旧缓存。
- WebSocket 客户端补充心跳、指数退避重连和重连后的全局刷新联动，首次点开任务详情页时的连接稳定性更好。
- 任务详情页把依赖数据的 hooks 固定放在加载态判断之前，修复首次查看详情时偶发的前端报错。
- 风险和严重等级颜色统一成三层级口径：`critical/high` 使用红色，`medium` 使用黄色，`low/info` 使用绿色；态势大屏中的“资产风险分布”按红/绿两档聚合展示，“漏洞严重等级”和资产/漏洞标签保持一致。
- 页面文案里的“置信度”统一明确为“识别置信度”，避免与漏洞验证置信度混淆。
- 默认扫描端口集统一补入 `18790`，配置模板、CLI 默认参数、后端扫描管线和前端新建任务表单保持一致。

## OpenClaw 规则库状态

- 当前规则更新时间：`2026-04-03`
- 上游核对截止：`2026-04-03`
- 当前 OpenClaw 版本规则：`177`
- 当前其中 CVE 规则：`167`
- 当前其中 GHSA 规则：`10`
- 当前其中 CNNVD 规则：`161`（已合并 155 条 2026 年 3 月 CNNVD OpenClaw 批量映射，并保留此前已核实的历史映射）
- 当前本地 PoC 规则：`4`
- 相比上游当前内置的 `7` 条 OpenClaw CVE，当前 fork 已扩展到 `177` 条版本规则，净增 `170` 条

当前版本规则严重等级分布：
- `critical`: `16`
- `high`: `62`
- `medium`: `85`
- `low`: `14`

规则文件位置：
- `configs/rules/openclaw-cves.yaml`
- `configs/rules/openclaw-id-mappings.yaml`
- `configs/rules/pocs.yaml`
- `configs/rules/skills.yaml`

规则判断原则：
- 先执行 PoC 实证命中，保证高置信度漏洞优先落库
- 仅对未被 PoC 命中的漏洞再使用版本号补充
- PoC 规则带 `cve_id` 时，会继承对应 CVE 的严重等级、CVSS 和修复建议，避免同一漏洞多套口径
- 所有版本规则均从 `configs/rules/openclaw-cves.yaml` 加载，新增/修订规则无需改 Go 代码
- 多编号别名从 `configs/rules/openclaw-id-mappings.yaml` 合并；同一漏洞若同时存在 `CVE/CNNVD/GHSA`，页面和导出会一起渲染
- 规则条目新增 `description_zh` 字段；旧漏洞记录在读取时也会按当前规则自动补齐中文描述
- 已合并的 CNNVD 映射已扩展为 155 条 OpenClaw 批量清单，并保留先前补录的历史映射；后续新增编号继续只需维护 `configs/rules/openclaw-id-mappings.yaml`

## 页面展示

当前登录页（2026-04-04，简化后的新版配色与一键登录入口）：

![GateScope Login Current](./docs/screenshots/login-current.png)

## 本次新增的官方漏洞

- 在原有 `10` 条 `GHSA` 官方规则基础上，本轮继续补齐 `131` 条基于 `NVD + CNNVD OpenClaw 批量清单` 的版本规则，重点覆盖 `CVE-2026-320xx`、`CVE-2026-329xx`、`CVE-2026-221xx`、`CVE-2026-275xx`、`CVE-2026-328xx`、`CVE-2026-345xx` 等批次。
- 新增批次里包含大量此前页面完全看不到的 `访问控制错误`、`路径遍历`、`操作系统命令注入`、`代码问题`、`信息泄露`、`日志信息泄露`、`跨站脚本`、`参数注入`、`后置链接`、`竞争条件问题` 漏洞。
- 这批规则全部走 `configs/rules/openclaw-cves.yaml + configs/rules/openclaw-id-mappings.yaml` 外置维护，不再把 CNNVD/CVE 映射写死在程序里。

- `GHSA-846p-hgpv-vphc`：QQ Bot 结构化媒体载荷可读取任意本地文件，修复版本 `>= 2026.4.2`
- `GHSA-m34q-h93w-vg5x`：OpenShell mirror 模式在根路径配置失当时可删除任意远程目录，修复版本 `>= 2026.4.2`
- `GHSA-98ch-45wp-ch47`：兼容 Windows 的环境变量覆盖键可绕过 `system.run` 审批绑定，修复版本 `>= 2026.4.2`
- `GHSA-2f7j-rp58-mr42`：Gateway hello 快照向非管理员泄露主机配置和状态目录路径，修复版本 `>= 2026.4.2`
- `GHSA-2qrv-rc5x-2g2h`：未受信任的工作区 channel shadow 可在内置 channel 初始化时执行，修复版本 `>= 2026.4.2`
- `GHSA-5hff-46vh-rxmw`：只读权限的身份承载式 HTTP 客户端仍可调用会话终止接口，修复版本 `>= 2026.4.2`
- `GHSA-9jpj-g8vv-j5mf`：Gemini OAuth 会通过 `state` 参数泄露 PKCE verifier，修复版本 `>= 2026.4.2`
- `GHSA-4p4f-fc8q-84m3`：iOS A2UI bridge 错信任局域网页面并触发 `agent.request`，修复版本 `>= 2026.4.2`
- `GHSA-jj6q-rrrf-h66h`：shared-secret 比较路径存在长度时序泄露，修复版本 `>= 2026.4.2`
- `GHSA-fvx6-pj3r-5q4q`：复杂解释器管道可绕过 exec 脚本预检，修复版本 `>= 2026.4.2`

登录页：

![GateScope Login](./docs/screenshots/login.png)

扫描任务页：

![GateScope Tasks](./docs/screenshots/tasks.png)

漏洞列表页：

![GateScope Vulnerabilities](./docs/screenshots/vulnerabilities.png)

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
