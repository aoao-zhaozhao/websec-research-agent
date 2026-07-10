# My Agent - 生产级开发路线图

## 当前状态：v1.1.0

当前 Agent 已具备 Web 安全扫描的基础闭环：

- LangGraph ReAct 引擎
- FastAPI + WebSocket 工作台
- 同源爬取、站点地图、安全头检查
- JS/API/JWT/SPA 分析
- LFI 专项验证工具
- 本地 RAG 知识库，支持 Qwen3 Embedding + Reranker，并已做 CUDA 加速
- 浏览器侧会话缓存、工具调用轨迹、停止扫描能力

当前短板也很明确：

- 扫描状态和当前会话证据仍保存在浏览器端；跨浏览器的历史、复测与差异对比仍需持久化层。

因此下一阶段优先级为：进入 v1.2，补认证上下文和多角色权限对比。

---

## v0.9 - 结构化证据协议 + 工具可靠性 ✅

> 目标：从“会调用工具的聊天 Agent”升级为“能产出结构化证据的扫描 Agent”。

### 为什么先做 v0.9

继续堆 UI 或新工具会让系统越来越难维护。当前工具结果多为自然语言文本，前端、报告、历史对比、复测都只能靠解析字符串。v0.9 先定义统一证据协议，让每次扫描都能沉淀为稳定数据。

### 工程改动

| 模块 | 内容 |
|---|---|
| 工具结果协议 | 新增统一结果结构：`tool`、`target`、`status`、`summary`、`findings`、`errors`、`raw_excerpt` |
| 证据模型 | 新增 `Finding` / `Evidence` / `RequestRecord` / `ResponseRecord` 数据结构 |
| 置信度字段 | 所有风险输出必须标记 `confirmed` / `likely` / `weak` / `info` |
| 复现字段 | 可疑或已确认漏洞必须包含 URL、参数、payload、响应差异摘要和复现步骤 |
| 工具适配 | `analyze_headers`、`extract_forms`、`extract_links`、`crawl`、`batch_scan`、`test_lfi_param` 逐步返回结构化结果 |
| 文本兼容 | 保留面向 LLM 的 readable summary，避免一次性重写 Agent 编排 |
| 错误分类 | 统一区分 timeout、connection_error、parse_error、out_of_scope、tool_bug |
| 工具回归测试 | 建立本地小型靶场或 mock HTTP 响应，覆盖 crawl/forms/links/headers/LFI |
| 已知问题修复 | 修复 `extract_links` 绕过统一 `http_client` 且缺少 `requests` import 的运行时问题 |
| HTTP 方法验证 | 新增受约束的 `http_request`，支持 GET/POST/PUT/PATCH/HEAD/OPTIONS，复用统一请求边界并拒绝 DELETE/TRACE/CONNECT |

### 交付标准

- 所有核心工具至少返回一个统一 envelope。
- 前端仍能展示现有文本流。
- Agent 最终报告能引用结构化 evidence，而不是只引用工具文本。
- 新增测试能覆盖核心工具的成功、空结果、超时、解析失败场景。

---

## v1.0 - 原生证据 + 主动验证引擎（DAST Core）✅

> 目标：将 v0.9 的兼容协议升级为工具原生事实，并把“疑似漏洞”推进为“已验证 / 弱信号 / 未确认”。

### 范围边界

v0.9.1 的原生证据工作并入 v1.0。本版本只完成 SQLi、XSS、LFI 的最小验证闭环；不包含显式状态机、认证扫描、持久化、报告导出或大规模 fuzz。

### 工程改动

| 模块 | 内容 |
|---|---|
| 原生结果模型 | `http_request`、`analyze_headers`、`extract_forms`、`extract_links`、`crawl`、`batch_scan`、`test_lfi_param` 直接构造 `ToolResult`，不再依赖 legacy text adapter |
| 请求/响应证据 | 每次验证记录方法、URL、参数、payload、状态码、响应长度、关键响应片段和差异摘要 |
| Baseline 差分 | 同一输入点发送正常值、非法值、payload，比较状态码、长度、关键词和正文相似度 |
| Payload 模板 | 用 YAML/JSON 定义受限的 SQLi、XSS、LFI payload 族 |
| 验证策略 | 根据参数名、表单类型、响应特征选择轻量验证策略 |
| 误报抑制 | 连续失败、弱差异、错误页噪声要降级为 weak 或 unconfirmed |
| 新工具 | `verify_injection(url, param, vuln_type)`，覆盖 GET 查询参数与表单 POST 的最小验证路径 |
| 证据闭环 | 每个 confirmed finding 必须有 payload、请求摘要、响应摘要、diff 和复现步骤 |
| 回归靶场 | 用本地 HTTP 靶场和 mock 响应验证成功、弱信号、超时、解析失败和误报降级 |

### 交付标准

- SQLi / XSS / LFI 至少各有一条可验证路径和固定回归样例。
- 核心工具直接输出 `ToolResult`，不再通过文本解析恢复证据字段。
- 最终报告按证据强度分组：已确认、疑似、信息项、未确认。
- LLM 不能把 weak signal 写成 confirmed。
- `v1.0.0-rc1` 已完成本地及授权靶场回归，正式发布 `v1.0.0`。

### 发布验证

- 核心 HTTP、页面分析、爬取、批量扫描与 LFI 工具直接构造 `ToolResult`；兼容包装器只处理尚未迁移的工具。
- `verify_injection` 已覆盖受限 GET 参数和表单 POST 的 SQLi/XSS/LFI 验证，保留 baseline、无效值、payload、响应片段和差分数据。
- 本地 HTTP 靶场回归覆盖 SQLi/XSS/LFI confirmed、弱信号、超时和 payload 解析失败；已在授权外部靶场确认 PHP filter LFI 的 Base64 文件读取证据。

---

## v1.1 - 扫描状态机 + UI 2.0 ✅

> 目标：让长任务可观察、可暂停、可恢复，并把结构化证据展示出来。

### 工程改动

| 模块 | 内容 |
|---|---|
| 状态机 | 显式阶段：scope -> crawl -> enumerate -> verify -> knowledge -> report |
| 任务事件 | 统一事件：stage_started、stage_progress、tool_started、tool_finished、finding_created、scan_finished |
| UI 2.0 | 展示阶段进度、工具耗时、错误分类、漏洞卡片、证据详情 |
| Markdown 渲染 | 引入更稳定的 Markdown/代码块/表格渲染 |
| 会话操作 | 支持重命名、删除、导出当前扫描结果 |
| 中断语义 | 停止扫描时标记任务状态，不再只取消当前 asyncio task |

### 交付标准

- UI 展示来自结构化事件，而不是解析纯文本。
- 停止扫描后能看到已完成阶段和已产生证据。
- 漏洞卡片能展开查看 payload、请求、响应摘要和复现步骤。

### 完成情况

- 新增 `ScanState`，以独立 `scan_id` 维护六阶段状态、工具/错误/finding 计数和终态；停止扫描会保留当前阶段和已创建证据。
- WebSocket 已发送 `scan_started`、`stage_started`、`stage_progress`、`tool_started`、`tool_finished`、`finding_created`、`scan_finished`。
- 工作台右栏完全消费结构化事件，展示阶段、工具耗时、错误分类和可展开的漏洞证据；会话支持本地重命名、删除与 JSON 导出。
- 浏览器验证覆盖桌面与移动布局，并验证结构化 finding、阶段状态、工具耗时和 Markdown 表格渲染。
- 默认模型升级为 `deepseek-v4-flash`；支持 Flash/Pro 切换、显式 thinking、`high/max` 强度及 `reasoning_content` 实时展示，并通过最大步骤和历史窗口限制避免长会话无提示中断。

---

## v1.2 - 认证扫描 + 高级利用工具 + 知识库扩展

> 目标：覆盖登录后的真实攻击面，同时补齐 CSS 注入 / Scriptless XSS 等高级利用链的构造与数据还原能力。

### 工程改动

| 模块 | 内容 |
|---|---|
| 登录流程 | 自动识别登录表单，提交凭证并维护 Cookie/Token |
| 手动凭证 | 支持手动设置 Cookie、Bearer Token、API Key |
| 凭证安全 | 凭证只存内存，不写日志，不回显完整值 |
| Token 刷新 | 检测 JWT / Session 过期并提示重新认证 |
| 多角色对比 | user/admin 等角色访问同一资源，检测 IDOR / 越权 |
| 认证工具 | `login`、`set_auth_header`、`current_auth_state`、`compare_roles` |
| **CSS 注入知识库** | 新增 `css_injection.md`：Scriptless XSS、CSS 属性选择器数据外带、CSP `style-src` 绕过、`@import` 链式加载、逐字符 OTP/CSRF token 窃取攻击链 |
| **CSS 外带 Payload 生成** | 新增 `css_exfil_payload(url, param, webhook_url, extract_length)`：自动生成逐字符匹配的 CSS 属性选择器 payload，通过 `background-image` 向外带数据 |
| **Webhook 数据还原** | 新增 `webhook_reconstruct(logs, param_name)`：从 webhook 请求日志中解析并还原逐字符泄露的 secret 值 |
| **System Prompt 增强** | 新增 CTF / 利用场景指引：识别注入点 → 构造 payload → 提交 bot → 收集外带 → 还原 secret → 拿 flag |

### 交付标准

- 能带 Cookie 扫描后台页面。
- 能对比两个角色看到的页面/API 差异。
- 报告中明确认证上下文和权限边界。
- **知识库覆盖 CSS 注入 / Scriptless XSS 完整攻击面**，RAG 可检索到相关攻击模式、CVE 参考和修复方案。
- **`css_exfil_payload` 输出可直接用于 CTF / 授权渗透测试**的 CSS payload 注入。
- **`webhook_reconstruct` 能从原始 webhook 日志还原完整 secret**，支持常见 webhook 服务（webhook.site / Burp Collaborator / 自建）。

---

## v1.3 - 持久化 + 报告 + 复测

> 目标：扫描结果可回看、可导出、可比较。

### 工程改动

| 模块 | 内容 |
|---|---|
| 数据库 | SQLite + SQLAlchemy，保存 scans / pages / findings / evidence |
| 历史扫描 | `/api/scans` 查看历史扫描列表和详情 |
| 报告导出 | Markdown / HTML / PDF 报告 |
| 复测 | 对历史漏洞重新发送验证请求，标记 fixed / still_exists / changed |
| 对比 | 同一目标两次扫描对比新增、修复、仍存在的问题 |

### 交付标准

- 关闭浏览器后扫描结果不丢失。
- 能导出一份包含证据链的报告。
- 能对比两次扫描差异。

---

## v1.4 - 生产化部署

> 目标：从单机工具变成可部署服务。

### 工程改动

| 模块 | 内容 |
|---|---|
| 任务队列 | Redis / RQ / Celery 管理扫描任务 |
| Worker 隔离 | 扫描在独立进程运行，超时自动终止 |
| 速率控制 | 按目标维度限速，避免误伤目标服务 |
| API 鉴权 | 支持 API Key |
| 结构化日志 | JSON 日志和审计日志 |
| Docker | Dockerfile + docker-compose |
| 监控 | Prometheus metrics：扫描数、漏洞数、耗时、失败率 |

---

## v1.5 - 能力扩展

| 方向 | 内容 |
|---|---|
| Nuclei 对接 | 调用 nuclei 模板并解析结果进入统一 Finding 模型 |
| SBOM/依赖分析 | 对 Python/npm 项目做依赖漏洞扫描 |
| API Security | 覆盖 OWASP API Security Top 10、GraphQL introspection、批量 API fuzz |
| AI 应用安全 | Prompt Injection、越权工具调用、敏感信息泄露检测 |
| 自适应策略 | Agent 根据已发现证据动态调整下一步扫描策略 |

---

## 版本总览

| 版本 | 主题 | 核心目标 |
|---|---|---|
| v0.8 | 已发布 | CUDA RAG 加速 + 工作台稳定性 |
| v0.9 | 已发布 | 结构化工具结果、证据模型、通用 HTTP 方法、工具回归测试 |
| v1.0 | 已发布 | 原生证据、主动验证、差分证据、误报抑制 |
| v1.1 | 已完成 | 长任务可观察、结构化漏洞卡片、扫描阶段管理 |
| v1.2 | 认证扫描 + 高级利用 | 登录态、凭证管理、多角色越权检测、CSS注入知识库、外带Payload生成、Webhook数据还原 |
| v1.3 | 持久化报告 | SQLite、历史扫描、导出、复测 |
| v1.4 | 生产部署 | 队列、Worker、Docker、监控、审计 |
| v1.5 | 能力扩展 | Nuclei、SBOM、API Security、AI 应用安全 |

## 不变的架构原则

- FastAPI 只做控制面，不侵入 Agent 推理层。
- LangGraph 继续作为编排引擎，但扫描事实必须落到结构化数据。
- 工具层必须可测试，不能只靠 LLM 运行时发现问题。
- LLM 负责规划和报告表达，不负责伪造证据或提升置信度。
- 所有主动测试都必须限制在授权目标和同源边界内。
