# WebSec Research Agent — Web 漏洞审查引擎

基于 DeepSeek + LangGraph 的 Web 应用安全扫描 Agent。覆盖 **SQLi / XSS / 命令注入 / SSTI / LFI / SSRF / JWT 攻击 / IDOR / 提权 / OOB 外带确认** 共 10 大攻击类别，39 个注册工具，80+ 内置 payload。通过 FastAPI + WebSocket 提供可观察的扫描阶段、实时工具轨迹、漏洞证据和运行指标工作台。v1.6 引入“案例优先、技能晋升制”；v1.7 增加可持久化、可复算的运行遥测。

> **v1.4** 从 [Shannon OSS](https://github.com/keygraph/shannon)（AI 白盒渗透测试引擎）迁移了 SSRF、命令注入、SSTI、JWT 攻击、授权攻击和 OOB 盲确认等攻击模式。所有工具为 Python 原创实现，设计思路源自 Shannon 的提示词架构。
>
> **v1.5** 新增代码驱动的技能遥测、确定性生命周期、durable review job、lease/retry worker 和持久化维护指令，形成最小完整自进化闭环。
>
> **v1.6** 新增案例记忆库、递归增量 RAG 索引和 `case_create`；DeepSeek curator 审查 agent-created Skill 的语义重复性；Skill 创建需要至少两条同类案例支持，避免“一题一 Skill”的知识库膨胀。
> **v1.7.1** 新增服务端会话持久化：会话、运行历史和最终答复保存在 `telemetry.db`，刷新或重启服务后可恢复；旧浏览器会话会一次性导入，凭据会在入库前脱敏。
>
> **v1.7.2（规划）** 将增加完整 HTTP 响应和渲染 DOM 的受限关键词/正则检索。它用于定位大页面深处的已知线索，不会把完整响应直接塞入模型上下文。

## 项目结构

```
my-agent/
├── .env                        # 环境变量（API Key 等）
├── requirements.txt            # Python 依赖
├── agent/
│   ├── __init__.py             # 模块入口
│   ├── config.py               # 配置管理 (AgentConfig)
│   ├── prompts.py              # System Prompt (v1.4 全类别工作流)
│   ├── agent.py                # Agent 核心引擎 (LangGraph)
│   ├── rag.py                  # RAG 知识库 (Chroma + Qwen3 两阶段检索)
│   ├── case_manager.py         # 案例记忆管理 (写入 knowledge/cases/)
│   ├── core.py                 # 向后兼容重导出
│   ├── scan_state.py           # 6 阶段扫描状态机
│   ├── skill_manager.py        # 技能生命周期管理 ← v1.3
│   ├── evolution/              # 遥测、生命周期、DeepSeek curator、Nudge Job
│   ├── session_db.py           # SQLite 持久化 (FTS5) ← v1.3
│   ├── telemetry.py            # 运行、行动、模型 usage 与评测账本 ← v1.7
│   ├── tools/                  # 扫描工具集（38 个工具）
│   │   ├── http_tools.py       #   http_get / http_post / http_request
│   │   ├── analysis_tools.py   #   analyze_headers / extract_forms / extract_links
│   │   ├── crawl_tools.py      #   crawl / sitemap / batch_scan
│   │   ├── static_tools.py     #   analyze_js / decode_jwt / discover_api / render_page
│   │   ├── lfi_tools.py        #   test_lfi_param
│   │   ├── verification_tools.py # verify_injection (SQLi/XSS/LFI 差分验证)
│   │   ├── exploit_tools.py    #   css_exfil_payload / webhook_reconstruct
│   │   ├── ssrf_tools.py       #   test_ssrf / probe_internal_port ← v1.4
│   │   ├── command_injection_tools.py # test_command_injection / test_ssti ← v1.4
│   │   ├── jwt_attack_tools.py #   jwt_alg_none_attack / jwt_hmac_brute / jwt_key_confusion ← v1.4
│   │   ├── authz_tools.py      #   test_idor / test_privilege_escalation / test_role_manipulation ← v1.4
│   │   ├── oob_tools.py        #   generate_oob_payload / check_oob_callbacks ← v1.4
│   │   ├── skill_tools.py      #   技能查看、晋升、维护、归档与恢复
│   │   ├── case_tools.py       #   case_create：保存可检索案例
│   │   ├── structured.py       #   ToolResult 协议包装器
│   │   ├── results.py          #   ToolResult / Finding / Evidence 数据模型
│   │   └── http_client.py      #   统一请求、同域边界、超时、限速、重试
│   ├── payloads/
│   │   └── injection.json      # 19 类别 × 80+ payload (SQLi盲注/UNION/NoSQL/命令注入/SSTI/SSRF/XXE) ← v1.4
│   ├── knowledge/              # 知识库 Markdown 源文件（8 个）
│   │   ├── cases/              #   已解决任务案例（RAG 自动增量索引）
│   │   ├── owasp_top10.md      #   OWASP Top 10 (2021) 全 10 类 + 检测/修复
│   │   ├── common_cves.md      #   精选 CVE 案例 (Log4Shell/Spring4Shell/XSS/SSRF...)
│   │   ├── remediation.md      #   代码级修复方案 (Python/Java/Nginx/Apache)
│   │   ├── css_injection.md    #   Scriptless XSS / CSS 数据外带 / CSP 绕过
│   │   ├── ssrf.md             #   SSRF 攻击分类 / 云元数据 / 协议绕过 ← v1.4
│   │   ├── command_injection.md #  命令注入 / Shell 元字符 / 盲注检测 ← v1.4
│   │   ├── auth_vulns.md       #   认证漏洞 / JWT 攻击 / 授权绕过大全 ← v1.4
│   │   └── ssti.md             #   SSTI 6 引擎 payload / 盲 SSTI ← v1.4
│   ├── skills/                 # 自进化技能库
│   │   └── css_injection/      #   种子技能: css-exfil-otp
│   └── models/                 # 本地模型 (.gitignore 排除)
├── server/
│   └── web_server.py           # FastAPI 服务器 (WebSocket + REST + 指标 API)
├── web/
│   └── index.html              # 浏览器工作台 (工具目录、运行指标与历史运行)
└── test_client.py              # 命令行交互客户端（可选）
```

## 快速开始

### 1. 配置 API Key

编辑 `.env`，填入 DeepSeek API Key：

```env
DEEPSEEK_API_KEY=sk-your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_THINKING_ENABLED=true
DEEPSEEK_REASONING_EFFORT=high
DEEPSEEK_SHOW_REASONING=true
AGENT_MAX_TURNS=120
AGENT_HISTORY_MESSAGES=24
SKILL_LLM_CURATION_ENABLED=true
SKILL_LLM_CURATION_MIN_CONFIDENCE=0.92
TELEMETRY_DB_PATH=data/telemetry.db
# 可选：配置后 /api/metrics 才计算成本（单位：USD / 1M tokens）
MODEL_INPUT_COST_PER_MILLION=
MODEL_OUTPUT_COST_PER_MILLION=
```

`deepseek-v4-flash` 用于默认扫描；在"模型与思考"设置中可切换到 `deepseek-v4-pro`。思考模式显式传递 `thinking.enabled` 和 `reasoning_effort`（`high` / `max`），运行时不会传递与思考模式不兼容的 `temperature`。模型、思考开关和强度会在下一次扫描生效。

每次扫描最多执行 `AGENT_MAX_TURNS` 个 LangGraph 步骤（默认 120，配置接口允许 10-240）；会话上下文保留系统提示和最近 `AGENT_HISTORY_MESSAGES` 条已完成消息（默认 24），避免长会话无限增长并导致模型上下文耗尽。

### 2. 安装依赖

```bash
python -m venv myagent
source myagent/Scripts/activate      # Windows Git Bash
# 或 myagent\Scripts\activate.bat    # Windows CMD
# 或 myagent\Scripts\Activate.ps1    # Windows PowerShell

pip install -r requirements.txt
```

国内网络环境建议使用清华 PyPI 源安装依赖：

```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn -r requirements.txt
```

`render_page` 使用 Playwright 渲染 SPA。首次使用前需要安装 Chromium 浏览器驱动：

```powershell
$env:PLAYWRIGHT_DOWNLOAD_HOST='https://npmmirror.com/mirrors/playwright'
python -m playwright install chromium
```

### 3. 下载知识库模型

RAG 模块使用 Qwen3-Embedding-0.6B + Qwen3-Reranker-0.6B 做两阶段检索：

```bash
pip install modelscope

# 下载 Embedding 模型
python -c "from modelscope import snapshot_download; snapshot_download('Qwen/Qwen3-Embedding-0.6B', cache_dir='agent/models')"
cp -r agent/models/models/Qwen--Qwen3-Embedding-0.6B/snapshots/master agent/models/qwen3-embedding-0.6b

# 下载 Reranker 模型
python -c "from modelscope import snapshot_download; snapshot_download('Qwen/Qwen3-Reranker-0.6B', cache_dir='agent/models')"
cp -r agent/models/models/Qwen--Qwen3-Reranker-0.6B/snapshots/master agent/models/qwen3-reranker-0.6b

# 清理 modelscope 缓存目录
rm -rf agent/models/models agent/models/.lock
```

> 模型共 ~2.4GB，首次启动时会自动索引知识库文档。v0.8 起 RAG 会自动检测 CUDA：可用时 Embedding 和 Reranker 使用 GPU，否则回退 CPU。

如需在 Windows + NVIDIA GPU 环境启用 CUDA 版 PyTorch：

```powershell
python -m pip install --upgrade --force-reinstall --no-deps "https://mirrors.aliyun.com/pytorch-wheels/cu130/torch-2.12.1%2Bcu130-cp313-cp313-win_amd64.whl"
python -m pip install "setuptools<82" -i https://pypi.tuna.tsinghua.edu.cn/simple
python -c "import torch; print(torch.__version__); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0))"
```

### 4. 启动服务

```bash
python server/web_server.py
```

浏览器打开 **http://127.0.0.1:9120** 进入工作台；再输入已授权的靶场或 Web 应用 URL 开始扫描。

### 5. 扫描能力

Agent 覆盖 10 大攻击类别，38 个工具自动协作：

| 阶段 | 执行的操作 |
|---|---|
| 攻击面测绘 | crawl 爬取 → sitemap 分类 → analyze_js / discover_api / render_page 发现 JS/API/SPA |
| 注入验证 | verify_injection (SQLi/XSS/LFI) + test_command_injection + test_ssti + test_lfi_param |
| SSRF 检测 | test_ssrf (云元数据/内网/协议) + probe_internal_port (端口扫描) |
| JWT 攻击 | decode_jwt → jwt_alg_none_attack → jwt_hmac_brute → jwt_key_confusion |
| 授权攻击 | test_idor (水平越权) + test_privilege_escalation (头注入提权) + test_role_manipulation |
| OOB 确认 | generate_oob_payload + check_oob_callbacks (盲 SSRF/命令注入/SQLi/XXE) |
| 高级利用 | css_exfil_payload + webhook_reconstruct (CSS 数据外带) |
| 知识验证 | search_knowledge (RAG 两阶段检索 → OWASP/CVE/CVSS/修复) |
| 案例记忆 | scan_reflect → case_create（保存证据、解题链和失败路径，供 RAG 检索） |
| 技能治理 | DeepSeek curator 合并高置信重复 Skill；两条独立案例后才允许 skill_create 晋升 |
| 报告 | 按 confirmed / likely / weak / unconfirmed 分组 + 证据 + 复现步骤 + 修复建议 |

## API 接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/chat` | WebSocket | 核心对话——逐 token 流式输出，提供 `scan_started`、`stage_started`、`stage_progress`、`tool_started`、`tool_finished`、`finding_created`、`scan_finished` 事件 |
| `/api/config` | GET/PUT | 查看/修改模型、thinking 开关、`high/max` 强度、最大步骤和会话历史窗口 |
| `/api/tools` | GET | 工具目录——返回 39 个工具按类别分组，含名称、描述、参数 Schema |
| `/api/skills` | GET | 返回已学习 Skill 的生命周期状态、标签和使用遥测，供工具目录动态展示 |
| `/api/evolution` | GET | 查看工具计数、review job、待处理指令和近期审查报告 |
| `/api/metrics` | GET | 查看运行数、工具/协议失败率、首次有效行动比例、solve rate 与 token 用量 |
| `/api/runs` | GET | 查看持久化运行记录；`/api/runs/{id}` 查看行动、usage 与评测详情 |
| `/api/runs/{id}/evaluation` | POST | 写入本地 benchmark 或人工判定的评测结果 |
| `/api/sessions` | GET | 活跃连接数 |
| `/api/health` | GET | 健康检查 |

## 扫描工具（39 个）

### 🌐 HTTP 基础
| 工具 | 说明 |
|---|---|
| `http_get(url)` | GET 请求，获取页面内容和响应头 |
| `http_post(url, data)` | POST 请求，发送测试 payload |
| `http_request(method, url, data, headers_json)` | 受约束的 GET/POST/PUT/PATCH/HEAD/OPTIONS |

### 🔍 攻击面测绘
| 工具 | 说明 |
|---|---|
| `crawl(url, depth, pages)` | BFS 爬虫 + 17 个敏感路径探测 |
| `sitemap(url)` | 攻击面分类（登录/表单/API/管理后台/静态资源） |
| `batch_scan(url)` | 批量安全头检查 + 安全评级 (A/B/C) |
| `extract_forms(url)` | 提取页面所有表单和输入参数 |
| `extract_links(url)` | 提取页面内链，扩展攻击面 |
| `analyze_js(url)` | 扫描 JS 中的密钥/JWT/API 路径/sourcemap/调试开关 |
| `discover_api(url)` | 探测 OpenAPI/Swagger/GraphQL/常见 API 入口 |
| `render_page(url)` | Playwright 渲染 SPA，提取 DOM 和网络请求 |
| `analyze_headers(url)` | 检查安全头（CSP/HSTS/X-Frame-Options 等） |

### 💉 注入验证
| 工具 | 说明 |
|---|---|
| `verify_injection(url, param, vuln_type, method, form_data)` | SQLi/XSS/LFI 受限差分验证（baseline+对照+payload） |
| `test_lfi_param(url, param)` | LFI 专项：22 payload + 响应差分 + flag 提取 |
| `test_command_injection(url, param, method, param_location, body)` | 命令注入：shell 元字符 + 时序盲注 + 响应分析 ← v1.4 |
| `test_ssti(url, param, method, param_location, body)` | SSTI 检测：6 种模板引擎数学表达式 + 错误指纹 ← v1.4 |
| `decode_jwt(token)` | JWT 被动审计：alg/exp/空签名/高权限声明 |

### 🔄 SSRF 检测
| 工具 | 说明 |
|---|---|
| `test_ssrf(url, param, method, body_template, param_location)` | 云元数据(AWS/Azure/GCP) + 内网主机 + 危险协议(file/gopher/dict) ← v1.4 |
| `probe_internal_port(url, param, host, ports)` | 通过 SSRF 向量扫描内网端口，发现服务 ← v1.4 |

### 🔑 JWT 攻击
| 工具 | 说明 |
|---|---|
| `jwt_alg_none_attack(jwt_token, target_url, ...)` | alg:none 签名绕过 + 自动 payload 提权 ← v1.4 |
| `jwt_hmac_brute(jwt_token, wordlist)` | HS256/384/512 弱密钥爆破（内置 18 个常见弱密钥） ← v1.4 |
| `jwt_key_confusion(jwt_token, public_key_pem, ...)` | RS256→HS256 密钥混淆攻击（CVE-2016-5431） ← v1.4 |

### 🛡️ 授权攻击
| 工具 | 说明 |
|---|---|
| `test_idor(url, param, method, headers_json)` | IDOR 水平越权：顺序 ID 枚举 + 响应差异分析 ← v1.4 |
| `test_privilege_escalation(url, method, headers_json)` | 垂直提权：16 种头注入（X-Role/X-Admin/X-Forwarded-For 等） ← v1.4 |
| `test_role_manipulation(url, method, body_json, headers_json)` | 角色操控：请求体中 role/is_admin/permission 字段篡改 ← v1.4 |

### 📡 OOB 外带确认
| 工具 | 说明 |
|---|---|
| `generate_oob_payload(vuln_type, session_id, exfil_param)` | 生成盲 SSRF/SQLi/命令注入/XXE/XSS 的外带 callback payload ← v1.4 |
| `check_oob_callbacks(session_id, poll_wait)` | 轮询 Interactsh 确认外带回调（盲漏洞确认） ← v1.4 |

### ⚡ 高级利用 (CTF)
| 工具 | 说明 |
|---|---|
| `css_exfil_payload(url, param, webhook_url, ...)` | CSS 属性选择器 payload 生成（Scriptless XSS 数据外带） |
| `webhook_reconstruct(logs, param_name)` | Webhook 日志解析还原逐字符泄露的 secret |

### 🧬 自进化技能
| 工具 | 说明 |
|---|---|
| `skill_list(category)` | 列出技能库中所有已沉淀的经验技能 |
| `skill_view(name)` | 只查看技能并记录 view 遥测，不计为使用 |
| `skill_load(name)` | 加载指定技能到当前扫描上下文 |
| `case_create(target, title, summary, evidence, solution, ...)` | 将已解决任务保存为 RAG 案例；禁止保存 flag、凭据或 token |
| `skill_create(title, description, body, category, tags)` | 仅在至少两条同类案例支持时，将稳定模式晋升为可复用技能 |
| `skill_patch(name, old_text, new_text)` | 改进已有技能 |
| `skill_pin(name, pinned)` | 设置或取消自动归档保护 |
| `skill_archive(name, absorbed_into)` | 将 agent-created 技能软归档到 `.archive/` |
| `skill_restore(name)` | 恢复已归档技能 |
| `scan_reflect(target, findings_summary, successful_techniques, failed_attempts)` | 扫描后反思：默认建议创建案例；重复验证后再建议晋升/更新 Skill |

> `/api/tools` 暴露 **39 个基础工具**；RAG 初始化成功时，Agent 运行时还会动态加入 `search_knowledge`。工具目录会通过 `/api/skills` 显示已学习 Skill，不再把案例混入工具列表。

案例保存于 `agent/knowledge/cases/`，与 OWASP/CVE 文档一起由 Chroma + Qwen3 两阶段检索；案例包含前提、证据、解决链和失败路径，但不得包含 flag、凭据或 token。技能内容保存在 `agent/skills/`，可变遥测与生命周期状态保存在 `data/evolution.db`。业务工具每完成 10 次会持久化一个幂等 `skill_review` job；带 lease/retry 的 worker 自动审查结构化工具结果。DeepSeek curator 仅合并高置信重复的 agent-created Skill，且归档可恢复。`bundled`、已 pin 或被保护引用的技能不会被自动归档。

## 架构

```
浏览器 / CLI
    │
    │ HTTP REST + WebSocket
    ▼
┌──────────────────────────────┐
│      FastAPI (控制面)         │  ← server/web_server.py
│      /api/chat /api/config    │
│      /api/tools /api/health   │
└──────────────┬───────────────┘
               │ 函数调用
               ▼
┌──────────────────────────────┐
│   LangGraph Agent (推理面)    │  ← agent/agent.py
│   • ChatOpenAI → DeepSeek    │
│   • create_react_agent       │
│   • 38 个 @tool 工具          │
│                              │
│   ┌──────────────────────┐   │
│   │   RAG 知识库          │   │  ← agent/rag.py
│   │   Stage 1: Embedding  │   │     Qwen3-Embedding-0.6B
│   │   Stage 2: Reranker   │   │     Qwen3-Reranker-0.6B
│   │   8 个知识文件 → 向量   │   │
│   └──────────────────────┘   │
│                              │
│   ┌──────────────────────┐   │
│   │   自进化技能库         │   │  ← agent/skill_manager.py
│   │   SKILL.md 格式        │   │
│   │   9 个漏洞类别          │   │
│   └──────────────────────┘   │
└──────────────────────────────┘
```

## 版本演进

### v0.1 — 基础框架
手写 ReAct 循环，支持 DeepSeek 调用 + 2 个工具。

### v0.2 — 多轮对话记忆
`self.messages` 跨 `run()` 累积，Agent 实例绑定 WS 连接生命周期。

### v0.3 — LangGraph 重构 + Web 漏洞扫描
手写 ReAct → `langgraph.prebuilt.create_react_agent`，新增 5 个扫描工具。

### v0.4 — 深度爬取 + Web 前端
新增 `crawl` / `sitemap` / `batch_scan`，浏览器前端直接对话。

### v0.5 — RAG 知识库
- Qwen3-Embedding-0.6B + Qwen3-Reranker-0.6B 两阶段检索
- 3 个知识文件 → 29 个向量块
- 新增 `search_knowledge(query)`

### v0.6 — 扫描基础 + 静态分析 + 浏览器渲染
- 统一同域过滤、URL 规范化、超时、限速、重试
- 新增 `analyze_js` / `discover_api` / `decode_jwt` / `render_page`

### v0.7 — LFI 专项验证 + 工作台 UI
- 新增 `test_lfi_param` + Flag 自动提取
- WebSocket 事件流 + 前端工具轨迹卡片

### v0.8 — CUDA RAG 加速 + 工作台稳定性
- GPU 自动检测 + float16 小批量推理
- 前端布局修复

### v0.9 — 结构化证据协议 + 工具可靠性
- 统一 `ToolResult` JSON envelope（tool/target/status/findings/errors）
- 所有工具原生输出结构化证据

### v1.0.0 — 原生证据 + 主动验证引擎
- 新增 `verify_injection`：baseline + 无效对照 + 受限 payload 差分验证
- confirmed / likely / weak / unconfirmed 四级置信度

### v1.1.0 — 扫描状态机 + UI 2.0
- 6 阶段扫描生命周期（scope → crawl → enumerate → verify → knowledge → report）
- 结构化事件流 + 证据工作台 + Markdown 渲染

### v1.2.0 — 高级利用工具 + 知识库扩展
- CSS 注入知识库 + `css_exfil_payload` + `webhook_reconstruct`
- 17 个注册工具 + CTF/利用场景工作流

### v1.3.0 — 自进化技能系统 + 持久化
- `SkillManager` + 5 个技能工具 + `SessionDB`（SQLite FTS5 + WAL）
- 22 个注册工具

### v1.4.0 — Shannon 迁移：全类别覆盖
- **12 个新工具**: SSRF 检测 (2) + 命令注入 + SSTI + JWT 主动攻击 (3) + 授权攻击 (3) + OOB 外带确认 (2)
- **Payload 库**: 3 类别 9 个 → 19 类别 80+ 个（新增盲注/UNION/NoSQL/SSTI/命令注入/SSRF/XXE 等）
- **知识库**: 4 → 8 文件（新增 SSRF/命令注入/认证授权/SSTI）
- **前端**: 新增工具目录面板（📦 按钮），支持搜索和分类浏览
- **API**: 新增 `/api/tools` 端点，返回完整工具清单和参数 Schema
- **System Prompt**: 重写为 v1.4 全类别工作流（步骤 1-33）
- **设计来源**: Shannon OSS（AI 白盒渗透测试引擎）的攻击模式，100% Python 原创实现
- **工具总数**: 34

### v1.5.0 — 稳定自进化闭环
- SQLite 技能遥测：独立记录 use / view / patch 次数与时间
- 代码级 Nudge：每 10 次业务工具调用创建 durable `skill_review` job
- Worker 支持 claim、lease、retry、超时恢复和 dead-letter
- 纯代码审查 confirmed / likely 证据，并持久化未完成维护指令
- `active → stale → archived` 确定性生命周期、Pin、引用保护、软归档和恢复
- 新增 `/api/evolution` 状态接口，基础工具总数提升至 38

### v1.6.0 — 案例优先的 DeepSeek 记忆治理
- 新增 `case_create` 与 `agent/knowledge/cases/`：已解决任务先沉淀为结构化案例，再通过 RAG 按技术栈、参数和证据特征检索
- RAG 改为递归、增量索引，检索结果标记 `reference` 或 `case` 来源
- DeepSeek curator 仅合并高置信重复 Skill；归档记录可恢复并保留审计证据
- `skill_create` 强制要求至少两条同分类且标签重叠的独立案例，阻止单题经验污染 Skill 库
- 新增 `/api/skills`，工具目录动态展示已学习 Skill；基础工具总数为 39

### v1.7.1 — 服务端会话持久化（当前）

- `conversations` 与 `telemetry_runs.conversation_id` 将会话与运行遥测关联，支持创建、恢复、重命名和删除。
- WebSocket 请求携带 `conversation_id`；用户输入、增量运行摘要和最终答复均可在服务重启后恢复。
- 旧 LocalStorage 会话将一次性、幂等导入；Cookie、Bearer token、API key 与密码字段在入库前脱敏。

### v1.7.0 — 运行遥测与指标工作台
- 新增 `telemetry.db`：持久化运行、工具行动、模型 usage 和评测结果；旧的演进遥测不再用于计算运行指标
- 工具包装器直接执行底层函数，避免同名嵌套工具调用造成重复终态观测
- 无效或缺失的 `ToolResult` envelope 标记为协议失败，与工具执行失败分开统计
- 新增 `/api/metrics`、`/api/runs` 和评测写入接口；前端可查看总体指标、能力域、历史运行和行动详情
- 模型供应商返回 usage 时记录输入/输出 token；配置价格后可计算成本
