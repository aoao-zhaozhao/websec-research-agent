# My Agent — Web 漏洞审查引擎

基于 DeepSeek + LangGraph 的 Web 应用安全扫描 Agent。支持自动爬取、漏洞探测、RAG 知识库验证、安全头分析。通过 FastAPI + WebSocket 提供服务。

## 项目结构

```
my-agent/
├── .env                        # 环境变量（API Key 等）
├── requirements.txt            # Python 依赖
├── agent/
│   ├── __init__.py             # 模块入口
│   ├── config.py               # 配置管理 (AgentConfig)
│   ├── prompts.py              # System Prompt (v0.5 三步工作流)
│   ├── agent.py                # Agent 核心引擎 (LangGraph)
│   ├── rag.py                  # RAG 知识库 (Chroma + Qwen3 两阶段检索)
│   ├── core.py                 # 向后兼容重导出
│   ├── tools/                  # 扫描工具集
│   │   ├── http_tools.py       #   http_get / http_post
│   │   ├── analysis_tools.py   #   analyze_headers / extract_forms / extract_links
│   │   └── crawl_tools.py      #   crawl / sitemap / batch_scan
│   ├── knowledge/              # 知识库 Markdown 源文件
│   │   ├── owasp_top10.md      #   OWASP Top 10 (2021) 全 10 类 + 检测/修复
│   │   ├── common_cves.md      #   精选 CVE 案例 (Log4Shell/Spring4Shell/XSS/SSRF...)
│   │   └── remediation.md      #   代码级修复方案 (Python/Java/Nginx/Apache)
│   └── models/                 # 本地模型 (.gitignore 排除)
│       ├── qwen3-embedding-0.6b/   # 1024 维 Embedding
│       └── qwen3-reranker-0.6b/   # CrossEncoder 精排
├── server/
│   └── web_server.py           # FastAPI 服务器 (WebSocket + REST + 前端页面)
├── web/
│   └── index.html              # 浏览器聊天页面
└── test_client.py              # 命令行交互客户端（可选）
```

## 快速开始

### 1. 配置 API Key

编辑 `.env`，填入 DeepSeek API Key：

```env
DEEPSEEK_API_KEY=sk-your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

### 2. 安装依赖

```bash
python -m venv myagent
source myagent/Scripts/activate      # Windows Git Bash
# 或 myagent\Scripts\activate.bat    # Windows CMD
# 或 myagent\Scripts\Activate.ps1    # Windows PowerShell

pip install -r requirements.txt
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

> 模型共 ~2.4GB，首次启动时会自动索引知识库文档。

### 4. 启动服务

```bash
python server/web_server.py
```

### 5. 开始扫描

浏览器打开 **http://127.0.0.1:9120**，在输入框输入 URL：

```
http://49.232.142.230:13403
```

Agent 会自动：
1. crawl 爬取所有同域页面 + 探测敏感路径
2. sitemap 分类统计攻击面
3. batch_scan 批量检查安全头
4. 深入每个输入点注入 XSS/SQLi payload
5. **search_knowledge 查知识库验证**，匹配 CVE/CVSS/修复方案
6. 输出完整安全审计报告（类型 + 风险等级 + CVE + 证据 + 修复建议）

也支持命令行模式：`python test_client.py`

## API 接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/chat` | WebSocket | 核心对话——逐 token 流式输出扫描结果 |
| `/api/config` | GET/PUT | 查看/修改配置 |
| `/api/sessions` | GET | 活跃连接数 |
| `/api/health` | GET | 健康检查 |

## 扫描工具

| 工具 | 用途 |
|---|---|
| `http_get(url)` | GET 请求，获取页面内容和响应头 |
| `http_post(url, data)` | POST 请求，发送测试 payload（XSS/SQLi） |
| `analyze_headers(url)` | 检查安全头（CSP/HSTS/X-Frame-Options 等） |
| `extract_forms(url)` | 提取页面所有表单和输入参数 |
| `extract_links(url)` | 提取页面内链，扩展攻击面 |
| `crawl(url, depth, pages)` | BFS 爬虫，自动发现所有同域页面 + 16 个敏感路径探测 |
| `sitemap(url)` | 攻击面分类统计（登录页/表单/API/管理后台/静态资源） |
| `batch_scan(url)` | 批量扫描所有页面安全头 + 整体安全评级 |
| `search_knowledge(query)` ⭐ | 两阶段 RAG 检索知识库（CVE/CVSS/修复方案） |

## 架构

```
浏览器 / CLI
    │
    │ HTTP REST + WebSocket
    ▼
┌──────────────────────────────┐
│      FastAPI (控制面)         │  ← server/web_server.py
│      WebSocket + REST         │
└──────────────┬───────────────┘
               │ 函数调用
               ▼
┌──────────────────────────────┐
│   LangGraph Agent (推理面)    │  ← agent/agent.py
│   • ChatOpenAI → DeepSeek    │
│   • create_react_agent       │
│   • 9 个 @tool 工具           │
│                              │
│   ┌──────────────────────┐   │
│   │   RAG 知识库          │   │  ← agent/rag.py
│   │   Stage 1: Embedding  │   │     Qwen3-Embedding-0.6B
│   │   Stage 2: Reranker   │   │     Qwen3-Reranker-0.6B
│   │   Chroma 向量库        │   │
│   └──────────────────────┘   │
└──────────────────────────────┘
```

## 版本演进

### v0.1 — 基础框架
- 手写 ReAct 循环，支持 DeepSeek 调用 + 2 个工具（计算器/时间）

### v0.2 — 多轮对话记忆
- `self.messages` 跨 `run()` 累积，Agent 实例绑定 WS 连接生命周期

### v0.3 — LangGraph 重构 + Web 漏洞扫描
- 手写 ReAct → `langgraph.prebuilt.create_react_agent`，新增 5 个扫描工具

### v0.4 — 深度爬取 + Web 前端
- 新增 `crawl` / `sitemap` / `batch_scan`，浏览器前端直接对话

### v0.5 — RAG 知识库 ⭐ 当前
- **文件拆分**: `core.py` → `config.py` `prompts.py` `agent.py` `tools/` `rag.py`
- **知识库**: OWASP Top 10 + 精选 CVE 案例 + 代码级修复方案 (3 个 Markdown → 29 个向量块)
- **两阶段检索**: Qwen3-Embedding-0.6B 粗排 → Qwen3-Reranker-0.6B 精排
- **新工具**: `search_knowledge(query)` — 语义检索知识库
- **System Prompt**: 发现漏洞 → 先查知识库 → 带 CVE/CVSS/修复方案输出
