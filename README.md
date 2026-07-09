# My Agent — Web 漏洞审查引擎

一个基于 DeepSeek + LangGraph 的 Web 应用安全扫描 Agent。支持自动爬取、漏洞探测、安全头分析。通过 FastAPI + WebSocket 提供服务。

## 项目结构

```
my-agent/
├── .env                  # 环境变量（API Key 等）
├── requirements.txt      # Python 依赖
├── agent/
│   ├── __init__.py
│   └── core.py           # Agent 核心（LangGraph 引擎 + 5 个扫描工具）
├── server/
│   └── web_server.py     # FastAPI 服务器（WebSocket + REST）
└── test_client.py        # 命令行交互客户端
```

## 快速开始

### 1. 配置 API Key

```bash
cp .env.example .env
```

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

### 3. 启动服务

```bash
python server/web_server.py
```

### 4. 开始扫描

另开终端：

```bash
python test_client.py
```

输入要扫描的 URL：

```
🔍 你: 扫描 http://testphp.vulnweb.com 的安全漏洞
```

Agent 会自动：
1. 访问页面 → 提取表单和链接
2. 对每个输入点注入 XSS/SQLi payload
3. 分析安全响应头
4. 输出漏洞报告（类型 + 风险等级 + 证据 + 修复建议）

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
│   LangGraph Agent (推理面)    │  ← agent/core.py
│   • ChatOpenAI → DeepSeek    │
│   • create_react_agent       │     LangGraph 管理 ReAct 循环
│   • @tool 装饰器定义工具       │     后续直接接 RAG
└──────────────────────────────┘
```

## 版本演进

### v0.1 — 基础框架
- 手写 ReAct 循环，支持 DeepSeek 调用 + 2 个工具（计算器/时间）
- 每条消息新建 Agent 实例，无记忆

### v0.2 — 多轮对话记忆
- `self.messages` 跨 `run()` 累积
- Agent 实例绑定到 WS 连接生命周期
- 新增 `/clear` 指令

### v0.3 — LangGraph 重构 + Web 漏洞扫描
- **引擎**: 手写 ReAct → `langgraph.prebuilt.create_react_agent`
- **工具**: 手写 JSON → `@tool` 装饰器，新增 5 个扫描工具
- **LLM**: 从 `AsyncOpenAI` 原始调用 → `ChatOpenAI`（LangChain 统一接口）
- FastAPI 层 **零改动** —— 证明了分层解耦的价值

| 维度 | v0.2 | v0.3 |
|---|---|---|
| Agent 循环 | 手写 for + tool_calls_map | LangGraph 自动 ReAct |
| 工具定义 | 手写 JSON dict | `@tool` 装饰器 |
| LLM 调用 | `AsyncOpenAI` 裸调 | `ChatOpenAI` |
| 流式输出 | 自己拼 delta | `astream_events(version="v2")` |
| 后续扩展 RAG | 需大改 | `create_retrieval_chain` 直接接 |
