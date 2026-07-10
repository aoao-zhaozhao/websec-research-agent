# My Agent — Web 漏洞审查引擎

基于 DeepSeek + LangGraph 的 Web 应用安全扫描 Agent。支持自动爬取、JS/API 发现、SPA 渲染、JWT 审计、LFI 专项验证、漏洞探测、RAG 知识库验证和安全头分析。通过 FastAPI + WebSocket 提供服务。

## 项目结构

```
my-agent/
├── .env                        # 环境变量（API Key 等）
├── requirements.txt            # Python 依赖
├── agent/
│   ├── __init__.py             # 模块入口
│   ├── config.py               # 配置管理 (AgentConfig)
│   ├── prompts.py              # System Prompt (v0.8 工作流)
│   ├── agent.py                # Agent 核心引擎 (LangGraph)
│   ├── rag.py                  # RAG 知识库 (Chroma + Qwen3 两阶段检索)
│   ├── core.py                 # 向后兼容重导出
│   ├── tools/                  # 扫描工具集
│   │   ├── http_tools.py       #   http_get / http_post
│   │   ├── analysis_tools.py   #   analyze_headers / extract_forms / extract_links
│   │   ├── crawl_tools.py      #   crawl / sitemap / batch_scan
│   │   ├── static_tools.py     #   analyze_js / decode_jwt / discover_api / render_page
│   │   ├── lfi_tools.py        #   test_lfi_param
│   │   └── http_client.py      #   统一请求、同域边界、超时、限速、重试
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

国内网络环境建议使用清华 PyPI 源安装依赖：

```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn -r requirements.txt
```

`render_page` 使用 Playwright 渲染 SPA。首次使用前需要安装 Chromium 浏览器驱动。国内网络环境建议使用 npmmirror 镜像：

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

如需在 Windows + NVIDIA GPU 环境启用 CUDA 版 PyTorch，可按实际驱动选择 PyTorch wheel。当前验证过的组合：

```powershell
python -m pip install --upgrade --force-reinstall --no-deps "https://mirrors.aliyun.com/pytorch-wheels/cu130/torch-2.12.1%2Bcu130-cp313-cp313-win_amd64.whl"
python -m pip install "setuptools<82" -i https://pypi.tuna.tsinghua.edu.cn/simple
python -c "import torch; print(torch.__version__); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0))"
```

### 4. 启动服务

```bash
python server/web_server.py
```

停止服务：

```powershell
# 当前终端启动时按 Ctrl+C；后台运行时释放 9120 端口
Get-NetTCPConnection -LocalPort 9120 | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force
}
```

### 5. 开始扫描

浏览器打开 **http://127.0.0.1:9120**，在输入框输入 URL：

```
http://49.232.142.230:13403
```

Agent 会自动：
1. crawl 爬取所有同域页面 + 探测敏感路径
2. sitemap 分类统计攻击面
3. analyze_js / discover_api 提取 JS 中的 API、JWT、密钥、sourcemap 和调试开关
4. 对 SPA 页面用 render_page 提取渲染后 DOM 和网络请求
5. batch_scan 批量检查安全头
6. 深入每个输入点注入轻量 XSS/SQLi payload
7. 对疑似 LFI 参数调用 `test_lfi_param` 做 bounded payload 验证、响应差分和 flag-like 提取
8. **search_knowledge 查知识库验证**，匹配漏洞分类、CVE/CVSS 参考和修复方案
9. 输出完整安全审计报告（类型 + 风险等级 + 参考分类/CVE + 证据 + 修复建议）

也支持命令行模式：`python test_client.py`

Web 工作台底部按钮：

| 按钮 | 作用 |
|---|---|
| `▶` | 开始扫描 |
| `■` | 停止当前扫描，不清空当前会话 |
| `×` | 清空当前会话内容和 Agent 记忆 |

关闭浏览器标签页会断开 WebSocket，会话生命周期随连接结束。当前侧边栏会话保存在浏览器 `localStorage`，不是后端持久化；换浏览器、换端口或清理站点数据后可能丢失。`×` 只清空内容，`■` 用于取消正在运行的扫描任务。

## API 接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/chat` | WebSocket | 核心对话——逐 token 流式输出扫描结果和工具事件；支持 `clear` / `stop` 命令 |
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
| `analyze_js(url)` | 扫描同域 JS 中的密钥、JWT、API 路径、sourcemap、调试开关 |
| `decode_jwt(token)` | 解码 JWT 并检查 alg、exp、空签名、高权限声明 |
| `discover_api(url)` | 探测 OpenAPI / Swagger / GraphQL / 常见 API 入口 |
| `render_page(url)` | 使用 Playwright 渲染 SPA，提取 DOM、同域请求和链接 |
| `test_lfi_param(url, param)` | 对疑似 LFI 参数做 bounded payload 验证、响应差分和 flag-like 提取 |
| `crawl(url, depth, pages)` | BFS 爬虫，自动发现所有同域页面 + 16 个敏感路径探测 |
| `sitemap(url)` | 攻击面分类统计（登录页/表单/API/管理后台/静态资源） |
| `batch_scan(url)` | 批量扫描所有页面安全头 + 整体安全评级 |
| `search_knowledge(query)` ⭐ | 两阶段 RAG 检索知识库（漏洞分类、CVE/CVSS 参考、修复方案） |

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
│   • 14 个 @tool 工具          │
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

### v0.5 — RAG 知识库
- **文件拆分**: `core.py` → `config.py` `prompts.py` `agent.py` `tools/` `rag.py`
- **知识库**: OWASP Top 10 + 精选 CVE 案例 + 代码级修复方案 (3 个 Markdown → 29 个向量块)
- **两阶段检索**: Qwen3-Embedding-0.6B 粗排 → Qwen3-Reranker-0.6B 精排
- **新工具**: `search_knowledge(query)` — 语义检索知识库
- **System Prompt**: 发现漏洞 → 先查知识库 → 带 CVE/CVSS/修复方案输出

### v0.6 — 扫描基础 + 静态分析 + 浏览器渲染
- **扫描边界**: 统一同域过滤、URL 规范化、超时、轻量限速和重试
- **JS/API 发现**: 新增 `analyze_js` / `discover_api`
- **JWT 审计**: 新增 `decode_jwt`
- **SPA 渲染**: 新增 `render_page`，通过 Playwright 提取渲染后 DOM 和网络请求
- **System Prompt**: 先做 JS/API/SPA 攻击面发现，再进入漏洞验证和知识库检索

### v0.7 — LFI 专项验证 + 工作台 UI
- **LFI 专项工具**: 新增 `test_lfi_param(url, param)`，自动建立 baseline、测试有限 payload、做响应差分和证据评分
- **Flag 提取**: 自动匹配 `flag{...}` / `ctf{...}` / `BUGKU{...}` / `key{...}` 等常见格式
- **工具事件流**: `Agent.run_events()` 透传 `tool_start` / `tool_end`，前端实时展示工具轨迹
- **停止扫描**: WebSocket 支持 `stop` 命令，前端新增 `■` 停止按钮
- **工作台 UI**: 会话历史、阶段进度、Markdown 报告、工具卡片和风险摘录
- **发布口径**: 原计划 v0.8 的核心 UI 能力合并到 v0.7 发布，tag 为 `v0.7`

### v0.8 — CUDA RAG 加速 + 工作台稳定性 ⭐ 当前
- **CUDA 运行环境**: 验证 Windows + NVIDIA GPU 下 `torch 2.12.1+cu130`，`torch.cuda.is_available()` 正常返回 `True`
- **RAG 自动设备选择**: Embedding 和 Reranker 统一使用 `cuda` / `cpu` 自动选择
- **Reranker 显存控制**: GPU 下使用 `float16`、小批量推理和动态 padding，避免固定 8192 token padding 导致 12GB 显存 OOM
- **前端布局修复**: 消息区独立滚动，输入栏固定在工作台底部，不再随对话增长被挤出视口
- **会话历史设计澄清**: 当前为 `localStorage` 本地缓存，后续后端持久化将参考 transcript/SQLite 方案实现
