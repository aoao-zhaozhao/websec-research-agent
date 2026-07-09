# My Agent - Web Security Scanner

基于 DeepSeek + LangGraph 的 Web 应用安全审计 Agent。当前版本为 **v0.7**。

v0.7 将原计划 v0.7 和 v0.8 合并发布：

- LFI 专项验证工具：`test_lfi_param(url, param)`
- LangGraph 工具事件透传：`tool_start` / `tool_end`
- Web 工作台 UI：会话历史、阶段进度、工具轨迹、Markdown 报告和风险摘录
- 保留 v0.6 能力：同源爬取、JS/API 发现、JWT 审计、SPA 渲染、RAG 知识库校验

## 项目结构

```text
my-agent/
├── .env
├── requirements.txt
├── agent/
│   ├── agent.py
│   ├── config.py
│   ├── prompts.py
│   ├── rag.py
│   ├── tools/
│   │   ├── http_tools.py
│   │   ├── analysis_tools.py
│   │   ├── crawl_tools.py
│   │   ├── static_tools.py
│   │   ├── lfi_tools.py
│   │   └── http_client.py
│   └── knowledge/
├── server/
│   └── web_server.py
├── web/
│   └── index.html
└── test_client.py
```

## 快速开始

### 1. 配置 API Key

编辑 `.env`：

```env
DEEPSEEK_API_KEY=sk-your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

### 2. 安装依赖

```bash
python -m venv myagent
myagent\Scripts\Activate.ps1
pip install -r requirements.txt
```

`render_page` 使用 Playwright。首次使用前安装 Chromium：

```powershell
$env:PLAYWRIGHT_DOWNLOAD_HOST='https://npmmirror.com/mirrors/playwright'
python -m playwright install chromium
```

### 3. 启动服务

```bash
python server/web_server.py
```

浏览器打开：

```text
http://127.0.0.1:9120
```

### 4. 停止服务

如果服务是在当前终端启动的，按 `Ctrl+C`。

如果服务在后台运行，释放 9120 端口：

```powershell
Get-NetTCPConnection -LocalPort 9120 | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force
}
```

## Web 工作台

底部输入区包含三个操作：

| 按钮 | 作用 |
| --- | --- |
| `▶` | 开始扫描 |
| `■` | 停止当前扫描，不清空当前会话 |
| `×` | 清空当前会话内容和 Agent 记忆 |

关闭浏览器标签页会断开 WebSocket，会话生命周期随连接结束。`×` 只清空内容，`■` 用于取消正在运行的扫描任务。

## API

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/api/chat` | WebSocket | 流式对话，返回 token 和工具事件；支持 `clear` / `stop` 命令 |
| `/api/config` | GET/PUT | 查看或修改运行配置 |
| `/api/sessions` | GET | 活跃连接数 |
| `/api/health` | GET | 健康检查 |

## 工具列表

| 工具 | 用途 |
| --- | --- |
| `http_get(url)` | GET 请求，查看状态码、响应头和正文摘要 |
| `http_post(url, data)` | POST 请求，提交轻量测试 payload |
| `analyze_headers(url)` | 检查 CSP、HSTS、X-Frame-Options 等安全头 |
| `extract_forms(url)` | 提取表单和输入参数 |
| `extract_links(url)` | 提取同源链接 |
| `crawl(root_url)` | 同源 BFS 爬取和敏感路径探测 |
| `sitemap(root_url)` | 攻击面分类 |
| `batch_scan(root_url)` | 批量安全头检查 |
| `analyze_js(url)` | 扫描 JS 中的密钥、JWT、API、sourcemap、debug 标记 |
| `decode_jwt(token)` | 解码 JWT 并审计常见配置风险 |
| `discover_api(url)` | 探测 OpenAPI / Swagger / GraphQL / API 入口 |
| `render_page(url)` | 使用 Playwright 渲染 SPA 并提取 DOM/网络请求 |
| `test_lfi_param(url, param)` | 对疑似 LFI 参数做 bounded payload 验证、响应差分和 flag-like 提取 |
| `search_knowledge(query)` | RAG 知识库检索漏洞分类、CVE/CVSS 参考和修复建议 |

## v0.7 说明

`test_lfi_param` 用来解决 LFI 验证反复试 payload、容易耗尽 Agent 步数的问题。它会：

- 建立正常值和非法值 baseline
- 对指定参数测试有限数量的路径穿越、编码、Windows、`php://filter` payload
- 对状态码、正文长度、关键字、响应差分做评分
- 自动提取 `flag{...}` / `ctf{...}` / `BUGKU{...}` / `key{...}` 等常见 CTF 证据
- 输出命中 payload、URL、证据摘要、置信度和下一步建议

Web UI 同时升级为工作台形态，包含工具轨迹、风险摘录、会话历史和停止扫描按钮；版本仍按 v0.7 发布。
