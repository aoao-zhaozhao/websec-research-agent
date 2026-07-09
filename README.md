# My Agent

一个基于 DeepSeek 的 AI Agent，支持工具调用、流式输出，通过 FastAPI + WebSocket 提供服务。

## 项目结构

```
my-agent/
├── .env                  # 环境变量（API Key 等）
├── requirements.txt      # Python 依赖
├── agent/
│   ├── __init__.py
│   └── core.py           # Agent 推理核心（与 FastAPI 解耦，可独立运行）
├── server/
│   └── web_server.py     # FastAPI 服务器（WebSocket 对话 + REST API）
└── test_client.py        # 命令行测试客户端
```

## 快速开始

### 1. 配置 API Key

```bash
cp .env.example .env
```

编辑 `.env`，填入你的 DeepSeek API Key：

```env
DEEPSEEK_API_KEY=sk-your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

### 2. 创建虚拟环境 & 安装依赖

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

看到以下输出表示启动成功：

```
🚀 Agent 服务启动: http://127.0.0.1:9120
   WebSocket 对话: ws://127.0.0.1:9120/api/chat
   配置接口:       http://127.0.0.1:9120/api/config
   健康检查:       http://127.0.0.1:9120/api/health
```

### 4. 测试对话

另开一个终端，激活虚拟环境后运行：

```bash
python test_client.py
```

Agent 会自动调用内置工具（计算器、获取时间），并流式输出回复。

## API 接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/chat` | WebSocket | 核心对话——逐 token 流式输出，支持工具调用 |
| `/api/config` | GET | 查看当前配置 |
| `/api/config` | PUT | 修改模型/System Prompt 等配置 |
| `/api/health` | GET | 健康检查 |

### WebSocket 消息格式

**发送（客户端 → 服务器）：**

```json
{"content": "帮我算一下 123 * 456"}
```

**接收（服务器 → 客户端）：**

```json
{"type": "token", "content": "好的"}
{"type": "token", "content": "，"}
...
{"type": "done"}
```

## 架构

```
浏览器 / CLI
    │
    │ HTTP REST + WebSocket
    ▼
┌──────────────┐
│   FastAPI    │  ← server/web_server.py
│  (控制面)    │    配置管理 / 会话入口 / 流式输出
└──────┬───────┘
       │ 函数调用
       ▼
┌──────────────┐
│  Agent Core  │  ← agent/core.py
│  (推理面)    │    DeepSeek 调用 / 工具执行 / 多轮循环
└──────────────┘
```

- `agent/core.py` 不依赖 FastAPI，可以脱离 Web 服务器独立使用
- FastAPI 只是 Agent 的一个"外壳"，负责把用户输入喂进去、把 token 推出来

## 内置工具

| 工具 | 说明 |
|---|---|
| `get_current_time` | 获取当前日期时间 |
| `calculate` | 安全的数学表达式计算 |

工具定义在 `agent/core.py` 的 `TOOLS` 列表中，添加新工具只需三个步骤：
1. 在 `TOOLS` 中添加函数定义
2. 在 `_execute_tool()` 中添加执行逻辑
3. 重启服务
