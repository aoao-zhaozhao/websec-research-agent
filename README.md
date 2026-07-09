# My Agent

一个基于 DeepSeek 的 AI Agent，支持工具调用、流式输出、多轮对话记忆。通过 FastAPI + WebSocket 提供服务。

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
└── test_client.py        # 命令行测试客户端（支持多轮对话）
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
🚀 Agent 服务启动 (v0.2): http://127.0.0.1:9120
   WebSocket 对话: ws://127.0.0.1:9120/api/chat
   配置接口:       http://127.0.0.1:9120/api/config
   健康检查:       http://127.0.0.1:9120/api/health
```

### 4. 测试多轮对话

另开一个终端，激活虚拟环境后运行：

```bash
python test_client.py
```

现在支持连续输入多轮对话：

```
👤 你: 我叫张三
🤖 Agent: 你好张三！有什么我可以帮你的吗？

👤 你: 我叫什么名字？
🤖 Agent: 你叫张三。

👤 你: /clear
🧹 对话记忆已清空

👤 你: exit
👋 退出
```

## API 接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/chat` | WebSocket | 核心对话——逐 token 流式输出，支持工具调用和多轮记忆 |
| `/api/config` | GET | 查看当前配置 |
| `/api/config` | PUT | 修改模型/System Prompt 等配置 |
| `/api/sessions` | GET | 查看当前活跃连接数 |
| `/api/health` | GET | 健康检查 |

### WebSocket 消息格式

**发送（客户端 → 服务器）：**

```json
// 普通消息
{"content": "帮我算一下 123 * 456"}

// 清空记忆
{"command": "clear"}
```

**接收（服务器 → 客户端）：**

```json
{"type": "token", "content": "好的"}
{"type": "token", "content": "，"}
...
{"type": "done"}
{"type": "info", "content": "对话记忆已清空"}
```

## 架构

```
浏览器 / CLI
    │
    │ HTTP REST + WebSocket
    ▼
┌──────────────────────────┐
│        FastAPI            │  ← server/web_server.py
│  (控制面 - v0.2)          │
│  • 配置管理                │
│  • WS 会话管理             │     每个 WS 连接内复用同一个
│  • 流式输出                │     Agent 实例 → 多轮记忆
└──────────┬───────────────┘
           │ 函数调用
           ▼
┌──────────────────────────┐
│       Agent Core          │  ← agent/core.py
│  (推理面 - v0.2)          │
│  • DeepSeek 调用           │
│  • 工具执行                │     messages 跨 run() 累积
│  • 多轮对话记忆            │     clear() 可随时清空
└──────────────────────────┘
```

- `agent/core.py` 不依赖 FastAPI，可以脱离 Web 服务器独立使用
- FastAPI 只是 Agent 的一个"外壳"，负责把用户输入喂进去、把 token 推出来

## 版本演进

### v0.1 → v0.2：多轮对话记忆

| 文件 | 改动 |
|---|---|
| `agent/core.py` | `_reset()` 移除；`messages` 在 `__init__` 时初始化只含 system_prompt；`run()` 每次追加 user 消息而非清空；新增 `clear()` 方法 |
| `server/web_server.py` | Agent 实例从"每条消息 new 一个"改为"每个 WS 连接创建一个，全程复用"；新增 `/clear` 指令和 `/api/sessions` 接口 |
| `test_client.py` | 从"发一条退出一条"改为 `while True` 循环 + `input()` 交互，支持 `/clear` 和 `exit` |

**核心思路**：Agent 的 `self.messages` 列表在实例生命周期内持续累积。FastAPI 不再每句话重建 Agent，而是把 Agent 的生命周期绑定到 WebSocket 连接上。WS 连上 → Agent 诞生，WS 断开 → Agent 销毁。同一连接内的所有对话自然累积在 messages 列表里。

## 内置工具

| 工具 | 说明 |
|---|---|
| `get_current_time` | 获取当前日期时间 |
| `calculate` | 安全的数学表达式计算 |

工具定义在 `agent/core.py` 的 `TOOLS` 列表中，添加新工具只需三个步骤：
1. 在 `TOOLS` 中添加函数定义
2. 在 `_execute_tool()` 中添加执行逻辑
3. 重启服务
