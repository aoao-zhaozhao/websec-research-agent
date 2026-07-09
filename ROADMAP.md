# My Agent Roadmap

## 当前状态：v0.7

v0.7 合并交付原计划的 v0.7 和 v0.8：

- v0.7：LFI 专项验证工具
- v0.8：Agent UI 2.0 的核心体验

版本发布口径统一为 **0.7.0**。

## 已交付

### v0.1 - 基础框架

- DeepSeek 调用
- 最小 ReAct 工作流
- 基础工具调用

### v0.2 - 多轮记忆

- Agent 实例绑定 WebSocket 连接生命周期
- 会话内保留消息上下文

### v0.3 - LangGraph 重构

- 使用 `langgraph.prebuilt.create_react_agent`
- 引入 Web 安全扫描工具

### v0.4 - 爬取和 Web 前端

- `crawl`
- `sitemap`
- `batch_scan`
- 浏览器页面直接对话

### v0.5 - RAG 知识库

- 拆分 `agent/` 模块结构
- 引入 OWASP Top 10、CVE 示例和修复建议知识库
- 使用 Qwen3 Embedding + Reranker 做两阶段检索
- 新增 `search_knowledge(query)`

### v0.6 - 静态分析和 SPA 渲染

- 统一 HTTP 客户端、同源边界、超时、限速和重试
- 新增 `analyze_js`
- 新增 `decode_jwt`
- 新增 `discover_api`
- 新增 `render_page`

### v0.7 - LFI 验证 + 工作台 UI

#### LFI 专项验证

- 新增 `test_lfi_param(url, param)`
- 自动建立 baseline 和非法值响应
- 内置 bounded payload 集合：
  - `/etc/passwd`
  - 路径穿越
  - URL 编码和双重编码
  - Windows `win.ini`
  - `php://filter`
- 响应差分评分
- 常见文件包含证据识别
- flag-like 值提取
- 连续失败后自动收敛

#### LangGraph 事件流

- `Agent.run_events()` 输出结构化事件：
  - `token`
  - `tool_start`
  - `tool_end`
- `Agent.run()` 保持旧的 token-only 兼容接口
- WebSocket 透传工具名称、参数和结果摘要
- WebSocket 支持 `stop` 命令取消当前扫描任务
- `clear` 会清空会话记忆，并在必要时取消正在运行的扫描

#### Web 工作台

- 会话历史保存到 `localStorage`
- 阶段进度：测绘、静态分析、验证、知识库、报告
- 工具调用卡片：执行中、完成、参数、结果摘要
- Markdown 报告渲染
- 风险摘录侧栏
- 底部操作区支持开始、停止当前扫描、清空当前会话
- 当前 UI 能力按 v0.7 发布，不单独提升版本号到 v0.8

## 下一步

### v0.8 - UI 打磨和协议增强

当前 v0.7 已包含核心工作台 UI。后续 v0.8 只保留增量打磨：

- 更完整的工具结果结构化协议
- 更稳定的漏洞卡片解析
- 更强的取消能力：对 CPU 密集型同步工具做子进程隔离或超时中断
- 工具调用耗时统计
- 前端文件拆分为 `style.css` / `app.js`

### v0.9 - 主动验证引擎

- 响应差分引擎
- YAML payload 模板
- 时间盲注检测
- OOB 回连检测
- 统一证据模型
- sqlmap / nuclei 外部引擎对接

### v1.0 - 认证扫描

- 登录表单识别
- Cookie / Token 状态保持
- 多角色对比
- IDOR 检测
- 凭证安全处理

### v1.1 - 持久化和报告

- SQLite 扫描结果入库
- 历史扫描对比
- Markdown / PDF 报告导出
- OWASP ASVS 映射

### v1.2 - 生产化部署

- Redis 队列
- Worker 进程
- API Key 鉴权
- 沙箱隔离
- Docker Compose
- Prometheus metrics

### v1.3 - 多租户前端

- React 重写前端
- PostgreSQL
- 多租户数据隔离
- 权限模型
