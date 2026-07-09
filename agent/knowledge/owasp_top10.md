# OWASP Top 10 (2021) — Web 应用安全风险

## A01: 访问控制失效 (Broken Access Control)

**CWE 参考**: CWE-200, CWE-201, CWE-352
**平均 CVSS**: 7.5 (高危)

### 常见场景
- 修改 URL 中的 ID 参数访问他人资源 (IDOR)
- 普通用户直接访问 /admin 路径
- 未验证 JWT Token 签名
- CORS 配置过于宽松 (`Access-Control-Allow-Origin: *` 配合凭证)

### 检测方法
1. 尝试直接访问管理类路径: /admin, /dashboard, /api/admin
2. 修改资源 ID 参数看是否越权
3. 用低权限 Token 访问高权限接口
4. 检查 CORS 头是否宽松

### 修复方案
- 所有 API 必须做服务端权限校验
- 使用基于角色的访问控制 (RBAC)
- JWT Token 必须验证签名和过期时间
- CORS 仅允许受信域，避免 `*`


## A02: 加密机制失效 (Cryptographic Failures)

**CWE 参考**: CWE-311, CWE-326, CWE-327
**平均 CVSS**: 7.2 (高危)

### 常见场景
- 使用 HTTP 而非 HTTPS 传输敏感数据
- 使用弱哈希算法 (MD5, SHA1) 存储密码
- 使用硬编码密钥
- 使用过时的 TLS 版本 (TLS 1.0/1.1)

### 检测方法
1. 检查是否强制 HTTPS (HSTS 头)
2. 检查 Cookie 是否有 Secure 标志
3. 查看证书是否有效
4. 检查密码重置流程是否安全

### 修复方案
- 全站 HTTPS + HSTS 头
- 密码使用 bcrypt/argon2 哈希
- Cookie 设置 Secure + HttpOnly + SameSite
- 密钥使用环境变量管理，不硬编码


## A03: 注入攻击 (Injection)

**关联 CVE**: CVE-2023-36123, CVE-2022-22965, CVE-2021-44228
**CWE 参考**: CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (命令注入)
**平均 CVSS**: 8.6 (严重)

### SQL 注入 (SQL Injection)

**典型 Payload**:
```
' OR '1'='1
' OR 1=1--
admin'--
' UNION SELECT 1,2,3--
'; DROP TABLE users;--
' OR SLEEP(5)--
```

**检测标志**:
- 输入单引号引发数据库错误 (如 "MySQL Error", "ORA-", "SQL syntax")
- 输入 `' OR '1'='1` 返回全部数据
- 时间盲注: `' OR SLEEP(5)--` 响应延迟 5 秒

**修复方案**:
```python
# ✅ 参数化查询 (Python/MySQL)
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))

# ✅ ORM 方式
User.objects.filter(name=username)

# ❌ 危险: 字符串拼接
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
```


### 跨站脚本 (XSS)

**典型 Payload**:
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
```

**检测方法**:
- 在输入框输入 `<script>alert('XSS')</script>`
- 查看页面源码，确认 payload 是否原样反射
- 检查是否在 `innerHTML` / `document.write` 中直接使用用户输入

**修复方案**:
```python
# ✅ HTML 实体编码
from html import escape
safe = escape(user_input)  # <script> → &lt;script&gt;

# ✅ 使用安全模板引擎
# Jinja2 自动转义: {{ user_input }}

# ✅ CSP 头
Content-Security-Policy: default-src 'self'; script-src 'self'
```


### 命令注入 (Command Injection)

**典型 Payload**:
```
; ls -la
| whoami
`cat /etc/passwd`
$(id)
&& cat /etc/hosts
```

**修复方案**:
- 避免直接调用系统命令处理用户输入
- 使用 subprocess 时设置 `shell=False`
- 使用白名单校验参数值


## A04: 不安全的设计 (Insecure Design)

**CWE 参考**: CWE-209, CWE-256, CWE-501
**平均 CVSS**: 7.0 (高危)

### 修复方案
- 威胁建模 (Threat Modeling) 前置
- 安全需求评审纳入开发流程
- 限制登录尝试次数 (防暴力破解)
- 关键操作二次确认


## A05: 安全配置错误 (Security Misconfiguration)

**CWE 参考**: CWE-16, CWE-611
**平均 CVSS**: 7.3 (高危)

### 常见场景
- 默认账号密码未修改 (admin/admin, root/root)
- 目录列表开启 (Directory Listing)
- 详细错误信息输出到前端 (Stack Trace 泄露)
- 不必要的 HTTP 方法启用 (PUT, DELETE, TRACE)
- server 版本号暴露 (Server: Apache/2.4.1)

### 检测方法
1. 探测 /.env, /.git/HEAD, /phpinfo.php
2. 检查 Server 响应头
3. 尝试 OPTIONS 方法查看允许的 HTTP 方法
4. 测试默认密码

### 修复方案
- 上线前检查清单: 修改默认密码、关闭 Debug 模式、禁用目录列表
- Nginx: `server_tokens off;`
- 移除不必要的 HTTP 方法


## A06: 脆弱和过时的组件 (Vulnerable and Outdated Components)

**平均 CVSS**: 7.2 (高危)

### 修复方案
- 定期 `npm audit` / `pip audit` / `dependency-check`
- 自动化依赖扫描 (Dependabot / Snyk)
- 关注 CVE 通报


## A07: 身份识别和认证失效 (Identification and Authentication Failures)

**CWE 参考**: CWE-287, CWE-384
**平均 CVSS**: 8.1 (严重)

### 常见场景
- 弱密码策略 (允许 123456)
- Session 固定攻击 (登录后 Session ID 不变)
- 敏感操作无二次认证
- Token 未过期或刷新机制不安全

### 检测方法
1. 测试弱密码: admin, 123456, password
2. 登录前后对比 Session ID
3. 长时间未操作后 Session 是否过期
4. 退出后 Session 是否失效

### 修复方案
- 多因素认证 (MFA)
- 密码强度策略: 8位以上 + 大小写 + 数字 + 特殊字符
- 登录限流: IP 级别 + 账号级别
- Session 管理: 登录后更换 Session ID


## A08: 软件和数据完整性失效 (Software and Data Integrity Failures)

**CWE 参考**: CWE-502, CWE-829
**平均 CVSS**: 7.5 (高危)

### 修复方案
- 验证第三方库的完整性 (Hash/Signature)
- 反序列化白名单
- CI/CD 管道安全检查


## A09: 安全日志和监控失效 (Security Logging and Monitoring Failures)

**CWE 参考**: CWE-778
**平均 CVSS**: 6.5 (中危)

### 修复方案
- 记录: 登录(成功/失败)、权限变更、数据修改、异常输入
- 日志格式: [时间] [IP] [用户] [操作] [结果] [详情]
- 日志不记录敏感信息: 密码、Token、身份证号


## A10: 服务端请求伪造 (SSRF)

**CWE 参考**: CWE-918
**平均 CVSS**: 8.5 (严重)

### 典型 Payload
```
http://169.254.169.254/latest/meta-data/  (AWS 元数据)
http://127.0.0.1:6379/  (内网 Redis)
file:///etc/passwd
```

### 修复方案
- URL 白名单
- 禁内网 IP 段 (10.x, 172.16-31.x, 192.168.x, 127.x)
- 禁用 file://, gopher:// 等危险协议
