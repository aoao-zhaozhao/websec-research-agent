# Web 安全漏洞修复方案 — 代码级最佳实践

## SQL 注入修复

### Python (参数化查询)
```python
# ❌ 危险 — 字符串拼接
cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")

# ✅ 安全 — 参数化查询
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))

# ✅ 安全 — ORM
user = session.query(User).filter(User.name == username).first()
```

### Java (PreparedStatement)
```java
// ❌ 危险
String query = "SELECT * FROM users WHERE name = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// ✅ 安全
String query = "SELECT * FROM users WHERE name = ?";
PreparedStatement ps = conn.prepareStatement(query);
ps.setString(1, username);
ResultSet rs = ps.executeQuery();
```

### Node.js (MySQL2)
```javascript
// ❌ 危险
const query = `SELECT * FROM users WHERE name = '${username}'`;
connection.query(query);

// ✅ 安全
const query = 'SELECT * FROM users WHERE name = ?';
connection.execute(query, [username]);
```


## XSS 修复

### HTML 实体编码
```python
from html import escape
safe_html = escape(user_input)
# <script> → &lt;script&gt;
```

### 内容安全策略 (CSP)
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' 'unsafe-inline'
```

### 前端框架安全
```javascript
// ❌ 危险 — innerHTML
element.innerHTML = userInput;

// ✅ 安全 — textContent
element.textContent = userInput;

// ✅ React 自动转义
<div>{userInput}</div>

// ⚠️ React 危险 — dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />
```


## CSRF 防护

### Token 验证模式
```python
# 后端 — 生成 CSRF Token
import secrets
csrf_token = secrets.token_hex(32)
session['csrf_token'] = csrf_token

# 后端 — 验证
if request.form['csrf_token'] != session['csrf_token']:
    raise Exception("CSRF validation failed")
```

### SameSite Cookie
```
Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Strict
```

### 关键操作建议
- 所有 POST/PUT/DELETE 请求验证 CSRF Token
- API 使用 Authorization Header 代替 Cookie
- 验证 Origin/Referer 请求头


## 安全头配置

### Nginx
```nginx
server {
    # 防止点击劫持
    add_header X-Frame-Options "DENY" always;

    # 强制 HTTPS (max-age=1年, 含子域)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 内容安全策略
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;

    # MIME 嗅探保护
    add_header X-Content-Type-Options "nosniff" always;

    # 引用策略
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # 隐藏服务器版本
    server_tokens off;
}
```

### Apache (.htaccess)
```apache
Header always set X-Frame-Options "DENY"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
ServerTokens Prod
```


## 密码安全

### 密码哈希 (Python)
```python
import bcrypt

# 存储密码
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
# 存储 hashed 到数据库

# 验证密码
bcrypt.checkpw(attempt.encode('utf-8'), hashed_from_db)
```

### 密码策略建议
- 最少 8 个字符
- 必须包含: 大写字母 + 小写字母 + 数字 + 特殊字符
- 密码过期: 90 天
- 密码历史: 禁止重复使用最近 5 个密码
- 失败锁定: 5 次失败后锁定 15 分钟


## 认证与授权

### JWT 安全实践
```python
# JWT 验证示例
import jwt

# ✅ 强制指定算法
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_exp": True})

# ✅ 短期 Token + Refresh Token
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ✅ 关键字段验证
if payload.get("iss") != "my-app":
    raise InvalidTokenError
```

### 会话安全
- 登录后更换 Session ID (防 Session 固定)
- 设置合理的超时时间 (应用: 30分钟, 敏感: 5分钟)
- 退出时销毁服务端 Session
- 限制同时登录设备数


## 文件上传安全

```python
# ✅ 白名单校验扩展名
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
if file_ext not in ALLOWED_EXTENSIONS:
    raise SecurityError("File type not allowed")

# ✅ 校验 MIME 类型
import magic
mime = magic.from_buffer(file.read(2048), mime=True)
if mime not in ALLOWED_MIMES:
    raise SecurityError("MIME type mismatch")

# ✅ 文件名安全化
import uuid, os
safe_name = str(uuid.uuid4()) + os.path.splitext(original_name)[1]

# ✅ 存储到非执行目录
# /var/www/uploads/   (不能通过 URL 直接执行)
# 不在 web root 下
```


## SSRF 防护

```python
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)

    # 1. 禁止危险协议
    if parsed.scheme not in ('http', 'https'):
        return False

    # 2. 解析目标 IP
    hostname = parsed.hostname
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    # 3. 禁止内网 IP
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False

    # 4. 禁止特殊范围
    if ip.is_multicast or ip.is_reserved:
        return False

    return True
```


## 输入校验通用原则

1. **白名单优先于黑名单**: 只允许已知安全的输入
2. **服务端校验不可省略**: 客户端校验仅改善体验，安全校验必须在服务端
3. **长度限制**: 所有字符串输入设定合理上限 (name ≤ 50, comment ≤ 5000)
4. **类型强校验**: 数字型参数必须转换为 int，字母数字型参数使用白名单正则
5. **编码统一**: 全站使用 UTF-8，输出时根据上下文选择正确的编码方式
