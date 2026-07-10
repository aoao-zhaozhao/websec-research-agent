# Authentication & Authorization Vulnerabilities

> 来源: Shannon OSS + OWASP Top 10 (2021) A01/A07

## 认证漏洞 (Authentication) - Shannon 9 类检查

### 1. 传输与缓存
- HTTPS 是否强制 (HSTS)
- Cache-Control: no-store 是否设置
- 敏感数据是否通过 URL 参数传递

### 2. 速率限制
- 登录端点是否有 per-IP / per-account 速率限制
- 是否有账户锁定/退避机制
- CAPTCHA 的存在与有效性

### 3. 会话管理
- Cookie 安全标志: HttpOnly, Secure, SameSite
- 登录后会话 ID 是否轮换
- 退出登录后会话是否失效
- 空闲/绝对超时策略
- URL 中是否暴露会话 ID

### 4. 令牌/会话属性
- 加密随机性 (非顺序 ID)
- HTTPS 限定传输
- 不在日志中记录
- 明确的过期时间 (exp)

### 5. 会话固定 (Session Fixation)
- 登录前 vs 登录后的会话 ID 是否变化
- 如果登录前后 session ID 不变 → 会话固定漏洞

### 6. 密码与账户策略
- 代码中无硬编码默认凭据
- 服务端密码复杂度验证
- 单向哈希 (bcrypt/argon2) 非可逆加密
- MFA/2FA 是否可用

### 7. 登录/注册响应
- 错误消息是否泛化 (不区分 "用户不存在" vs "密码错误")
- 防止用户枚举

### 8. 找回密码与退出
- 密码重置令牌: 一次性、短期 TTL、速率限制
- 退出登录时的服务端会话失效

### 9. SSO / OAuth 安全
- state 参数 (防 CSRF)
- nonce (防重放)
- 精确的 redirect_uri 白名单
- 签名验证
- PKCE (公共客户端)
- **nOAuth 检查**: 使用不可变的 `sub` 声明，不是 email/name

## JWT 攻击技术 (Shannon exploit-auth)

### alg:none 攻击
```
1. 捕获 JWT: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature
2. 解码 header → 将 "alg" 改为 "none"
3. 修改 payload: sub 改为 "admin"
4. 移除签名 (保留末尾点号)
5. 发送: eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
```

### HMAC 弱密钥爆破
```
常用弱密钥: secret, password, changeme, jwt_secret, admin, test
工具: jwt-cracker, hashcat -m 16500, john
```

### 密钥混淆 (CVE-2016-5431)
```
1. 获取 RSA 公钥 (从 /.well-known/jwks.json)
2. 将 JWT header.alg 从 RS256 改为 HS256
3. 用 RSA 公钥 PEM 作为 HMAC secret 签名
4. 服务器使用公钥 → 作为 HMAC key 验证通过
```

### kid 头注入
```
{
  "alg": "HS256",
  "kid": "../../../../etc/passwd"
}
→ 服务器用 /etc/passwd 内容当作 HMAC key
```

## 授权漏洞 (Authorization) - Shannon 攻击分类

### 水平越权 (IDOR)
- 顺序 ID 枚举: ?id=42 → ?id=43
- 标识符操控: ?user_id=123 → ?user_id=456
- 引用令牌替换: 用自己的访问令牌访问他人资源
- 跨租户参数修改
- 共享资源泄露 (缓存、日志、通知)

### 垂直越权 (Privilege Escalation)
- 低权限会话直接访问管理端点
- 头注入绕过:
  ```
  X-Role: admin
  X-Admin: true
  X-Forwarded-For: 127.0.0.1
  X-Original-URL: /admin
  X-Forwarded-Prefix: /admin
  ```
- 请求体权限字段篡改: `{"role": "admin"}`, `{"is_admin": true}`
- 中间件/网关绕过

### 上下文/工作流绕过
- 步骤跳过: 直接从 step=1 跳到 step=4
- 状态操控: 将状态改为 "已支付" 或 "已批准"
- 乱序执行: 在验证前完成操作
- 强制状态转换: 取消/退款/删除操作绕过审批

## 防御检查清单 (Shannon 检测标准)

### 认证
- [ ] HTTPS + HSTS + secure-only cookies
- [ ] 速率限制 + 账户锁定
- [ ] 会话 ID 在登录后轮换
- [ ] JWT: 验证 alg、exp、签名
- [ ] SSO: state/nonce/PKCE 验证

### 授权
- [ ] 每个端点的显式角色/权限守卫
- [ ] 对象所有权验证 (不是仅验证 "是否已登录")
- [ ] 数据库查询包含租户/用户过滤
- [ ] 管理端点不暴露在公共路由
- [ ] 拒绝默认访问 (zero-trust 模式)

## 修复方案

```python
# 认证: JWT 验证
import jwt
payload = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_exp": True})

# 授权: 对象所有权 + 角色守卫
def get_order(order_id: int, current_user: User) -> Order:
    order = Order.get(order_id)
    if order.user_id != current_user.id and current_user.role != "admin":
        raise Forbidden("not your order")
    return order

# 授权: 中间件守卫
@app.middleware
async def admin_required(request, call_next):
    if request.headers.get("X-Role") == "admin":  # ❌ 危险
        return await call_next(request)
    # ✅ 应从服务端会话中读取角色，不信任客户端头
    if request.session.get("role") == "admin":
        return await call_next(request)
    raise HTTPException(403)
```
