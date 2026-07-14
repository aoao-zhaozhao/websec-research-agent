---
id: hecker-express-no-sql-injection-patched-port-19434-1f24a5a3
title: hecker-express-no-sql-injection-patched-port-19434
target: http://49.232.142.230:19434
category: general
tags:
- express
- hecker
- mongodb
- nosql-injection
- patched
source: agent
created_at: '2026-07-13T05:38:55Z'
---

# hecker-express-no-sql-injection-patched-port-19434

## Summary

Express MongoDB Hecker 应用 - 端口19434。zombo:zombo凭证有效但非admin。NoSQL注入在端口10422有效但19434上已被修补。/register端点泄露应用路径信息。未成功提权为admin。

## Evidence

1. /register GET 返回500错误堆栈，泄露文件路径/challenge/app/app.js:21 2. zombo:zombo登录成功，响应1413B显示"Sorry, you are not an admin" 3. 所有NoSQL注入操作符($ne/$regex/$gt/$exists/$eq/$nin)均返回2088B(Invalid) 4. 安全响应头(CSP/HSTS/XFO等)全面缺失 5. 应用无session/cookie机制

## Resolution

未找到完整的攻击链。可能解法：1. 端口10422上$ne注入有效，可尝试username=admin&password[$ne]=直接以admin登录 2. 19434可能被修补，需寻找其他漏洞

## Failed Attempts

NoSQL注入所有变体均无效、SQL注入(unconfirmed)、SSTI、原型链污染、权限提升header(17种)、Cookie操纵、暴力破解admin密码
