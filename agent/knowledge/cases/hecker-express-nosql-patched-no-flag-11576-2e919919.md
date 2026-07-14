---
id: hecker-express-nosql-patched-no-flag-11576-2e919919
title: hecker-express-nosql-patched-no-flag-11576
target: http://49.232.142.230:11576
category: general
tags:
- ctf
- express
- hecker
- nosql-injection
- patched
- shellmates
source: agent
created_at: '2026-07-13T06:28:24Z'
---

# hecker-express-nosql-patched-no-flag-11576

## Summary

Hecker Express.js 应用 - 端口11576。NoSQL 注入已被修补（与端口10422不同）。zombo:zombo 凭据有效但非 admin。/register 500错误暴露路径 /challenge/app/app.js。未找到 shellmates flag。

## Evidence

1. /register GET 返回500错误，堆栈暴露路径：file:///challenge/app/app.js:21:7 2. 登录响应差分：zombo:zombo=1413B (not admin), 无效凭据=2088B (Invalid) 3. 所有 NoSQL payload (form-urlencoded + JSON) 均返回2088B，无差分

## Resolution

未找到完整解题路径。NoSQL注入被修补，admin密码未知，无法提权。

## Failed Attempts

NoSQL注入($ne/$gt/$regex via form-urlencoded + JSON)，SQL注入(verify_injection)，密码爆破(admin常见密码)，SSTI探测，敏感路径访问
