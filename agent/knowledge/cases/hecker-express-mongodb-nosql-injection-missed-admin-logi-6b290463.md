---
id: hecker-express-mongodb-nosql-injection-missed-admin-logi-6b290463
title: hecker-express-mongodb-nosql-injection-missed-admin-login
target: http://49.232.142.230:10422
category: general
tags:
- authentication-bypass
- ctf
- express
- missed-opportunity
- mongodb
- nosql-injection
source: agent
created_at: '2026-07-13T05:35:52Z'
---

# hecker-express-mongodb-nosql-injection-missed-admin-login

## Summary

Express.js（Hecker 应用）NoSQL 注入漏洞扫描。通过 $ne 操作符确认了 NoSQL 注入存在（响应长度差分：2088B vs 1413B），但未跟进利用。正确解法：用 username=admin&password[$ne]= 注入登录为 admin，flag 可能直接在成功响应体中。应用无 session/cookie 机制，因此 flag 不依赖会话状态。

## Evidence

(1) POST /login with username=zombo&password=[REDACTED] → 2088B (Invalid)；(2) POST /login with username=zombo&password[$ne]= → 1413B (different response，注入成功)；(3) 响应头无 Set-Cookie，应用无会话机制；(4) GET /register → 500 error 泄露应用路径 /challenge/app/app.js 和视图目录 /challenge/views；(5) 技术栈：Express.js (X-Powered-By: Express)，疑似 MongoDB。

## Resolution

正确解法链：发现 NoSQL 注入($ne) → 注入为 admin(username=admin&password[$ne]=) → 从成功响应体提取 flag。无需 session/cookie 维持状态，flag 在响应体中。未完成因未跟进利用已确认的注入点。

## Failed Attempts

(1) SQL 注入全部无效；(2) SSTI 测试无求值结果；(3) Cookie/Header 权限提升无效；(4) 原型链污染无效；(5) 路径遍历 404；(6) 最关键失误：确认 NoSQL 注入后，未尝试以 admin 身份注入登录，未搜索成功响应体中的 flag 模式，过度关注 session 维持。
