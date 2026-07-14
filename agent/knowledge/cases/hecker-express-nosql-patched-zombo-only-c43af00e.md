---
id: hecker-express-nosql-patched-zombo-only-c43af00e
title: hecker-express-nosql-patched-zombo-only
target: http://49.232.142.230:11576
category: general
tags:
- ctf
- express
- mongodb
- nosql-injection-patched
- privesc-failed
- zombo
source: agent
created_at: '2026-07-13T06:23:59Z'
---

# hecker-express-nosql-patched-zombo-only

## Summary

Express.js Hecker CTF 应用（端口11576）- NoSQL注入已被修补。已知凭据 zombo:zombo 有效但仅为普通用户（"Sorry, you are not an admin"）。/register 端点泄露应用路径 /challenge/app/app.js。未找到提权为admin的方法。

## Evidence

(1) POST /login with username=zombo&password=[REDACTED] → 1413B "Sorry, you are not an admin"；(2) POST /login with NoSQL payloads → 2088B "Invalid Username or Password" (patched)；(3) GET /register → 500 error 泄露路径 /challenge/app/app.js:21:7 和视图目录 /challenge/views；(4) 响应头无Set-Cookie，无会话机制；(5) 技术栈：Express.js (X-Powered-By: Express)，疑似MongoDB + EJS

## Resolution

已确认 zombo:zombo 登录成功。NoSQL注入在此端口被修补。未找到提权为admin的安全漏洞。可能的后续方向：利用EJS模板渲染漏洞、尝试更复杂的NoSQL注入绕过、或者通过未公开的API端点。

## Failed Attempts

NoSQL注入（$ne/$gt/$regex/$exists）urlencoded和JSON均失败；SQL注入(XSS/SSTI未确认；角色操控参数被接受但不影响权限；路径遍历被Express阻止；原型链污染无效果
