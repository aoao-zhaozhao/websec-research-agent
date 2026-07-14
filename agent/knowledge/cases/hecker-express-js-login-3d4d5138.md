---
id: hecker-express-js-login-3d4d5138
title: Hecker Express.js Login 应用安全审计
target: http://49.232.142.230:10422
category: general
tags:
- ctf
- express
- hecker
- login
- nodejs
- shellmates
source: agent
created_at: '2026-07-13T05:07:25Z'
---

# Hecker Express.js Login 应用安全审计

## Summary

目标为 Express.js 构建的简单登录应用（Hecker），共有 / 和 /login 两个路由页面。GET /register 触发 500 错误泄露服务器端路径信息。所有安全响应头（CSP/HSTS/X-Frame-Options等）均缺失。尝试了 SQL 注入、NoSQL 注入、SSTI、Cookie 权限提升、原型链污染和路径遍历等多种攻击向量，均未得到确认。应用使用视图引擎渲染但视图模板不全（register视图不存在），认证逻辑未发现可注入漏洞。

## Evidence

通过 analyze_headers 确认所有6项安全头缺失；通过 GET /register 获取 Express 错误堆栈，泄露文件路径 /challenge/app/app.js:21 和视图目录 /challenge/views；通过 verify_injection 确认 SQLi 未产生差分信号；test_ssti 确认所有模板注入 payload 未触发；test_ssrf 未测试（无明显 URL 参数）

## Resolution

本次扫描未发现可确认的高危漏洞。建议的审计路径：1) 尝试更多认证绕过技巧（如默认凭证、暴力破解弱口令）；2) 检查是否有隐藏的 API 端点或资源文件；3) 进一步分析 Express 视图引擎是否存在 EJS/Pug SSTI 漏洞；4) 检查是否有反向代理配置错误导致内部网络访问。

## Failed Attempts

SQL注入（' OR '1'='1, "等）→ 无差分；NoSQL注入（$ne, $gt, $regex, JSON体）→ 全部返回Invalid Username；SSTI（{{7*7}}, ${7*7}, <%=7*7%>, #{7*7}）→ 未触发；Cookie权限提升（role=admin, is_admin=1, VIP=1等）→ 未改变/home响应；原型链污染（__proto__[isAdmin]=true）→ 未生效；路径遍历（..%2f, %2e%2e）→ 404
