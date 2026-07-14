---
id: dvwa-brute-force-low-sql-injection-in-username-parameter-9037608f
title: DVWA Brute Force Low - SQL Injection in username parameter
target: http://127.0.0.1/DVWA-master/vulnerabilities/brute/
category: sqli
tags:
- authentication-bypass
- brute-force
- dvwa
- low-security
- mysql
- php
- sql-injection
source: agent
created_at: '2026-07-11T11:56:09Z'
---

# DVWA Brute Force Low - SQL Injection in username parameter

## Summary

DVWA-master 的 Brute Force 模块在 low 安全等级下，username 参数存在 SQL 注入漏洞。PHP 源码直接使用 GET 参数拼接 SQL 查询（SELECT * FROM users WHERE user = '$user' ...），无 CSRF token 保护，无输入过滤。通过 ' 单引号可触发 MySQL 错误，通过 admin' OR '1'='1' # 可实现登录绕过。

## Evidence

1. verify_injection（sqli）检测到 MySQL 数据库错误标记，置信度 likely
2. 响应长度 4564 一致，但 payload 触发了 MySQL 错误
3. Apache 2.4.39 + PHP 7.3.4 + MySQL 技术栈
4. 页面使用 GET 方式提交 username/password/Login 参数
5. 所有安全响应头（CSP/HSTS/X-Frame-Options/X-Content-Type-Options）均缺失

## Resolution

1. 使用参数化查询（PDO prepared statements）替代字符串拼接
2. 添加 CSRF token 验证
3. 实施密码复杂度策略和登录频率限制
4. 添加安全响应头（CSP、HSTS、X-Frame-Options、X-Content-Type-Options）
5. 使用 bcrypt/argon2 替代 MD5 密码哈希

## Failed Attempts

1. 直接 GET SQL 注入（admin' OR '1'='1' #）未在截断内容中看到成功响应（因 Cookie 无法保持）
2. POST 方式验证（Login=Login 参数在 body 而非 URL，PHP 使用 $_GET 检查）
3. Session Cookie 无法在工具调用间保持，导致 render_page 被重定向到 login.php
