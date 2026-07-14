---
id: hecker-express-jwt-alg-none-no-flag-11576-82eb4a80
title: hecker-express-jwt-alg-none-no-flag-11576
target: http://49.232.142.230:11576
category: auth
tags:
- alg-none
- ctf
- express
- hecker
- hs256
- jwt
- nosql-injection-patched
source: agent
created_at: '2026-07-13T06:34:32Z'
---

# hecker-express-jwt-alg-none-no-flag-11576

## Summary

Hecker Express.js 应用，端口 11576。zombo:zombo 登录成功但非 admin。JWT (HS256) 存在弱密钥且 alg:none 攻击绕过签名验证被确认。NoSQL/SQL/SSTI/LFI 注入均已被修补。所有权限提升尝试（角色操控、头注入、Cookie 篡改）均未成功提取 flag。Flag 可能在 admin JWT 登录后的 home 页面中，但无法成功伪造有效的 admin JWT。

## Evidence

1. POST /login 返回 302 重定向并设置 JWT Cookie (token)
2. JWT: HS256, sub: {admin: false, data: {username: "zombo"}}
3. session_jwt_hmac_check 确认弱密钥存在
4. jwt_alg_none_attack 确认签名绕过（工具声明成功）
5. 所有 NoSQL 注入 payload 返回 2088B (Invalid)
6. verify_injection (sqli) 返回 unconfirmed 相似度 1.0
7. test_privilege_escalation: 0/17 个头注入绕过
8. test_role_manipulation: 10 个 JSON 修改均为 2088B (Invalid)
9. 原型链污染、register 端点、额外路径搜索均无结果

## Resolution

登录 zombo:zombo 后 JWT 的 admin: false。需要将 JWT payload 中 sub.admin 改为 true 并正确签名。
session_jwt_hmac_check 确认密钥弱但在其 22 候选词表中，而 jwt_hmac_brute 使用不同词表未找到密钥。
alg:none 攻击工具确认成功但返回页面仍为 "not admin"。
理论上 alg:none + sub.admin: true 的 JWT 通过 Cookie(token) 发送应能提权，但实际测试返回 2088B (未认证视图)。

## Failed Attempts

所有 NoSQL 注入变体失败。SQL 注入失败(相似度1.0)。SSTI 失败。LFI 失败。角色操控(JSON)返回 Invalid。权限提升头注入0/17。原型链污染失败。JWT HMAC 爆破 1063 候选词未找到密钥。JWT 通过 Cookie 发送 alg:none token 返回未认证视图。
