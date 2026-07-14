---
id: hecker-express-jwt-weak-key-privilege-escalation-77614e60
title: Hecker Express JWT Weak Key Privilege Escalation
target: http://49.232.142.230:11240
category: auth
tags:
- alg-none
- express
- hecker
- hs256
- jwt
- privilege-escalation
- weak-key
source: agent
created_at: '2026-07-13T06:52:46Z'
---

# Hecker Express JWT Weak Key Privilege Escalation

## Summary

Express.js应用使用HS256 JWT进行认证，zombo:zombo登录成功但非admin。JWT弱密钥(HS256)经session_jwt_hmac_check确认，session_jwt_privilege_check验证sub.admin:false→true提权成功(SHA-256变更)。alg:none签名绕过也被确认。无法通过jwt_hmac_brute找到具体密钥值，flag位于admin JWT认证后的/home页面中。

## Evidence

1. auth_login成功捕获JWT会话(HS256, admin:false) 2. session_jwt_hmac_check确认弱密钥 3. session_jwt_privilege_check验证admin提权成功(返回不同SHA-256: b7da05d0...) 4. jwt_alg_none_attack确认alg:none绕过 5. /register端点泄露源代码路径(/challenge/app/app.js) 6. 缺少6项安全响应头

## Resolution

登录zombo:zombo后获取JWT，将sub.admin改为true并用弱密钥重签名访问/home。session_jwt_privilege_check已验证此攻击路径可行，但具体弱密钥值未知(在session_jwt_hmac_check内部22候选词表中但jwt_hmac_brute不同词表未命中)。需找到正确的弱密钥或使用其他方式查看admin页面内容。

## Failed Attempts

jwt_hmac_brute测试315+密钥未找到、alg:none通过Cookie被拒绝、头注入(17种)未生效、路径遍历无果
