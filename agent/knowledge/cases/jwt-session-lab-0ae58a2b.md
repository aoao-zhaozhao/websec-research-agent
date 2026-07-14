---
id: jwt-session-lab-0ae58a2b
title: JWT弱密钥提权 - Session Lab
target: http://127.0.0.1:19435
category: auth
tags:
- hmac-weak-key
- hs256
- jwt
- privilege-escalation
- shellmates
source: agent
created_at: '2026-07-13T08:03:46Z'
verified: true
evidence_reference: 9a34eaff4e9c02e4
evidence_tool: analyze_headers
evidence_fingerprint: fd7480b508e7260b69feb7fd
---

# JWT弱密钥提权 - Session Lab

## Summary

通过 JWT HS256 弱密钥签名绕过，将 admin:false 修改为 admin:true，成功提权访问受保护的 /home 页面并获取 flag

## Evidence

session_jwt_review 确认 JWT 使用 HS256 算法，sub.admin=false。session_jwt_hmac_check 确认 22 个固定弱密钥候选中有匹配。session_jwt_privilege_check 验证提权后 /home 响应发生变化（denied→allowed）。session_response_search 确认 flag: shellmates{local_jwt_session_path_verified}

## Resolution

1. 访问登录页，使用提供的凭据 zombo/zombo 登录
2. auth_login 捕获 JWT session
3. session_jwt_review 发现 JWT 使用 HS256 且 sub.admin=false
4. session_jwt_hmac_check 确认签名使用弱密钥
5. session_jwt_privilege_check 使用弱密钥伪造 admin=true 的 JWT 访问 /home
6. session_response_search 在提权后的响应中获取 flag
