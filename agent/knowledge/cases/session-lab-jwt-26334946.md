---
id: session-lab-jwt-26334946
title: Session Lab JWT弱密钥提权
target: http://127.0.0.1:19435
category: auth
tags:
- jwt
- privilege-escalation
- session
- weak-key
source: agent
created_at: '2026-07-13T08:14:04Z'
verified: true
evidence_reference: 849c8d79a49d1160
evidence_tool: session_jwt_privilege_check
evidence_fingerprint: 9c4f21b063e5128ea5992732
---

# Session Lab JWT弱密钥提权

## Summary

JWT使用HS256弱签名密钥，admin:false可篡改为admin:true获得管理员权限，访问/home获取flag

## Evidence

session_jwt_hmac_check确认弱密钥，session_jwt_privilege_check验证admin提权成功，响应从拒绝变为允许，session_response_search匹配 flag: shellmates{local_jwt_session_path_verified}

## Resolution

1. 使用凭据zombo:zombo登录 2. JWT session_jwt_hmac_check确认弱密钥 3. session_jwt_privilege_check修改admin:false为admin:true 4. session_response_search访问/home获取flag
