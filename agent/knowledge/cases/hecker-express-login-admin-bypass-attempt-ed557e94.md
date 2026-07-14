---
id: hecker-express-login-admin-bypass-attempt-ed557e94
title: hecker-express-login-admin-bypass-attempt
target: http://49.232.142.230:10422
category: auth
tags:
- ctf
- express
- information-disclosure
- login
- nodejs
- nosql-injection
source: agent
created_at: '2026-07-13T05:12:44Z'
---

# hecker-express-login-admin-bypass-attempt

## Summary

对Express.js应用" Hecker"进行安全审计。登录zombo:zombo成功但用户不是admin。/register端点500错误泄露了服务器文件路径(/challenge/app/app.js)。安全头全面缺失。未成功提权到admin。所有注入类攻击(NoSQL/SQL/SSTI/LFI)和权限提升尝试均未确认。

## Evidence

1. /register端点返回500错误堆栈泄露: "Error: Failed to lookup view 'register' in views directory '/challenge/views' at file:///challenge/app/app.js:21:7"
2. 登录zombo:zombo成功,返回/home页面显示"Sorry, you are not an admin"
3. 6项安全响应头全部缺失
4. 仅有2个公开页面(/ 和 /login), /home 和 /register 为额外路由

## Resolution

需要找到使zombo用户成为admin的方法。可能涉及: 1) NoSQL注入通过请求体操作符(需确认express.urlencoded是否为extended:true模式); 2) 原型链污染; 3) 管理员密码暴力破解; 4) MongoDB $where注入; 5) SSTI在模板引擎中执行代码

## Failed Attempts

NoSQL注入($ne/$gt/$regex/$where/$exists)通过form-urlencoded和JSON均失败; SSTI({{7*7}}/${7*7}/<%=7*7%>/#{7*7})未触发; 原型链污染(__proto__)未生效; 权限提升头(X-Role/X-Admin等)17种均未绕过; 路径遍历访问源码失败; 常见admin密码(bruteforce)失败
