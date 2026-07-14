---
id: hack-ini-9th-sqli-sqlite-union-a8e69539
title: Hack.INI 9th SQLi - SQLite UNION注入绕过黑名单认证
target: http://49.232.142.230:16289
category: sqli
tags:
- authentication-bypass
- blacklist-bypass
- ctf
- hackini
- sqlite
- union-injection
source: agent
created_at: '2026-07-13T05:00:26Z'
---

# Hack.INI 9th SQLi - SQLite UNION注入绕过黑名单认证

## Summary

Hack.INI 9th CTF SQL注入挑战。登录页面存在SQLite SQL注入，username参数被PHP黑名单函数过滤(禁止单引号+空格组合、双引号、反引号、尖括号)，且要求单引号必须被字母数字字符包围。通过构造`x'UNION SELECT'admin','hash$salt'WHERE'1'='1`绕过过滤器，利用WHERE'1'='1自然吸收SQL模板中的尾随单引号，注入已知密码哈希实现认证绕过，获取flag。

## Evidence

1. 页面源码通过`/?pls_help`泄露，包含完整PHP逻辑 2. 数据库为SQLite3(/var/db.sqlite) 3. 查询为`SELECT * FROM users WHERE username='$user'` 4. 密码格式为`hash$salt`(explode by $) 5. 认证检查`hash("sha256", $pass.$salt)` 6. UNION SELECT 2列注入成功 7. 使用已知sha256哈希值构造注入payload

## Resolution

1. 发现`/?pls_help`页面泄露源码 2. 分析黑名单: `["' ", " '", '"', "`", " `", "` ", ">", "<"]` + 正则约束`[0-9a-zA-Z]'[0-9a-zA-Z]` 3. 构造绕过payload: `x'UNION SELECT'admin','{sha256_hash}$'WHERE'1'='1` 4. `WHERE'1'='1`中的`'1'`自然消耗模板中的尾随单引号 5. 密码字段使用已知sha256(password+salt)值 6. 传入匹配的password参数完成认证 7. 获取flag: shellmates{c0ngr4tul4t10ns_U_d1d_1t!!_fe4cd84591ea}

## Failed Attempts

1. `admin'OR'1`通过过滤器但无法通过密码哈希校验 2. 标准`' OR '1'='1`被黑名单拦截 3. `/*'*/`注释方式导致SQL语法错误(遗留尾随单引号) 4. 1-5列UNION注入测试发现只有2列正确
