---
id: phpinfo-flag-10b5e68b
title: phpinfo 环境变量泄露 Flag
target: http://49.232.142.230:14226
category: recon
tags:
- environment-variable
- flag
- information-disclosure
- phpinfo
source: agent
created_at: '2026-07-13T04:55:45Z'
---

# phpinfo 环境变量泄露 Flag

## Summary

目标站点使用了 /info.php (phpinfo()) 页面，其中泄露了环境变量 FLAG，包含 wctf{} 格式的 flag 值。同时主页面 / 存在 PHP filter wrapper LFI 漏洞，可通过 madness 参数读取任意文件并应用过滤器，但 resource 硬编码为 /etc/passwd，且输入中 / 被过滤。

## Evidence

在 /info.php 页面的 phpinfo() 输出中，环境变量 FLAG 和 $_ENV['FLAG'] 显示 flag 值。search_http_body 在偏移量 55883 和 61029 处分别匹配到"FLAG"和"$_ENV['FLAG']"条目。

## Resolution

直接访问 /info.php 页面，在 phpinfo 的环境变量表格中查找 FLAG 条目即可获取 flag。
