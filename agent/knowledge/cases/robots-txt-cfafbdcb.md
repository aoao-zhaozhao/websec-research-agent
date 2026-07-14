---
id: robots-txt-cfafbdcb
title: robots.txt 信息泄露导致隐藏路径发现
target: http://49.232.142.230:19537
category: recon
tags:
- ctf
- information-disclosure
- robots.txt
- sensitive-path
source: agent
created_at: '2026-07-14T02:38:07Z'
verified: true
evidence_reference: 0f49901d0f663e86
evidence_tool: analyze_headers
evidence_fingerprint: 7539969a58df215bc8da6664
---

# robots.txt 信息泄露导致隐藏路径发现

## Summary

通过 robots.txt 中 User-agent: CTFer / Disallow: /flaaaggg.php 的配置，发现隐藏 PHP 页面并获取 flag

## Evidence

robots.txt 返回 200，内容显示 Disallow: /flaaaggg.php；访问 /flaaaggg.php 返回 200，内容为 0xGame{now_you_k0nw_robots_Protocol}

## Resolution

1. 爬取站点发现 robots.txt (200) 2. 读取 robots.txt 发现 User-agent: CTFer 的 Disallow 规则指向 /flaaaggg.php 3. 直接 GET 访问 /flaaaggg.php 获取 flag
