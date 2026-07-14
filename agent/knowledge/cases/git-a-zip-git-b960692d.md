---
id: git-a-zip-git-b960692d
title: Git仓库泄露 - a.zip包含.git目录
target: http://49.232.142.230:19503
category: recon
tags:
- ctf
- directory-listing
- git-leak
- zip-exposure
source: agent
created_at: '2026-07-14T02:33:01Z'
verified: true
evidence_reference: f7ae2104a1425e3d
evidence_tool: batch_scan
evidence_fingerprint: 0a550cfd330d32895ed17657
---

# Git仓库泄露 - a.zip包含.git目录

## Summary

Apache 目录列表服务器泄露了 a.zip，其中包含完整的 .git 目录（包括 objects、refs、HEAD、config 等）。flag 隐藏在 Git 仓库的被删除/历史文件或标签(1.0)中。需要下载 a.zip 解压后用 git 命令提取。

## Evidence

1. 根目录存在 Apache 目录列表，显示 a.zip(21KB)、css/、index2.html、js/ 2. a.zip 包含完整 .git 目录：COMMIT_EDITMSG, config, HEAD, objects(10个), refs/heads/master, refs/tags/1.0, ORIG_HEAD, index 等 3. 所有动态路径返回 404，无 PHP 或其他后端处理

## Resolution

下载 http://49.232.142.230:19503/a.zip，解压后执行 git 命令查看提交历史、切换分支/标签、恢复被删除文件，从中提取 flag。

## Failed Attempts

无法在服务器端解压 zip 二进制文件；.git 路径直接访问返回 404；无动态参数可测试注入；无 PHP 或后端处理页面
