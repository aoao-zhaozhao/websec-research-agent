---
id: php-whois-command-injection-via-trailing-newline-regex-b-d8302748
title: PHP Whois Command Injection via Trailing Newline Regex Bypass
target: authorized CTF Whois service
category: general
tags:
- command-injection
- ctf
- newline-bypass
- php
- preg-match
- source-disclosure
source: agent
created_at: '2026-07-11T10:51:08Z'
---

# PHP Whois Command Injection via Trailing Newline Regex Bypass

## Summary

A PHP Whois endpoint exposed source code when called without parameters. User-controlled host and query values were concatenated into shell_exec after regex validation.

## Evidence

The host regex used a trailing dollar anchor without strict end-of-subject mode, while host was inserted into shell_exec without quoting. A percent-encoded trailing newline passed validation and separated the shell command.

## Resolution

Retrieve the source, verify the exact regex and unquoted shell construction, then use a harmless command such as id to prove command execution. Enumerate only the current challenge working directory as needed to complete the authorized task.

## Failed Attempts

Treating the host field only as a TCP Whois proxy led to empty responses. The decisive evidence was the parameterless source disclosure and PCRE end-anchor behavior.
