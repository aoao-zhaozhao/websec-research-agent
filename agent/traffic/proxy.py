"""mitmproxy 代理生命周期管理器 —— 启动/停止本地代理实例。

启动 mitmdump 子进程 + 内置 addon 脚本，将所有 HTTP 流量路由到
TrafficCapture，统一落盘到 TrafficStore。子进程方式跨 mitmproxy 版本
兼容，不依赖特定 Python API。

使用:
    manager = ProxyManager(capture, port=8080)
    manager.start()
    ...
    manager.stop()
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from agent.traffic.capture import TrafficCapture
from agent.traffic.mitm_addon import mitmproxy_available, exchange_from_flow

# ── mitmdump addon 脚本（内联，写入临时文件传给 mitmdump -s） ──

_ADDON_SCRIPT = r'''
"""mitmdump addon: 将所有流量写入 TrafficStore。"""

import json, sys, os

# 从环境变量读取 capture 数据存储路径
_store_dir = os.environ.get("MYAGENT_TRAFFIC_DIR", "")
_port = int(os.environ.get("MYAGENT_PROXY_PORT", "8080"))

if _store_dir:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(_store_dir))))
    try:
        from agent.traffic.store import TrafficStore
        from agent.traffic.capture import TrafficCapture
        from agent.traffic.mitm_addon import TrafficCaptureAddon

        store = TrafficStore(_store_dir)
        # Scope: OPEN mode in subprocess (the parent manages scope via http_client)
        from agent.traffic.scope import ScopeChecker, ScopeMode
        scope = ScopeChecker(mode=ScopeMode.OPEN)
        capture = TrafficCapture(store, scope)
        _addon = TrafficCaptureAddon(capture)
    except Exception as _e:
        print(f"[myagent-addon] init error: {_e}", file=sys.stderr)
        _addon = None
else:
    _addon = None

# mitmproxy addon hooks
def response(flow):
    if _addon is not None:
        _addon.response(flow)

def error(flow):
    if _addon is not None and getattr(flow, "response", None) is None:
        _addon.error(flow)

def done():
    if _addon is not None:
        print(f"[myagent-addon] captured {_addon.flow_count} flows", file=sys.stderr)
'''


class ProxyManager:
    """管理 mitmdump 子进程的生命周期。

    用法:
        manager = ProxyManager(capture, port=8080)
        manager.start()     # 后台启动 mitmdump
        ...                 # 扫描期间
        manager.stop()      # 停止子进程
    """

    def __init__(self, capture: TrafficCapture, port: int = 8080) -> None:
        self.capture = capture
        self.port = port
        self._process: subprocess.Popen | None = None
        self._addon_script: str | None = None
        self._running = False
        self._error: str | None = None
        self._flow_count = 0
        self._store_dir = str(capture.store.base_dir) if capture and capture.store else ""

    @property
    def running(self) -> bool:
        return self._running

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def flow_count(self) -> int:
        return self._flow_count

    def start(self) -> bool:
        """在后台子进程中启动 mitmdump。返回 True 表示成功。"""
        if self._running:
            return True

        if not mitmproxy_available():
            self._error = "mitmproxy 未安装（pip install mitmproxy）"
            return False

        # 写 addon 脚本到临时文件
        try:
            fd, script_path = tempfile.mkstemp(suffix=".py", prefix="myagent_mitm_")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(_ADDON_SCRIPT)
            self._addon_script = script_path
        except Exception as exc:
            self._error = f"无法写入 addon 脚本: {exc}"
            return False

        # 定位 mitmdump 可执行文件（优先使用 Scripts 下的二进制）
        mitmdump_path = self._find_mitmdump()
        if mitmdump_path is None:
            self._error = "mitmdump 未找到（pip install mitmproxy）"
            self._cleanup_script()
            return False

        cmd = [
            mitmdump_path,
            "--listen-port", str(self.port),
            "--ssl-insecure",
            "--quiet",
            "-s", script_path,
        ]

        env = os.environ.copy()
        env["MYAGENT_TRAFFIC_DIR"] = self._store_dir
        env["MYAGENT_PROXY_PORT"] = str(self.port)

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
        except FileNotFoundError:
            self._error = "mitmdump 未找到（pip install mitmproxy）"
            self._cleanup_script()
            return False
        except Exception as exc:
            self._error = f"启动 mitmdump 失败: {exc}"
            self._cleanup_script()
            return False

        # 等待代理端口就绪
        ready = self._wait_for_port(timeout=5.0)
        if ready:
            self._running = True
            # 启动后台线程读取 stderr 并解析流量计数
            self._stderr_thread = threading.Thread(
                target=self._read_stderr, daemon=True
            )
            self._stderr_thread.start()
            return True
        else:
            self._error = "代理端口未在超时时间内就绪"
            self.stop()
            return False

    def _wait_for_port(self, timeout: float = 5.0) -> bool:
        """等待代理端口开始监听。"""
        import socket
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect(("127.0.0.1", self.port))
                sock.close()
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        return False

    def _read_stderr(self) -> None:
        """后台读取 mitmdump 的 stderr。"""
        if self._process is None or self._process.stderr is None:
            return
        try:
            for line in self._process.stderr:
                line = line.strip()
                if "[myagent-addon] captured" in line:
                    try:
                        self._flow_count = int(line.split()[-2])
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass

    def stop(self) -> None:
        """停止 mitmdump 子进程。"""
        if self._process is not None:
            try:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=2.0)
            except Exception:
                pass
            self._process = None

        self._running = False
        self._cleanup_script()

    def _cleanup_script(self) -> None:
        """删除临时 addon 脚本。"""
        if self._addon_script and os.path.exists(self._addon_script):
            try:
                os.unlink(self._addon_script)
            except Exception:
                pass
            self._addon_script = None

    def __enter__(self) -> ProxyManager:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    @staticmethod
    def _find_mitmdump() -> str | None:
        """查找 mitmdump 可执行文件路径。"""
        # 1. 优先查找 venv Scripts 下的二进制
        scripts_dir = os.path.dirname(sys.executable)
        if sys.platform == "win32":
            candidates = [
                os.path.join(scripts_dir, "mitmdump.exe"),
                os.path.join(scripts_dir, "mitmdump"),
            ]
        else:
            candidates = [os.path.join(scripts_dir, "mitmdump")]
        for path in candidates:
            if os.path.isfile(path):
                return path

        # 2. PATH 中查找
        import shutil
        found = shutil.which("mitmdump")
        if found:
            return found

        return None

    # ── 诊断 ──

    def diagnostics(self) -> dict:
        return {
            "running": self._running,
            "port": self.port,
            "proxy_url": self.proxy_url,
            "flow_count": self._flow_count,
            "error": self._error,
            "mitmproxy_available": mitmproxy_available(),
        }
