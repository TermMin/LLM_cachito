"""MCP server：把玩具暴露成 LLM 可以调用的工具。

启动（推荐 HTTP，不用配免密 sudo）::

    sudo python -m cachito.mcp_server --transport streamable-http --port 8765

设计约束：

* 工具调用**不阻塞**。pattern 这种要跑几十秒的丢到后台线程，立刻返回；
  任何新指令都会打断正在跑的 pattern。
* 所有通道值都受 device.json 里 ``safety.channel_limits`` 的限制。
* Controller 自带看门狗，空闲超时自动停；进程退出也会补一条停止。
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Optional

# mcp 2.0 把 FastMCP 改名成了 MCPServer，host/port 也从 settings 挪到了
# run() 的关键字参数上。两个大版本都支持一下。
_MCP_MAJOR = 2
try:
    from mcp.server.mcpserver import MCPServer as _Server      # mcp >= 2.0
except ImportError:  # pragma: no cover
    try:
        from mcp.server.fastmcp import FastMCP as _Server      # mcp 1.x
        _MCP_MAJOR = 1
    except ImportError:
        print("缺少 mcp 包。安装：\n  pip install 'mcp[cli]'", file=sys.stderr)
        raise

from . import protocol
from .config import DEFAULT_PATH, DeviceConfig
from .control import Controller

mcp = _Server("cachito")

_cfg = DeviceConfig.load()
# 常驻进程：退出/收到信号时补一条停止。一次性的 CLI 命令则相反 ——
# 见 Controller 里 stop_on_exit 的说明。
_ctl = Controller(_cfg, stop_on_exit=True)

#: pattern 单步 / 总时长上限，防止 LLM 排出一个跑几小时的序列
MAX_STEP_SECONDS = 300.0
MAX_TOTAL_SECONDS = 1800.0


class _Background:
    """同一时刻只允许一个后台序列在跑。"""

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._cancel = threading.Event()
        self._desc = ""
        self._lock = threading.Lock()

    def cancel(self) -> None:
        with self._lock:
            self._cancel.set()
            t = self._thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=2.0)
        with self._lock:
            self._thread = None
            self._desc = ""

    def start(self, fn, desc: str) -> None:
        self.cancel()
        with self._lock:
            self._cancel = threading.Event()
            self._desc = desc
            self._thread = threading.Thread(target=fn, args=(self._cancel,),
                                            daemon=True)
            self._thread.start()

    @property
    def running(self) -> Optional[str]:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self._desc
            return None


_bg = _Background()


def _guard() -> Optional[dict]:
    """检查配置是否够用；不够就返回能指导用户的错误。"""
    if not _cfg.pairing_id:
        return {
            "ok": False,
            "error": "还没有配对 ID，无法控制玩具。",
            "how_to_fix": [
                "1. Windows: usbipd attach --wsl --busid 1-14",
                "2. WSL:     bash scripts/setup-wsl-bt.sh",
                "3. 引导式标定： sudo python -m cachito.wizard",
                "   （iPhone 上前台开着 Cachito App，按提示一次只动一个控件）",
            ],
        }
    if not _cfg.uses_templates and not _cfg.params:
        return {
            "ok": False,
            "error": "还没有标定出任何可控通道。",
            "how_to_fix": ["跑引导式标定： sudo python -m cachito.wizard"],
        }
    return None


def _err(e: Exception) -> dict:
    return {"ok": False, "error": str(e)}


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------

@mcp.tool()
def get_status() -> dict:
    """查询玩具当前状态：各通道的值、蓝牙适配器是否就绪、有无后台序列在跑。

    执行控制指令之前先调一次，可以确认链路是通的、通道名叫什么。
    """
    st = _ctl.state()
    st["background_task"] = _bg.running
    st["config_path"] = DEFAULT_PATH
    return st


@mcp.tool()
def list_channels() -> dict:
    """列出所有可调通道和它们的取值范围。

    通道是标定出来的，不同型号不一样。典型的 Cachito Daxiu 有：
    depth（深浅）、speed_out（伸出速度）、speed_in（缩回速度）、
    vibration（震动强度）、temperature（温度）。

    注意：有些通道**共用同一个指令包**（比如运动的三个参数），
    这没关系 —— set_channels 会自动带上同包其它通道的当前值。
    """
    if not _cfg.uses_templates:
        return {"ok": False, "model": "legacy",
                "actions": _cfg.known_actions(),
                "note": "这台设备还在用旧的单动作模型，请用 vibrate / stop"}
    cm = _cfg.channel_map()
    return {
        "ok": True,
        "model": "channels",
        "channels": {
            ch: {"min": f.min, "max": _cfg.limit_for(ch, f),
                 "unit": f.unit, "shares_packet_with":
                     sorted(c for c, (p, _f) in cm.items()
                            if p == pkt and c != ch)}
            for ch, (pkt, f) in sorted(cm.items())
        },
        "stop_command": _cfg.stop_command or None,
    }


@mcp.tool()
def set_channels(values: dict[str, int],
                 duration_seconds: Optional[float] = None) -> dict:
    """设置一到多个通道的值。这是主要的控制入口。

    Args:
        values: 通道名 -> 值，例如 {"depth": 50, "speed_out": 3}。
            超出范围会被夹到合法区间。用 list_channels 查通道名和范围。
        duration_seconds: 可选。给了的话，到时间自动全部停止。

    玩具是「锁存」的：设一次就保持那个状态，不需要反复调用。
    没在 values 里提到的通道保持原值不变。
    """
    err = _guard()
    if err:
        return err
    _bg.cancel()
    try:
        res = _ctl.set_channels(values)
    except (ValueError, RuntimeError) as e:
        return _err(e)

    if duration_seconds and duration_seconds > 0 and _ctl.is_active():
        secs = min(float(duration_seconds), MAX_STEP_SECONDS)

        def run(cancel: threading.Event):
            if not cancel.wait(secs):
                try:
                    _ctl.stop()
                except Exception:
                    pass

        _bg.start(run, "%.0f 秒后自动停止" % secs)
        res["auto_stop_in_seconds"] = secs
    return res


@mcp.tool()
def stop() -> dict:
    """立刻全部停止，并取消正在运行的序列。"""
    err = _guard()
    if err:
        return err
    _bg.cancel()
    try:
        return _ctl.stop()
    except (ValueError, RuntimeError) as e:
        return _err(e)


@mcp.tool()
def run_pattern(steps: list[dict], repeat: int = 1) -> dict:
    """按一串步骤跑一个节奏，后台执行、立刻返回。

    Args:
        steps: 步骤列表。每步是一组通道值加上 seconds，例如::

            [{"depth": 30, "speed_out": 2, "seconds": 5},
             {"depth": 60, "speed_out": 4, "seconds": 8},
             {"depth": 30, "speed_out": 2, "seconds": 5}]

            除 seconds 外的键都当成通道名。单步最长 300 秒。
        repeat: 整个序列重复几遍。

    序列跑完自动停止。任何新的控制指令都会打断它。
    调 get_status 可以看当前有没有序列在跑。
    """
    err = _guard()
    if err:
        return err
    if not steps:
        return {"ok": False, "error": "steps 不能为空"}

    known = set(_cfg.channel_map()) if _cfg.uses_templates else set()
    plan: list[tuple[dict[str, int], float]] = []
    total = 0.0
    for i, s in enumerate(steps):
        if not isinstance(s, dict):
            return {"ok": False, "error": "第 %d 步不是对象" % i}
        try:
            sec = float(s.get("seconds", 1))
        except (TypeError, ValueError):
            return {"ok": False, "error": "第 %d 步的 seconds 不是数字" % i}
        vals: dict[str, int] = {}
        for k, v in s.items():
            if k == "seconds":
                continue
            if known and k not in known:
                return {"ok": False,
                        "error": "第 %d 步有未知通道 %r" % (i, k),
                        "known_channels": sorted(known)}
            try:
                vals[k] = int(v)
            except (TypeError, ValueError):
                return {"ok": False,
                        "error": "第 %d 步通道 %r 的值不是整数" % (i, k)}
        if not vals:
            return {"ok": False, "error": "第 %d 步没有任何通道值" % i}
        sec = max(0.1, min(sec, MAX_STEP_SECONDS))
        plan.append((vals, sec))
        total += sec

    reps = max(1, int(repeat))
    if total * reps > MAX_TOTAL_SECONDS:
        return {"ok": False,
                "error": "序列总时长 %.0f 秒，超过上限 %.0f 秒"
                         % (total * reps, MAX_TOTAL_SECONDS)}

    def run(cancel: threading.Event):
        try:
            for _ in range(reps):
                for vals, sec in plan:
                    if cancel.is_set():
                        return
                    try:
                        _ctl.set_channels(vals)
                    except Exception:
                        return
                    if cancel.wait(sec):
                        return
        finally:
            if not cancel.is_set():
                try:
                    _ctl.stop()
                except Exception:
                    pass

    desc = "%d 步 × %d 遍，约 %.0f 秒" % (len(plan), reps, total * reps)
    _bg.start(run, desc)
    return {"ok": True, "started": True, "description": desc,
            "steps": [{**v, "seconds": s} for v, s in plan],
            "repeat": reps, "estimated_seconds": round(total * reps, 1)}


@mcp.tool()
def vibrate(intensity: int, duration_seconds: Optional[float] = None) -> dict:
    """设置震动强度（set_channels 的便捷包装）。

    Args:
        intensity: 强度，0 等同于停止。
        duration_seconds: 可选，到时间自动停止。
    """
    err = _guard()
    if err:
        return err
    if int(intensity) <= 0:
        return stop()
    cm = _cfg.channel_map() if _cfg.uses_templates else {}
    for cand in ("vibration", "vibrate"):
        if cand in cm:
            return set_channels({cand: int(intensity)}, duration_seconds)
    _bg.cancel()
    try:
        return _ctl.vibrate(int(intensity))
    except (ValueError, RuntimeError) as e:
        return _err(e)


@mcp.tool()
def trigger_packet(packet: str) -> dict:
    """发一个无参数的指令包（标定出来的那些，比如 stop）。

    用 get_status 或 list_channels 看有哪些包可用。
    正常控制请优先用 set_channels / stop。
    """
    err = _guard()
    if err:
        return err
    try:
        return _ctl.trigger(packet)
    except (ValueError, RuntimeError) as e:
        return {**_err(e), "known_packets": sorted(_cfg.commands)}


@mcp.tool()
def send_raw_command(payload_hex: str, repeats: int = 3) -> dict:
    """发送任意 16 字节 payload —— 逆向试探用的低层工具。

    Args:
        payload_hex: 32 个 hex 字符，或带连字符的 UUID 字符串。
            随机序号和校验和会自动重算，这两位随便填。
        repeats: 重发几次。

    正常控制请用 set_channels / stop。这个是给「试探未标定的功能」用的。
    """
    try:
        return _ctl.raw(payload_hex, repeats=max(1, min(10, int(repeats))))
    except (ValueError, RuntimeError) as e:
        return _err(e)


@mcp.tool()
def decode_command(uuid_or_hex: str) -> dict:
    """把一个 Cachito 指令 UUID / payload 解成各个字段。不发射，纯解析。

    会同时按已标定的包模板解读 —— 如果匹配上某个包，会告诉你各通道的值。
    """
    try:
        s = uuid_or_hex.strip()
        payload = (protocol.uuid_to_payload(s) if "-" in s
                   else bytes.fromhex(s.replace(" ", "")))
    except ValueError as e:
        return _err(e)

    out: dict[str, Any] = protocol.Command.decode(payload).to_dict()
    out["body"] = protocol.body_hex(payload)
    sel = payload[4:6]
    for name, t in _cfg.templates().items():
        if t.selector == sel:
            out["packet"] = name
            out["channel_values"] = {ch: payload[f.offset]
                                     for ch, f in t.fields.items()}
            break
    return out


@mcp.tool()
def get_setup_help() -> dict:
    """还没配好的时候，返回该做什么。

    适配器没就绪、配对 ID 缺失、通道没标定时调这个，能拿到针对性的步骤。
    """
    st = _ctl.state()
    steps: list[str] = []
    if not st["adapter_present"]:
        steps += [
            "蓝牙适配器没进 WSL。管理员 PowerShell：",
            "    usbipd bind   --busid 1-14      # 只需一次",
            "    usbipd attach --wsl --busid 1-14",
            "然后 WSL： bash scripts/setup-wsl-bt.sh",
        ]
    if not st["pairing_id"] or not _cfg.uses_templates:
        steps += [
            "跑引导式标定（会依次让你操作每个控件）：",
            "    sudo python -m cachito.wizard",
            "iPhone 上要**前台**开着 Cachito App，并且先让玩具动起来。",
        ]
    if not steps:
        steps = ["一切就绪。用 list_channels 看能调什么，再用 set_channels 控制。"]
    return {"status": st, "next_steps": steps}


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    import os

    ap = argparse.ArgumentParser(
        prog="python -m cachito.mcp_server",
        description="Cachito 玩具的 MCP server",
    )
    ap.add_argument("--transport", choices=("stdio", "streamable-http", "sse"),
                    default="stdio",
                    help="stdio = 由 MCP 客户端拉起（需要免密 sudo）；"
                         "streamable-http = 自己 sudo 起一个常驻服务，"
                         "客户端用 URL 连（推荐）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        # 不直接退出：get_status / decode_command / get_setup_help 这些
        # 不碰硬件的工具照样能用，真要发射时再报错更有帮助。
        print("[警告] 不是 root —— 只读工具可用，但发射指令会失败。"
              "用 sudo 启动才能真正控制玩具。", file=sys.stderr)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return 0

    print("MCP server 监听 http://%s:%d/mcp  (mcp %d.x)"
          % (args.host, args.port, _MCP_MAJOR), file=sys.stderr)
    if _MCP_MAJOR >= 2:
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    else:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport=args.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
