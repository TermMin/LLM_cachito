"""控制玩具：Controller 类 + 命令行。

    sudo python -m cachito.control status
    sudo python -m cachito.control channels
    sudo python -m cachito.control set depth 40
    sudo python -m cachito.control set depth 40 speed_out 3 speed_in 2
    sudo python -m cachito.control stop

加 ``--dry-run`` 只打印要发的包、不真发，用来在没接适配器时验证逻辑。

两套模型
--------
配置里有 ``commands``（包模板）就走**通道模型**：``set <通道> <值>``。
这是 DX 用的 —— 一个包里可能有好几个字段，改一个要带上同包其它字段的
当前值，Controller 会替你维护这份状态。

没有 ``commands`` 就退回 Venus 风格的 ``vibrate`` / ``stop`` 单动作模型。
"""

from __future__ import annotations

import argparse
import atexit
import signal
import sys
import threading
import time
from typing import Optional

from . import hci, protocol
from .config import DEFAULT_PATH, DeviceConfig


class Controller:
    """持有 HCI 适配器，把指令广播出去。

    三个关键设计：

    * **适配器常开**：打开一次（down + 独占绑定 + 复位）要几百毫秒，
      每条指令都重来一遍会很卡。第一次用时打开，之后一直持有。
    * **通道状态**：同一个包里的多个字段是一起发出去的。只改深浅时，
      必须把伸出/缩回速度的当前值也带上，否则会把它们清零。所以这里
      记着每个通道的当前值。
    * **看门狗**：广播是锁存的 —— 进程崩了、网断了，玩具不会自己停。
      常驻进程（MCP server）需要在超时和退出时补发停止。

    ``stop_on_exit`` 默认**关闭**，这一点很重要：一次性的 CLI 命令
    （``set depth 40``）跑完就退出，如果退出时补一条停止，玩具会在
    一秒多之后自己停下来 —— 那不是用户要的。只有常驻进程才该开。
    """

    def __init__(self, cfg: Optional[DeviceConfig] = None,
                 dry_run: bool = False, verbose: bool = False,
                 stop_on_exit: bool = False):
        self.cfg = cfg or DeviceConfig.load()
        self.dry_run = dry_run
        self.verbose = verbose
        self.stop_on_exit = stop_on_exit
        self.dev: Optional[hci.HciDevice] = None

        self._lock = threading.RLock()
        self._values: dict[str, int] = {}     # 通道 -> 当前值
        self._intensity = 0                   # Venus 模型用
        self._action = "stop"
        self._last_cmd_at = 0.0
        self._sent = 0
        self._closing = threading.Event()
        self._hooked = False
        self._hold_packets: dict[str, bytes] = {}   # 心跳要重播的包

        # 通道初值 = 各自的 min
        if self.cfg.uses_templates:
            for ch, (_pkt, f) in self.cfg.channel_map().items():
                self._values[ch] = f.min

    # ---------------- 生命周期 ----------------

    def open(self) -> None:
        with self._lock:
            self._install_hooks()
            if self.dev is not None or self.dry_run:
                return
            self.dev = hci.HciDevice(self.cfg.adapter, verbose=self.verbose).open()
            self._start_watchdog()
            if self.cfg.broadcast.hold:
                self._start_hold()

    def _install_hooks(self) -> None:
        """常驻进程无论怎么退，都尽量补一条停止。

        只在 stop_on_exit 打开时装 —— 见类文档里的说明。
        """
        if self._hooked or not self.stop_on_exit:
            return
        self._hooked = True
        atexit.register(self._panic_stop)
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                prev = signal.getsignal(sig)

                def handler(s, f, _prev=prev):
                    self._panic_stop()
                    if callable(_prev):
                        _prev(s, f)
                    else:
                        raise KeyboardInterrupt

                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass   # 非主线程注册不了，忽略

    def _panic_stop(self) -> None:
        # 没开 stop_on_exit 就什么都不做：一次性命令设完就该保持住，
        # 退出时补停止会让玩具在一秒多后自己停下来。
        if not self.stop_on_exit or not self.is_active():
            return
        try:
            self.stop()
        except Exception:
            pass

    def close(self) -> None:
        self._closing.set()
        with self._lock:
            self._panic_stop()
            if self.dev is not None:
                self.dev.close()
                self.dev = None

    def __enter__(self) -> "Controller":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------- 后台线程 ----------------

    def is_active(self) -> bool:
        """有没有任何通道处于「非静止」状态。"""
        with self._lock:
            if self.cfg.uses_templates:
                cm = self.cfg.channel_map()
                return any(v > cm[ch][1].min
                           for ch, v in self._values.items() if ch in cm)
            return self._intensity > 0

    def _start_watchdog(self) -> None:
        timeout = self.cfg.safety.auto_stop_seconds
        if not timeout or timeout <= 0:
            return

        def run():
            while not self._closing.wait(1.0):
                if not self.is_active() or not self._last_cmd_at:
                    continue
                idle = time.time() - self._last_cmd_at
                if idle < timeout:
                    continue
                if self.verbose:
                    print("[看门狗] 空闲 %.0f 秒，自动停止" % idle, file=sys.stderr)
                try:
                    self.stop()
                except Exception:
                    pass

        threading.Thread(target=run, daemon=True).start()

    def _start_hold(self) -> None:
        """周期性重播当前状态包。

        App 实测是持续重播的（60 秒发了上千条）。多数情况下玩具是锁存的，
        不需要心跳；但如果你的机器会在几秒后自己停下来，把 broadcast.hold
        打开就能维持住。
        """
        period = max(0.2, self.cfg.broadcast.hold_period_s)

        def run():
            while not self._closing.wait(period):
                if not self.is_active():
                    continue
                with self._lock:
                    pkts = list(self._hold_packets.values())
                    dev = self.dev
                if dev is None:
                    continue
                for p in pkts:
                    try:
                        # 心跳重发也要换随机序号，否则会被玩具当重复包丢掉
                        cmd = protocol.Command.decode(p)
                        cmd.raw = None
                        dev.broadcast(
                            protocol.to_air(cmd.encode()),
                            duration_s=self.cfg.broadcast.duration_s,
                            interval_ms=self.cfg.broadcast.interval_ms,
                            adv_type=self.cfg.broadcast.adv_type,
                            flags=self.cfg.broadcast.flags,
                        )
                    except Exception:
                        pass

        threading.Thread(target=run, daemon=True).start()

    # ---------------- 底层发送 ----------------

    def _emit(self, payload: bytes, repeats: Optional[int] = None) -> list[str]:
        """把一个 payload 广播出去（自动重发、每次换随机序号）。"""
        bc = self.cfg.broadcast
        n = bc.repeats if repeats is None else repeats
        uuids = []
        with self._lock:
            if not self.dry_run:
                self.open()
            for i in range(max(1, n)):
                cmd = protocol.Command.decode(payload)
                cmd.raw = None                    # 重算随机序号和校验和
                p = cmd.encode()
                uuids.append(protocol.payload_to_uuid(p))
                if self.dry_run:
                    if self.verbose:
                        print("  [dry-run] -> %s" % uuids[-1])
                else:
                    assert self.dev is not None
                    self.dev.broadcast(
                        protocol.to_air(p),
                        duration_s=bc.duration_s,
                        interval_ms=bc.interval_ms,
                        adv_type=bc.adv_type,
                        flags=bc.flags,
                    )
                    if i + 1 < n:
                        time.sleep(bc.gap_s)
                self._sent += 1
            self._last_cmd_at = time.time()
        return uuids

    # ---------------- 通道模型 ----------------

    def set_channels(self, values: dict[str, int]) -> dict:
        """一次设置一到多个通道。

        同一个包里的通道会合并成一条指令发出去；不同包的分别发。
        没显式给的通道用当前记着的值填 —— 这一点很重要，否则改深浅会
        把速度清零。
        """
        if not self.cfg.uses_templates:
            raise ValueError(
                "配置里没有 commands（包模板），用不了通道模型。\n"
                "先跑引导式标定： sudo python -m cachito.wizard")

        cm = self.cfg.channel_map()
        unknown = [k for k in values if k not in cm]
        if unknown:
            raise ValueError("未知通道: %s。已知的: %s"
                             % (", ".join(unknown), ", ".join(sorted(cm))))

        # 按包分组
        touched: dict[str, set[str]] = {}
        for ch in values:
            touched.setdefault(cm[ch][0], set()).add(ch)

        pid = self.cfg.pairing_bytes()
        out_uuids: list[str] = []
        applied: dict[str, int] = {}

        with self._lock:
            for ch, v in values.items():
                f = cm[ch][1]
                hi = self.cfg.limit_for(ch, f)
                self._values[ch] = max(f.min, min(hi, int(v)))
                applied[ch] = self._values[ch]

            for pkt_name in touched:
                t = self.cfg.template(pkt_name)
                # 同包的**全部**字段都要带上当前值
                payload = protocol.build_packet(
                    self.cfg.device_type, pid, t,
                    {name: self._values.get(name, f.min)
                     for name, f in t.fields.items()},
                )
                self._hold_packets[pkt_name] = payload
                out_uuids += self._emit(payload)

        return {"ok": True, "applied": applied, "packets": sorted(touched),
                "uuids": out_uuids, "dry_run": self.dry_run,
                "state": dict(self._values)}

    def set_channel(self, name: str, value: int) -> dict:
        return self.set_channels({name: value})

    def trigger(self, packet_name: str) -> dict:
        """发一个无参数的指令包（比如「全部停止」）。"""
        t = self.cfg.template(packet_name)
        payload = protocol.build_packet(
            self.cfg.device_type, self.cfg.pairing_bytes(), t,
            {name: self._values.get(name, f.min) for name, f in t.fields.items()},
        )
        uuids = self._emit(payload)
        return {"ok": True, "packet": packet_name, "uuids": uuids,
                "dry_run": self.dry_run}

    # ---------------- 停止 ----------------

    def stop(self) -> dict:
        """全部停止。

        优先用标定出来的停止指令包；没有的话退而求其次，把所有通道归零 ——
        对大多数设备来说效果一样。
        """
        if self.cfg.uses_templates:
            with self._lock:
                self._hold_packets.clear()
            res: dict
            if self.cfg.stop_command and self.cfg.stop_command in self.cfg.commands:
                res = self.trigger(self.cfg.stop_command)
            else:
                cm = self.cfg.channel_map()
                res = self.set_channels({ch: f.min for ch, (_p, f) in cm.items()})
                res["note"] = "没有标定出专门的停止指令，改用「所有通道归零」"
            with self._lock:
                for ch, (_p, f) in self.cfg.channel_map().items():
                    self._values[ch] = f.min
                self._action = "stop"
                self._intensity = 0
            return res

        return self._legacy_act("stop")

    # ---------------- Venus 风格（旧） ----------------

    def _legacy_act(self, action: str, intensity: int = 0) -> dict:
        param1 = self.cfg.param1_for(action)
        pid = self.cfg.pairing_bytes()
        if action == "stop":
            level = self.cfg.stop_intensity
        else:
            cap = max(0, min(100, self.cfg.safety.max_intensity))
            level = max(0, min(cap, int(intensity)))
        cmd = protocol.Command(
            device_type=self.cfg.device_type, pairing_id=pid, param1=param1,
            intensity=level, cmd_code=self.cfg.cmd_code_bytes(),
        )
        uuids = self._emit(cmd.encode())
        with self._lock:
            self._action = action
            self._intensity = 0 if action == "stop" else level
        return {"ok": True, "action": action, "intensity": self._intensity,
                "param1": param1.hex(), "uuids": uuids, "repeats": len(uuids),
                "dry_run": self.dry_run}

    def act(self, action: str, intensity: int = 0) -> dict:
        if self.cfg.uses_templates and action in self.cfg.channel_map():
            return self.set_channel(action, intensity)
        if self.cfg.uses_templates and action in self.cfg.commands:
            return self.trigger(action)
        return self._legacy_act(action, intensity)

    def vibrate(self, intensity: int) -> dict:
        """震动。0 当停止处理。"""
        if int(intensity) <= 0:
            return self.stop()
        if self.cfg.uses_templates:
            cm = self.cfg.channel_map()
            for cand in ("vibration", "vibrate", "震动强度", "震动"):
                if cand in cm:
                    return self.set_channel(cand, intensity)
            raise ValueError("没有震动通道。已知通道: %s" % ", ".join(sorted(cm)))
        return self._legacy_act("vibrate", intensity)

    def raw(self, payload_hex: str, repeats: Optional[int] = None) -> dict:
        """发送任意 16 字节 payload（或 UUID 字符串）。逆向试探时用。"""
        s = payload_hex.strip()
        payload = (protocol.uuid_to_payload(s) if "-" in s
                   else bytes.fromhex(s.replace(" ", "")))
        if len(payload) != protocol.PAYLOAD_LEN:
            raise ValueError("payload 必须 16 字节，得到 %d" % len(payload))
        uuids = self._emit(payload, repeats=repeats)
        return {"ok": True, "uuids": uuids, "repeats": len(uuids),
                "decoded": protocol.Command.decode(payload).to_dict(),
                "dry_run": self.dry_run}

    # ---------------- 状态 ----------------

    def state(self) -> dict:
        adapters = hci.list_adapters()
        with self._lock:
            st = {
                "device_type": "0x%02x" % self.cfg.device_type,
                "device_name": self.cfg.device_name,
                "pairing_id": self.cfg.pairing_id or None,
                "model": "channels" if self.cfg.uses_templates else "legacy",
                "active": self.is_active(),
                "commands_sent": self._sent,
                "seconds_since_last": (round(time.time() - self._last_cmd_at, 1)
                                       if self._last_cmd_at else None),
                "auto_stop_seconds": self.cfg.safety.auto_stop_seconds,
                "adapter": "hci%d" % self.cfg.adapter,
                "adapter_present": ("hci%d" % self.cfg.adapter) in adapters,
                "adapters_found": adapters,
                "radio_open": self.dev is not None,
                "hold": self.cfg.broadcast.hold,
                "dry_run": self.dry_run,
            }
            if self.cfg.uses_templates:
                cm = self.cfg.channel_map()
                st["channels"] = {
                    ch: {"value": self._values.get(ch, f.min),
                         "min": f.min, "max": self.cfg.limit_for(ch, f),
                         "packet": pkt, "offset": f.offset,
                         "unit": f.unit}
                    for ch, (pkt, f) in sorted(cm.items())
                }
                st["stop_command"] = self.cfg.stop_command or None
            else:
                st["current_action"] = self._action
                st["current_intensity"] = self._intensity
                st["configured_actions"] = self.cfg.known_actions()
            return st


# --------------------------------------------------------------------------
# 命令行
# --------------------------------------------------------------------------

def _need_root(dry_run: bool) -> bool:
    import os
    if dry_run or os.geteuid() == 0:
        return False
    print("需要 root（要独占 HCI 控制器）。用 sudo 跑，或加 --dry-run 只看不发。",
          file=sys.stderr)
    return True


def cmd_status(ctl: Controller, args) -> int:
    st = ctl.state()
    print("Cachito 控制器状态")
    print("-" * 60)
    for k, v in st.items():
        if k == "channels":
            print("  %-22s" % "channels")
            for ch, d in v.items():
                print("      %-14s = %-4s  (%d-%d, 包 %s 字节[%d])"
                      % (ch, d["value"], d["min"], d["max"],
                         d["packet"], d["offset"]))
        else:
            print("  %-22s %s" % (k, v))
    if not st["adapter_present"]:
        print()
        print("  找不到 %s。检查：" % st["adapter"])
        print("    Windows: usbipd attach --wsl --busid 1-14")
        print("    WSL:     sudo modprobe btusb")
    if not st["pairing_id"]:
        print()
        print("  还没有配对 ID —— 先跑引导式标定： sudo python -m cachito.wizard")
    return 0


def cmd_channels(ctl: Controller, args) -> int:
    if not ctl.cfg.uses_templates:
        print("配置里没有包模板。先跑： sudo python -m cachito.wizard")
        return 1
    print("已标定的指令包")
    print("-" * 70)
    for name, t in sorted(ctl.cfg.templates().items()):
        print("  " + t.describe())
    print()
    print("可调通道：%s" % ", ".join(ctl.cfg.channels()))
    print("停止指令：%s" % (ctl.cfg.stop_command or "（未识别，将用「所有通道归零」）"))
    return 0


def cmd_set(ctl: Controller, args) -> int:
    pairs = args.pairs
    if len(pairs) % 2 != 0:
        print("参数要成对给：set <通道> <值> [<通道> <值> ...]", file=sys.stderr)
        return 1
    values = {}
    for i in range(0, len(pairs), 2):
        try:
            values[pairs[i]] = int(pairs[i + 1])
        except ValueError:
            print("值必须是整数: %r" % pairs[i + 1], file=sys.stderr)
            return 1
    res = ctl.set_channels(values)
    print("已设置: " + ", ".join("%s=%s" % kv for kv in sorted(res["applied"].items())))
    print("涉及的包: %s" % ", ".join(res["packets"]))
    for u in res["uuids"]:
        print("  -> %s" % u)
    print("当前状态: " + ", ".join("%s=%s" % kv for kv in sorted(res["state"].items())))
    if not res.get("dry_run"):
        print()
        print("玩具会保持这个状态 —— 广播是锁存的，本命令退出不会停它。")
        print("要停： sudo python -m cachito.control stop")
    return 0


def cmd_trigger(ctl: Controller, args) -> int:
    res = ctl.trigger(args.packet)
    print("已触发 %s" % res["packet"])
    for u in res["uuids"]:
        print("  -> %s" % u)
    return 0


def cmd_stop(ctl: Controller, args) -> int:
    res = ctl.stop()
    print("停止" + ("  （%s）" % res["note"] if res.get("note") else ""))
    for u in res.get("uuids", []):
        print("  -> %s" % u)
    return 0


def cmd_vibrate(ctl: Controller, args) -> int:
    res = ctl.vibrate(args.intensity)
    if res.get("action") == "stop" or not res.get("applied"):
        print("已按停止处理")
    else:
        print("已设置: " + ", ".join("%s=%s" % kv
                                     for kv in sorted(res["applied"].items())))
    for u in res.get("uuids", []):
        print("  -> %s" % u)
    return 0


def cmd_sweep(ctl: Controller, args) -> int:
    ch = args.channel
    if ctl.cfg.uses_templates:
        _t, f = ctl.cfg.channel(ch)
        lo, hi = f.min, ctl.cfg.limit_for(ch, f)
    else:
        lo, hi = 0, min(args.max, ctl.cfg.safety.max_intensity)
    step = max(1, args.step)
    seq = list(range(lo, hi + 1, step)) + list(range(hi, lo - 1, -step))
    print("扫档 %s：%d -> %d -> %d，每档停 %.1f 秒（Ctrl+C 中断）"
          % (ch, lo, hi, lo, args.dwell))
    try:
        for v in seq:
            print("  %s = %d" % (ch, v))
            if ctl.cfg.uses_templates:
                ctl.set_channel(ch, v)
            else:
                ctl.vibrate(v)
            time.sleep(args.dwell)
    finally:
        ctl.stop()
        print("已停止")
    return 0


def cmd_raw(ctl: Controller, args) -> int:
    res = ctl.raw(args.payload, repeats=args.repeats)
    print("已发送 %d 次：" % res["repeats"])
    for u in res["uuids"]:
        print("  -> %s" % u)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m cachito.control",
        description="通过 BLE 广播控制 Cachito 玩具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--config", default=DEFAULT_PATH, help="device.json 路径")
    ap.add_argument("--dry-run", action="store_true", help="只打印不发射")
    ap.add_argument("--verbose", "-v", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="显示配置和适配器状态").set_defaults(fn=cmd_status)
    sub.add_parser("channels", help="列出已标定的包和通道").set_defaults(fn=cmd_channels)

    p = sub.add_parser("set", help="设置一到多个通道：set depth 40 speed_out 3")
    p.add_argument("pairs", nargs="+", metavar="通道 值")
    p.set_defaults(fn=cmd_set)

    p = sub.add_parser("trigger", help="发一个无参数指令包")
    p.add_argument("packet")
    p.set_defaults(fn=cmd_trigger)

    sub.add_parser("stop", help="全部停止").set_defaults(fn=cmd_stop)

    p = sub.add_parser("vibrate", help="震动（会自动找震动通道）")
    p.add_argument("intensity", type=int)
    p.set_defaults(fn=cmd_vibrate)

    p = sub.add_parser("sweep", help="对某个通道扫档演示")
    p.add_argument("channel", nargs="?", default="vibration")
    p.add_argument("--max", type=int, default=60, help="仅旧模型用")
    p.add_argument("--step", type=int, default=10)
    p.add_argument("--dwell", type=float, default=1.5)
    p.set_defaults(fn=cmd_sweep)

    p = sub.add_parser("raw", help="发送任意 16 字节 payload 或 UUID")
    p.add_argument("payload")
    p.add_argument("--repeats", type=int, default=None)
    p.set_defaults(fn=cmd_raw)

    args = ap.parse_args(argv)

    if args.cmd not in ("status", "channels") and _need_root(args.dry_run):
        return 1

    cfg = DeviceConfig.load(args.config)
    ctl = Controller(cfg, dry_run=args.dry_run, verbose=args.verbose)
    try:
        return args.fn(ctl, args)
    except (ValueError, hci.HciError) as e:
        print("\n错误: %s" % e, file=sys.stderr)
        return 1
    finally:
        ctl.close()


if __name__ == "__main__":
    sys.exit(main())
