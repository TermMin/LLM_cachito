"""引导式抓包：一次只标定一个控制项。

    sudo python -m cachito.wizard

为什么需要它：DX 的 App 会**持续重播状态包**（实测 60 秒发了 1113 条运动包），
而且运动的三个参数挤在同一个包里。自由抓包的结果是所有通道混在一起 ——
光看「哪个包出现了」区分不出来，必须看「哪个字节在哪段时间变」。

所以流程是：每个控制项配一段**静置基线** + 一段**只动这一个**的操作窗口。
分析时拿操作窗口和基线做差分，只有在这一步变、别的步都不变的字节，才会
被绑定到这个通道上。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from . import channels as chan
from . import hci, protocol
from .config import DEFAULT_PATH


@dataclass
class Step:
    """一个标定步骤。"""
    name: str                 # 通道名（写进 device.json 的键）
    label: str                # 给人看的名字
    kind: str = "sweep"       # sweep = 拖滑杆；press = 按一下
    hint: str = ""


#: 默认步骤 —— 对应 Cachito Daxiu 的 6 个控制项
DEFAULT_STEPS = [
    Step("depth", "深浅", "sweep", "从最浅慢慢拖到最深，再拖回最浅"),
    Step("speed_out", "伸出速度", "sweep", "从最慢逐档加到最快，再回到最慢"),
    Step("speed_in", "缩回速度", "sweep", "从最慢逐档加到最快，再回到最慢"),
    Step("vibration", "震动强度", "sweep", "从 0 拖到最大，再拖回 0"),
    Step("temperature", "温度", "sweep", "从最低调到最高，再调回来"),
    Step("stop", "全部停止", "press", "按一下停止按钮就行"),
]

BASELINE_S = 5.0     # 每步之前的静置时长
SETTLE_S = 1.0       # 操作结束后再多录一点，抓住最后的状态包


class _Recorder:
    """后台扫描线程：把每条广播打上「当前步骤/阶段」的标签落盘。"""

    def __init__(self, path: str, adapter: int):
        self.path = path
        self.adapter = adapter
        self.step = ""
        self.step_index = -1
        self.phase = "warmup"
        self.n = 0
        self.n_cachito = 0
        self.pairing_ids: dict[str, int] = {}
        self.error: Optional[str] = None
        self.ready = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._fh = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.ready.wait(timeout=20.0)

    def _run(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self._fh = open(self.path, "w", encoding="utf-8")
            with hci.HciDevice(self.adapter) as dev:
                self.ready.set()
                for rep in dev.scan(duration_s=None, passive=True):
                    if self._stop.is_set():
                        break
                    self._record(rep)
        except hci.HciError as e:
            self.error = str(e)
            self.ready.set()
        except Exception as e:                      # pragma: no cover
            self.error = "%s: %s" % (type(e).__name__, e)
            self.ready.set()
        finally:
            if self._fh:
                self._fh.close()

    def _record(self, rep: hci.AdvReport) -> None:
        for air in hci.iter_uuid128(rep.sections):
            payload = protocol.from_air(air)
            if not protocol.looks_like_cachito(payload):
                continue
            row = {
                "t": round(rep.timestamp, 4),
                "step": self.step,
                "step_index": self.step_index,
                "phase": self.phase,
                "label": self.step,          # 兼容旧的 analyze
                "addr": rep.address,
                "rssi": rep.rssi,
                "kind": "uuid128",
                "air": air.hex(),
                "payload": payload.hex(),
                "uuid": protocol.payload_to_uuid(payload),
                "is_cachito": True,
            }
            self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self._fh.flush()
            self.n += 1
            self.n_cachito += 1
            pid = payload[6:8].hex()
            self.pairing_ids[pid] = self.pairing_ids.get(pid, 0) + 1

    def set(self, step: str, index: int, phase: str) -> None:
        self.step, self.step_index, self.phase = step, index, phase

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)


def _countdown(seconds: float, prefix: str) -> None:
    end = time.time() + seconds
    while True:
        left = end - time.time()
        if left <= 0:
            break
        sys.stdout.write("\r    %s %.0f 秒 ... " % (prefix, left + 0.5))
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()


def run(steps: list[Step], out_path: str, adapter: int,
        baseline_s: float, config_path: str, write_config: bool) -> int:
    rec = _Recorder(out_path, adapter)

    print("=" * 70)
    print(" Cachito 引导式标定")
    print("=" * 70)
    print(" 会依次标定 %d 个控制项。每一步都是：先静置几秒录基线，" % len(steps))
    print(" 然后**只动这一个**控件，动完回车。")
    print()
    print(" 输出: %s" % out_path)
    print("-" * 70)

    print()
    print(" 正在打开蓝牙适配器 ...")
    rec.start()
    if rec.error:
        print()
        print(" [错误] %s" % rec.error, file=sys.stderr)
        return 1
    print(" 适配器就绪。")

    # ---- 准备：让设备先跑起来 ----
    print()
    print("=" * 70)
    print(" 准备")
    print("=" * 70)
    print(" 1. iPhone 上**前台**打开 Cachito App，手机靠近这台机器")
    print(" 2. 连上玩具，**让它先运动起来**（随便什么档位都行）")
    print()
    print("    这一步很关键：如果标定过程中才启动设备，运动的几个参数会")
    print("    同时从 0 跳到默认值，分不清谁是谁。")
    print()
    input(" 设备已经在动了？按回车开始 >>> ")

    rec.set("__warmup__", -1, "warmup")
    _countdown(3.0, "录一段热身基线，请勿操作，还剩")

    if rec.n_cachito == 0:
        print()
        print(" [警告] 到现在一条 Cachito 广播都没抓到。")
        print(" 检查：App 是否在前台？手机是否靠近？先 Ctrl+C 退出，")
        print(" 用 `sudo python -m cachito.sniff --all` 看看到底收到了什么。")
        print()
        if input(" 还要继续吗？(y/N) >>> ").strip().lower() != "y":
            rec.stop()
            return 1

    # ---- 逐步标定 ----
    for i, st in enumerate(steps):
        print()
        print("=" * 70)
        print(" [%d/%d] %s" % (i + 1, len(steps), st.label))
        print("=" * 70)

        rec.set(st.name, i, "idle")
        before = rec.n_cachito
        _countdown(baseline_s, "静置录基线，什么都别碰，还剩")
        idle_n = rec.n_cachito - before

        rec.set(st.name, i, "active")
        if st.kind == "press":
            print("    现在：**按一下【%s】**" % st.label)
        else:
            print("    现在：**只动【%s】这一个控件** —— %s" % (st.label, st.hint))
        print("    （其它控件一概别碰）")
        print()
        input("    做完后按回车 >>> ")

        rec.set(st.name, i, "settle")
        time.sleep(SETTLE_S)
        active_n = rec.n_cachito - before - idle_n
        print("    本步录到 %d 条（基线 %d + 操作 %d）"
              % (idle_n + active_n, idle_n, active_n))
        if active_n == 0:
            print("    [警告] 操作窗口里一条都没录到 —— 这一步会分析不出结果")

    rec.set("__end__", len(steps), "end")
    time.sleep(0.5)
    rec.stop()

    print()
    print("=" * 70)
    print(" 采集结束：%d 条 -> %s" % (rec.n_cachito, out_path))
    if rec.pairing_ids:
        print(" 配对 ID: " + ", ".join("%s×%d" % kv for kv in
                                       sorted(rec.pairing_ids.items(),
                                              key=lambda kv: -kv[1])))
    print("=" * 70)

    if rec.n_cachito == 0:
        print(" 什么都没抓到，无法分析。")
        return 1

    # ---- 直接分析 ----
    print()
    return chan.report(out_path, write_config=write_config,
                       config_path=config_path)


def _load_steps(path: Optional[str]) -> list[Step]:
    if not path:
        return list(DEFAULT_STEPS)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [Step(name=d["name"], label=d.get("label", d["name"]),
                 kind=d.get("kind", "sweep"), hint=d.get("hint", ""))
            for d in data]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m cachito.wizard",
        description="引导式抓包标定：一次只动一个控件，自动把通道绑到字节上",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--output", "-o", default=None, help="输出 JSONL 路径")
    ap.add_argument("--adapter", "-i", type=int, default=0, help="hciN，默认 0")
    ap.add_argument("--baseline", type=float, default=BASELINE_S,
                    help="每步静置基线秒数，默认 %g" % BASELINE_S)
    ap.add_argument("--steps", default=None,
                    help="自定义步骤的 JSON 文件；不给则用内置的 6 个控制项")
    ap.add_argument("--config", default=DEFAULT_PATH, help="device.json 路径")
    ap.add_argument("--no-write-config", action="store_true",
                    help="只分析，不写 device.json")
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        print("需要 root（要独占 HCI 控制器）。请用 sudo 运行。", file=sys.stderr)
        return 1

    out = args.output
    if out is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = os.path.join(root, "captures",
                           "wizard-%s.jsonl" % time.strftime("%Y%m%d-%H%M%S"))

    try:
        return run(_load_steps(args.steps), out, args.adapter, args.baseline,
                   args.config, not args.no_write_config)
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130


if __name__ == "__main__":
    sys.exit(main())
