"""抓包：监听 BLE 广播，抓 Cachito 指令。

用法::

    sudo python -m cachito.sniff                    # 一直抓到 Ctrl+C
    sudo python -m cachito.sniff --seconds 60
    sudo python -m cachito.sniff --all              # 连无关广播一起记（找玩具本体用）

抓的时候直接在终端里**打字回车**就能给后面的记录打标签，比如::

    vibrate 30 <回车>     # 然后在 App 里把强度拖到 30
    vibrate 80 <回车>
    stop <回车>           # 然后在 App 里点停止

标签会写进 JSONL，analyze 靠它把 param1 和动作对上号。这是整个逆向
流程里最省事的一步 —— 不打标签的话，事后很难分清哪条是哪个按钮。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from collections import Counter
from typing import Optional

from . import hci, protocol

#: 玩具自己广播时用的厂商 ID（来自参考实现的观察）
TOY_COMPANY_ID = 0x2502
#: 万一指令改走 Manufacturer Data，company id 会是这个
CACHITO_COMPANY_ID = 0x0071


class LabelInput:
    """后台线程读 stdin，把当前标签实时更新给主循环。"""

    def __init__(self) -> None:
        self.label = ""
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not sys.stdin.isatty():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                line = sys.stdin.readline()
            except Exception:
                return
            if not line:
                return
            self.label = line.strip()
            print("    >>> 标签已设为: %r" % self.label, flush=True)

    def stop(self) -> None:
        self._stop.set()


def _classify(report: hci.AdvReport) -> list[dict]:
    """把一条广播上报拆成若干条「感兴趣的记录」。"""
    out: list[dict] = []
    sections = report.sections

    # 1) 128-bit Service UUID —— 指令就藏在这儿
    for air in hci.iter_uuid128(sections):
        payload = protocol.from_air(air)
        rec = {
            "kind": "uuid128",
            "air": air.hex(),
            "payload": payload.hex(),
            "uuid": protocol.payload_to_uuid(payload),
            "is_cachito": protocol.looks_like_cachito(payload),
        }
        if rec["is_cachito"]:
            cmd = protocol.Command.decode(payload)
            rec["decoded"] = cmd.to_dict()
        out.append(rec)

    # 2) Manufacturer Data
    for company, data in report.manufacturer_data().items():
        kind = ("cachito_mfr" if company == CACHITO_COMPANY_ID else
                "toy_adv" if company == TOY_COMPANY_ID else "mfr")
        out.append({
            "kind": kind,
            "company_id": company,
            "data": data.hex(),
        })

    return out


def sniff(seconds: Optional[float], out_path: str, adapter: int,
          record_all: bool, quiet: bool) -> str:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    labels = LabelInput()
    labels.start()

    seen_uuids: set[str] = set()
    counts: Counter = Counter()
    pairing_ids: Counter = Counter()
    n_records = 0

    stopping = threading.Event()

    def _sigint(_sig, _frm):
        stopping.set()

    old_handler = signal.signal(signal.SIGINT, _sigint)

    print("=" * 68)
    print(" Cachito 抓包中 —— 现在去 iPhone 上操作 Cachito App")
    print("=" * 68)
    print(" 适配器 : hci%d" % adapter)
    print(" 输出   : %s" % out_path)
    print(" 时长   : %s" % ("%.0f 秒" % seconds if seconds else "直到 Ctrl+C"))
    if sys.stdin.isatty():
        print()
        print(" 提示：直接打字回车可以给后续记录打标签，例如输入 `vibrate 50`")
        print("       再去 App 里把强度拖到 50。标签能让 analyze 自动对上 param1。")
    print("-" * 68, flush=True)

    fh = open(out_path, "a", encoding="utf-8")
    try:
        with hci.HciDevice(adapter) as dev:
            for report in dev.scan(duration_s=seconds, passive=True):
                if stopping.is_set():
                    break
                recs = _classify(report)
                if not recs and not record_all:
                    continue

                interesting = [r for r in recs
                               if r.get("is_cachito")
                               or r["kind"] in ("cachito_mfr", "toy_adv")]
                if not interesting and not record_all:
                    continue

                for r in (recs if record_all else interesting):
                    row = {
                        "t": round(report.timestamp, 4),
                        "label": labels.label,
                        "addr": report.address,
                        "addr_type": report.addr_type,
                        "rssi": report.rssi,
                        "ad_raw": report.data.hex(),
                        **r,
                    }
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                    n_records += 1
                    counts[r["kind"]] += 1

                    if r.get("is_cachito"):
                        d = r["decoded"]
                        pairing_ids[d["pairing_id"]] += 1
                        key = "%s|%s|%s" % (d["param1"], d["intensity"],
                                            d["pairing_id"])
                        if key not in seen_uuids:
                            seen_uuids.add(key)
                            if not quiet:
                                print()
                                print("  [%s] rssi=%ddBm  标签=%r"
                                      % (time.strftime("%H:%M:%S"),
                                         report.rssi, labels.label))
                                print("  " + protocol.Command.decode(
                                    bytes.fromhex(r["payload"])
                                ).describe().replace("\n", "\n  "))
                                sys.stdout.flush()
                fh.flush()
    except hci.HciError as e:
        print("\n[错误] %s" % e, file=sys.stderr)
        return out_path
    finally:
        signal.signal(signal.SIGINT, old_handler)
        labels.stop()
        fh.close()

    # ---------------- 收尾汇总 ----------------
    print()
    print("=" * 68)
    print(" 抓包结束：共 %d 条记录 -> %s" % (n_records, out_path))
    for kind, c in counts.most_common():
        print("   %-14s %d" % (kind, c))
    if pairing_ids:
        print()
        print(" 观察到的配对 ID：")
        for pid, c in pairing_ids.most_common():
            print("   %s   (%d 次)" % (pid, c))
        if len(pairing_ids) == 1:
            print()
            print(" 只出现了一个配对 ID —— 基本可以确定就是它: %s"
                  % next(iter(pairing_ids)))
    else:
        print()
        print(" 没抓到任何 Cachito 指令。排查：")
        print("   * App 要在**前台**打开着（iOS 退到后台会把 Service UUID")
        print("     挪进 Apple 的 overflow 区，抓不到）")
        print("   * 操作时手机要靠近这台机器")
        print("   * 用 --all 看看到底收到了些什么广播")
    print("=" * 68)
    print()
    print(" 下一步： python -m cachito.analyze %s --write-config" % out_path)
    return out_path


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m cachito.sniff",
        description="抓 Cachito App 发出的 BLE 广播指令",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--seconds", type=float, default=None,
                    help="抓多少秒（默认一直抓到 Ctrl+C）")
    ap.add_argument("--output", "-o", default=None,
                    help="输出 JSONL 路径（默认 captures/cachito-<时间戳>.jsonl）")
    ap.add_argument("--adapter", "-i", type=int, default=0, help="hciN，默认 0")
    ap.add_argument("--all", action="store_true", dest="record_all",
                    help="记录所有广播，不只是 Cachito 的（找玩具本体时用）")
    ap.add_argument("--quiet", "-q", action="store_true", help="不实时打印解码结果")
    args = ap.parse_args(argv)

    out = args.output
    if out is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = os.path.join(root, "captures",
                           "cachito-%s.jsonl" % time.strftime("%Y%m%d-%H%M%S"))

    if os.geteuid() != 0:
        print("需要 root 权限（要独占 HCI 控制器）。请用 sudo 运行：",
              file=sys.stderr)
        print("  sudo %s -m cachito.sniff %s"
              % (sys.executable, " ".join(sys.argv[1:])), file=sys.stderr)
        return 1

    sniff(args.seconds, out, args.adapter, args.record_all, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
