"""分析抓包结果，推断协议字段，生成 device.json。

用法::

    python -m cachito.analyze captures/xxx.jsonl
    python -m cachito.analyze captures/xxx.jsonl --write-config
    python -m cachito.analyze captures/xxx.jsonl --dump

分析分两层：

**逐字节差分**（不假设任何布局）
    把所有抓到的 payload 按字节位对齐，看每一位是恒定、随机、还是跟
    标签/强度相关。这一层不预设 DX 和 Venus 的布局一样 —— 如果厂商
    在 DX 上改了字段位置，差分表会直接把异常暴露出来。

**协议对照**（按已知布局解读）
    把差分结果和文档里的布局比对，不一致的地方明确报警，而不是
    默默按老布局解析出一堆垃圾。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from typing import Optional

from . import config as cfgmod
from . import protocol

#: 文档记载的字段布局，用来和实测差分结果对照
EXPECTED_LAYOUT = [
    (0, 0, "协议头", "常量 0x71"),
    (1, 1, "保留", "常量 0x00"),
    (2, 2, "设备类型", "常量（本机玩具型号）"),
    (3, 3, "随机序号", "随机 0x64-0xFF"),
    (4, 5, "指令码", "常量 0x0400"),
    (6, 7, "配对 ID", "常量（你的 App 安装）"),
    (8, 9, "param1", "随动作变化"),
    (10, 10, "强度", "随滑杆变化 0x00-0x64"),
    (11, 14, "填充", "常量 0x00"),
    (15, 15, "校验和", "= sum(0..14) & 0xFF"),
]


# --------------------------------------------------------------------------
# 载入
# --------------------------------------------------------------------------

def load(path: str) -> tuple[list[dict], list[dict]]:
    """返回 (cachito 指令记录, 其它记录)。"""
    cmds, others = [], []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                print("  [警告] 第 %d 行不是合法 JSON，跳过" % lineno,
                      file=sys.stderr)
                continue
            if row.get("is_cachito") and row.get("payload"):
                row["_bytes"] = bytes.fromhex(row["payload"])
                cmds.append(row)
            else:
                others.append(row)
    return cmds, others


# --------------------------------------------------------------------------
# 逐字节差分
# --------------------------------------------------------------------------

def byte_profile(payloads: list[bytes]) -> list[dict]:
    """对每个字节位做统计。"""
    prof = []
    n = len(payloads)
    for off in range(protocol.PAYLOAD_LEN):
        vals = Counter(p[off] for p in payloads if len(p) > off)
        distinct = len(vals)
        top, topn = vals.most_common(1)[0] if vals else (0, 0)
        if distinct == 1:
            kind = "常量"
        elif distinct > max(8, n * 0.5):
            kind = "随机/高熵"
        elif distinct <= 6:
            kind = "少量取值"
        else:
            kind = "多值"
        prof.append({
            "offset": off,
            "distinct": distinct,
            "kind": kind,
            "top": top,
            "top_ratio": (topn / n) if n else 0.0,
            "values": vals,
        })
    return prof


def print_byte_table(prof: list[dict], n: int) -> None:
    print()
    print("逐字节差分（共 %d 条指令）" % n)
    print("-" * 78)
    print("%-4s %-12s %-8s %-34s %s" % ("位", "特征", "取值数", "取值（出现次数）", "文档预期"))
    print("-" * 78)
    expect_by_off = {}
    for lo, hi, name, desc in EXPECTED_LAYOUT:
        for o in range(lo, hi + 1):
            expect_by_off[o] = "%s / %s" % (name, desc)

    for p in prof:
        vals = p["values"]
        if p["distinct"] <= 5:
            shown = " ".join("%02x(%d)" % (v, c) for v, c in vals.most_common(5))
        else:
            shown = "%d 种，最常见 %02x(%.0f%%)" % (
                p["distinct"], p["top"], p["top_ratio"] * 100)
        print("%-4d %-12s %-8d %-34s %s"
              % (p["offset"], p["kind"], p["distinct"], shown,
                 expect_by_off.get(p["offset"], "")))
    print("-" * 78)


def check_layout(prof: list[dict], n: int) -> list[str]:
    """把实测差分和文档预期对照，返回警告列表。"""
    warn = []
    by_off = {p["offset"]: p for p in prof}

    if by_off[0]["distinct"] != 1 or by_off[0]["top"] != protocol.HEADER:
        warn.append("offset 0 不是恒定的 0x71 —— 协议头可能变了")
    if by_off[2]["distinct"] != 1:
        warn.append("offset 2（设备类型）不恒定：抓到了多台不同型号的玩具？")
    for off in (6, 7):
        if by_off[off]["distinct"] != 1:
            warn.append("offset %d（配对 ID）不恒定：抓到了多个 App 安装的广播，"
                        "需要按 RSSI 或时间段筛一下" % off)
    if n >= 8 and by_off[3]["distinct"] < 3:
        warn.append("offset 3（随机序号）几乎不变 —— 样本太少，或该位不是随机序号")
    for off in range(11, 15):
        if by_off[off]["distinct"] != 1 or by_off[off]["top"] != 0:
            warn.append("offset %d（填充）不是恒定的 0x00 —— DX 可能在这里放了别的字段"
                        % off)
    return warn


# --------------------------------------------------------------------------
# 校验和
# --------------------------------------------------------------------------

def _candidates():
    """一组候选校验和算法，用来在文档公式对不上时兜底。"""
    def s(a, b, k=0):
        return lambda p: (sum(p[a:b]) + k) & 0xFF

    def x(a, b):
        return lambda p: _xor(p[a:b])

    yield "sum(0..14) & 0xFF", s(0, 15)
    yield "sum(1..14) & 0xFF", s(1, 15)
    yield "sum(2..14) & 0xFF", s(2, 15)
    yield "(sum(0..14)+1) & 0xFF", s(0, 15, 1)
    yield "(-sum(0..14)) & 0xFF", lambda p: (-sum(p[0:15])) & 0xFF
    yield "xor(0..14)", x(0, 15)


def _xor(bs: bytes) -> int:
    r = 0
    for b in bs:
        r ^= b
    return r


def analyze_checksum(payloads: list[bytes]) -> tuple[str, float]:
    """返回 (最佳公式描述, 命中率)。"""
    best, best_rate = "（无）", -1.0
    for name, fn in _candidates():
        hit = sum(1 for p in payloads if len(p) == 16 and fn(p) == p[15])
        rate = hit / len(payloads) if payloads else 0.0
        if rate > best_rate:
            best, best_rate = name, rate
    return best, best_rate


# --------------------------------------------------------------------------
# 按标签归类
# --------------------------------------------------------------------------

_NUM_RE = re.compile(r"(\d+)")

_ACTION_ALIASES = [
    (("vibrate", "vib", "震动", "振动", "抖"), "vibrate"),
    (("stop", "off", "停止", "停", "关"), "stop"),
    (("pulse", "脉冲", "点动"), "pulse"),
    (("wave", "波浪"), "wave"),
]


def normalize_action(label: str) -> str:
    """把人写的标签归一成动作名。认不出来的就用标签本身（去掉数字）。"""
    low = label.strip().lower()
    if not low:
        return ""
    for keys, action in _ACTION_ALIASES:
        if any(k in low for k in keys):
            return action
    slug = re.sub(r"[^a-z0-9一-鿿]+", "_", _NUM_RE.sub("", low)).strip("_")
    return slug or "unknown"


def group_by_label(cmds: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for c in cmds:
        groups[c.get("label") or ""].append(c)
    return dict(groups)


def analyze_actions(cmds: list[dict]) -> tuple[dict[str, Counter], list[str]]:
    """按动作归类 param1，返回 (动作 -> param1 计数, 警告)。"""
    actions: dict[str, Counter] = defaultdict(Counter)
    warns: list[str] = []
    for label, rows in group_by_label(cmds).items():
        action = normalize_action(label)
        if not action:
            continue
        for r in rows:
            actions[action][r["_bytes"][8:10].hex()] += 1
    for action, params in actions.items():
        if len(params) > 1:
            warns.append(
                "动作 %r 出现了 %d 种 param1（%s）—— 可能标签打得跨了动作边界，"
                "或该动作本身有多个子模式"
                % (action, len(params),
                   ", ".join("%s×%d" % (k, v) for k, v in params.most_common())))
    return dict(actions), warns


def check_intensity_correlation(cmds: list[dict]) -> Optional[str]:
    """如果标签里带数字（如 `vibrate 50`），验证 offset 10 是不是就是它。"""
    pairs = []
    for c in cmds:
        m = _NUM_RE.search(c.get("label") or "")
        if m:
            pairs.append((int(m.group(1)), c["_bytes"][10]))
    if len(pairs) < 3:
        return None
    exact = sum(1 for want, got in pairs if want == got)
    rate = exact / len(pairs)
    if rate >= 0.8:
        return ("强度确认：标签里的数字和 offset 10 完全对上（%d/%d）"
                % (exact, len(pairs)))
    # 也可能有缩放，比如 0-100 映射到 0-255
    scaled = sum(1 for want, got in pairs
                 if abs(got - round(want * 2.55)) <= 2)
    if scaled / len(pairs) >= 0.8:
        return ("强度确认：offset 10 ≈ 标签数字 × 2.55（0-100 映射到 0-255），"
                "%d/%d 命中" % (scaled, len(pairs)))
    return ("强度存疑：标签数字和 offset 10 对不上（精确命中 %d/%d）—— "
            "确认打标签的时机和实际拖滑杆的时机一致" % (exact, len(pairs)))


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def report(path: str, write_config: bool, dump: bool,
           config_path: str) -> int:
    cmds, others = load(path)

    print("=" * 78)
    print(" 分析 %s" % path)
    print("=" * 78)
    print(" Cachito 指令 : %d 条" % len(cmds))
    print(" 其它记录     : %d 条" % len(others))

    if others:
        kinds = Counter(o.get("kind", "?") for o in others)
        print("   " + "  ".join("%s×%d" % (k, v) for k, v in kinds.most_common()))
        # 玩具本体的广播对确认「玩具在附近」有用
        toys = [o for o in others if o.get("kind") == "toy_adv"]
        if toys:
            print(" 玩具本体广播 : %d 条（company 0x2502），说明玩具在范围内"
                  % len(toys))

    if not cmds:
        print()
        print(" 没有可分析的指令。检查：App 是否在前台、手机是否靠近本机。")
        return 1

    payloads = [c["_bytes"] for c in cmds]

    if dump:
        print()
        print("-" * 78)
        for c in cmds:
            print("[%s] label=%r rssi=%s"
                  % (c.get("t"), c.get("label"), c.get("rssi")))
            print(protocol.Command.decode(c["_bytes"]).describe())
            print()

    # --- 逐字节差分 ---
    prof = byte_profile(payloads)
    print_byte_table(prof, len(payloads))

    warns = check_layout(prof, len(payloads))

    # --- 校验和 ---
    formula, rate = analyze_checksum(payloads)
    print()
    print("校验和：最佳匹配 %s，命中率 %.1f%%" % (formula, rate * 100))
    if rate < 1.0:
        warns.append("有 %.0f%% 的包校验和对不上（最佳公式 %s）—— "
                     "要么抓包有误码，要么 DX 的校验方式不同"
                     % ((1 - rate) * 100, formula))

    # --- 关键字段 ---
    by_off = {p["offset"]: p for p in prof}
    dev_types = by_off[2]["values"]
    pairing = Counter(p[6:8].hex() for p in payloads)
    cmd_codes = Counter(p[4:6].hex() for p in payloads)

    print()
    print("关键字段")
    print("-" * 78)
    print(" 设备类型 : " + ", ".join(
        "0x%02x=%s (%d 次)" % (v, protocol.DEVICE_TYPES.get(v, "未知"), c)
        for v, c in dev_types.most_common()))
    print(" 指令码   : " + ", ".join("%s (%d 次)" % (k, c)
                                     for k, c in cmd_codes.most_common()))
    print(" 配对 ID  : " + ", ".join("%s (%d 次)" % (k, c)
                                     for k, c in pairing.most_common()))

    # --- 动作 / param1 ---
    actions, awarns = analyze_actions(cmds)
    warns += awarns
    print()
    print("动作 -> param1")
    print("-" * 78)
    if actions:
        for action, params in sorted(actions.items()):
            top = params.most_common(1)[0]
            print(" %-12s %s  (%d 次%s)"
                  % (action, top[0], top[1],
                     "，另有 " + ", ".join("%s×%d" % (k, v)
                                           for k, v in params.most_common()[1:])
                     if len(params) > 1 else ""))
    else:
        print(" （抓包时没打标签，只能列出观察到的 param1）")
        for v, c in Counter(p[8:10].hex() for p in payloads).most_common():
            print("   %s  (%d 次)" % (v, c))
        print()
        print(" 建议重抓一次，抓的时候用标签把动作分开：")
        print("   sudo python -m cachito.sniff")
        print("   然后输入 `vibrate 50` 回车 -> 去 App 拖到 50")
        print("   再输入 `stop` 回车 -> 去 App 点停止")

    note = check_intensity_correlation(cmds)
    if note:
        print()
        print(" " + note)

    # --- 警告 ---
    if warns:
        print()
        print("警告")
        print("-" * 78)
        for w in warns:
            print(" ! " + w)

    # --- 生成配置 ---
    if write_config:
        print()
        print("-" * 78)
        if len(pairing) != 1:
            print(" 配对 ID 不唯一，不能自动生成配置。")
            print(" 抓包时附近可能有别的 Cachito App 在广播；")
            print(" 请只在自己操作时抓，或按 RSSI 筛掉远处的。")
            return 2
        if len(dev_types) != 1:
            print(" 设备类型不唯一，不能自动生成配置。")
            return 2

        cfg = cfgmod.DeviceConfig.load(config_path)
        cfg.device_type = next(iter(dev_types))
        cfg.pairing_id = next(iter(pairing))
        cfg.cmd_code = cmd_codes.most_common(1)[0][0]
        for action, params in actions.items():
            cfg.params[action] = params.most_common(1)[0][0]
        saved = cfg.save(config_path)

        print(" 已写入 %s" % saved)
        print("   设备类型 : 0x%02x (%s)" % (cfg.device_type, cfg.device_name))
        print("   配对 ID  : %s" % cfg.pairing_id)
        print("   指令码   : %s" % cfg.cmd_code)
        print("   动作     : %s" % (", ".join("%s=%s" % kv
                                              for kv in sorted(cfg.params.items()))
                                    or "（无，需要打标签重抓）"))
        missing = [a for a in ("vibrate", "stop") if a not in cfg.params]
        if missing:
            print()
            print("   还缺这些动作：%s" % ", ".join(missing))
            print("   （vibrate 可以退回内置的已知值，stop 对 DX 没有公开记录，"
                  "必须自己抓）")
        print()
        print(" 下一步试着控制：")
        print("   sudo python -m cachito.control status")
        print("   sudo python -m cachito.control vibrate 30")
        print("   sudo python -m cachito.control stop")

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m cachito.analyze",
        description="分析抓包结果，推断字段并生成 device.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("capture", nargs="?", help="抓包 JSONL 路径（默认取最新一个）")
    ap.add_argument("--write-config", action="store_true",
                    help="把推断结果写入 device.json")
    ap.add_argument("--config", default=cfgmod.DEFAULT_PATH, help="device.json 路径")
    ap.add_argument("--dump", action="store_true", help="逐条打印解码结果")
    args = ap.parse_args(argv)

    path = args.capture
    if path is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cap_dir = os.path.join(root, "captures")
        files = sorted(
            (os.path.join(cap_dir, f) for f in os.listdir(cap_dir)
             if f.endswith(".jsonl")),
            key=os.path.getmtime,
        ) if os.path.isdir(cap_dir) else []
        if not files:
            ap.error("captures/ 下没有 .jsonl，请显式指定路径")
        path = files[-1]
        print("（未指定文件，取最新的：%s）" % os.path.basename(path))

    if not os.path.exists(path):
        print("找不到文件: %s" % path, file=sys.stderr)
        return 1
    return report(path, args.write_config, args.dump, args.config)


if __name__ == "__main__":
    sys.exit(main())
