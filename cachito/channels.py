"""多通道分析：把引导式抓包的结果绑定成「通道 -> 包内字节」。

    python -m cachito.channels captures/wizard-xxx.jsonl --write-config

思路
----
DX 的 App 持续重播状态包，所以「哪个包出现了」几乎没有区分度 ——
运动包全程都在发。真正有区分度的是**哪个字节在哪一步变了**。

对每个标定步骤，拿它的「操作窗口」和「静置基线」做差分：

1. **新出现的选择子**：基线里没有、操作时才出现的包类型 —— 说明这个控件
   触发了一类新的包（温度、停止这种）。
2. **出现新值的字节**：包类型两边都有，但某个字节在操作时冒出了基线里
   没见过的值 —— 说明这个字节被这个控件改动了。

然后做**跨步消歧**：一个字节如果只在某一步变过，就干净地绑给它。如果在
多步都变过（典型情况：按下「全部停止」时运动的几个参数会一起归零），
就按「引入的新值有多少种」打分 —— 拖滑杆会产生一串值，而停止只产生一个 0。

不做任何关于布局的预设：绑定完全由数据决定，结果写进 device.json 的
``commands``，代码里不写死任何型号。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from . import config as cfgmod
from . import protocol
from .protocol import Field, PacketTemplate

#: 判定「这一步确实动了这个字节」所需的最少新值种类
MIN_NEW_VALUES = 1
#: 跨步消歧时，赢家的新值种类要比亚军多这么多倍才算干净
MARGIN = 2.0


# --------------------------------------------------------------------------
# 载入
# --------------------------------------------------------------------------

@dataclass
class Rec:
    t: float
    step: str
    step_index: int
    phase: str
    payload: bytes

    @property
    def selector(self) -> bytes:
        return self.payload[4:6]


def load(path: str) -> list[Rec]:
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not r.get("is_cachito") or not r.get("payload"):
            continue
        out.append(Rec(
            t=float(r.get("t", 0)),
            step=r.get("step", r.get("label", "")) or "",
            step_index=int(r.get("step_index", -1)),
            phase=r.get("phase", "active"),
            payload=bytes.fromhex(r["payload"]),
        ))
    out.sort(key=lambda r: r.t)
    return out


# --------------------------------------------------------------------------
# 分析
# --------------------------------------------------------------------------

@dataclass
class Evidence:
    """某一步对某个 (选择子, 字节位) 的证据。"""
    step: str
    selector: bytes
    offset: int
    baseline_values: set[int] = field(default_factory=set)
    new_values: set[int] = field(default_factory=set)

    @property
    def score(self) -> int:
        return len(self.new_values)


@dataclass
class Analysis:
    steps: list[str]
    #: (selector, offset) -> {step -> Evidence}
    evidence: dict[tuple[bytes, int], dict[str, Evidence]]
    #: step -> 该步新出现的选择子
    new_selectors: dict[str, set[bytes]]
    #: selector -> offset -> 全局观察到的取值
    observed: dict[bytes, dict[int, Counter]]
    #: 最终绑定 (selector, offset) -> step
    binding: dict[tuple[bytes, int], str]
    #: 有歧义的绑定，给人看
    ambiguous: list[str]
    pairing_ids: Counter
    device_types: Counter


def _is_active(r: Rec) -> bool:
    return r.phase in ("active", "settle")


def _is_idle(r: Rec) -> bool:
    return r.phase in ("idle", "warmup")


def analyze(rows: list[Rec]) -> Analysis:
    by_step: dict[str, list[Rec]] = defaultdict(list)
    order: list[str] = []
    for r in rows:
        if r.step.startswith("__"):
            continue
        if r.step not in by_step:
            order.append(r.step)
        by_step[r.step].append(r)

    # 全局观察：每个选择子的每个字节都见过哪些值
    observed: dict[bytes, dict[int, Counter]] = defaultdict(
        lambda: defaultdict(Counter))
    for r in rows:
        for off in protocol.FIELD_OFFSETS:
            observed[r.selector][off][r.payload[off]] += 1

    evidence: dict[tuple[bytes, int], dict[str, Evidence]] = defaultdict(dict)
    new_selectors: dict[str, set[bytes]] = {}

    for step in order:
        recs = by_step[step]
        idle = [r for r in recs if _is_idle(r)]
        active = [r for r in recs if _is_active(r)]
        if not active:
            continue

        # 基线用**这一步自己的**静置窗口，不能用全局。
        # 原因：App 会持续重播设过的包，所以某个控件第一次触发的包类型，
        # 会出现在**后续所有步骤**的基线里。拿全局基线判「新包」，就永远
        # 判不出来 —— 只有 per-step 基线才能抓住「首次引入」这个时刻。
        base: dict[bytes, dict[int, set[int]]] = defaultdict(
            lambda: defaultdict(set))
        for r in idle:
            for off in protocol.FIELD_OFFSETS:
                base[r.selector][off].add(r.payload[off])

        own_idle_sel = {r.selector for r in idle}
        act_sel = {r.selector for r in active}
        introduced = act_sel - own_idle_sel
        new_selectors[step] = introduced

        by_sel_active: dict[bytes, list[Rec]] = defaultdict(list)
        for r in active:
            by_sel_active[r.selector].append(r)

        for sel, arecs in by_sel_active.items():
            for off in protocol.FIELD_OFFSETS:
                seen = {r.payload[off] for r in arecs}
                if sel in introduced:
                    # 整个包都是这一步才冒出来的：包内**自身在变**的字节
                    # 才是字段，恒定的那些是这类包的固定值（如温度包的
                    # [8]=01 [10]=64 [14]=02）。
                    if len(seen) > 1:
                        ev = Evidence(step=step, selector=sel, offset=off)
                        ev.new_values = set(seen)
                        evidence[(sel, off)][step] = ev
                else:
                    # 基线里就有这个包：找冒出来的新值
                    known = base[sel][off]
                    new = seen - known
                    if new:
                        ev = Evidence(step=step, selector=sel, offset=off,
                                      baseline_values=set(known))
                        ev.new_values = set(new)
                        evidence[(sel, off)][step] = ev

    # ---- 跨步消歧 ----
    binding: dict[tuple[bytes, int], str] = {}
    ambiguous: list[str] = []
    for key, per_step in evidence.items():
        ranked = sorted(per_step.values(), key=lambda e: -e.score)
        ranked = [e for e in ranked if e.score >= MIN_NEW_VALUES]
        if not ranked:
            continue
        win = ranked[0]
        if len(ranked) == 1:
            binding[key] = win.step
            continue
        second = ranked[1]
        if win.score >= max(MARGIN * second.score, second.score + 1):
            binding[key] = win.step
            ambiguous.append(
                "[%d] (包 %s) 在 %d 步里都变过，按新值数量判给了 %r"
                "（%d 种 vs 亚军 %r 的 %d 种）"
                % (win.offset, win.selector.hex(), len(ranked), win.step,
                   win.score, second.step, second.score))
        else:
            ambiguous.append(
                "[%d] (包 %s) 分不清属于哪一步：%s —— 请只动这一个控件重抓这几步"
                % (win.offset, win.selector.hex(),
                   ", ".join("%s(%d种)" % (e.step, e.score) for e in ranked)))

    return Analysis(
        steps=order,
        evidence=evidence,
        new_selectors=new_selectors,
        observed=observed,
        binding=binding,
        ambiguous=ambiguous,
        pairing_ids=Counter(r.payload[6:8].hex() for r in rows),
        device_types=Counter(r.payload[2] for r in rows),
    )


# --------------------------------------------------------------------------
# 生成包模板
# --------------------------------------------------------------------------

def _packet_name(selector: bytes, channels: list[str]) -> str:
    if channels:
        if len(channels) == 1:
            return channels[0]
        # 多个通道共用一个包（运动那种），取个组合名
        return "+".join(sorted(channels))
    return "cmd_%s" % selector.hex()


def build_templates(a: Analysis) -> tuple[dict[str, PacketTemplate], list[str]]:
    """把绑定结果变成包模板。返回 (模板表, 说明性备注)。"""
    notes: list[str] = []

    # selector -> {channel: offset}
    by_sel: dict[bytes, dict[str, int]] = defaultdict(dict)
    for (sel, off), step in a.binding.items():
        by_sel[sel][step] = off

    # 只在某一步出现的选择子，且没绑到任何字节 —— 当成「无参数指令」
    for step, sels in a.new_selectors.items():
        for sel in sels:
            if step not in by_sel[sel]:
                by_sel[sel].setdefault("__trigger__:" + step, -1)

    templates: dict[str, PacketTemplate] = {}
    for sel, chans in by_sel.items():
        real = {c: o for c, o in chans.items() if o >= 0}
        triggers = [c.split(":", 1)[1] for c in chans if c.startswith("__trigger__:")]

        fields: dict[str, Field] = {}
        for ch, off in real.items():
            vals = a.observed[sel][off]
            lo, hi = min(vals), max(vals)
            fields[ch] = Field(offset=off, min=lo, max=hi)
            if hi - lo < 3:
                notes.append("通道 %r 只观察到 %d-%d 这么窄的范围 —— "
                             "重抓时把滑杆拖满，范围才准" % (ch, lo, hi))

        used = {f.offset for f in fields.values()}
        static: dict[int, int] = {}
        varying_unbound: list[int] = []
        for off in protocol.FIELD_OFFSETS:
            if off in used:
                continue
            vals = a.observed[sel][off]
            if len(vals) == 1:
                v = next(iter(vals))
                if v:                       # 只记非零的固定值，0 是默认
                    static[off] = v
            else:
                varying_unbound.append(off)

        name = triggers[0] if (triggers and not fields) else _packet_name(
            sel, sorted(fields))
        t = PacketTemplate(name=name, selector=sel, fields=fields, static=static)
        t.validate()
        templates[name] = t

        if varying_unbound:
            notes.append(
                "包 %s（%s）里 %s 这几个字节会变，但没能绑到任何控件 —— "
                "可能是 App 内部状态，也可能是漏标的控件"
                % (sel.hex(), name,
                   ", ".join("[%d]" % o for o in varying_unbound)))

    return templates, notes


# --------------------------------------------------------------------------
# 报告
# --------------------------------------------------------------------------

def report(path: str, write_config: bool, config_path: str) -> int:
    rows = load(path)
    if not rows:
        print("没有可分析的 Cachito 指令。", file=sys.stderr)
        return 1

    # 这个分析器靠「操作窗口 vs 静置基线」做差分，没有基线就没法差分。
    if not any(_is_idle(r) for r in rows):
        print("=" * 78)
        print(" 这份抓包里没有静置基线，不是引导式采集的结果。")
        print("=" * 78)
        print(" 本分析器要靠「每步的操作窗口」和「该步的静置基线」做差分才能")
        print(" 分清通道。自由抓包（sniff）没有这个结构，所有操作混在一起。")
        print()
        print(" 请改用引导式标定：")
        print("     sudo python -m cachito.wizard")
        print()
        print(" 想看这份自由抓包的概况，用旧分析器：")
        print("     python -m cachito.analyze %s" % path)
        return 1

    a = analyze(rows)

    print("=" * 78)
    print(" 多通道分析 %s" % os.path.basename(path))
    print("=" * 78)
    print(" 指令 %d 条，标定步骤 %d 个: %s"
          % (len(rows), len(a.steps), ", ".join(a.steps)))
    print(" 设备类型: " + ", ".join(
        "0x%02x=%s(%d)" % (v, protocol.DEVICE_TYPES.get(v, "未知"), c)
        for v, c in a.device_types.most_common()))
    print(" 配对 ID : " + ", ".join("%s(%d)" % kv
                                    for kv in a.pairing_ids.most_common()))

    # ---- 各步证据 ----
    print()
    print("各步差分证据")
    print("-" * 78)
    for step in a.steps:
        print()
        print(" [%s]" % step)
        ns = a.new_selectors.get(step) or set()
        if ns:
            print("   新出现的包类型: %s"
                  % ", ".join(sorted(s.hex() for s in ns)))
        hits = [(key, per[step]) for key, per in a.evidence.items()
                if step in per]
        hits.sort(key=lambda kv: -kv[1].score)
        if not hits:
            if not ns:
                print("   没检测到任何变化 —— 这一步可能没录到操作，"
                      "或该控件不通过广播下发")
        for (sel, off), ev in hits[:6]:
            mark = "<<<" if a.binding.get((sel, off)) == step else "   "
            vals = sorted(ev.new_values)
            shown = " ".join("%02x" % v for v in vals[:10])
            if len(vals) > 10:
                shown += " ..."
            print("   %s 包 %s 字节[%2d]  新值 %d 种: %s"
                  % (mark, sel.hex(), off, len(vals), shown))

    # ---- 绑定结果 ----
    templates, notes = build_templates(a)

    print()
    print("=" * 78)
    print(" 推断结果")
    print("=" * 78)
    if not templates:
        print(" 没能推断出任何指令包。")
    for name, t in sorted(templates.items()):
        print("  " + t.describe())

    unmapped = [s for s in a.steps
                if not any(s in t.fields or s == t.name
                           for t in templates.values())]
    if unmapped:
        print()
        print(" 没能绑定的步骤: %s" % ", ".join(unmapped))
        print(" 这些控件在操作窗口里没产生可区分的变化。可能原因：")
        print("   * 操作时机和回车不同步（提示出来之后再动控件）")
        print("   * 该控件不走 BLE 广播（比如只是 App 本地状态）")
        print("   * 基线太短，把操作也录进基线了 —— 试试 --baseline 8")

    if a.ambiguous or notes:
        print()
        print("提示")
        print("-" * 78)
        for m in a.ambiguous + notes:
            print(" ! " + m)

    # ---- 写配置 ----
    if write_config:
        print()
        print("-" * 78)
        if len(a.pairing_ids) != 1:
            print(" 配对 ID 不唯一，不写配置。附近可能有别的 Cachito App 在广播。")
            return 2
        cfg = cfgmod.DeviceConfig.load(config_path)
        cfg.device_type = a.device_types.most_common(1)[0][0]
        cfg.pairing_id = next(iter(a.pairing_ids))
        cfg.commands = {}
        for name, t in templates.items():
            cfg.set_template(t)
        for cand in ("stop", "全部停止", "stop_all"):
            if cand in templates or any(cand in t.fields for t in templates.values()):
                cfg.stop_command = cand
                break
        saved = cfg.save(config_path)
        print(" 已写入 %s" % saved)
        print("   设备类型 : 0x%02x (%s)" % (cfg.device_type, cfg.device_name))
        print("   配对 ID  : %s" % cfg.pairing_id)
        print("   通道     : %s" % (", ".join(cfg.channels()) or "（无）"))
        print("   停止指令 : %s" % (cfg.stop_command or "（未识别）"))
        print()
        print(" 下一步：")
        print("   sudo python -m cachito.control status")
        print("   sudo python -m cachito.control set depth 40")
        print("   sudo python -m cachito.control stop")

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m cachito.channels",
        description="把引导式抓包的结果分析成通道绑定",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("capture", nargs="?", help="JSONL 路径（默认取最新的 wizard-*）")
    ap.add_argument("--write-config", action="store_true")
    ap.add_argument("--config", default=cfgmod.DEFAULT_PATH)
    args = ap.parse_args(argv)

    path = args.capture
    if path is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cap = os.path.join(root, "captures")
        files = sorted((os.path.join(cap, f) for f in os.listdir(cap)
                        if f.startswith("wizard-") and f.endswith(".jsonl")),
                       key=os.path.getmtime) if os.path.isdir(cap) else []
        if not files:
            ap.error("captures/ 下没有 wizard-*.jsonl，请显式指定路径")
        path = files[-1]
        print("（未指定文件，取最新的：%s）" % os.path.basename(path))

    if not os.path.exists(path):
        print("找不到文件: %s" % path, file=sys.stderr)
        return 1
    return report(path, args.write_config, args.config)


if __name__ == "__main__":
    sys.exit(main())
