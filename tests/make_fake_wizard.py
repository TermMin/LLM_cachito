"""生成一份仿真的引导式抓包，用来验证 channels 分析器。

    python tests/make_fake_wizard.py /tmp/fw.jsonl
    python -m cachito.channels /tmp/fw.jsonl

结构是照着**真机抓到的 1441 条样本**复刻的，包括那些让分析变难的特性：

* 运动包 0x8800 全程以心跳形式重播，一个包里带 3 个字段（[10][11][12]）
* 温度包 0x8200 一旦设过就一直重播（[13] 是温度，[8]/[10]/[14] 是固定值）
* 震动包 0x9000 同理（[10] 是强度）
* 「全部停止」时运动三个字段**一起归零** —— 专门用来考验跨步消歧
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cachito import protocol  # noqa: E402

DEVICE_TYPE = 0x03
PAIRING = bytes.fromhex("49d1")

TICK = 0.2          # 心跳间隔
IDLE_S = 5.0
ACTIVE_S = 8.0
SETTLE_S = 1.0

# 真值：通道 -> (选择子, 字节位, 取值序列)
TRUTH = {
    "depth":       ("8800", 10, [0, 8, 16, 27, 35, 44, 53, 62, 70, 53, 30, 12]),
    "speed_out":   ("8800", 11, [1, 2, 3, 4, 5, 6, 5, 3, 2]),
    "speed_in":    ("8800", 12, [1, 2, 3, 4, 3, 2, 1]),
    "vibration":   ("9000", 10, [0, 12, 24, 32, 42, 50, 32, 16]),
    "temperature": ("8200", 13, [27, 33, 38, 41, 48, 56, 41]),
}
STOP_SELECTOR = "1f00"

STATIC = {                       # 选择子 -> {offset: 固定值}
    "8200": {8: 0x01, 10: 0x64, 14: 0x02},
}

STEPS = ["depth", "speed_out", "speed_in", "vibration", "temperature", "stop"]


def make(selector_hex, fields, t, step, idx, phase):
    """构造一条记录。fields = {offset: value}"""
    body = bytearray(16)
    body[0] = 0x71
    body[2] = DEVICE_TYPE
    body[3] = random.randint(0x64, 0xFF)
    body[4:6] = bytes.fromhex(selector_hex)
    body[6:8] = PAIRING
    for off, v in STATIC.get(selector_hex, {}).items():
        body[off] = v
    for off, v in fields.items():
        body[off] = v & 0xFF
    body[15] = protocol.checksum(bytes(body))
    payload = bytes(body)
    return {
        "t": round(t, 4), "step": step, "step_index": idx, "phase": phase,
        "label": step, "addr": "4C:1A:00:00:00:01", "rssi": -55,
        "kind": "uuid128", "air": protocol.to_air(payload).hex(),
        "payload": payload.hex(), "uuid": protocol.payload_to_uuid(payload),
        "is_cachito": True,
    }


def main(out_path):
    random.seed(11)
    rows = []
    t = 1000.0

    # 当前状态：选择子 -> {offset: value}，只有设过的包才会被重播
    live = {"8800": {10: 20, 11: 2, 12: 2}}     # 设备一开始就在动

    def beat(step, idx, phase, seconds):
        nonlocal t
        end = t + seconds
        while t < end:
            for sel, f in live.items():
                rows.append(make(sel, f, t, step, idx, phase))
            t += TICK

    beat("__warmup__", -1, "warmup", 3.0)

    for idx, step in enumerate(STEPS):
        beat(step, idx, "idle", IDLE_S)

        if step == "stop":
            # 停止包本身
            for _ in range(6):
                rows.append(make(STOP_SELECTOR, {}, t, step, idx, "active"))
                t += TICK
            # 运动三个字段一起归零 —— 消歧的考点
            live["8800"] = {10: 0, 11: 0, 12: 0}
            if "9000" in live:
                live["9000"] = {10: 0}
            beat(step, idx, "active", ACTIVE_S - 1.2)
        else:
            sel, off, seq = TRUTH[step]
            live.setdefault(sel, dict(STATIC.get(sel, {})))
            per = ACTIVE_S / len(seq)
            for v in seq:
                live[sel][off] = v
                beat(step, idx, "active", per)

        beat(step, idx, "settle", SETTLE_S)

    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("已生成 %d 条 -> %s" % (len(rows), out_path))
    print()
    print("真值：")
    for ch, (sel, off, _seq) in TRUTH.items():
        print("  %-12s 包 %s 字节[%2d]" % (ch, sel, off))
    print("  %-12s 包 %s（无参数）" % ("stop", STOP_SELECTOR))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fake-wizard.jsonl")
