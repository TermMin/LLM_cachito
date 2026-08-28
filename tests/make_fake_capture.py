"""生成一份假的抓包文件，用来在没有硬件时验证 analyze 的整条链路。

    python tests/make_fake_capture.py /tmp/fake.jsonl
    python -m cachito.analyze /tmp/fake.jsonl

模拟的是一台 DX：配对 ID a3f1，震动 param1=0100，停止 param1=0601
（停止码是编的 —— 真值必须自己抓，这里只为验证分析器能把它认出来）。
"""

import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cachito import protocol  # noqa: E402

DEVICE_TYPE = 0x03
PAIRING_ID = bytes.fromhex("a3f1")
VIBRATE_P1 = bytes.fromhex("0100")
STOP_P1 = bytes.fromhex("0601")


def row(label, payload, t, rssi=-52):
    air = protocol.to_air(payload)
    cmd = protocol.Command.decode(payload)
    return {
        "t": round(t, 4),
        "label": label,
        "addr": "4C:1A:%02X:%02X:%02X:%02X" % tuple(random.randrange(256)
                                                    for _ in range(4)),
        "addr_type": 1,
        "rssi": rssi,
        "ad_raw": ("020106" "1107" + air.hex()),
        "kind": "uuid128",
        "air": air.hex(),
        "payload": payload.hex(),
        "uuid": protocol.payload_to_uuid(payload),
        "is_cachito": True,
        "decoded": cmd.to_dict(),
    }


def main(out_path):
    random.seed(7)
    t = time.time()
    rows = []

    # App 拖滑杆时会连发好几包，这里每档发 6 条
    for level in (20, 50, 80):
        for _ in range(6):
            cmd = protocol.Command(
                device_type=DEVICE_TYPE, pairing_id=PAIRING_ID,
                param1=VIBRATE_P1, intensity=level,
            )
            rows.append(row("vibrate %d" % level, cmd.encode(), t))
            t += 0.12

    for _ in range(5):
        cmd = protocol.Command(
            device_type=DEVICE_TYPE, pairing_id=PAIRING_ID,
            param1=STOP_P1, intensity=protocol.STOP_INTENSITY,
        )
        rows.append(row("stop", cmd.encode(), t))
        t += 0.12

    # 一点噪声：玩具自己的广播 + 无关设备
    for i in range(4):
        rows.append({
            "t": round(t + i * 0.5, 4), "label": "", "addr": "C0:FF:EE:00:00:01",
            "addr_type": 0, "rssi": -66, "ad_raw": "",
            "kind": "toy_adv", "company_id": 0x2502, "data": "0103%02x" % i,
        })

    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("已生成 %d 条 -> %s" % (len(rows), out_path))
    print("真值：配对 ID=%s  震动 param1=%s  停止 param1=%s"
          % (PAIRING_ID.hex(), VIBRATE_P1.hex(), STOP_P1.hex()))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fake-capture.jsonl")
