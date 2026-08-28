"""协议层自检。不需要蓝牙硬件，随时可以跑：

    python -m pytest tests/ -q
    python tests/test_protocol.py        # 不装 pytest 也能跑
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cachito import protocol  # noqa: E402

#: 协议文档里的样例指令（Venus，强度 0x37=55）
DOC_UUID = "71000182-0400-cbc5-040a-3700000000cd"
DOC_PAYLOAD = bytes.fromhex("71000182" "0400" "cbc5" "040a" "3700000000cd")


def test_doc_example_checksum():
    """文档样例：前 15 字节之和 = 0x2CD，校验和取低 8 位 = 0xCD。"""
    assert sum(DOC_PAYLOAD[:15]) == 0x2CD
    assert protocol.checksum(DOC_PAYLOAD) == 0xCD
    assert DOC_PAYLOAD[15] == 0xCD


def test_uuid_roundtrip():
    assert protocol.uuid_to_payload(DOC_UUID) == DOC_PAYLOAD
    assert protocol.payload_to_uuid(DOC_PAYLOAD) == DOC_UUID


def test_air_byte_order_is_reversed():
    """BLE 上 128-bit UUID 是小端传输的，空中字节流是 payload 的逆序。"""
    air = protocol.to_air(DOC_PAYLOAD)
    assert air[0] == 0xCD      # 校验和先上天
    assert air[-1] == 0x71     # 协议头最后
    assert protocol.from_air(air) == DOC_PAYLOAD


def test_decode_fields():
    cmd = protocol.Command.from_uuid(DOC_UUID)
    assert cmd.header == 0x71
    assert cmd.device_type == 0x01
    assert cmd.device_name == "Venus"
    assert cmd.random_sn == 0x82
    assert cmd.cmd_code == b"\x04\x00"
    assert cmd.pairing_id == bytes.fromhex("cbc5")
    assert cmd.param1 == bytes.fromhex("040a")
    assert cmd.intensity == 0x37 == 55
    assert cmd.padding == b"\x00" * 4
    ok, note = cmd.verify()
    assert ok, note


def test_encode_matches_doc_example():
    """固定随机序号后，重新编码应当逐字节还原文档样例。"""
    cmd = protocol.Command(
        device_type=0x01,
        pairing_id=bytes.fromhex("cbc5"),
        param1=bytes.fromhex("040a"),
        intensity=0x37,
        random_sn=0x82,
    )
    assert cmd.encode() == DOC_PAYLOAD
    assert cmd.uuid() == DOC_UUID


def test_checksum_is_recomputed_on_encode():
    cmd = protocol.Command(
        device_type=0x03,
        pairing_id=bytes.fromhex("dead"),
        param1=bytes.fromhex("0100"),
        intensity=42,
        random_sn=0x99,
    )
    p = cmd.encode()
    assert p[15] == protocol.checksum(p)
    assert protocol.Command.decode(p).verify()[0]


def test_bad_checksum_is_detected():
    bad = bytearray(DOC_PAYLOAD)
    bad[15] ^= 0xFF
    ok, note = protocol.Command.decode(bytes(bad)).verify()
    assert not ok
    assert "校验和" in note


def test_random_sn_in_documented_range():
    """随机序号应落在 0x64-0xFF。"""
    for _ in range(200):
        p = protocol.Command(
            device_type=0x03, pairing_id=b"\x00\x01",
            param1=b"\x01\x00", intensity=10,
        ).encode()
        assert 0x64 <= p[3] <= 0xFF


def test_vibrate_clamps_intensity():
    pid = bytes.fromhex("cbc5")
    assert protocol.vibrate(pid, 500, device_type=0x01).intensity == 100
    assert protocol.vibrate(pid, -10, device_type=0x01).intensity == 0


def test_unknown_param1_raises_with_guidance():
    """DX 的停止码没有公开记录 —— 报错要说清楚怎么补上，而不是瞎猜一个。"""
    try:
        protocol.stop(bytes.fromhex("cbc5"), device_type=0x03)
    except ValueError as e:
        assert "sniff" in str(e)
    else:
        raise AssertionError("应当抛 ValueError")


def test_looks_like_cachito():
    assert protocol.looks_like_cachito(DOC_PAYLOAD)
    assert not protocol.looks_like_cachito(b"\x00" * 16)
    assert not protocol.looks_like_cachito(DOC_PAYLOAD[:15])


def test_parse_pairing_id_forms():
    want = bytes.fromhex("cbc5")
    for s in ("cbc5", "CBC5", "cb:c5", "0xcbc5", " cbc5 "):
        assert protocol.parse_pairing_id(s) == want


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print("  PASS  %s" % name)
        except Exception as e:
            failed += 1
            print("  FAIL  %s: %s" % (name, e))
    print("\n%d/%d 通过" % (len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
