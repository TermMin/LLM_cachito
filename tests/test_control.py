"""Controller 行为自检。不需要蓝牙硬件。

    python tests/test_control.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cachito import protocol                      # noqa: E402
from cachito.config import DeviceConfig           # noqa: E402
from cachito.control import Controller            # noqa: E402
from cachito.protocol import Field, PacketTemplate  # noqa: E402


class _DummyRadio:
    def close(self):
        pass


def _cfg():
    """一台仿 DX 的设备：运动包三字段共包，另有独立的温度包和停止包。"""
    c = DeviceConfig(device_type=0x03, pairing_id="49d1")
    c.set_template(PacketTemplate(
        name="motion", selector=bytes.fromhex("8800"),
        fields={"depth": Field(10, 0, 100),
                "speed_out": Field(11, 0, 6),
                "speed_in": Field(12, 0, 4)}))
    c.set_template(PacketTemplate(
        name="temperature", selector=bytes.fromhex("8200"),
        fields={"temperature": Field(13, 20, 60)},
        static={8: 0x01, 10: 0x64, 14: 0x02}))
    c.set_template(PacketTemplate(
        name="stop", selector=bytes.fromhex("1f00")))
    c.stop_command = "stop"
    return c


def _spy(stop_on_exit=False):
    ctl = Controller(_cfg(), dry_run=True, stop_on_exit=stop_on_exit)
    sent = []
    orig = ctl._emit

    def emit(payload, repeats=None):
        sent.append(payload)
        return orig(payload, repeats)

    ctl._emit = emit
    ctl.dev = _DummyRadio()      # 假装电台已开，好走到真实的收尾逻辑
    return ctl, sent


# --------------------------------------------------------------------------

def test_cli_exit_does_not_stop_the_toy():
    """一次性 CLI 命令退出时**不能**补发停止。

    这是个真实踩过的坑：退出时补停止，玩具会在一秒多后自己停下来
    （正好等于一次广播 burst 的时长），看起来像是玩具坏了。
    """
    ctl, sent = _spy(stop_on_exit=False)
    ctl.set_channel("depth", 40)
    n = len(sent)
    assert n == 1, "set 应该只发一组包"
    ctl.close()
    assert len(sent) == n, "退出时不该再发任何包，实际多发了 %d 条" % (len(sent) - n)


def test_daemon_exit_does_stop_the_toy():
    """常驻进程（MCP server）退出时**要**补发停止。"""
    ctl, sent = _spy(stop_on_exit=True)
    ctl.set_channel("depth", 40)
    n = len(sent)
    ctl.close()
    assert len(sent) > n, "常驻进程退出时应当补一条停止"
    assert sent[-1][4:6] == bytes.fromhex("1f00"), "补的应该是停止包"


def test_shared_packet_preserves_other_fields():
    """改一个通道时，同包其它通道的当前值必须带上，不能被清零。"""
    ctl, sent = _spy()
    ctl.set_channels({"speed_out": 5, "speed_in": 3})
    ctl.set_channel("depth", 40)
    p = sent[-1]
    assert p[4:6] == bytes.fromhex("8800")
    assert p[10] == 40, "深浅没设上"
    assert p[11] == 5, "伸出速度被清零了"
    assert p[12] == 3, "缩回速度被清零了"


def test_static_bytes_are_included():
    ctl, sent = _spy()
    ctl.set_channel("temperature", 42)
    p = sent[-1]
    assert p[4:6] == bytes.fromhex("8200")
    assert (p[8], p[10], p[14]) == (0x01, 0x64, 0x02), "固定字节没带上"
    assert p[13] == 42


def test_values_are_clamped():
    ctl, _ = _spy()
    assert ctl.set_channel("depth", 999)["applied"]["depth"] == 100
    assert ctl.set_channel("depth", -5)["applied"]["depth"] == 0
    assert ctl.set_channel("speed_out", 99)["applied"]["speed_out"] == 6


def test_channel_limit_overrides_template_max():
    c = _cfg()
    c.safety.channel_limits = {"temperature": 45}
    ctl = Controller(c, dry_run=True)
    assert ctl.set_channel("temperature", 60)["applied"]["temperature"] == 45


def test_every_emitted_packet_is_wellformed():
    """发出去的每个包都得校验和正确、协议头正确、随机序号在范围内。"""
    ctl, sent = _spy()
    ctl.set_channels({"depth": 30, "speed_out": 2})
    ctl.set_channel("temperature", 38)
    ctl.stop()
    assert sent
    for p in sent:
        assert len(p) == 16
        assert p[0] == protocol.HEADER
        assert p[6:8] == bytes.fromhex("49d1")
        assert p[15] == protocol.checksum(p), "校验和不对: %s" % p.hex()


def test_stop_resets_state_and_uses_stop_packet():
    ctl, sent = _spy()
    ctl.set_channel("depth", 50)
    assert ctl.is_active()
    ctl.stop()
    assert not ctl.is_active()
    assert sent[-1][4:6] == bytes.fromhex("1f00")


def test_unknown_channel_raises():
    ctl, _ = _spy()
    try:
        ctl.set_channel("没有这个通道", 1)
    except ValueError as e:
        assert "未知通道" in str(e)
    else:
        raise AssertionError("应当抛 ValueError")


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
