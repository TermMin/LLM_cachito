"""Cachito 广播协议：指令编解码。

Cachito 系列玩具（Venus / SK / DX / SK4）**不是**用 GATT 写特征值控制的，
而是控制端（手机 App）发出 BLE 广播，把整条指令编码进一个
128-bit Service UUID 里。玩具被动监听广播 —— 不连接、不配对。

之所以这么设计，是因为 iOS 的 CBPeripheralManager 只允许 App 广播
LocalName 和 ServiceUUIDs 两种字段，塞不进 Manufacturer Data，
于是厂商把整条指令塞进了 UUID。

16 字节 payload 布局（顺序与 UUID 字符串一致）::

    offset  内容
    ------  ----------------------------------------------------
    0       0x71        协议头
    1       0x00        保留
    2       设备类型     Venus=0x01 / SK=0x02 / DX=0x03 / SK4=0x17
    3       随机序号     0x64-0xFF，每条指令重新生成
    4-5     指令码       通常 0x04 0x00
    6-7     配对 ID      每个 App 安装随机生成，玩具在物理配对时学到
    8-9     param1      指令种类（震动 / 停止 / ...），随型号不同
    10      强度         0x00-0x64 = 0-100%
    11-14   填充         4 字节 0x00
    15      校验和       sum(payload[0:15]) & 0xFF

UUID 字符串 = payload 的 hex，按 8-4-4-4-12 分组::

    71000182-0400-cbc5-040a-3700000000cd

字节序注意：BLE 广播里的 128-bit UUID 是**小端**传输的，空中字节流是
payload 的完全逆序。收发两个方向都要转换 —— 见 to_air() / from_air()。
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

HEADER = 0x71
PAYLOAD_LEN = 16

#: 已知设备类型（payload[2]）
DEVICE_TYPES: dict[int, str] = {
    0x01: "Venus",
    0x02: "SK",
    0x03: "DX",     # Daxiu / 大秀
    0x17: "SK4",
}

NAME_TO_TYPE: dict[str, int] = {v.lower(): k for k, v in DEVICE_TYPES.items()}

#: 默认指令码（payload[4:6]）
DEFAULT_CMD_CODE = b"\x04\x00"

#: 各型号的 param1。None = 尚未确认，需要抓包。
#:
#: 这些值来自对 Cachito Android APK 的逆向。DX 的停止码没有公开记录，
#: 必须自己抓包 —— 抓到后写进 device.json，protocol 这边不写死。
KNOWN_PARAM1: dict[int, dict[str, Optional[bytes]]] = {
    0x01: {"vibrate": b"\x04\x0a", "stop": b"\x06\x01"},
    0x02: {"vibrate": b"\x03\x02", "stop": None},
    0x03: {"vibrate": b"\x01\x00", "stop": None},
    0x17: {"vibrate": b"\x01\x00", "stop": None},
}

#: Venus 的停止指令强度字节固定为 0x02（不是 0）
STOP_INTENSITY = 0x02

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


# --------------------------------------------------------------------------
# 校验和 / 字节序
# --------------------------------------------------------------------------

def checksum(payload15: bytes) -> int:
    """校验和 = 前 15 字节之和 mod 256。"""
    if len(payload15) < 15:
        raise ValueError("需要至少 15 字节，得到 %d" % len(payload15))
    return sum(payload15[:15]) & 0xFF


def to_air(payload: bytes) -> bytes:
    """payload -> 空中字节序（128-bit UUID 小端传输，即逆序）。"""
    if len(payload) != PAYLOAD_LEN:
        raise ValueError("payload 必须 16 字节，得到 %d" % len(payload))
    return payload[::-1]


def from_air(air: bytes) -> bytes:
    """空中字节序 -> payload。与 to_air 互逆。"""
    if len(air) != PAYLOAD_LEN:
        raise ValueError("空中数据必须 16 字节，得到 %d" % len(air))
    return air[::-1]


def payload_to_uuid(payload: bytes) -> str:
    """16 字节 payload -> 标准 UUID 字符串（8-4-4-4-12）。"""
    if len(payload) != PAYLOAD_LEN:
        raise ValueError("payload 必须 16 字节，得到 %d" % len(payload))
    h = payload.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def uuid_to_payload(uuid_str: str) -> bytes:
    """UUID 字符串 -> 16 字节 payload。"""
    s = uuid_str.strip()
    if not _UUID_RE.match(s):
        raise ValueError("不是合法的 UUID 字符串: %r" % uuid_str)
    return bytes.fromhex(s.replace("-", ""))


def looks_like_cachito(payload: bytes) -> bool:
    """快速判断一段 16 字节数据是否像 Cachito 指令。

    只看协议头，不看校验和 —— 校验和交给 verify() 单独报告，这样抓包时
    能看见「头对但校验和不对」的异常包，而不是被静默丢掉。
    """
    return len(payload) == PAYLOAD_LEN and payload[0] == HEADER


# --------------------------------------------------------------------------
# 指令对象
# --------------------------------------------------------------------------

@dataclass
class Command:
    """一条 Cachito 指令。"""

    device_type: int
    pairing_id: bytes           # 2 字节
    param1: bytes               # 2 字节
    intensity: int              # 0-255（协议上 0x00-0x64 有效）
    cmd_code: bytes = DEFAULT_CMD_CODE
    random_sn: int = 0          # 0 = 编码时自动生成
    reserved: int = 0x00
    padding: bytes = b"\x00\x00\x00\x00"
    header: int = HEADER

    #: 解码时保存原始字节；编码时为 None
    raw: Optional[bytes] = field(default=None, repr=False, compare=False)

    # ---------------- 编码 ----------------

    def encode(self) -> bytes:
        """生成 16 字节 payload（自动补随机序号和校验和）。"""
        sn = self.random_sn or random.randint(0x64, 0xFF)
        if not 0 <= sn <= 0xFF:
            raise ValueError("random_sn 越界: %d" % sn)
        for name, val in (("pairing_id", self.pairing_id),
                          ("param1", self.param1),
                          ("cmd_code", self.cmd_code)):
            if len(val) != 2:
                raise ValueError("%s 必须 2 字节，得到 %d" % (name, len(val)))
        if len(self.padding) != 4:
            raise ValueError("padding 必须 4 字节")

        body = bytes([
            self.header,
            self.reserved,
            self.device_type & 0xFF,
            sn,
            self.cmd_code[0], self.cmd_code[1],
            self.pairing_id[0], self.pairing_id[1],
            self.param1[0], self.param1[1],
            self.intensity & 0xFF,
        ]) + self.padding
        return body + bytes([checksum(body)])

    def uuid(self) -> str:
        return payload_to_uuid(self.raw if self.raw is not None else self.encode())

    def air_bytes(self) -> bytes:
        return to_air(self.raw if self.raw is not None else self.encode())

    # ---------------- 解码 ----------------

    @classmethod
    def decode(cls, payload: bytes) -> "Command":
        """从 16 字节 payload 解析。不校验 checksum —— 用 verify() 单独查。"""
        if len(payload) != PAYLOAD_LEN:
            raise ValueError("payload 必须 16 字节，得到 %d" % len(payload))
        return cls(
            header=payload[0],
            reserved=payload[1],
            device_type=payload[2],
            random_sn=payload[3],
            cmd_code=payload[4:6],
            pairing_id=payload[6:8],
            param1=payload[8:10],
            intensity=payload[10],
            padding=payload[11:15],
            raw=bytes(payload),
        )

    @classmethod
    def from_uuid(cls, uuid_str: str) -> "Command":
        return cls.decode(uuid_to_payload(uuid_str))

    @classmethod
    def from_air(cls, air: bytes) -> "Command":
        return cls.decode(from_air(air))

    # ---------------- 校验与展示 ----------------

    def verify(self) -> tuple[bool, str]:
        """返回 (是否合法, 说明)。只对解码得来的指令有意义。"""
        if self.raw is None:
            return True, "（新构造的指令）"
        problems = []
        if self.raw[0] != HEADER:
            problems.append("协议头 0x%02x != 0x71" % self.raw[0])
        expect = checksum(self.raw)
        if self.raw[15] != expect:
            problems.append("校验和 0x%02x != 0x%02x" % (self.raw[15], expect))
        if any(self.padding):
            problems.append("填充区非零: %s" % self.padding.hex())
        if problems:
            return False, "; ".join(problems)
        return True, "OK"

    @property
    def device_name(self) -> str:
        return DEVICE_TYPES.get(self.device_type, "未知(0x%02x)" % self.device_type)

    def describe(self) -> str:
        ok, note = self.verify()
        mark = "OK " if ok else "BAD"
        return (
            "[%s] %s\n"
            "      设备类型 : 0x%02x (%s)\n"
            "      随机序号 : 0x%02x\n"
            "      指令码   : %s\n"
            "      配对 ID  : %s\n"
            "      param1   : %s\n"
            "      强度     : %d (0x%02x)\n"
            "      校验     : %s"
            % (mark, self.uuid(), self.device_type, self.device_name,
               self.random_sn, self.cmd_code.hex(), self.pairing_id.hex(),
               self.param1.hex(), self.intensity, self.intensity, note)
        )

    def to_dict(self) -> dict:
        ok, note = self.verify()
        return {
            "uuid": self.uuid(),
            "header": self.header,
            "reserved": self.reserved,
            "device_type": self.device_type,
            "device_name": self.device_name,
            "random_sn": self.random_sn,
            "cmd_code": self.cmd_code.hex(),
            "pairing_id": self.pairing_id.hex(),
            "param1": self.param1.hex(),
            "intensity": self.intensity,
            "padding": self.padding.hex(),
            "checksum_ok": ok,
            "checksum_note": note,
        }


# --------------------------------------------------------------------------
# 便捷构造
# --------------------------------------------------------------------------

def _param1_for(device_type: int, action: str, override: Optional[bytes]) -> bytes:
    if override is not None:
        return override
    p = KNOWN_PARAM1.get(device_type, {}).get(action)
    if p is None:
        raise ValueError(
            "%s 的 '%s' param1 未知。\n"
            "请先抓包确认：在 App 里按下对应按钮，用 `python -m cachito.sniff` 抓，\n"
            "再用 `python -m cachito.analyze` 分析，把结果写进 device.json。"
            % (DEVICE_TYPES.get(device_type, hex(device_type)), action)
        )
    return p


def vibrate(pairing_id: bytes, intensity: int, device_type: int = 0x03,
            param1: Optional[bytes] = None,
            cmd_code: bytes = DEFAULT_CMD_CODE) -> Command:
    """构造震动指令。intensity 会被夹到 0-100。"""
    return Command(
        device_type=device_type,
        pairing_id=pairing_id,
        param1=_param1_for(device_type, "vibrate", param1),
        intensity=max(0, min(100, int(intensity))),
        cmd_code=cmd_code,
    )


def stop(pairing_id: bytes, device_type: int = 0x03,
         param1: Optional[bytes] = None,
         cmd_code: bytes = DEFAULT_CMD_CODE,
         intensity: int = STOP_INTENSITY) -> Command:
    """构造停止指令。"""
    return Command(
        device_type=device_type,
        pairing_id=pairing_id,
        param1=_param1_for(device_type, "stop", param1),
        intensity=intensity,
        cmd_code=cmd_code,
    )


def parse_pairing_id(s: str) -> bytes:
    """把 'cbc5' / 'CB:C5' / '0xcbc5' 统一解析成 2 字节。"""
    t = s.strip().lower().replace("0x", "").replace(":", "").replace("-", "")
    if len(t) != 4:
        raise ValueError("配对 ID 应为 4 个 hex 字符，得到 %r" % s)
    return bytes.fromhex(t)


def parse_hex2(s: str, what: str = "值") -> bytes:
    """把 '040a' / '04:0a' 解析成 2 字节。"""
    t = s.strip().lower().replace("0x", "").replace(":", "").replace("-", "")
    if len(t) != 4:
        raise ValueError("%s 应为 4 个 hex 字符，得到 %r" % (what, s))
    return bytes.fromhex(t)


# ==========================================================================
# 通用包模板
#
# 上面那套 Command 是按 Venus 的语义写的：param1 选动作、offset 10 放强度。
# 实测发现 DX（Daxiu）根本不是这个模型 —— 它用 offset 4 选包类型，包内可以
# 同时带好几个字段，位置随包类型而变。比如运动包 0x88 一个包里同时装了
# 深浅、伸出速度、缩回速度三个值。
#
# 所以这里用一套**数据驱动**的模板来描述包结构：哪些字节是选择子、哪些是
# 固定值、哪些是可变字段。模板由抓包分析（wizard + channels）自动推断出来，
# 存进 device.json，代码里不写死任何型号的布局。
#
# 不变的部分（在真机 1441 条样本上验证过 100%）：
#     [0]=0x71  [1]=0x00  [2]=设备类型  [3]=随机序号
#     [6:8]=配对 ID       [15]=sum(0..14) & 0xFF
# 可变的部分：[4:6] 选择子，[8:15] 包体
# ==========================================================================

#: 包体里允许被模板占用的字节位（0-3、6-7、15 是协议不变量）
BODY_OFFSETS = (4, 5, 8, 9, 10, 11, 12, 13, 14)
#: 其中可以放可变字段的位置（4-5 是选择子，不当字段用）
FIELD_OFFSETS = (8, 9, 10, 11, 12, 13, 14)


@dataclass
class Field:
    """包里的一个可变字段（占 1 字节）。"""
    offset: int
    min: int = 0
    max: int = 100
    #: 人类可读的单位，纯展示用（如 "%"、"°C"、"档"）
    unit: str = ""

    def clamp(self, v: int) -> int:
        return max(self.min, min(self.max, int(v))) & 0xFF

    def to_dict(self) -> dict:
        return {"offset": self.offset, "min": self.min,
                "max": self.max, "unit": self.unit}

    @classmethod
    def from_dict(cls, d: dict) -> "Field":
        return cls(offset=int(d["offset"]), min=int(d.get("min", 0)),
                   max=int(d.get("max", 100)), unit=d.get("unit", ""))


@dataclass
class PacketTemplate:
    """一类指令包：选择子 + 固定字节 + 可变字段。"""
    name: str
    selector: bytes                      # [4:6]
    fields: dict[str, Field] = field(default_factory=dict)
    static: dict[int, int] = field(default_factory=dict)   # offset -> 固定值

    def validate(self) -> None:
        if len(self.selector) != 2:
            raise ValueError("selector 必须 2 字节")
        for off in self.static:
            if off not in FIELD_OFFSETS:
                raise ValueError(
                    "static 只能落在 %s，不能是 %d（那是协议不变量）"
                    % (list(FIELD_OFFSETS), off))
        for name, f in self.fields.items():
            if f.offset not in FIELD_OFFSETS:
                raise ValueError(
                    "字段 %r 的 offset=%d 不在 %s 里"
                    % (name, f.offset, list(FIELD_OFFSETS)))

    def to_dict(self) -> dict:
        return {
            "selector": self.selector.hex(),
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
            "static": {str(k): v for k, v in sorted(self.static.items())},
        }

    @classmethod
    def from_dict(cls, name: str, d: dict) -> "PacketTemplate":
        t = cls(
            name=name,
            selector=parse_hex2(d["selector"], "selector"),
            fields={k: Field.from_dict(v) for k, v in (d.get("fields") or {}).items()},
            static={int(k): int(v) for k, v in (d.get("static") or {}).items()},
        )
        t.validate()
        return t

    def describe(self) -> str:
        parts = []
        for n, f in sorted(self.fields.items(), key=lambda kv: kv[1].offset):
            parts.append("%s@[%d] %d-%d%s"
                         % (n, f.offset, f.min, f.max,
                            (" " + f.unit) if f.unit else ""))
        s = "%-14s 选择子=%s" % (self.name, self.selector.hex())
        if parts:
            s += "  字段: " + ", ".join(parts)
        if self.static:
            s += "  固定: " + " ".join("[%d]=%02x" % kv
                                       for kv in sorted(self.static.items()))
        return s


def build_packet(device_type: int, pairing_id: bytes, template: PacketTemplate,
                 values: Optional[dict[str, int]] = None,
                 random_sn: int = 0) -> bytes:
    """按模板生成 16 字节 payload。

    values 里没给的字段留 0x00 —— 但注意，同一个包里的多个字段是**一起发出去**的，
    所以调用方通常要把该包的**全部**字段都填上当前值，否则会把别的参数清零。
    Controller 会替你维护这份状态。
    """
    template.validate()
    if len(pairing_id) != 2:
        raise ValueError("配对 ID 必须 2 字节")

    body = bytearray(PAYLOAD_LEN)
    body[0] = HEADER
    body[1] = 0x00
    body[2] = device_type & 0xFF
    body[3] = random_sn or random.randint(0x64, 0xFF)
    body[4:6] = template.selector
    body[6:8] = pairing_id
    for off, v in template.static.items():
        body[off] = v & 0xFF
    for name, f in template.fields.items():
        if values and name in values and values[name] is not None:
            body[f.offset] = f.clamp(values[name])
    body[15] = checksum(bytes(body))
    return bytes(body)


def body_hex(payload: bytes) -> str:
    """把 payload 按「不变量 | 选择子 | 包体」分段显示，方便肉眼比对。"""
    p = payload
    return ("%02x%02x %02x %02x | %s | %s | %02x"
            % (p[0], p[1], p[2], p[3], p[4:6].hex(),
               " ".join("%02x" % b for b in p[8:15]), p[15]))
