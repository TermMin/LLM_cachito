"""设备配置：device.json 的读写。

抓包分析出来的东西存在这里，控制端和 MCP server 都从这里读。

两套模型并存：

``commands``（通用包模板，DX 用这套）
    ``名字 -> {selector, fields, static}``。一个包里可以有多个字段，
    比如运动包同时带深浅、伸出速度、缩回速度。由 wizard + channels
    自动推断填入。

``params``（Venus 风格，旧）
    ``动作 -> param1``，配合固定的 ``cmd_code`` 和 offset 10 强度字节。
    Venus/SK 那套单动作单强度的模型。

有 ``commands`` 就优先用 ``commands``。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

from . import protocol
from .protocol import Field, PacketTemplate

DEFAULT_PATH = os.environ.get(
    "CACHITO_CONFIG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "device.json"),
)


@dataclass
class BroadcastSettings:
    """一条指令怎么发出去。

    玩具是「锁存」语义：收到指令就保持那个状态。不过 DX 的 App 会持续重播
    状态包（实测 60 秒里发了 1113 条运动包），所以 ``hold`` 打开时我们也
    照做 —— 有些固件会在收不到心跳时自己停下来。
    """
    duration_s: float = 0.35    # 每次 burst 持续多久
    repeats: int = 3            # 重复几次（每次换新随机序号，抗丢包）
    gap_s: float = 0.05         # 两次 burst 之间的间隔
    interval_ms: float = 30.0   # 广播间隔
    adv_type: int = 0x00        # 0x00 = ADV_IND，和 iOS App 一致
    flags: Optional[int] = 0x06  # AD Flags；None = 不带
    hold: bool = False          # 是否后台持续重播当前状态（心跳）
    hold_period_s: float = 1.0  # 心跳间隔


@dataclass
class SafetySettings:
    """安全兜底。

    广播是锁存的 —— 进程一死玩具会保持在最后状态，所以需要看门狗。
    """
    auto_stop_seconds: float = 300   # 距上一条指令多久后自动停；0 = 关闭
    max_intensity: int = 100         # Venus 风格强度上限
    #: 每个通道的上限，覆盖模板里的 max。例如 {"temperature": 45}
    channel_limits: dict[str, int] = field(default_factory=dict)


@dataclass
class DeviceConfig:
    device_type: int = 0x03                 # DX
    pairing_id: str = ""                    # 4 个 hex 字符，抓包得到

    #: 通用包模板：名字 -> {selector, fields, static}
    commands: dict[str, dict] = field(default_factory=dict)
    #: 哪个包 / 哪套动作代表「全部停止」
    stop_command: str = ""

    # ---- Venus 风格的旧模型，保留兼容 ----
    cmd_code: str = "0400"
    params: dict[str, str] = field(default_factory=dict)
    stop_intensity: int = protocol.STOP_INTENSITY

    adapter: int = 0                        # hciN
    broadcast: BroadcastSettings = field(default_factory=BroadcastSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)

    # ---------------- 基本 ----------------

    @property
    def device_name(self) -> str:
        return protocol.DEVICE_TYPES.get(self.device_type,
                                         "未知(0x%02x)" % self.device_type)

    def pairing_bytes(self) -> bytes:
        if not self.pairing_id:
            raise ValueError(
                "还没有配对 ID。先抓包拿到它：\n"
                "  sudo python -m cachito.wizard\n"
                "（或 sudo python -m cachito.sniff 自由抓，再用 analyze 分析）"
            )
        return protocol.parse_pairing_id(self.pairing_id)

    def cmd_code_bytes(self) -> bytes:
        return protocol.parse_hex2(self.cmd_code, "cmd_code")

    # ---------------- 通用包模板 ----------------

    @property
    def uses_templates(self) -> bool:
        return bool(self.commands)

    def templates(self) -> dict[str, PacketTemplate]:
        return {name: PacketTemplate.from_dict(name, d)
                for name, d in self.commands.items()}

    def template(self, name: str) -> PacketTemplate:
        if name not in self.commands:
            raise ValueError("没有名为 %r 的指令包。已知的: %s"
                             % (name, ", ".join(sorted(self.commands)) or "（无）"))
        return PacketTemplate.from_dict(name, self.commands[name])

    def set_template(self, t: PacketTemplate) -> None:
        t.validate()
        self.commands[t.name] = t.to_dict()

    def channel_map(self) -> dict[str, tuple[str, Field]]:
        """通道名 -> (所在包的名字, 字段定义)。

        通道就是「一个可以调的东西」，比如深浅、温度。多个通道可能挤在
        同一个包里 —— 改其中一个时必须把同包的其它字段一起带上。
        """
        out: dict[str, tuple[str, Field]] = {}
        for name, t in self.templates().items():
            for ch, f in t.fields.items():
                out[ch] = (name, f)
        return out

    def channels(self) -> list[str]:
        return sorted(self.channel_map())

    def channel(self, name: str) -> tuple[PacketTemplate, Field]:
        cm = self.channel_map()
        if name not in cm:
            raise ValueError("没有名为 %r 的通道。已知的: %s"
                             % (name, ", ".join(sorted(cm)) or "（无）"))
        pkt_name, f = cm[name]
        return self.template(pkt_name), f

    def limit_for(self, channel: str, f: Field) -> int:
        """通道上限：safety.channel_limits 可以把模板里的 max 再压低。"""
        lim = self.safety.channel_limits.get(channel)
        return min(f.max, int(lim)) if lim is not None else f.max

    # ---------------- Venus 风格（旧） ----------------

    def param1_for(self, action: str) -> bytes:
        if action in self.params:
            return protocol.parse_hex2(self.params[action], "param1")
        p = protocol.KNOWN_PARAM1.get(self.device_type, {}).get(action)
        if p is None:
            known = ", ".join(sorted(self.params)) or "（无）"
            raise ValueError(
                "%s 的 '%s' param1 未知。已配置的动作: %s\n"
                "在 App 里按下这个动作对应的按钮，抓包分析后写进 device.json。"
                % (self.device_name, action, known)
            )
        return p

    def known_actions(self) -> list[str]:
        acts = set(self.params)
        for a, v in protocol.KNOWN_PARAM1.get(self.device_type, {}).items():
            if v is not None:
                acts.add(a)
        return sorted(acts)

    # ---------------- 序列化 ----------------

    def to_dict(self) -> dict:
        d = asdict(self)
        d["device_name"] = self.device_name
        return d

    def save(self, path: str = DEFAULT_PATH) -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            f.write("\n")
        return path

    @classmethod
    def load(cls, path: str = DEFAULT_PATH) -> "DeviceConfig":
        if not os.path.exists(path):
            return cls()
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        d.pop("device_name", None)
        bc = d.pop("broadcast", {}) or {}
        sf = d.pop("safety", {}) or {}
        known = {f.name for f in DeviceConfig.__dataclass_fields__.values()}
        d = {k: v for k, v in d.items() if k in known}
        cfg = cls(**d)
        for k, v in bc.items():
            if hasattr(cfg.broadcast, k):
                setattr(cfg.broadcast, k, v)
        for k, v in sf.items():
            if hasattr(cfg.safety, k):
                setattr(cfg.safety, k, v)
        return cfg
