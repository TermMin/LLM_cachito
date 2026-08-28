"""原始 HCI 传输层（Linux / WSL2）。

为什么要走裸 HCI，而不是 bleak / bluez：

* **发送**：Cachito 指令必须以 AD Type 0x07（Complete List of 128-bit
  Service UUIDs）广播出去。Windows 的 WinRT
  ``BluetoothLEAdvertisementPublisher`` 明确把 0x06/0x07 列为系统保留、
  禁止应用广播，所以 Windows 原生做不到。BlueZ 的上层 API（以及
  ``btmgmt``）也会对广播内容做校验和改写。裸 HCI 没有这些限制 ——
  ``LE Set Advertising Data`` 是什么就发什么。
* **接收**：裸 HCI 能拿到完整的 AD 原始字节，而不是被库解析、
  归一化、去重之后的结果。逆向阶段这点很重要。

用 ``HCI_CHANNEL_USER`` 独占打开控制器：内核和 bluetoothd 都不会插手，
广播内容不会被改写。代价是必须先把适配器 down 掉，而且复位、事件掩码
这些初始化要自己做。

全部基于 stdlib + ctypes，不需要装任何第三方包，也不需要 bluez。
"""

from __future__ import annotations

import errno
import fcntl
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

# --------------------------------------------------------------------------
# Linux ABI 常量
#
# conda 编译的 Python 往往缺 socket.AF_BLUETOOTH（编译时没有蓝牙头文件），
# 所以这里直接写死数值 —— 这些是稳定的内核 ABI，不会变。
# --------------------------------------------------------------------------

AF_BLUETOOTH = 31
BTPROTO_HCI = 1

HCI_CHANNEL_RAW = 0
HCI_CHANNEL_USER = 1
HCI_CHANNEL_MONITOR = 2
HCI_CHANNEL_CONTROL = 3

# ioctl: _IOW('H', 201/202/203, int)
HCIDEVUP = 0x400448C9
HCIDEVDOWN = 0x400448CA
HCIDEVRESET = 0x400448CB

# HCI 包类型（socket 上每个包的第一个字节）
HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT = 0x04

# 事件码
EVT_CMD_COMPLETE = 0x0E
EVT_CMD_STATUS = 0x0F
EVT_LE_META = 0x3E

# LE 子事件
LE_ADVERTISING_REPORT = 0x02
LE_EXT_ADVERTISING_REPORT = 0x0D

# opcode = (OGF << 10) | OCF
OP_RESET = 0x0C03               # OGF 0x03 / OCF 0x0003
OP_SET_EVENT_MASK = 0x0C01      # OGF 0x03 / OCF 0x0001
OP_READ_BD_ADDR = 0x1009        # OGF 0x04 / OCF 0x0009
OP_READ_LOCAL_VERSION = 0x1001  # OGF 0x04 / OCF 0x0001

OP_LE_SET_EVENT_MASK = 0x2001
OP_LE_SET_ADV_PARAMS = 0x2006
OP_LE_READ_ADV_TX_POWER = 0x2007
OP_LE_SET_ADV_DATA = 0x2008
OP_LE_SET_SCAN_RSP_DATA = 0x2009
OP_LE_SET_ADV_ENABLE = 0x200A
OP_LE_SET_SCAN_PARAMS = 0x200B
OP_LE_SET_SCAN_ENABLE = 0x200C

# 广播类型
ADV_IND = 0x00           # 可连接、非定向（iOS App 用的就是这种）
ADV_SCAN_IND = 0x02      # 可扫描、非定向
ADV_NONCONN_IND = 0x03   # 不可连接、非定向（纯广播）

# AD Type
AD_FLAGS = 0x01
AD_INCOMPLETE_UUID128 = 0x06
AD_COMPLETE_UUID128 = 0x07
AD_SHORT_NAME = 0x08
AD_COMPLETE_NAME = 0x09
AD_MANUFACTURER = 0xFF

#: 广播间隔单位是 0.625ms
ADV_UNIT_MS = 0.625


class HciError(RuntimeError):
    """HCI 层错误，message 里带排查建议。"""


# --------------------------------------------------------------------------
# 适配器枚举 / 上下电
# --------------------------------------------------------------------------

def list_adapters() -> list[str]:
    """列出系统里的 HCI 适配器，如 ['hci0']。

    直接读 sysfs，比 HCIGETDEVLIST ioctl 简单且没有结构体对齐坑。
    """
    try:
        return sorted(os.listdir("/sys/class/bluetooth"))
    except FileNotFoundError:
        return []


def adapter_address(dev: str = "hci0") -> Optional[str]:
    try:
        with open("/sys/class/bluetooth/%s/address" % dev) as f:
            return f.read().strip()
    except OSError:
        return None


def _ctl_socket() -> socket.socket:
    """未绑定的 HCI socket，只用来发 ioctl。"""
    return socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)


def dev_down(dev_id: int = 0) -> None:
    """把适配器 down 掉（等价于 `hciconfig hciN down`）。"""
    s = _ctl_socket()
    try:
        fcntl.ioctl(s.fileno(), HCIDEVDOWN, dev_id)
    except OSError as e:
        # EALREADY / ENODEV 都当成「本来就是 down 的」，不算错误
        if e.errno not in (errno.EALREADY, errno.ENODEV):
            raise HciError("无法 down hci%d: %s（需要 root）" % (dev_id, e)) from e
    finally:
        s.close()


def dev_up(dev_id: int = 0) -> None:
    """把适配器拉起来（等价于 `hciconfig hciN up`）。"""
    s = _ctl_socket()
    try:
        fcntl.ioctl(s.fileno(), HCIDEVUP, dev_id)
    except OSError as e:
        if e.errno != errno.EALREADY:
            raise HciError("无法 up hci%d: %s" % (dev_id, e)) from e
    finally:
        s.close()


# --------------------------------------------------------------------------
# AD 结构
# --------------------------------------------------------------------------

def build_ad(sections: list[tuple[int, bytes]]) -> bytes:
    """把 [(ad_type, data), ...] 拼成 BLE 广播负载。

    每段格式是 [长度][类型][数据]，长度含类型字节本身。
    """
    out = bytearray()
    for ad_type, data in sections:
        if len(data) > 254:
            raise ValueError("AD 段过长")
        out.append(len(data) + 1)
        out.append(ad_type)
        out += data
    if len(out) > 31:
        raise ValueError("广播负载 %d 字节，超过传统广播上限 31" % len(out))
    return bytes(out)


def parse_ad(data: bytes) -> list[tuple[int, bytes]]:
    """解析广播负载成 [(ad_type, data), ...]。容忍截断/补零的尾巴。"""
    out: list[tuple[int, bytes]] = []
    i = 0
    n = len(data)
    while i < n:
        length = data[i]
        if length == 0:          # 补零区，正常结束
            break
        if i + 1 + length > n:   # 截断了，能拿多少算多少
            out.append((data[i + 1], data[i + 2:n]))
            break
        out.append((data[i + 1], data[i + 2:i + 1 + length]))
        i += 1 + length
    return out


def iter_uuid128(sections: list[tuple[int, bytes]]) -> Iterator[bytes]:
    """从 AD 段里挑出所有 128-bit UUID，按**空中字节序**逐个吐出。

    AD 0x06/0x07 的数据区可以放多个 UUID，每个 16 字节。
    """
    for ad_type, data in sections:
        if ad_type in (AD_INCOMPLETE_UUID128, AD_COMPLETE_UUID128):
            for off in range(0, len(data) - 15, 16):
                yield data[off:off + 16]


# --------------------------------------------------------------------------
# 广播上报
# --------------------------------------------------------------------------

@dataclass
class AdvReport:
    """一条 LE 广播上报。"""
    timestamp: float
    event_type: int
    addr_type: int
    address: str
    rssi: int
    data: bytes

    @property
    def sections(self) -> list[tuple[int, bytes]]:
        return parse_ad(self.data)

    def name(self) -> Optional[str]:
        for t, d in self.sections:
            if t in (AD_SHORT_NAME, AD_COMPLETE_NAME):
                return d.decode("utf-8", "replace")
        return None

    def manufacturer_data(self) -> dict[int, bytes]:
        out = {}
        for t, d in self.sections:
            if t == AD_MANUFACTURER and len(d) >= 2:
                out[d[0] | (d[1] << 8)] = d[2:]
        return out


# --------------------------------------------------------------------------
# HCI 设备
# --------------------------------------------------------------------------

class HciDevice:
    """独占打开一个 HCI 控制器（HCI_CHANNEL_USER），收发裸 HCI。

    用法::

        with HciDevice(0) as hci:
            hci.broadcast(payload_air, duration_s=0.5)
    """

    def __init__(self, dev_id: int = 0, restore_on_close: bool = False,
                 verbose: bool = False):
        self.dev_id = dev_id
        self.restore_on_close = restore_on_close
        self.verbose = verbose
        self.sock: Optional[socket.socket] = None
        self._advertising = False
        self._scanning = False

    # ---------------- 生命周期 ----------------

    def open(self) -> "HciDevice":
        if not os.path.exists("/sys/class/bluetooth/hci%d" % self.dev_id):
            adapters = list_adapters()
            raise HciError(
                "找不到 hci%d。当前适配器: %s\n"
                "  * 蓝牙 USB 设备透传进 WSL 了吗？ usbipd attach --wsl --busid <id>\n"
                "  * btusb 驱动加载了吗？          sudo modprobe btusb"
                % (self.dev_id, adapters or "（无）")
            )

        # CHANNEL_USER 要求适配器处于 down 状态
        dev_down(self.dev_id)

        s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        addr = struct.pack("<HHH", AF_BLUETOOTH, self.dev_id, HCI_CHANNEL_USER)

        # bluetoothd 可能在我们 down 之后又把它拉起来，重试几次
        last: Optional[OSError] = None
        for _ in range(10):
            try:
                _bind_raw(s, addr)
                last = None
                break
            except OSError as e:
                last = e
                if e.errno == errno.EBUSY:   # 被别人占着
                    dev_down(self.dev_id)
                    time.sleep(0.1)
                    continue
                break
        if last is not None:
            s.close()
            if last.errno == errno.EPERM:
                raise HciError("权限不足，需要 root：用 sudo 跑，或给解释器加 "
                               "cap_net_raw,cap_net_admin 能力") from last
            if last.errno == errno.EBUSY:
                raise HciError(
                    "hci%d 被占用。试试先停掉 bluetoothd：\n"
                    "  sudo systemctl stop bluetooth" % self.dev_id) from last
            raise HciError("绑定 hci%d 失败: %s" % (self.dev_id, last)) from last

        s.settimeout(3.0)
        self.sock = s

        # CHANNEL_USER 下内核什么都不做，初始化得自己来
        self.cmd(OP_RESET)
        # 打开全部事件（复位后的默认掩码不含 LE Meta Event，不设就收不到广播上报）
        self.cmd(OP_SET_EVENT_MASK, b"\xff" * 8)
        self.cmd(OP_LE_SET_EVENT_MASK, b"\xff" * 8)
        if self.verbose:
            print("[hci] hci%d 已独占打开，BD_ADDR=%s"
                  % (self.dev_id, self.read_bd_addr()))
        return self

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            if self._advertising:
                self.stop_advertising()
            if self._scanning:
                self.stop_scan()
        except Exception:
            pass
        try:
            self.sock.close()
        finally:
            self.sock = None
        if self.restore_on_close:
            try:
                dev_up(self.dev_id)
            except HciError:
                pass

    def __enter__(self) -> "HciDevice":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------- 命令收发 ----------------

    def cmd(self, opcode: int, params: bytes = b"", timeout: float = 3.0) -> bytes:
        """发一条 HCI 命令，等 Command Complete，返回其返回参数（不含 status）。"""
        if self.sock is None:
            raise HciError("设备未打开")
        pkt = struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params
        self.sock.send(pkt)

        deadline = time.time() + timeout
        while time.time() < deadline:
            evt = self._read_event(deadline - time.time())
            if evt is None:
                continue
            code, data = evt
            if code == EVT_CMD_COMPLETE and len(data) >= 3:
                _ncmd, op = struct.unpack("<BH", data[:3])
                if op != opcode:
                    continue
                ret = data[3:]
                if ret and ret[0] != 0x00:
                    raise HciError("命令 0x%04x 失败，status=0x%02x (%s)"
                                   % (opcode, ret[0], _hci_status(ret[0])))
                return ret[1:] if ret else b""
            if code == EVT_CMD_STATUS and len(data) >= 4:
                status, _ncmd, op = struct.unpack("<BBH", data[:4])
                if op != opcode:
                    continue
                if status != 0x00:
                    raise HciError("命令 0x%04x 失败，status=0x%02x (%s)"
                                   % (opcode, status, _hci_status(status)))
                return b""
        raise HciError("命令 0x%04x 超时未响应" % opcode)

    def _read_event(self, timeout: float) -> Optional[tuple[int, bytes]]:
        """读一个事件包，返回 (事件码, 参数)。超时返回 None。"""
        if self.sock is None:
            return None
        if timeout <= 0:
            return None
        self.sock.settimeout(timeout)
        try:
            buf = self.sock.recv(1024)
        except socket.timeout:
            return None
        except OSError:
            return None
        if len(buf) < 3 or buf[0] != HCI_EVENT_PKT:
            return None
        code = buf[1]
        plen = buf[2]
        return code, buf[3:3 + plen]

    def read_bd_addr(self) -> str:
        ret = self.cmd(OP_READ_BD_ADDR)
        if len(ret) < 6:
            return "??"
        return ":".join("%02X" % b for b in reversed(ret[:6]))

    # ---------------- 广播（发送） ----------------

    def set_adv_params(self, interval_ms: float = 30.0,
                       adv_type: int = ADV_IND) -> None:
        iv = max(1, int(round(interval_ms / ADV_UNIT_MS)))
        params = struct.pack(
            "<HHBBB6sBB",
            iv,          # interval min
            iv,          # interval max
            adv_type,
            0x00,        # own address type: public
            0x00,        # peer address type
            b"\x00" * 6, # peer address
            0x07,        # 三个广播信道全用
            0x00,        # filter policy: 不过滤
        )
        try:
            self.cmd(OP_LE_SET_ADV_PARAMS, params)
        except HciError:
            # 有些控制器对非连接广播的最小间隔卡得更严，退到 100ms 再试
            iv = int(round(100.0 / ADV_UNIT_MS))
            self.cmd(OP_LE_SET_ADV_PARAMS, struct.pack(
                "<HHBBB6sBB", iv, iv, adv_type, 0x00, 0x00, b"\x00" * 6, 0x07, 0x00))

    def set_adv_data(self, ad_payload: bytes) -> None:
        """LE Set Advertising Data：1 字节有效长度 + 31 字节数据（补零）。"""
        if len(ad_payload) > 31:
            raise ValueError("广播负载 %d 字节 > 31" % len(ad_payload))
        params = bytes([len(ad_payload)]) + ad_payload.ljust(31, b"\x00")
        self.cmd(OP_LE_SET_ADV_DATA, params)

    def set_adv_enable(self, enable: bool) -> None:
        self.cmd(OP_LE_SET_ADV_ENABLE, bytes([0x01 if enable else 0x00]))
        self._advertising = enable

    def stop_advertising(self) -> None:
        try:
            self.set_adv_enable(False)
        except HciError:
            self._advertising = False

    def broadcast(self, uuid128_air: bytes, duration_s: float = 0.5,
                  interval_ms: float = 30.0, adv_type: int = ADV_IND,
                  flags: Optional[int] = 0x06) -> None:
        """把一个 128-bit UUID 当作 AD 0x07 广播出去，持续 duration_s。

        Args:
            uuid128_air: 16 字节，**空中字节序**（即 payload 逆序）。
            flags: AD Flags 的值；None 表示不带 Flags 段。iOS 广播时会带，
                   默认 0x06 = LE General Discoverable + 不支持 BR/EDR。
        """
        if len(uuid128_air) != 16:
            raise ValueError("UUID 必须 16 字节")
        sections: list[tuple[int, bytes]] = []
        if flags is not None:
            sections.append((AD_FLAGS, bytes([flags])))
        sections.append((AD_COMPLETE_UUID128, uuid128_air))

        self.stop_advertising()
        self.set_adv_params(interval_ms=interval_ms, adv_type=adv_type)
        self.set_adv_data(build_ad(sections))
        self.set_adv_enable(True)
        try:
            time.sleep(duration_s)
        finally:
            self.stop_advertising()

    # ---------------- 扫描（接收） ----------------

    def start_scan(self, passive: bool = True, interval_ms: float = 30.0,
                   window_ms: float = 30.0) -> None:
        """开始 LE 扫描。

        被动扫描就够了 —— 指令全在 ADV 包里，不需要 SCAN_REQ 去要扫描响应，
        而且被动扫描不发包，不会干扰手机和玩具之间的通信。
        """
        iv = max(4, int(round(interval_ms / ADV_UNIT_MS)))
        win = max(4, int(round(window_ms / ADV_UNIT_MS)))
        self.cmd(OP_LE_SET_SCAN_PARAMS, struct.pack(
            "<BHHBB",
            0x00 if passive else 0x01,
            iv, win,
            0x00,   # own address type: public
            0x00,   # filter policy: 全收
        ))
        # 第二个字节 = filter_duplicates，必须为 0：
        # 我们要看到每一条重复广播，否则会漏掉 App 的连续下发
        self.cmd(OP_LE_SET_SCAN_ENABLE, b"\x01\x00")
        self._scanning = True

    def stop_scan(self) -> None:
        try:
            self.cmd(OP_LE_SET_SCAN_ENABLE, b"\x00\x00")
        except HciError:
            pass
        self._scanning = False

    def scan(self, duration_s: Optional[float] = None,
             on_report: Optional[Callable[[AdvReport], None]] = None,
             passive: bool = True) -> Iterator[AdvReport]:
        """扫描并逐条产出广播上报。duration_s=None 表示一直扫到被中断。"""
        self.start_scan(passive=passive)
        deadline = None if duration_s is None else time.time() + duration_s
        try:
            while deadline is None or time.time() < deadline:
                remain = 1.0 if deadline is None else min(1.0, deadline - time.time())
                evt = self._read_event(remain)
                if evt is None:
                    continue
                code, data = evt
                if code != EVT_LE_META or not data:
                    continue
                for rep in _parse_le_meta(data):
                    if on_report is not None:
                        on_report(rep)
                    yield rep
        finally:
            self.stop_scan()


# --------------------------------------------------------------------------
# 内部工具
# --------------------------------------------------------------------------

def _bind_raw(sock: socket.socket, sockaddr: bytes) -> None:
    """用 ctypes 直接调 bind()。

    CPython 的 socket.bind() 对 BTPROTO_HCI 只接受 (dev,) 且把 channel
    写死成 HCI_CHANNEL_RAW，没法指定 HCI_CHANNEL_USER；而且 conda 版
    Python 干脆没编进 AF_BLUETOOTH 支持。绕过它，直接调 libc。
    """
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    buf = ctypes.create_string_buffer(sockaddr, len(sockaddr))
    if libc.bind(sock.fileno(), buf, len(sockaddr)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _parse_le_meta(data: bytes) -> list[AdvReport]:
    """解析 LE Meta Event 里的广播上报。"""
    now = time.time()
    sub = data[0]
    out: list[AdvReport] = []

    if sub == LE_ADVERTISING_REPORT:
        num = data[1] if len(data) > 1 else 0
        off = 2
        for _ in range(num):
            if off + 9 > len(data):
                break
            event_type = data[off]
            addr_type = data[off + 1]
            addr = data[off + 2:off + 8]
            dlen = data[off + 8]
            off += 9
            if off + dlen + 1 > len(data):
                break
            adv = data[off:off + dlen]
            off += dlen
            rssi = struct.unpack("<b", data[off:off + 1])[0]
            off += 1
            out.append(AdvReport(
                timestamp=now, event_type=event_type, addr_type=addr_type,
                address=":".join("%02X" % b for b in reversed(addr)),
                rssi=rssi, data=adv,
            ))

    elif sub == LE_EXT_ADVERTISING_REPORT:
        # 扩展广播上报；我们不主动开扩展扫描，但有的控制器仍会上报
        num = data[1] if len(data) > 1 else 0
        off = 2
        for _ in range(num):
            if off + 24 > len(data):
                break
            event_type = struct.unpack("<H", data[off:off + 2])[0]
            addr_type = data[off + 2]
            addr = data[off + 3:off + 9]
            rssi = struct.unpack("<b", data[off + 18:off + 19])[0]
            dlen = data[off + 23]
            off += 24
            if off + dlen > len(data):
                break
            adv = data[off:off + dlen]
            off += dlen
            out.append(AdvReport(
                timestamp=now, event_type=event_type, addr_type=addr_type,
                address=":".join("%02X" % b for b in reversed(addr)),
                rssi=rssi, data=adv,
            ))

    return out


_STATUS = {
    0x01: "Unknown HCI Command",
    0x0C: "Command Disallowed",
    0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters",
    0x1A: "Unsupported Remote Feature",
}


def _hci_status(code: int) -> str:
    return _STATUS.get(code, "见蓝牙规范 Vol 1 Part F")
