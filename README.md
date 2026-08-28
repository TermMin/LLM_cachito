# cachito — 用 LLM 控制 Cachito Daxiu

抓包分析 Cachito App 的 BLE 广播协议，然后用裸 HCI 复现指令，最后包成
MCP server 让 Claude 直接控制玩具。

```
iPhone (Cachito App)  ──BLE 广播──>  玩具
        │
        │  抓包
        ▼
   WSL2 + 裸 HCI  ──分析──>  device.json  ──控制──>  玩具
        ▲                                    │
        └──────── MCP server <─── Claude ────┘
```

---

## 协议长什么样

Cachito 玩具**不用 GATT**。控制端把整条指令编码进一个 **128-bit Service
UUID**，直接广播出去；玩具被动监听，不连接、不配对。

之所以这么设计，是因为 iOS 的 `CBPeripheralManager` 只允许 App 广播
`LocalName` 和 `ServiceUUIDs` 两种字段 —— 塞不进 Manufacturer Data，
于是厂商把指令塞进了 UUID。

16 字节 payload，顺序和 UUID 字符串一致：

```
71000182-0400-cbc5-040a-3700000000cd
││ │ │  │    │    │    ││          └─ [15]    校验和 = sum(0..14) & 0xFF
││ │ │  │    │    │    │└─ [11:15] 填充 0x00 ×4
││ │ │  │    │    │    └── [10]    强度 0x00-0x64 = 0-100%
││ │ │  │    │    └─────── [8:10]  param1：动作种类（震动/停止/…）
││ │ │  │    └──────────── [6:8]   配对 ID：你这个 App 安装独有
││ │ │  └───────────────── [4:6]   指令码，通常 0x0400
││ │ └──────────────────── [3]     随机序号 0x64-0xFF，去重用
││ └────────────────────── [2]     设备类型：Venus=01 SK=02 DX=03 SK4=17
│└──────────────────────── [1]     保留 0x00
└───────────────────────── [0]     协议头 0x71
```

**字节序**：BLE 上 128-bit UUID 是小端传输的，空中字节流是 payload 的
完全逆序。收发两个方向都要转换（`protocol.to_air` / `from_air`）。

上面这套是 **Venus 的语义**（单动作 + 单强度字节），来自公开的逆向文档。

### DX（Daxiu）不是这个模型

实测 1441 条真机样本后发现，DX 的包体结构完全不同：

| 位置 | Venus | **DX 实测** |
|------|-------|------------|
| `[0:4]` | 头 / 保留 / 型号 / 随机 | **一样** |
| `[4:6]` | 固定指令码 `0400` | **包类型选择子，6 个取值** |
| `[6:8]` | 配对 ID | **一样** |
| `[8:15]` | param1 + 强度 + 填充 | **包体，字段位置随包类型而变** |
| `[15]` | `sum(0..14) & 0xFF` | **一样（命中 100%）** |

也就是说：**协议外壳不变，包体换了一套**。DX 用 `[4:6]` 选包类型，一个包里
可以同时装好几个字段 —— 比如运动包一个包里就带了深浅、伸出速度、缩回速度
三个值。这意味着**改其中一个参数时，必须把同包其它参数的当前值一起带上**，
否则会把它们清零。Controller 会替你维护这份状态。

另外 DX 的 App 会**持续重播状态包**（60 秒发了 1113 条运动包），所以光看
「哪个包出现了」区分不出通道，必须看「哪个字节在哪段时间变」。这正是
`wizard` + `channels` 要解决的问题。

所以代码里**不写死任何型号的布局**：包结构由标定推断出来，存进
`device.json` 的 `commands`。

---

## 为什么必须用 WSL，不能纯 Windows

指令要以 **AD Type 0x07**（Complete List of 128-bit Service UUIDs）广播。
微软文档明确把 `0x06` / `0x07` 列进「系统保留、应用不得广播」的名单
（[BluetoothLEAdvertisementPublisher][ms-pub] 的 Remarks），WinRT 只放行
Manufacturer Data (`0xFF`) 和少数非标准类型。**Windows 原生做不到这件事**，
换库也没用 —— 这是系统层面的限制。

BlueZ 的上层 API 和 `btmgmt` 也会对广播内容做校验改写。所以本项目走
**裸 HCI**（`HCI_CHANNEL_USER` 独占控制器）：`LE Set Advertising Data`
给什么就发什么，没人插手。

代价：蓝牙适配器要透传进 WSL，**透传期间 Windows 会失去蓝牙**。

[ms-pub]: https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementpublisher

> 如果不想让 Windows 断蓝牙，买个几十块的 USB 蓝牙小棒专门透传给 WSL 就行，
> 内置的那个继续留给 Windows。

---

## 装

### 1. Windows 侧：把蓝牙透传进 WSL

```powershell
winget install --interactive --exact dorssel.usbipd-win
```

装完**必须重开 PowerShell**（刷新 PATH），然后用**管理员** PowerShell：

```powershell
usbipd list                          # 找到蓝牙那行的 BUSID
usbipd bind   --busid 1-14           # 只需一次，要管理员
usbipd attach --wsl --busid 1-14     # 执行后 Windows 会断蓝牙
```

BUSID 可以从设备管理器的位置信息预判：`Port_#0014.Hub_#0001` 就是 `1-14`。

也可以用脚本代劳（自动找 BUSID、bind、attach）：

```powershell
.\scripts\attach-bt.ps1
```

> **如果报 “running scripts is disabled on this system”**：Windows 默认的
> 执行策略是 `Restricted`。不想改系统设置的话，单次绕过就行：
>
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\scripts\attach-bt.ps1
> ```
>
> 或者持久放行当前用户：`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`。
> 当然，直接敲上面那三条 usbipd 命令最省事，压根不碰执行策略。

用完还给 Windows：

```powershell
usbipd detach --busid 1-14
```

### 2. WSL 侧：拉起适配器

```bash
bash scripts/setup-wsl-bt.sh
```

检查内核蓝牙支持、加载 `btusb`、确认 `hci0` 出现。
如果卡在「没有 hci 设备」，多半是缺 Intel 固件：

```bash
sudo apt update && sudo apt install -y linux-firmware
```

装完在 Windows 侧 detach + attach 一次再重试。

### 3. Python 环境

**已经建好了**：conda env `cachito`（Python 3.12），装了 `mcp[cli]` 2.1.1。

```bash
export PY=$HOME/miniconda3/envs/cachito/bin/python
```

下面的命令都用这个 `$PY`。要在别的机器上重建：

```bash
conda env create -f environment.yml
```

抓包、分析、控制这三块**零第三方依赖**（纯 stdlib + ctypes，不需要 bleak，
也不需要 bluez），任何 Python 3.10+ 都能跑。只有 MCP server 需要 `mcp` 包。

> `mcp` 2.0 把 `FastMCP` 改名成了 `MCPServer`，host/port 也从 settings 挪到了
> `run()` 的参数上。代码里做了 1.x/2.x 兼容，装哪个大版本都能跑。

---

## 用

> 下面假设 `export PY=$HOME/miniconda3/envs/cachito/bin/python`，
> 且当前目录是项目根目录。

### 第一步：引导式标定（推荐）

```bash
sudo $PY -m cachito.wizard
```

向导会**一次只标定一个控制项**，默认这 6 个：深浅、伸出速度、缩回速度、
震动强度、温度、全部停止。每一步都是：

1. **静置 5 秒录基线** —— 什么都别碰
2. **只动这一个控件**，从最小拖到最大再拖回来
3. 回车进入下一步

开始前会让你**先把玩具跑起来**。这一步很关键：如果标定过程中才启动设备，
运动的几个参数会同时从 0 跳到默认值，分不清谁是谁。

采集完自动分析并写入 `device.json`。

> 自由抓包（不带引导）用 `sudo $PY -m cachito.sniff`，配 `--all` 可以看到
> 收到的所有广播。但对 DX 这种「持续重播 + 多字段共包」的设备，自由抓包
> 的结果会混在一起，分不出通道 —— 所以优先用向导。

### 第二步：看分析结果

向导跑完会直接输出，也可以单独再跑：

```bash
$PY -m cachito.channels --write-config
```

分析逻辑是**分段差分**：拿每一步的操作窗口和该步的静置基线比，找出

- **新出现的包类型** —— 这个控件触发了一类新包（温度、停止这种）
- **冒出新值的字节** —— 这个字节被这个控件改动了

然后**跨步消歧**：一个字节只在某一步变过就干净地绑给它；在多步都变过
（典型情况：按「全部停止」时运动参数会一起归零）就按「引入的新值有多少种」
打分 —— 拖滑杆产生一串值，停止只产生一个 0。

报告里会把每一步的证据都列出来，`<<<` 标记的是最终绑定，方便你自己复核。
绑不上的步骤会明确说明可能原因。

### 第三步：控制

```bash
sudo $PY -m cachito.control channels          # 看有哪些通道
sudo $PY -m cachito.control set depth 40
sudo $PY -m cachito.control set depth 40 speed_out 3 speed_in 2
sudo $PY -m cachito.control stop
sudo $PY -m cachito.control sweep depth       # 对某个通道扫档演示
```

加 `--dry-run` 只打印要发的包、不真发，用来在没接适配器时验证逻辑。

**共包的通道会自动带上彼此的当前值** —— 比如运动三参数在同一个包里，
你只 `set depth 40`，发出去的包里速度仍然是当前值，不会被清零。

**如果某个控件没被标定出来**，可以手动试探：

```bash
sudo $PY -m cachito.control raw 710003xx-8800-49d1-0000-2805030000xx
```

随机序号和校验和会自动重算，你只要改包体那几个字节。

> **玩具几秒后自己停了？** 把 `device.json` 里的 `broadcast.hold` 设成
> `true`，控制器会像 App 那样周期性重播当前状态包。

### 第四步：MCP

#### 一键启停（Windows，推荐）

从 cmd 里跑，或者直接双击：

```
scripts\start-mcp.cmd        启动
scripts\stop-mcp.cmd         停止并把蓝牙还给 Windows
scripts\stop-mcp.cmd /keepbt 停止但蓝牙留在 WSL（下次启动更快）
```

`start-mcp.cmd` 会自动：检查 usbipd → 找到蓝牙 BUSID → 透传进 WSL →
加载 `btusb` → 等 `hci0` 就绪 → 在新窗口启动 MCP 服务器 → 打印连接地址。
重复运行不会重复启动。

**不需要管理员，也不会弹 sudo 密码。** WSL 允许 Windows 用户直接以 root
身份运行命令（`wsl -u root`），所以既不用配 NOPASSWD sudoers，也不用手动
输密码。唯一需要管理员的是**首次** `usbipd bind`，脚本会告诉你怎么做：

```powershell
usbipd bind --busid 1-14
```

`stop-mcp.cmd` 的顺序是有讲究的：先 SIGTERM 服务器（它的退出钩子会给玩具
补一条停止指令），**等它真的退出把 `hci0` 让出来**（服务器是独占占用适配器
的，它还活着时别的进程根本打不开 `hci0`），再补一次 `control stop` 兜底，
最后才 detach 蓝牙。

参数：`start-mcp.cmd [BUSID] [端口]`，两个都可省。
也可以用环境变量 `CACHITO_WSLPY` 指定 WSL 里的 Python 路径。

#### 注册到 Claude Code

**Claude Code 桌面版不提供 `claude` 命令行工具**，所以网上常见的
`claude mcp add ...` 在这里跑不了（`'claude' is not recognized`）。
直接写配置文件即可，二选一：

**项目级** —— 在项目根目录建 `.mcp.json`（推荐，跟着项目走）：

```json
{
  "mcpServers": {
    "cachito": { "type": "http", "url": "http://127.0.0.1:8765/mcp" }
  }
}
```

**用户级** —— 在 `%USERPROFILE%\.claude.json` 里，找到
`projects` -> 你的项目路径 -> `mcpServers`，加同样的一条。

两种都配好后**要重启 Claude Code** 才会连上。

> WSL 的 localhost 转发对绑在 `127.0.0.1` 的服务有效，已实测：
> 从 Windows `POST http://127.0.0.1:8765/mcp` 返回 200。
> 所以服务不用暴露到 `0.0.0.0`。

如果用的是命令行版 Claude Code（`npm i -g @anthropic-ai/claude-code`），
那才有 `claude` 命令，可以用：

```bash
claude mcp add --transport http cachito http://127.0.0.1:8765/mcp
```

#### 手动启动（在 WSL 里）

```bash
sudo $PY -m cachito.mcp_server --transport streamable-http --port 8765
```

<details>
<summary>另一种：stdio 模式（需要配免密 sudo，注意安全代价）</summary>

stdio 模式由 MCP 客户端拉起进程，没法交互输密码，所以要配
`/etc/sudoers.d` 免密规则。

**安全代价要想清楚**：项目代码在 `/mnt/d/...`，那是 Windows 侧可写的。
给它配 NOPASSWD root，等于任何能改 `D:\Program\cachito` 的东西都能拿到
WSL 的 root。个人机器上通常可以接受，但你得知道这一点。

要用的话，把项目复制到 WSL 自己的文件系统里（比如 `~/cachito`）再配规则，
风险小很多。

</details>

MCP 工具一览：

| 工具 | 作用 |
|------|------|
| `get_status` | 各通道当前值、适配器状态、有无序列在跑 |
| `list_channels` | 有哪些通道、范围、哪些通道共包 |
| `set_channels(values, duration_seconds?)` | **主控制入口**，一次设一到多个通道 |
| `stop()` | 立刻全部停止 |
| `run_pattern(steps, repeat)` | 按「通道值 + 时长」序列跑节奏，后台执行 |
| `vibrate(intensity, duration_seconds?)` | 震动的便捷包装 |
| `trigger_packet(packet)` | 发无参数指令包 |
| `send_raw_command(payload_hex)` | 发任意 payload（逆向试探用） |
| `decode_command(uuid_or_hex)` | 解析指令并按模板还原通道值，不发射 |
| `get_setup_help()` | 没配好时返回排查步骤 |

`run_pattern` 的步骤长这样：

```json
[{"depth": 30, "speed_out": 2, "seconds": 5},
 {"depth": 60, "speed_out": 4, "seconds": 8},
 {"depth": 30, "speed_out": 2, "seconds": 5}]
```

---

## 安全设计

玩具是**锁存**语义：收到「震动 60」就一直转，不需要持续广播。
这意味着**进程崩了、网断了，玩具不会自己停**。所以：

- **看门狗**：距上一条指令超过 `safety.auto_stop_seconds`（默认 300 秒）
  自动补发停止。
- **退出兜底**：`atexit` + `SIGINT`/`SIGTERM` 补一条停止。
- **通道上限**：`safety.channel_limits` 夹住每个通道，MCP 也绕不过。
  **温度建议设上限**，例如 `{"temperature": 45}`。
- **序列时长上限**：`run_pattern` 单步最长 300 秒，总时长最长 1800 秒。

> **看门狗和退出兜底只对常驻进程（MCP server）生效。**
>
> 一次性的 CLI 命令（`set depth 40`）跑完就退出，**不会**补发停止 ——
> 玩具保持在你设定的状态，跟 App 的行为一致。
>
> 早期版本这里搞反了：CLI 退出时也补停止，结果玩具在一秒多后自己停下来
> （那个时长正好等于一次广播 burst）。`tests/test_control.py` 里
> `test_cli_exit_does_not_stop_the_toy` 就是防这个的回归测试。

都在 `device.json` 里可调。

---

## 目录

```
cachito/
  protocol.py    指令编解码 + 通用包模板
  hci.py         裸 HCI：独占控制器、收发广播
  config.py      device.json 读写（commands 包模板 / params 旧模型）
  wizard.py      引导式标定：一次只动一个控件      <- DX 走这条
  channels.py    分段差分分析 -> 通道绑定           <- DX 走这条
  sniff.py       自由抓包 CLI
  analyze.py     单动作模型的分析（Venus 那套）
  control.py     Controller + 控制 CLI
  mcp_server.py  MCP server
scripts/
  start-mcp.cmd     Windows：一键启动（透传 + 驱动 + MCP 服务器）
  stop-mcp.cmd      Windows：一键停止（停服务 + 停玩具 + 归还蓝牙）
  attach-bt.ps1     Windows：只做 usbipd bind/attach
  setup-wsl-bt.sh   WSL：modprobe + 自检
tests/
  test_protocol.py      协议自检（不需要硬件）
  make_fake_capture.py  假抓包（Venus 单动作模型）
  make_fake_wizard.py   假引导抓包（照真机结构复刻，验证通道分析）
captures/          抓包落盘
device.json        标定出来的配置
```

不接硬件验证整条通道分析链路：

```bash
$PY tests/make_fake_wizard.py /tmp/fw.jsonl
```

```bash
$PY -m cachito.channels /tmp/fw.jsonl
```

自检：

```bash
$PY tests/test_protocol.py
```

不接硬件跑通分析链路：

```bash
$PY tests/make_fake_capture.py /tmp/fake.jsonl
$PY -m cachito.analyze /tmp/fake.jsonl
```

---

## 排查

**`找不到 hci0`**
适配器没进 WSL。Windows 侧 `usbipd list` 看状态是不是 `Attached`；
WSL 里 `ls /sys/class/bluetooth/`。再检查 `sudo dmesg | tail -25`，
缺固件的话装 `linux-firmware`。

**`hci0 被占用` / EBUSY**
`sudo systemctl stop bluetooth`。本项目不需要 bluez。

**抓不到任何 Cachito 指令**
App 必须在**前台**。iOS 一退到后台就会把 Service UUID 挪进 Apple 的
overflow 区（Manufacturer Data 0x004C），那里的编码完全不同。
先用 `--all` 确认到底收到了些什么。

**能抓到、发出去玩具没反应**
- 配对 ID 对不对？（`device.json` 里的要和抓到的一致）
- 设备类型对不对？DX 应该是 `0x03`。
- 试试调 `broadcast.repeats` 和 `duration_s`（默认 3 次 × 0.35 秒）。
- 用另一台设备同时抓自己发的包，确认空中字节序没搞反。

**校验和命中率不是 100%**
分析器会自动试几种候选公式。如果最佳公式也不是 `sum(0..14)`，
说明 DX 的校验方式和 Venus 不同 —— 差分表里 offset 15 的表现能给线索。

---

## 出处

协议布局来自 [AmandaClarke61/toybridge](https://github.com/AmandaClarke61/toybridge)
对 Cachito Android APK 的逆向（`docs/protocol.md`）。那个项目是 macOS 专用的
（CoreBluetooth + pyobjc）；本项目为 Windows/WSL 重写了传输层，改用裸 HCI，
并补上了差分分析和安全兜底。
