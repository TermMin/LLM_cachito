"""Cachito 玩具的 BLE 广播控制 + MCP 桥接。

模块一览：

    protocol    指令编解码（16 字节 payload <-> 128-bit Service UUID）
    hci         裸 HCI 传输层（Linux/WSL2，独占控制器，收发广播）
    config      device.json 读写
    sniff       抓包 CLI
    analyze     抓包分析 + 生成配置
    control     控制器 + CLI
    mcp_server  MCP server
"""

__version__ = "0.1.0"
