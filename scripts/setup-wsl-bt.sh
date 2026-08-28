#!/usr/bin/env bash
# 在 WSL 里把透传进来的蓝牙适配器拉起来。
#
#   bash scripts/setup-wsl-bt.sh
#
# 前提：已经在 Windows 侧跑过 scripts/attach-bt.ps1。

set -u

say()  { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  OK  %s\033[0m\n' "$*"; }
bad()  { printf '\033[31m  !!  %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ..  %s\033[0m\n' "$*"; }

say "== 1. 内核有没有蓝牙支持 =="
if [ -f /proc/config.gz ] && zcat /proc/config.gz | grep -q '^CONFIG_BT=[my]'; then
    ok "内核带蓝牙 ($(zcat /proc/config.gz | grep -m1 '^CONFIG_BT='))"
elif find /lib/modules -name 'bluetooth.ko*' 2>/dev/null | grep -q .; then
    ok "找到 bluetooth 模块文件"
else
    bad "这个 WSL 内核没有蓝牙支持，需要自己编内核。"
    bad "先 'wsl --update' 升到较新的内核再试。"
    exit 1
fi

say ""
say "== 2. USB 设备有没有透传进来 =="
if command -v lsusb >/dev/null 2>&1; then
    if lsusb | grep -qi 'bluetooth\|8087:'; then
        ok "$(lsusb | grep -i 'bluetooth\|8087:' | head -1)"
    else
        warn "lsusb 里没看到蓝牙 —— 可能只是描述符没有 'Bluetooth' 字样，继续"
    fi
else
    warn "没装 lsusb（sudo apt install usbutils），跳过这步检查"
fi

say ""
say "== 3. 加载 btusb 驱动 =="
if ! lsmod | grep -q '^btusb'; then
    sudo modprobe btusb 2>&1 && ok "btusb 已加载" || { bad "modprobe btusb 失败"; exit 1; }
else
    ok "btusb 已经加载着"
fi

say ""
say "== 4. 适配器有没有出现 =="
for i in $(seq 1 10); do
    if [ -d /sys/class/bluetooth ] && ls /sys/class/bluetooth/hci* >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

if ls /sys/class/bluetooth/hci* >/dev/null 2>&1; then
    for d in /sys/class/bluetooth/hci*; do
        ok "$(basename "$d")  地址 $(cat "$d/address" 2>/dev/null || echo '?')"
    done
else
    bad "还是没有 hci 设备。最近的内核日志："
    sudo dmesg | tail -25
    echo
    bad "常见原因：缺 Intel 蓝牙固件。装一下："
    bad "    sudo apt update && sudo apt install -y linux-firmware"
    bad "然后在 Windows 侧 detach + attach 一次，再重跑本脚本。"
    exit 1
fi

say ""
say "== 5. bluetoothd 会不会来抢 =="
if systemctl is-active --quiet bluetooth 2>/dev/null; then
    warn "bluetoothd 正在跑。本项目用 HCI_CHANNEL_USER 独占控制器，"
    warn "通常能抢过来，但保险起见可以先停掉："
    warn "    sudo systemctl stop bluetooth"
else
    ok "bluetoothd 没在跑（本项目也不需要 bluez）"
fi

say ""
say "== 就绪 =="
echo "接下来："
echo "    sudo \$(which python) -m cachito.sniff --seconds 60"
echo "抓的时候 iPhone 上要**前台**打开 Cachito App 并实际操作。"
