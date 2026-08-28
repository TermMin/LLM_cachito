<#
.SYNOPSIS
    把蓝牙适配器透传进 WSL（usbipd-win）。

.DESCRIPTION
    Windows 的 WinRT 不允许应用广播 AD Type 0x07（128-bit Service UUID
    列表），而 Cachito 的指令恰恰编码在那里 —— 所以必须把蓝牙交给
    WSL，用裸 HCI 发。这个脚本负责把 USB 蓝牙设备 bind + attach 过去。

    注意：透传期间 **Windows 会失去蓝牙**（蓝牙耳机/鼠标会断）。
    用 -Detach 可以还回去。

.EXAMPLE
    # 管理员 PowerShell
    .\scripts\attach-bt.ps1

.EXAMPLE
    .\scripts\attach-bt.ps1 -Detach      # 把蓝牙还给 Windows

.EXAMPLE
    .\scripts\attach-bt.ps1 -BusId 1-14  # 手动指定
#>
[CmdletBinding()]
param(
    [string]$BusId,
    [switch]$Detach,
    [string]$Distribution
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---- 1. usbipd 是否就绪 ----
if (-not (Get-Command usbipd -ErrorAction SilentlyContinue)) {
    Write-Host "没找到 usbipd。先安装（管理员 PowerShell）：" -ForegroundColor Yellow
    Write-Host "    winget install --interactive --exact dorssel.usbipd-win"
    Write-Host ""
    Write-Host "装完请**重开** PowerShell 再跑本脚本。"
    exit 1
}

# ---- 2. 找到蓝牙的 BUSID ----
$listing = usbipd list
if (-not $BusId) {
    $match = $listing | Select-String -Pattern '^\s*(\d+-\d+)\s+(\w{4}:\w{4})\s+(.*?)\s{2,}(.*)$' |
        Where-Object { $_.Matches[0].Groups[3].Value -match 'Bluetooth' } |
        Select-Object -First 1
    if (-not $match) {
        Write-Host "在 usbipd list 里没找到蓝牙设备：" -ForegroundColor Red
        $listing
        Write-Host ""
        Write-Host "用 -BusId 手动指定，例如： .\scripts\attach-bt.ps1 -BusId 1-14"
        exit 1
    }
    $BusId = $match.Matches[0].Groups[1].Value
    $devName = $match.Matches[0].Groups[3].Value
    Write-Host ("找到蓝牙设备: {0}  (BUSID {1})" -f $devName, $BusId) -ForegroundColor Cyan
}

# ---- 3. detach ----
if ($Detach) {
    Write-Host "把 BUSID $BusId 还给 Windows ..."
    usbipd detach --busid $BusId
    Write-Host "已 detach。Windows 蓝牙应当在几秒内恢复。" -ForegroundColor Green
    Write-Host "（如果想彻底解除共享： usbipd unbind --busid $BusId）"
    exit 0
}

# ---- 4. bind（首次需要，要管理员） ----
$state = ($listing | Select-String -Pattern ("^\s*" + [regex]::Escape($BusId) + "\s")).Line
if ($state -match 'Not shared') {
    if (-not (Test-Admin)) {
        Write-Host "首次 bind 需要管理员权限。请用管理员 PowerShell 重跑本脚本。" -ForegroundColor Yellow
        Write-Host "（bind 只需做一次，之后 attach 就不用管理员了）"
        exit 1
    }
    Write-Host "bind BUSID $BusId （只需一次）..."
    usbipd bind --busid $BusId
}

# ---- 5. attach ----
Write-Host ""
Write-Host "注意：接下来 Windows 会暂时失去蓝牙。" -ForegroundColor Yellow
Write-Host ""
$attachArgs = @('attach', '--wsl', '--busid', $BusId)
if ($Distribution) { $attachArgs += @('--distribution', $Distribution) }
usbipd @attachArgs

Write-Host ""
Write-Host "已 attach。接下来在 WSL 里：" -ForegroundColor Green
Write-Host "    bash scripts/setup-wsl-bt.sh"
Write-Host ""
Write-Host "用完还给 Windows： .\scripts\attach-bt.ps1 -Detach"
