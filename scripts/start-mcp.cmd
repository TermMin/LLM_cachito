@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM ===================================================================
REM  Cachito MCP 服务器 - 一键启动
REM
REM  用法:  start-mcp.cmd [BUSID] [端口]
REM         双击也行，全部走默认值。
REM
REM  不需要管理员，也不会弹 sudo 密码：
REM  WSL 允许 Windows 用户直接以 root 身份运行命令（wsl -u root），
REM  所以既不用配 NOPASSWD sudoers，也不用手动输密码。
REM  唯一需要管理员的是**首次** usbipd bind，脚本会提示你怎么做。
REM ===================================================================

title Cachito MCP

set "PORT=8765"
if not "%~2"=="" set "PORT=%~2"
if not "%CACHITO_PORT%"=="" set "PORT=%CACHITO_PORT%"

set "WSLPY=/home/tyd/miniconda3/envs/cachito/bin/python"
if not "%CACHITO_WSLPY%"=="" set "WSLPY=%CACHITO_WSLPY%"

echo ===================================================================
echo   Cachito MCP 服务器 - 启动
echo ===================================================================
echo.

REM ---------- 1. 项目路径 ----------
pushd "%~dp0.."
set "WINROOT=%CD%"
popd

set "WSLROOT="
for /f "delims=" %%p in ('wsl -e wslpath -a "%WINROOT%" 2^>nul') do set "WSLROOT=%%p"
if not defined WSLROOT (
    echo   [错误] 没法把项目路径转成 WSL 路径。
    echo          WSL 装好了吗？试试在 cmd 里跑: wsl -e echo ok
    goto :fail
)
echo   项目 : %WINROOT%
echo   WSL  : %WSLROOT%
echo   端口 : %PORT%
echo.

REM ---------- 2. 已经在跑就直接退出 ----------
wsl -u root -e pgrep -f "cachito.mcp_server" >nul 2>&1
if not errorlevel 1 (
    echo   MCP 服务器已经在运行了，不重复启动。
    goto :ready
)

REM ---------- 3. 蓝牙透传 ----------
where usbipd >nul 2>&1
if errorlevel 1 (
    echo   [错误] 没找到 usbipd。用管理员 PowerShell 装一次:
    echo          winget install --exact --id dorssel.usbipd-win
    echo          装完要重开终端。
    goto :fail
)

set "BUSID=%~1"
if not defined BUSID (
    for /f "tokens=1" %%i in ('usbipd list 2^>nul ^| findstr /i /c:"Bluetooth"') do (
        if not defined BUSID set "BUSID=%%i"
    )
)
if not defined BUSID (
    echo   [错误] usbipd list 里没找到蓝牙设备。
    echo          手动指定: start-mcp.cmd 1-14
    echo.
    usbipd list
    goto :fail
)

set "BTLINE="
for /f "delims=" %%l in ('usbipd list 2^>nul ^| findstr /b /c:"%BUSID% "') do set "BTLINE=%%l"

echo   蓝牙 : BUSID %BUSID%
echo !BTLINE! | findstr /i /c:"Attached" >nul
if not errorlevel 1 (
    echo          已经透传给 WSL 了
    goto :modprobe
)

echo !BTLINE! | findstr /i /c:"Not shared" >nul
if not errorlevel 1 (
    echo.
    echo   [需要管理员] 这个设备还没 bind 过。用**管理员** PowerShell 跑一次:
    echo.
    echo          usbipd bind --busid %BUSID%
    echo.
    echo   bind 只需做一次，之后本脚本就不再需要管理员了。
    goto :fail
)

echo          正在透传给 WSL... （Windows 会暂时失去蓝牙）
usbipd attach --wsl --busid %BUSID%
if errorlevel 1 (
    echo   [错误] usbipd attach 失败。
    goto :fail
)

:modprobe
REM ---------- 4. 驱动 + 适配器 ----------
wsl -u root -e modprobe btusb >nul 2>&1

set "HCIOK="
for /L %%i in (1,1,12) do (
    if not defined HCIOK (
        wsl -u root -e test -e /sys/class/bluetooth/hci0 >nul 2>&1
        if not errorlevel 1 (
            set "HCIOK=1"
        ) else (
            ping -n 2 127.0.0.1 >nul
        )
    )
)
if not defined HCIOK (
    echo   [错误] hci0 没出现。看看内核日志:
    echo          wsl -u root -e dmesg ^| tail -25
    echo          常见原因是缺 Intel 固件:
    echo          wsl -u root -e apt install -y linux-firmware
    goto :fail
)
echo   适配器: hci0 就绪
echo.

REM ---------- 5. 启动服务器 ----------
echo   正在启动 MCP 服务器...
start "Cachito MCP Server" wsl.exe --cd "%WSLROOT%" -u root -- "%WSLPY%" -m cachito.mcp_server --transport streamable-http --port %PORT%

set "UP="
for /L %%i in (1,1,15) do (
    if not defined UP (
        ping -n 2 127.0.0.1 >nul
        wsl -u root -e pgrep -f "cachito.mcp_server" >nul 2>&1
        if not errorlevel 1 set "UP=1"
    )
)
if not defined UP (
    echo   [错误] 服务器没起来。看那个新开的窗口里的报错。
    goto :fail
)

:ready
echo.
echo ===================================================================
echo   已就绪:  http://127.0.0.1:%PORT%/mcp
echo ===================================================================
echo.
echo   Claude Code 连接（只需配一次，桌面版没有 claude CLI）:
echo       在 %USERPROFILE%\.claude.json 或项目根 .mcp.json 的 mcpServers 里加:
echo           "cachito": { "type": "http", "url": "http://127.0.0.1:%PORT%/mcp" }
echo       配好后需要**重启 Claude Code** 才会连上本服务器。
echo.
echo   停止服务器并把蓝牙还给 Windows:
echo.
echo       scripts\stop-mcp.cmd
echo.
if "%~1"=="" if "%CACHITO_NOPAUSE%"=="" pause
exit /b 0

:fail
echo.
echo   启动失败。
echo.
if "%CACHITO_NOPAUSE%"=="" pause
exit /b 1
