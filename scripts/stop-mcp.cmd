@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM ===================================================================
REM  Cachito MCP 服务器 - 一键停止
REM
REM  用法:  stop-mcp.cmd [/keepbt]
REM         默认会把蓝牙还给 Windows；加 /keepbt 则保持透传在 WSL
REM         （下次启动更快）。
REM
REM  停止顺序是有讲究的：
REM    1. 先 SIGTERM 服务器 —— 它的退出钩子会给玩具补一条停止指令
REM    2. 等它真的退出，把 hci0 让出来（服务器是**独占**占用适配器的，
REM       它还活着的时候别的进程根本打不开 hci0）
REM    3. 再补一次 control stop 兜底
REM    4. 最后 detach 蓝牙
REM ===================================================================

title Cachito MCP - 停止

echo ===================================================================
echo   Cachito MCP 服务器 - 停止
echo ===================================================================
echo.

pushd "%~dp0.."
set "WINROOT=%CD%"
popd
set "WSLROOT="
for /f "delims=" %%p in ('wsl -e wslpath -a "%WINROOT%" 2^>nul') do set "WSLROOT=%%p"

set "WSLPY=/home/tyd/miniconda3/envs/cachito/bin/python"
if not "%CACHITO_WSLPY%"=="" set "WSLPY=%CACHITO_WSLPY%"

REM ---------- 1. 停服务器 ----------
wsl -u root -e pgrep -f "cachito.mcp_server" >nul 2>&1
if errorlevel 1 (
    echo   服务器本来就没在跑。
    goto :toystop
)

echo   正在停止服务器（它会先给玩具补一条停止指令）...
wsl -u root -e pkill -TERM -f "cachito.mcp_server" >nul 2>&1

set "GONE="
for /L %%i in (1,1,10) do (
    if not defined GONE (
        ping -n 2 127.0.0.1 >nul
        wsl -u root -e pgrep -f "cachito.mcp_server" >nul 2>&1
        if errorlevel 1 set "GONE=1"
    )
)

if not defined GONE (
    echo   优雅退出超时，强制结束。
    wsl -u root -e pkill -KILL -f "cachito.mcp_server" >nul 2>&1
    ping -n 3 127.0.0.1 >nul
)
echo   服务器已停止。

:toystop
REM ---------- 2. 兜底：再给玩具发一次停止 ----------
REM 服务器已经退出，hci0 空出来了，这时才能打开适配器。
if defined WSLROOT (
    wsl -u root -e test -e /sys/class/bluetooth/hci0 >nul 2>&1
    if not errorlevel 1 (
        echo   正在给玩具补发停止指令...
        wsl --cd "%WSLROOT%" -u root -- "%WSLPY%" -m cachito.control stop >nul 2>&1
        if errorlevel 1 (
            echo   [提示] 兜底停止没发成功 —— 服务器退出时通常已经发过一次了。
        ) else (
            echo   玩具已停止。
        )
    )
)

REM ---------- 3. 蓝牙还给 Windows ----------
if /i "%~1"=="/keepbt" (
    echo   蓝牙保持透传在 WSL（下次启动更快）。
    goto :done
)

where usbipd >nul 2>&1
if errorlevel 1 goto :done

set "BUSID="
for /f "tokens=1" %%i in ('usbipd list 2^>nul ^| findstr /i /c:"Bluetooth"') do (
    if not defined BUSID set "BUSID=%%i"
)
if not defined BUSID goto :done

set "BTLINE="
for /f "delims=" %%l in ('usbipd list 2^>nul ^| findstr /b /c:"%BUSID% "') do set "BTLINE=%%l"
echo !BTLINE! | findstr /i /c:"Attached" >nul
if errorlevel 1 (
    echo   蓝牙本来就不在 WSL 手里。
    goto :done
)

echo   正在把蓝牙还给 Windows（BUSID %BUSID%）...
usbipd detach --busid %BUSID%
if errorlevel 1 (
    echo   [提示] detach 失败，可以手动跑: usbipd detach --busid %BUSID%
) else (
    echo   已归还，Windows 蓝牙几秒内恢复。
)

:done
echo.
echo ===================================================================
echo   完成。
echo ===================================================================
echo.
if "%CACHITO_NOPAUSE%"=="" pause
exit /b 0
