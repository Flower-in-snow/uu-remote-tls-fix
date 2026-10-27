@echo off
chcp 65001 >nul 2>&1
title 校园网 UU远程 TLS 握手阻断一键修复工具

rem ============ 管理员权限检查（带防重复提权保护，避免无限弹窗） ============
net session >nul 2>&1
if %errorlevel% equ 0 goto Run
if /i "%~1"=="--elevated" goto NoAdmin

echo [*] 正在请求管理员权限以完成全自动修复...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '--elevated' -Verb RunAs"
if errorlevel 1 goto ElevateFailed
exit /b

:ElevateFailed
echo [X] 已取消管理员权限请求，修复未执行。
pause
exit /b 1

:NoAdmin
echo [X] 未能获得管理员权限，修复未执行。
echo     请右键本文件，选择“以管理员身份运行”。
pause
exit /b 1

:Run
echo [*] 正在执行修复脚本，请稍候...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
echo.
pause
exit /b 0