@echo off
chcp 65001 >nul
title 校园网 UU远程 TLS 握手阻断一键修复工具

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] 正在请求管理员权限以完成全自动修复...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
echo.
pause
