#Requires -Version 5.1
<#
.SYNOPSIS
    网易 UU 远程 (GameViewer) 校园网 TLS 握手阻断修复工具 — 一键卸载与恢复默认脚本
.DESCRIPTION
    支持一行 PowerShell 命令在线卸载或本地运行：
      irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/uninstall.ps1 | iex
#>

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Ok([string]$msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }

$isAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$installDir   = Join-Path $env:LOCALAPPDATA "UURemoteTlsFix"
$runKey       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$uuDataDir    = Join-Path $env:ProgramData "Netease\GameViewer"
$proxyIniPath = Join-Path $uuDataDir "proxy_config.ini"
$hostsPath    = Join-Path $env:WINDIR "System32\drivers\etc\hosts"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         正在卸载 UU 远程校园网 TLS 破阻断服务并恢复默认配置          " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. 停止后台进程并移除自启
Stop-Process -Name "UUTlsFragmenter" -Force -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'python' -and $_.CommandLine -match 'uu_tls_fragmenter'
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-ItemProperty -Path $runKey -Name "UURemoteTLSFragmenter" -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
if (Test-Path $installDir) {
    Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Ok "已停止后台分片服务并移除开机自启项与安装目录"

# 2. 恢复 UU 远程原生 proxy_config.ini 为无代理状态
if (Test-Path $proxyIniPath) {
    $resetIni = "[Proxy]`nsettingType=0`ntype=0`nhost=`nport=0`nusername=`nbypass=`npassword=`n"
    [System.IO.File]::WriteAllText($proxyIniPath, $resetIni, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok "已将 UU 远程 proxy_config.ini 恢复为默认无代理状态 (settingType=0)"
}

# 3. 清理系统 hosts (若为管理员)
if ($isAdmin -and (Test-Path $hostsPath)) {
    $hLines = Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object {
        $_ -notmatch 'UU_REMOTE_TLS_FIX' -and $_ -notmatch 'nrd\.nie\.163\.com'
    }
    [System.IO.File]::WriteAllLines($hostsPath, $hLines, (New-Object System.Text.UTF8Encoding($false)))
    & ipconfig.exe /flushdns | Out-Null
    Write-Ok "已清理系统 hosts 映射条目"
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " 卸载完成！UU 远程已恢复出厂默认网络设置。" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
