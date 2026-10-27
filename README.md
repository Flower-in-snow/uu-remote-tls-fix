# UU Remote TLS Fix — 校园网 UU 远程 TLS 握手阻断一键修复工具

<p align="left">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0078D6?logo=windows" alt="Windows 10/11" />
  <img src="https://img.shields.io/badge/Dependencies-Zero%20(Built--in%20.NET)-2EA44F" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/Mode-100%25%20Local%20Direct-008080" alt="Local Direct" />
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License" />
</p>

---

## ⚠️ 本仓库是 fork：已修复 bat 无法启动的问题

| | |
|---|---|
| 上游项目 | [yunyancuo/uu-remote-tls-fix](https://github.com/yunyancuo/uu-remote-tls-fix) |
| 问题反馈 | [👉 原 issue：bat 首行乱码 + 修复脚本无限弹窗](<ISSUE_URL>) |
| 本 fork 用途 | 修复下述 bat 启动问题，其余功能与上游一致 |

### 问题现象

在上游当前版本中，双击运行两个 `.bat` 均不正常：

| 文件 | 现象 |
| --- | --- |
| `一键卸载恢复.bat` | 第一行输出一行乱码报错，之后仍能正常完成卸载 |
| `一键修复UU远程.bat` | 第一行乱码后**持续弹出新的 cmd 窗口**，不按 Ctrl+C 就停不下来，修复流程从未真正启动 |

### 根本原因

两个 bat 原先是 **UTF-8 无 BOM + 纯 LF（`\n`）换行**，而脚本第 2 行是 `chcp 65001` 切换代码页。

cmd.exe 逐行解析批处理文件，`chcp` 切换代码页后，后续内容会按新代码页重新换算字节偏移；LF 换行叠加中文多字节字符导致**行被从中间截断**：

- **卸载脚本**：截断产生的碎片被当作命令执行 → 只多出一行乱码，之后各行恰好又对齐 → 能跑完；
- **修复脚本**：截断点正好落在 `if %errorlevel% neq 0 (` 的括号块内 → 块结构被破坏、`exit /b` 未生效 → 提权分支被反复执行 `Start-Process -FilePath '%~f0'` → **无限弹窗**。

### 本仓库的修复内容

1. **两个 bat 统一转为 CRLF 换行**（编码仍为 UTF-8 无 BOM，`chcp 65001` 保留），并新增 `.gitattributes`（`*.bat -text`）让 CRLF 原样入库，保证 GitHub「Download ZIP」下载到的也是 CRLF；
2. **移除 `if (...)` 括号块，改用 `goto` 标签**，绕过 cmd 对「括号块 + 切代码页」的解析缺陷；
3. **加入防重复提权保护**：提权后的子进程携带 `--elevated` 参数，若仍非管理员则明确报错退出，不再自我复制弹窗；
4. UAC 被取消时给出提示并正常退出，而不是静默进入循环；
5. 顺带在提权判断上保留 `net session`，如需更稳妥可换成 `fltmc`（不依赖 Server 服务，见原 issue 讨论）。

### 使用方式

与上游完全一致：解压后直接双击 **`一键修复UU远程.bat`**，在弹出的 UAC 提示中点「是」即可；卸载双击 `一键卸载恢复.bat`。

> 已在 Windows 11（build 26100，活动代码页 936）实测：两个 bat 输出全中文正常、无乱码行，提权后不再重复弹窗。
>
> 若上游作者愿意接受，此修复也欢迎以 PR 形式回馈上游。

---

针对部分高校校园网或局域网防火墙对网易 UU 远程（`GameViewer`）控制与信令域名 `*.nrd.nie.163.com` 的 TLS `ClientHello`（SNI）握手异常拦截问题，提供一套 **纯本地运行、免安装 Python、一行命令 / 双击即用** 的 TLS Record 分片直连修复工具。

---

## ⚡ 3 秒极简使用（任选其一）

### 方式一：PowerShell 一行命令在线一键修复（推荐，无需下载压缩包）

按下 `Win + X`，打开 **终端** 或 **Windows PowerShell**，复制粘贴以下任意一行命令并回车即可自动完成编译、启动、开机自启与 6 项握手测速：

- **国内镜像加速通道（校园网可直接拉取）**：
  ```powershell
  irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/install.ps1 | iex
  ```
- **GitHub 官方通道**：
  ```powershell
  irm https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/install.ps1 | iex
  ```

### 方式二：下载压缩包双击一键修复

1. 点击本仓库右上角 `Code` -> `Download ZIP` 并解压；
2. 直接双击运行 **`一键修复UU远程.bat`** 即可自动完成部署并展示全部核心端点的握手延迟。

### 一键卸载与恢复出厂默认

- **在线一行命令卸载**：
  ```powershell
  irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/uninstall.ps1 | iex
  ```
- **本地双击卸载**：直接双击 **`一键卸载恢复.bat`**。

---

## 🔍 问题根因分析

部分校园网出口网关设备会对出站 TCP 连接的首个 TLS `ClientHello` 握手包进行协议特征检测。当检测到明文 SNI 扩展为 `*.nrd.nie.163.com`（包括控制接口 `api.nrd.nie.163.com`、灾备接口 `api-dcdn.nrd.nie.163.com`、事件上报 `api-event.nrd.nie.163.com`、设备唤醒 `api-ipv4.nrd.nie.163.com`、WebSocket 信令 `sig-*.nrd.nie.163.com` 以及媒体中继 `relay-mg-*.nrd.nie.163.com`）时，网关会丢弃该握手包导致连接超时。

实测验证：向同一台网易服务器 IP `117.148.172.102:443` 发起连接时，使用 `uuyc.webapp.163.com` 作为 SNI 仅需 50ms 即可返回 `200 OK`，而使用 `api-dcdn.nrd.nie.163.com` 作为 SNI 则 100% 发生 TLS 握手超时。

---

## 🛠️ 工作原理（纯本机回环闭环 + 物理网卡直连）

```text
┌───────────────────────────────────────────────────────────────────────────┐
│  UU 远程客户端 (GameViewer.exe) / 后台被控服务 (GameViewerServer.exe)       │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │ 读取官方内置配置:
                                      │ C:\ProgramData\Netease\GameViewer\proxy_config.ini
                                      │ (通过 Windows 本机回环 127.0.0.1 发往端口 17899)
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  本机无窗口守护进程: UUTlsFragmenter.exe (127.0.0.1:17899 & 443, 仅 24 KB) │
│  1. 双帧标准 TLS Record 切分: 对 *.nrd.nie.163.com 的首包 TLS ClientHello  │
│     在 SNI 字段中间切分为 2 个符合 RFC 规范的 TLS Record 帧                │
│  2. 网关智能优选: 通过阿里公共 DoH (223.5.5.5) 解析支持分片重组的官方网关  │
│  3. 降级自愈: 自动将已降级的 80 端口明文请求透明升级为 443 加密 TLS 通道   │
│  4. 物理网卡直连: 出站 Socket 直接绑定本机物理网卡 (以太网/WLAN) 发出      │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │ 校园网物理网卡直连
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  网易 UU 远程官方服务器 (杭州 BGP 112.13.123.98 / DCDN / APISIX 信令网关)  │
└───────────────────────────────────────────────────────────────────────────┘
```

### 核心特性

- **零外部依赖，免安装 Python**：利用每台 Windows 10/11 系统自带的 `.NET Framework csc.exe` 在本地即时编译出仅 **24 KB** 的原生无窗口程序 `%LOCALAPPDATA%\UURemoteTlsFix\UUTlsFragmenter.exe`，无需安装任何开发环境或第三方软件即可直接运行。
- **符合 TLS 协议规范的双帧切分**：依据 TLS 记录层标准（RFC 5246 / RFC 8446），将单个握手消息拆分为两个连续的 TLS Record 帧发送，既解决了网关设备对单帧 SNI 的误拦截，又使远端服务器能够标准重组并完成握手。
- **开机无感自启**：自动注册当前用户 `HKCU\...\Run\UURemoteTLSFragmenter`，随系统登录无窗口静默运行（内存占用 < 5 MB）。

---

## 📁 项目结构

```text
uu-remote-tls-fix/
├── install.ps1                # 一键安装/修复主脚本（内嵌 C# 源码，支持 irm ... | iex 在线执行）
├── uninstall.ps1              # 一键卸载与恢复出厂默认脚本（支持 irm ... | iex 在线执行）
├── 一键修复UU远程.bat          # Windows 双击一键安装/修复启动器
├── 一键卸载恢复.bat            # Windows 双击一键卸载并恢复默认设置
├── src/
│   └── UUTlsFragmenter.cs     # 零依赖原生 C#/.NET 本地 TLS Record 分片服务独立源码
├── LICENSE                    # MIT 开源许可证
├── .gitignore                 # Git 忽略规则配置
└── README.md                  # 项目说明文档
```

---

## 📊 覆盖的 UU 远程端点与实测表现

脚本部署最后一步会自动对以下 6 个核心端点执行端到端 TLS 握手测速：

| 域名端点 | 作用 | 修复前状态 | 修复后状态（本机直连） |
| :--- | :--- | :---: | :---: |
| `api.nrd.nie.163.com` | 核心控制与房间 API | ❌ TLS 握手超时 | ✅ 握手成功 (`~70–110 ms`) |
| `api-dcdn.nrd.nie.163.com` | DCDN 灾备控制 API | ❌ TLS 握手超时 | ✅ 握手成功 (`~90–120 ms`) |
| `api-event.nrd.nie.163.com` | 客户端事件上报 API | ❌ TLS 握手超时 | ✅ 握手成功 (`~60–80 ms`) |
| `api-ipv4.nrd.nie.163.com` | IPv4 远程唤醒与初始化 | ❌ TLS 握手超时 | ✅ 握手成功 (`~65–80 ms`) |
| `sig-3303-d.nrd.nie.163.com` | WebSocket 远程控制信令 | ❌ TLS 握手超时 | ✅ 握手成功 (`~300–600 ms`) |
| `relay-mg-3303-d.nrd.nie.163.com` | TURN/TLS 桌面画面流中继 | ❌ TLS 握手超时 | ✅ 握手成功 (`~30–50 ms`) |

---

## ❓ 常见问题 (FAQ)

1. **运行脚本需要提前安装 Python 或 Git 吗？**
   不需要。脚本调用的是 Windows 10/11 系统出厂自带的 PowerShell 与 `.NET Framework`，零第三方依赖。
2. **重启电脑后还需要重新运行脚本吗？**
   不需要。脚本已将 `%LOCALAPPDATA%\UURemoteTlsFix\UUTlsFragmenter.exe` 注册到当前用户的开机自启项中，随系统登录无窗口静默运行。
3. **如何彻底卸载并恢复 UU 远程默认设置？**
   双击运行 `一键卸载恢复.bat` 或在 PowerShell 中执行在线卸载命令即可停止服务、删除自启项并将 `proxy_config.ini` 还原为默认状态。

---

## 📄 License

本项目基于 [MIT License](./LICENSE) 开源。
