#Requires -Version 5.1
<#
.SYNOPSIS
    某高校校园网 UU 远程 (GameViewer) TLS 握手阻断一键修复脚本（纯本地直连 · 免安装 Python）
.DESCRIPTION
    解决部分校园网出口网关阻断 *.nrd.nie.163.com TLS ClientHello (SNI) 握手的问题：
    1. 免 Python / 免第三方软件：调用 Windows 10/11 系统自带 .NET 编译器生成 24KB 原生无窗口分片守护程序 UUTlsFragmenter.exe (127.0.0.1:17899 & 443)；
    2. 原生对接 UU 远程：自动配置 UU 远程官方内置配置文件 (C:\ProgramData\Netease\GameViewer\proxy_config.ini)，
       让 UU 远程通过本机回环 (127.0.0.1:17899) 将请求交由 UUTlsFragmenter.exe 在本地将 TLS SNI 切分为 2 个标准 Record 帧后，
       直接绑定本机物理网卡 (以太网/WLAN) 发出；
    3. 自动注册当前用户开机无窗口静默自启，并对全部 6 个核心域名执行端到端 TLS 握手测速。
#>

param(
    [switch]$SkipRestartClient,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Step([string]$msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host "  [X] $msg" -ForegroundColor Red }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$installDir   = Join-Path $env:LOCALAPPDATA "UURemoteTlsFix"
$exePath      = Join-Path $installDir "UUTlsFragmenter.exe"
$csPath       = Join-Path $installDir "UUTlsFragmenter.cs"
$runKey       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$uuDataDir    = Join-Path $env:ProgramData "Netease\GameViewer"
$proxyIniPath = Join-Path $uuDataDir "proxy_config.ini"
$hostsPath    = Join-Path $env:WINDIR "System32\drivers\etc\hosts"

if ($Uninstall) {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "         正在卸载 UU 远程校园网 TLS 破阻断服务并恢复默认配置          " -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan

    Stop-Process -Name "UUTlsFragmenter" -Force -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'python' -and $_.CommandLine -match 'uu_tls_fragmenter'
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Remove-ItemProperty -Path $runKey -Name "UURemoteTLSFragmenter" -ErrorAction SilentlyContinue
    Write-Ok "已停止后台分片服务并移除开机自启项"

    if (Test-Path $proxyIniPath) {
        $resetIni = "[Proxy]`nsettingType=0`ntype=0`nhost=`nport=0`nusername=`nbypass=`npassword=`n"
        [System.IO.File]::WriteAllText($proxyIniPath, $resetIni, (New-Object System.Text.UTF8Encoding($false)))
        Write-Ok "已将 UU 远程 proxy_config.ini 恢复为默认无代理状态 (settingType=0)"
    }

    if ($isAdmin -and (Test-Path $hostsPath)) {
        $hLines = Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object {
            $_ -notmatch 'UU_REMOTE_TLS_FIX' -and $_ -notmatch 'nrd\.nie\.163\.com'
        }
        [System.IO.File]::WriteAllLines($hostsPath, $hLines, (New-Object System.Text.UTF8Encoding($false)))
        & ipconfig.exe /flushdns | Out-Null
        Write-Ok "已清理系统 hosts 映射条目"
    }

    Write-Host "`n[OK] 卸载并恢复完成！" -ForegroundColor Green
    return
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "    UU 远程校园网 TLS 握手阻断一键修复工具 (纯本地直连 · 免 Python)   " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ("当前权限状态: " + ($(if ($isAdmin) { "管理员 (支持完整重启 GameViewerService 后台服务与 Hosts 双保险)" } else { "普通用户 (支持本地分片服务 + UU 远程原生配置直连)" })))

# ----------------------------------------------------------------------
# 步骤 1/4: 使用系统内置 .NET 编译零依赖原生守护进程 UUTlsFragmenter.exe
# ----------------------------------------------------------------------
Write-Step "步骤 1/4: 编译并启动零依赖原生 TLS 分片守护程序 (UUTlsFragmenter.exe)"

New-Item -ItemType Directory -Path $installDir -Force | Out-Null

Stop-Process -Name "UUTlsFragmenter" -Force -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'python' -and $_.CommandLine -match 'uu_tls_fragmenter'
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 300

$csSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UURemoteTlsFix
{
    internal sealed class FragmentedFirstWriteStream : Stream
    {
        private readonly Stream _inner;
        private bool _firstWrite = true;

        public FragmentedFirstWriteStream(Stream inner) { _inner = inner; }
        public override bool CanRead { get { return _inner.CanRead; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return _inner.CanWrite; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { _inner.Flush(); }
        public override int Read(byte[] buffer, int offset, int count) { return _inner.Read(buffer, offset, count); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_firstWrite && count > 0)
            {
                _firstWrite = false;
                byte[] slice = new byte[count];
                Buffer.BlockCopy(buffer, offset, slice, 0, count);
                byte[] frag = Program.FragmentTlsClientHello(slice, count);
                _inner.Write(frag, 0, frag.Length);
            }
            else
            {
                _inner.Write(buffer, offset, count);
            }
        }
    }

    internal static class Program
    {
        private static readonly int MainPort = 17899;
        private static readonly int TransparentTlsPort = 443;
        private static string LogPath;
        private static readonly object LogLock = new object();

        private static IPAddress _cachedPhysIp = null;
        private static DateTime _cachedPhysIpTime = DateTime.MinValue;
        private static readonly ConcurrentDictionary<string, Tuple<string, DateTime>> DnsCache =
            new ConcurrentDictionary<string, Tuple<string, DateTime>>();

        private static readonly Dictionary<string, string> FallbackHostIps =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "api.nrd.nie.163.com", "112.13.123.98" },
                { "api-ipv4.nrd.nie.163.com", "112.13.123.98" },
                { "api-dcdn.nrd.nie.163.com", "117.148.172.102" },
                { "api-event.nrd.nie.163.com", "117.147.201.23" },
                { "sig-3303-d.nrd.nie.163.com", "34.95.122.33" },
                { "relay-mg-3303-d.nrd.nie.163.com", "117.147.201.40" },
                { "uuyc.163.com", "59.111.44.89" },
                { "uuyc.webapp.163.com", "117.148.172.102" },
                { "nrd-ugc.fp.ps.netease.com", "111.3.79.64" }
            };

        [STAThread]
        public static void Main(string[] args)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            LogPath = Path.Combine(baseDir, "uu_tls_fragmenter.log");

            bool createdNew;
            using (Mutex mutex = new Mutex(true, @"Local\UURemoteTlsFragmenterNativeMutex", out createdNew))
            {
                if (!createdNew) return;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)3072;
                NetworkChange.NetworkAddressChanged += (s, e) => { _cachedPhysIp = null; };
                NetworkChange.NetworkAvailabilityChanged += (s, e) => { _cachedPhysIp = null; };
                Log("Starting UUTlsFragmenter Standalone Native Service (0.0.0.0:17899 & 127.0.0.1:443)");
                Task t1 = StartListenerAsync(IPAddress.Any, MainPort);
                Task t2 = StartListenerAsync(IPAddress.Loopback, TransparentTlsPort);
                Task.WaitAll(t1, t2);
            }
        }

        private static void Log(string msg)
        {
            try
            {
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " [INFO] " + msg + Environment.NewLine;
                lock (LogLock)
                {
                    FileInfo fi = new FileInfo(LogPath);
                    if (fi.Exists && fi.Length > 2 * 1024 * 1024)
                        File.WriteAllText(LogPath, line, Encoding.UTF8);
                    else
                        File.AppendAllText(LogPath, line, Encoding.UTF8);
                }
            }
            catch { }
        }

        private static async Task StartListenerAsync(IPAddress bindAddr, int port)
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(bindAddr, port);
                listener.Start(128);
                Log("Listening on " + bindAddr + ":" + port);
                while (true)
                {
                    TcpClient client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    Task _ = HandleClientAsync(client);
                }
            }
            catch (Exception ex)
            {
                Log("Listener on port " + port + " skipped/stopped: " + ex.Message);
            }
            finally
            {
                if (listener != null) { try { listener.Stop(); } catch { } }
            }
        }

        private static IPAddress DetectPhysicalIp()
        {
            if (_cachedPhysIp != null && (DateTime.UtcNow - _cachedPhysIpTime).TotalSeconds < 30)
                return _cachedPhysIp;

            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    string desc = (ni.Name + " " + ni.Description).ToLowerInvariant();
                    if (desc.Contains("wintun") || desc.Contains("tun") || desc.Contains("tap") ||
                        desc.Contains("vethernet") || desc.Contains("wsl") || desc.Contains("hyper-v") ||
                        desc.Contains("vmware") || desc.Contains("virtual"))
                        continue;

                    IPInterfaceProperties props = ni.GetIPProperties();
                    if (props.GatewayAddresses == null || props.GatewayAddresses.Count == 0) continue;

                    bool hasIpv4Gw = false;
                    foreach (GatewayIPAddressInformation gw in props.GatewayAddresses)
                    {
                        if (gw.Address != null && gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                            !gw.Address.Equals(IPAddress.Any))
                        {
                            hasIpv4Gw = true;
                            break;
                        }
                    }
                    if (!hasIpv4Gw) continue;

                    foreach (UnicastIPAddressInformation uni in props.UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            string ipStr = uni.Address.ToString();
                            if (!ipStr.StartsWith("198.18.") && !ipStr.StartsWith("127.") && !ipStr.StartsWith("169.254."))
                            {
                                _cachedPhysIp = uni.Address;
                                _cachedPhysIpTime = DateTime.UtcNow;
                                return _cachedPhysIp;
                            }
                        }
                    }
                }
            }
            catch { }
            return _cachedPhysIp;
        }

        private static Socket CreateBoundSocket(string targetIp, int targetPort)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                IPAddress physIp = DetectPhysicalIp();
                Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                sock.NoDelay = true;
                sock.ReceiveTimeout = 8000;
                sock.SendTimeout = 8000;
                if (physIp != null)
                {
                    try { sock.Bind(new IPEndPoint(physIp, 0)); } catch { _cachedPhysIp = null; }
                }

                try
                {
                    IAsyncResult res = sock.BeginConnect(IPAddress.Parse(targetIp), targetPort, null, null);
                    if (!res.AsyncWaitHandle.WaitOne(5000, true))
                    {
                        sock.Close();
                        throw new TimeoutException("Connect timeout to " + targetIp + ":" + targetPort);
                    }
                    sock.EndConnect(res);
                    return sock;
                }
                catch
                {
                    sock.Close();
                    _cachedPhysIp = null;
                    if (attempt == 1) throw;
                }
            }
            throw new TimeoutException("Connect failed to " + targetIp + ":" + targetPort);
        }

        private static string QueryDoh223(string domain, string ecs)
        {
            string key = domain + "|" + (ecs ?? "");
            Tuple<string, DateTime> cached;
            if (DnsCache.TryGetValue(key, out cached) && DateTime.UtcNow < cached.Item2)
                return cached.Item1;

            string path = "/resolve?name=" + Uri.EscapeDataString(domain) + "&type=A";
            if (!string.IsNullOrEmpty(ecs))
                path += "&edns_client_subnet=" + Uri.EscapeDataString(ecs);

            try
            {
                using (Socket sock = CreateBoundSocket("223.5.5.5", 443))
                using (NetworkStream ns = new NetworkStream(sock, false))
                using (SslStream ssl = new SslStream(ns, false, (s, c, ch, e) => true))
                {
                    ssl.AuthenticateAsClient("223.5.5.5");
                    string req = "GET " + path + " HTTP/1.1\r\nHost: 223.5.5.5\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
                    byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                    ssl.Write(reqBytes, 0, reqBytes.Length);
                    using (StreamReader sr = new StreamReader(ssl, Encoding.UTF8))
                    {
                        string resp = sr.ReadToEnd();
                        int bodyIdx = resp.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                        string body = bodyIdx >= 0 ? resp.Substring(bodyIdx + 4) : resp;
                        MatchCollection matches = Regex.Matches(body, "\"data\"\\s*:\\s*\"((?:\\d{1,3}\\.){3}\\d{1,3})\"");
                        foreach (Match m in matches)
                        {
                            string ip = m.Groups[1].Value;
                            if (!string.IsNullOrEmpty(ip) && !ip.StartsWith("198.18."))
                            {
                                DnsCache[key] = Tuple.Create(ip, DateTime.UtcNow.AddMinutes(5));
                                return ip;
                            }
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private static string ResolveOptimalTargetIp(string host)
        {
            string h = (host ?? "").Trim().ToLowerInvariant();
            if (h == "123.58.163.37" || h == "123.58.184.232" || h == "42.186.225.155") return "112.13.123.98";
            if (h == "223.252.194.149") return "34.95.122.33";

            IPAddress parsed;
            if (IPAddress.TryParse(h, out parsed)) return h;

            if (h == "api.nrd.nie.163.com" || h == "api-ipv4.nrd.nie.163.com")
            {
                string ip = QueryDoh223("api.nrd.nie.163.com", null);
                if (!string.IsNullOrEmpty(ip) && ip != "123.58.163.37") return ip;
                return "112.13.123.98";
            }

            if (h.StartsWith("sig-") && h.EndsWith(".nrd.nie.163.com"))
            {
                string ip = QueryDoh223(h, "8.8.8.0/24");
                if (!string.IsNullOrEmpty(ip) && ip != "223.252.194.149") return ip;
                return "34.95.122.33";
            }

            string dohIp = QueryDoh223(h, null);
            if (!string.IsNullOrEmpty(dohIp)) return dohIp;

            string fb;
            if (FallbackHostIps.TryGetValue(h, out fb)) return fb;

            try
            {
                IPAddress[] addrs = Dns.GetHostAddresses(h);
                foreach (IPAddress a in addrs)
                {
                    if (a.AddressFamily == AddressFamily.InterNetwork && !a.ToString().StartsWith("198.18."))
                        return a.ToString();
                }
            }
            catch { }
            return "112.13.123.98";
        }

        private static string ExtractSniFromClientHello(byte[] buf, int len)
        {
            try
            {
                if (len < 43 || buf[0] != 0x16 || buf[1] != 0x03 || buf[5] != 0x01) return null;
                string ascii = Encoding.ASCII.GetString(buf, 0, len);
                Match m = Regex.Match(ascii, @"([a-zA-Z0-9_-]+\.)+(?:nrd\.nie\.163\.com|163\.com|netease\.com)");
                if (m.Success) return m.Value;
            }
            catch { }
            return null;
        }

        internal static byte[] FragmentTlsClientHello(byte[] data, int len)
        {
            if (len < 6 || data[0] != 0x16 || data[1] != 0x03)
            {
                byte[] copy = new byte[len];
                Buffer.BlockCopy(data, 0, copy, 0, len);
                return copy;
            }

            int recLen = (data[3] << 8) | data[4];
            int totalFirstRec = 5 + recLen;
            if (len < totalFirstRec || recLen <= 0 || data[5] != 0x01)
            {
                byte[] copy = new byte[len];
                Buffer.BlockCopy(data, 0, copy, 0, len);
                return copy;
            }

            string payloadAscii = Encoding.ASCII.GetString(data, 5, recLen);
            int idx = payloadAscii.IndexOf("nrd.nie.163.com", StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                byte[] copy = new byte[len];
                Buffer.BlockCopy(data, 0, copy, 0, len);
                return copy;
            }

            byte verMajor = data[1];
            byte verMinor = data[2];
            int splitPos = idx + 5;
            if (splitPos >= recLen) splitPos = recLen / 2;

            int len1 = splitPos;
            int len2 = recLen - splitPos;
            int remLen = len - totalFirstRec;

            byte[] outBuf = new byte[5 + len1 + 5 + len2 + remLen];
            outBuf[0] = 0x16;
            outBuf[1] = verMajor;
            outBuf[2] = verMinor;
            outBuf[3] = (byte)((len1 >> 8) & 0xFF);
            outBuf[4] = (byte)(len1 & 0xFF);
            Buffer.BlockCopy(data, 5, outBuf, 5, len1);

            int off2 = 5 + len1;
            outBuf[off2] = 0x16;
            outBuf[off2 + 1] = verMajor;
            outBuf[off2 + 2] = verMinor;
            outBuf[off2 + 3] = (byte)((len2 >> 8) & 0xFF);
            outBuf[off2 + 4] = (byte)(len2 & 0xFF);
            Buffer.BlockCopy(data, 5 + len1, outBuf, off2 + 5, len2);

            if (remLen > 0)
                Buffer.BlockCopy(data, totalFirstRec, outBuf, off2 + 5 + len2, remLen);

            return outBuf;
        }

        private static async Task ReadExactAsync(Stream s, byte[] buf, int count)
        {
            await ReadExactAsync(s, buf, 0, count).ConfigureAwait(false);
        }

        private static async Task ReadExactAsync(Stream s, byte[] buf, int offset, int count)
        {
            int read = 0;
            while (read < count)
            {
                int n = await s.ReadAsync(buf, offset + read, count - read).ConfigureAwait(false);
                if (n <= 0) throw new EndOfStreamException();
                read += n;
            }
        }

        private static async Task HandleClientAsync(TcpClient client)
        {
            Socket remoteSock = null;
            try
            {
                client.NoDelay = true;
                NetworkStream cStream = client.GetStream();
                byte[] firstBuf = new byte[1];
                int n0 = await cStream.ReadAsync(firstBuf, 0, 1).ConfigureAwait(false);
                if (n0 <= 0) return;

                byte b0 = firstBuf[0];
                string targetHost = "";
                int targetPort = 443;
                byte[] initialClientData = null;

                if (b0 == 0x05)
                {
                    byte[] nm = new byte[1];
                    await ReadExactAsync(cStream, nm, 1).ConfigureAwait(false);
                    byte[] methods = new byte[nm[0]];
                    await ReadExactAsync(cStream, methods, nm[0]).ConfigureAwait(false);
                    await cStream.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2).ConfigureAwait(false);

                    byte[] hdr = new byte[4];
                    await ReadExactAsync(cStream, hdr, 4).ConfigureAwait(false);
                    byte atyp = hdr[3];
                    if (atyp == 1)
                    {
                        byte[] ipb = new byte[4];
                        await ReadExactAsync(cStream, ipb, 4).ConfigureAwait(false);
                        targetHost = new IPAddress(ipb).ToString();
                    }
                    else if (atyp == 3)
                    {
                        byte[] dlen = new byte[1];
                        await ReadExactAsync(cStream, dlen, 1).ConfigureAwait(false);
                        byte[] db = new byte[dlen[0]];
                        await ReadExactAsync(cStream, db, dlen[0]).ConfigureAwait(false);
                        targetHost = Encoding.ASCII.GetString(db);
                    }
                    else return;

                    byte[] pb = new byte[2];
                    await ReadExactAsync(cStream, pb, 2).ConfigureAwait(false);
                    targetPort = (pb[0] << 8) | pb[1];

                    byte[] reply = new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                    await cStream.WriteAsync(reply, 0, reply.Length).ConfigureAwait(false);
                }
                else if (b0 == 0x16)
                {
                    byte[] hdr4 = new byte[4];
                    await ReadExactAsync(cStream, hdr4, 4).ConfigureAwait(false);
                    int recLen = (hdr4[2] << 8) | hdr4[3];
                    initialClientData = new byte[5 + recLen];
                    initialClientData[0] = b0;
                    Buffer.BlockCopy(hdr4, 0, initialClientData, 1, 4);
                    await ReadExactAsync(cStream, initialClientData, 5, recLen).ConfigureAwait(false);

                    string sni = ExtractSniFromClientHello(initialClientData, initialClientData.Length);
                    targetHost = !string.IsNullOrEmpty(sni) ? sni : "api.nrd.nie.163.com";
                    targetPort = 443;
                }
                else
                {
                    MemoryStream ms = new MemoryStream();
                    ms.WriteByte(b0);
                    byte[] b1 = new byte[1];
                    while (true)
                    {
                        int r = await cStream.ReadAsync(b1, 0, 1).ConfigureAwait(false);
                        if (r <= 0) break;
                        ms.WriteByte(b1[0]);
                        byte[] arr = ms.ToArray();
                        int l = arr.Length;
                        if (l >= 4 && arr[l - 4] == '\r' && arr[l - 3] == '\n' && arr[l - 2] == '\r' && arr[l - 1] == '\n')
                            break;
                    }
                    string reqStr = Encoding.ASCII.GetString(ms.ToArray());
                    string firstLine = reqStr.Split('\r', '\n')[0];
                    string[] parts = firstLine.Split(' ');
                    if (parts.Length < 2) return;
                    string hp = parts[1];
                    int colon = hp.LastIndexOf(':');
                    if (colon > 0)
                    {
                        targetHost = hp.Substring(0, colon);
                        int.TryParse(hp.Substring(colon + 1), out targetPort);
                    }
                    else
                    {
                        targetHost = hp;
                        targetPort = 443;
                    }
                    byte[] okResp = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    await cStream.WriteAsync(okResp, 0, okResp.Length).ConfigureAwait(false);
                }

                if (initialClientData == null)
                {
                    byte[] buf = new byte[16384];
                    int n = await cStream.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false);
                    if (n <= 0) return;
                    initialClientData = new byte[n];
                    Buffer.BlockCopy(buf, 0, initialClientData, 0, n);

                    string sni = ExtractSniFromClientHello(initialClientData, n);
                    IPAddress dummy;
                    if (!string.IsNullOrEmpty(sni) && IPAddress.TryParse(targetHost, out dummy))
                        targetHost = sni;
                }

                bool isFallbackHttp = (targetPort == 80) &&
                    (targetHost == "123.58.184.232" || targetHost == "42.186.225.155" || targetHost == "api.nrd.nie.163.com");
                int connectPort = isFallbackHttp ? 443 : targetPort;

                string targetIp = await Task.Run(() => ResolveOptimalTargetIp(targetHost)).ConfigureAwait(false);
                remoteSock = await Task.Run(() => CreateBoundSocket(targetIp, connectPort)).ConfigureAwait(false);
                NetworkStream rStream = new NetworkStream(remoteSock, false);

                Log(string.Format("[DIRECT+TLS-FRAG] {0}:{1} -> {2}:{3}", targetHost, targetPort, targetIp, connectPort));

                if (isFallbackHttp)
                {
                    using (FragmentedFirstWriteStream fragStream = new FragmentedFirstWriteStream(rStream))
                    using (SslStream ssl = new SslStream(fragStream, false, (s, c, ch, e) => true))
                    {
                        await Task.Run(() => ssl.AuthenticateAsClient("api.nrd.nie.163.com", null, SslProtocols.Tls12, false)).ConfigureAwait(false);
                        string plainReq = Encoding.UTF8.GetString(initialClientData);
                        plainReq = Regex.Replace(plainReq, @"(?im)^Host:\s*(123\.58\.184\.232|42\.186\.225\.155)(:\d+)?\r\n", "Host: api.nrd.nie.163.com\r\n");
                        byte[] rewritten = Encoding.UTF8.GetBytes(plainReq);
                        await ssl.WriteAsync(rewritten, 0, rewritten.Length).ConfigureAwait(false);

                        Task c2s = PumpAsync(cStream, ssl);
                        Task s2c = PumpAsync(ssl, cStream);
                        await Task.WhenAny(c2s, s2c).ConfigureAwait(false);
                    }
                    return;
                }

                byte[] firstOut = FragmentTlsClientHello(initialClientData, initialClientData.Length);
                await rStream.WriteAsync(firstOut, 0, firstOut.Length).ConfigureAwait(false);

                Task tUp = PumpAsync(cStream, rStream);
                Task tDown = PumpAsync(rStream, cStream);
                await Task.WhenAny(tUp, tDown).ConfigureAwait(false);
            }
            catch { }
            finally
            {
                try { client.Close(); } catch { }
                if (remoteSock != null) { try { remoteSock.Close(); } catch { } }
            }
        }

        private static async Task PumpAsync(Stream input, Stream output)
        {
            byte[] buf = new byte[16384];
            try
            {
                while (true)
                {
                    int n = await input.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false);
                    if (n <= 0) break;
                    await output.WriteAsync(buf, 0, n).ConfigureAwait(false);
                }
            }
            catch { }
        }
    }
}
'@

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($csPath, $csSource, $utf8NoBom)

$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    $csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
& $csc /nologo /optimize+ /target:winexe /out:"$exePath" "$csPath" | Out-Null
if (-not (Test-Path $exePath)) {
    throw "编译 UUTlsFragmenter.exe 失败。"
}
Write-Ok "已编译生成零依赖原生分片服务: $exePath"

Start-Process -FilePath $exePath -WorkingDirectory $installDir -WindowStyle Hidden

$portReady = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 200
    $tc = New-Object System.Net.Sockets.TcpClient
    try {
        $tc.Connect("127.0.0.1", 17899)
        if ($tc.Connected) {
            $portReady = $true
            $tc.Close()
            break
        }
    } catch {} finally {
        $tc.Dispose()
    }
}
if ($portReady) {
    Write-Ok "UUTlsFragmenter.exe 已在后台启动 (127.0.0.1:17899 & 127.0.0.1:443)"
} else {
    throw "UUTlsFragmenter.exe 端口 17899 启动超时。"
}

Set-ItemProperty -Path $runKey -Name "UURemoteTLSFragmenter" -Value "`"$exePath`""
Write-Ok "已注册开机静默自启 (HKCU\...\Run\UURemoteTLSFragmenter)"

# ----------------------------------------------------------------------
# 步骤 2/4: 写入 UU 远程原生配置 proxy_config.ini (本机回环 127.0.0.1:17899)
# ----------------------------------------------------------------------
Write-Step "步骤 2/4: 配置 UU 远程原生回环分片通道 (C:\ProgramData\Netease\GameViewer\proxy_config.ini)"

if (-not (Test-Path $uuDataDir)) {
    New-Item -ItemType Directory -Path $uuDataDir -Force | Out-Null
}
$proxyIniContent = "[Proxy]`nsettingType=2`ntype=2`nhost=127.0.0.1`nport=17899`nusername=`nbypass=`npassword=`n"
[System.IO.File]::WriteAllText($proxyIniPath, $proxyIniContent, $utf8NoBom)
Write-Ok "已写入 UU 远程原生配置文件 proxy_config.ini (socks5h://127.0.0.1:17899)"
Write-Ok "UU 远程现已直接走本机回环 -> UUTlsFragmenter.exe -> 物理网卡直连"

if ($isAdmin -and (Test-Path $hostsPath)) {
    $uuDomains = @(
        "api.nrd.nie.163.com",
        "api-dcdn.nrd.nie.163.com",
        "api-event.nrd.nie.163.com",
        "api-ipv4.nrd.nie.163.com",
        "sig-3303-d.nrd.nie.163.com",
        "relay-mg-3303-d.nrd.nie.163.com"
    )
    $existingHosts = @(Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object {
        $_ -notmatch 'UU_REMOTE_TLS_FIX' -and $_ -notmatch 'nrd\.nie\.163\.com'
    })
    foreach ($ud in $uuDomains) {
        $existingHosts += "127.0.0.1 $ud # UU_REMOTE_TLS_FIX"
    }
    [System.IO.File]::WriteAllLines($hostsPath, $existingHosts, $utf8NoBom)
    Write-Ok "已同步写入系统 hosts 本地透明 SNI 映射双保险 (127.0.0.1:443)"
}

# ----------------------------------------------------------------------
# 步骤 3/4: 刷新系统 DNS 缓存并同步重启 UU 远程服务/客户端
# ----------------------------------------------------------------------
Write-Step "步骤 3/4: 刷新系统 DNS 缓存并重启 UU 远程客户端加载新配置"
& ipconfig.exe /flushdns | Out-Null
Write-Ok "系统 DNS 缓存已刷新"

if ($isAdmin) {
    $svc = Get-Service -Name "GameViewerService" -ErrorAction SilentlyContinue
    if ($svc) {
        Restart-Service -Name "GameViewerService" -Force
        Write-Ok "已重启系统服务 GameViewerService (后台被控服务已同步切换至本地分片器)"
    }
}

if (-not $SkipRestartClient) {
    $gvProc = Get-Process -Name "GameViewer" -ErrorAction SilentlyContinue
    $gvLauncher = Join-Path $env:ProgramFiles "Netease\GameViewer\bin\GameViewerLauncher.exe"
    if (-not (Test-Path $gvLauncher) -and ${env:ProgramFiles(x86)}) {
        $gvLauncher = Join-Path ${env:ProgramFiles(x86)} "Netease\GameViewer\bin\GameViewerLauncher.exe"
    }
    if ($gvProc) {
        Stop-Process -Name "GameViewer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    if (Test-Path $gvLauncher) {
        Start-Process -FilePath $gvLauncher
        Write-Ok "已通过 GameViewerLauncher.exe 重启 UU 远程客户端"
    }
}

# ----------------------------------------------------------------------
# 步骤 4/4: 端到端实测验证本地独立分片器 (127.0.0.1:17899) TLS 握手
# ----------------------------------------------------------------------
Write-Step "步骤 4/4: 实测本地独立分片器 (127.0.0.1:17899 -> 物理网卡) 全端点 TLS 握手"

$testDomains = @(
    @{ Domain = "api.nrd.nie.163.com";            Role = "核心控制 API (HTTPS)" },
    @{ Domain = "api-dcdn.nrd.nie.163.com";       Role = "DCDN 灾备 API (HTTPS)" },
    @{ Domain = "api-event.nrd.nie.163.com";      Role = "事件日志 API (HTTPS)" },
    @{ Domain = "api-ipv4.nrd.nie.163.com";       Role = "IPv4 WOL/初始化 API (HTTPS)" },
    @{ Domain = "sig-3303-d.nrd.nie.163.com";     Role = "WebSocket 远程信令 (WSS/TLS)" },
    @{ Domain = "uuyc.163.com";                   Role = "UU 远程门户服务 (HTTPS)" }
)

$allPassed = $true
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
foreach ($item in $testDomains) {
    $d = $item.Domain
    $role = $item.Role
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $code = & curl.exe -sS -o NUL -w "%{http_code}" --socks5-hostname 127.0.0.1:17899 --max-time 6 "https://$d" 2>&1
    $sw.Stop()
    if ($code -match '^\d{3}$' -and $code -ne '000') {
        Write-Ok ("{0,-28} [{1}] -> 独立分片握手成功 ({2,3} ms) [HTTP {3}]" -f $d, $role, $sw.ElapsedMilliseconds, $code)
    } else {
        Write-Err ("{0,-28} [{1}] -> 独立分片握手失败 ({2,3} ms) [{3}]" -f $d, $role, $sw.ElapsedMilliseconds, $code)
        $allPassed = $false
    }
}
$ErrorActionPreference = $prevEap

Write-Host "`n======================================================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host " 修复完成！UU 远程所有 TLS 握手均已通过本机分片直连恢复正常。" -ForegroundColor Green
} else {
    Write-Host " 部分端点测试未通过，请查看上方日志输出。" -ForegroundColor Yellow
}
Write-Host "======================================================================" -ForegroundColor Cyan
