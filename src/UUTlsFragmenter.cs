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
        private static readonly int DnsPort = 53;
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
                { "nrd-ugc.fp.ps.netease.com", "111.3.79.64" },
                { "fp.ps.netease.com", "111.3.79.64" }
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

                Log("Starting UUTlsFragmenter Service (0.0.0.0:17899, 0.0.0.0:443, LAN DNS :53)");

                Task t1 = StartListenerAsync(IPAddress.Any, MainPort);
                Task t2 = StartListenerAsync(IPAddress.Any, TransparentTlsPort);
                Task t3 = StartLanDnsServerAsync();

                Task.WaitAll(t1, t2, t3);
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
                Log("Listening TCP on " + bindAddr + ":" + port);
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

        private static async Task StartLanDnsServerAsync()
        {
            await Task.Yield();
            IPAddress physIp = DetectPhysicalIp();
            if (physIp == null) return;

            Socket udp = null;
            try
            {
                udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udp.Bind(new IPEndPoint(physIp, DnsPort));
                Log("Listening LAN DNS on " + physIp + ":" + DnsPort + " (for Router / Wi-Fi devices)");

                byte[] buf = new byte[512];
                while (true)
                {
                    EndPoint remoteEp = new IPEndPoint(IPAddress.Any, 0);
                    int n = await Task.Run(() => udp.ReceiveFrom(buf, ref remoteEp)).ConfigureAwait(false);
                    if (n <= 12) continue;

                    byte[] reqCopy = new byte[n];
                    Buffer.BlockCopy(buf, 0, reqCopy, 0, n);
                    IPEndPoint clientEp = (IPEndPoint)remoteEp;
                    Socket udpRef = udp;
                    Task _ = Task.Run(() => HandleDnsQuery(udpRef, clientEp, reqCopy, physIp));
                }
            }
            catch (Exception ex)
            {
                Log("LAN DNS listener skipped: " + ex.Message);
            }
            finally
            {
                if (udp != null) { try { udp.Close(); } catch { } }
            }
        }

        private static void HandleDnsQuery(Socket udp, IPEndPoint clientEp, byte[] req, IPAddress lanIp)
        {
            try
            {
                int pos = 12;
                StringBuilder sb = new StringBuilder();
                while (pos < req.Length)
                {
                    int labLen = req[pos++];
                    if (labLen == 0) break;
                    if ((labLen & 0xC0) == 0xC0) { pos++; break; }
                    if (pos + labLen > req.Length) return;
                    if (sb.Length > 0) sb.Append('.');
                    sb.Append(Encoding.ASCII.GetString(req, pos, labLen));
                    pos += labLen;
                }
                if (pos + 4 > req.Length) return;
                int qtype = (req[pos] << 8) | req[pos + 1];
                int qEnd = pos + 4;
                string qname = sb.ToString().ToLowerInvariant();

                if (qname.EndsWith(".nrd.nie.163.com") || qname == "nrd.nie.163.com")
                {
                    if (qtype == 1) // A record -> return LAN IP so Wi-Fi device connects to our port 443 transparent fragmenter
                    {
                        byte[] resp = new byte[qEnd + 16];
                        Buffer.BlockCopy(req, 0, resp, 0, qEnd);
                        resp[2] = 0x81; resp[3] = 0x80; // Standard query response, no error
                        resp[6] = 0x00; resp[7] = 0x01; // 1 answer
                        resp[8] = 0x00; resp[9] = 0x00;
                        resp[10] = 0x00; resp[11] = 0x00;
                        int aOff = qEnd;
                        resp[aOff] = 0xC0; resp[aOff + 1] = 0x0C; // Name pointer
                        resp[aOff + 2] = 0x00; resp[aOff + 3] = 0x01; // Type A
                        resp[aOff + 4] = 0x00; resp[aOff + 5] = 0x01; // Class IN
                        resp[aOff + 6] = 0x00; resp[aOff + 7] = 0x00; resp[aOff + 8] = 0x00; resp[aOff + 9] = 0x3C; // TTL 60s
                        resp[aOff + 10] = 0x00; resp[aOff + 11] = 0x04; // Data len 4
                        byte[] ipBytes = lanIp.GetAddressBytes();
                        Buffer.BlockCopy(ipBytes, 0, resp, aOff + 12, 4);
                        udp.SendTo(resp, clientEp);
                        Log("[LAN-DNS] " + qname + " -> " + lanIp + " (for " + clientEp.Address + ")");
                        return;
                    }
                    else if (qtype == 28) // AAAA -> return empty NOERROR so client uses IPv4
                    {
                        byte[] resp = new byte[qEnd];
                        Buffer.BlockCopy(req, 0, resp, 0, qEnd);
                        resp[2] = 0x81; resp[3] = 0x80;
                        resp[6] = 0x00; resp[7] = 0x00;
                        resp[8] = 0x00; resp[9] = 0x00;
                        resp[10] = 0x00; resp[11] = 0x00;
                        udp.SendTo(resp, clientEp);
                        return;
                    }
                }

                // Forward other DNS queries to 223.5.5.5:53 bound to physical NIC
                using (Socket fSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    fSock.ReceiveTimeout = 2500;
                    fSock.SendTimeout = 2500;
                    fSock.Bind(new IPEndPoint(lanIp, 0));
                    fSock.SendTo(req, new IPEndPoint(IPAddress.Parse("223.5.5.5"), 53));
                    byte[] rBuf = new byte[512];
                    EndPoint upEp = new IPEndPoint(IPAddress.Any, 0);
                    int rn = fSock.ReceiveFrom(rBuf, ref upEp);
                    if (rn > 0)
                    {
                        byte[] outB = new byte[rn];
                        Buffer.BlockCopy(rBuf, 0, outB, 0, rn);
                        udp.SendTo(outB, clientEp);
                    }
                }
            }
            catch { }
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
                    ssl.AuthenticateAsClient("223.5.5.5", null, SslProtocols.Tls12, false);
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
