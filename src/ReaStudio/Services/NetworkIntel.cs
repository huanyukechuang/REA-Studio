using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ReaStudio.Services
{
    internal sealed class Endpoint
    {
        public string Scheme { get; set; } = "";
        public string Host { get; set; } = "";
        public int Port { get; set; }
        public string Direction { get; set; } = "上行/外发";
        public int Hits { get; set; }
        public int Score { get; set; }
        public string Level { get; set; } = "低";
        public List<string> Paths { get; set; } = new List<string>();
        public List<string> Reasons { get; set; } = new List<string>();
        public List<string> Fields { get; set; } = new List<string>();
    }

    internal sealed class PrivacyHit
    {
        public string Category { get; set; } = "";
        public string Key { get; set; } = "";
        public string Meaning { get; set; } = "";
        public string Risk { get; set; } = "中";
        public int Hits { get; set; }
        public List<string> Samples { get; set; } = new List<string>();
    }

    internal sealed class PacketSample
    {
        public string Method { get; set; } = "POST";
        public string Target { get; set; } = "";
        public string Kind { get; set; } = "";      // JSON / Query / Header
        public string Content { get; set; } = "";
        public List<string> Fields { get; set; } = new List<string>();
        public int Score { get; set; }
        public List<string> Reasons { get; set; } = new List<string>();
    }

    internal sealed class NetworkReport
    {
        public string Target { get; set; } = "";
        public bool Ok { get; set; }
        public string Error { get; set; } = "";
        public int Strings { get; set; }
        public int UrlCount { get; set; }
        public int IpCount { get; set; }
        public int TotalEndpoints { get; set; }
        public int TotalDangerous { get; set; }
        public string PlainHttpShare { get; set; } = "";
        public List<Endpoint> Endpoints { get; set; } = new List<Endpoint>();
        public List<Endpoint> Dangerous { get; set; } = new List<Endpoint>();
        public List<PrivacyHit> Privacy { get; set; } = new List<PrivacyHit>();
        public List<PacketSample> Packets { get; set; } = new List<PacketSample>();
        public List<string> UserAgents { get; set; } = new List<string>();
        public List<string> Services { get; set; } = new List<string>();
        public string Verdict { get; set; } = "";
    }

    /// <summary>静态网络情报：从样本字符串/资源中还原流量指向、隐私字段与危险外发行为。</summary>
    internal static class NetworkIntel
    {
        private static readonly Regex UrlRx = new Regex(@"\b(https?)://([A-Za-z0-9\-\._]+|\[[0-9a-fA-F:]+\])(:(\d{1,5}))?([/A-Za-z0-9\-\._~%!\$&'\(\)\*\+,;=:@]*)", RegexOptions.Compiled);
        private static readonly Regex IpRx = new Regex(@"\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b", RegexOptions.Compiled);
        private static readonly Regex EmailRx = new Regex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled);
        private static readonly Regex JsonRx = new Regex(@"\{[^{}]{4,400}\}", RegexOptions.Compiled);
        private static readonly Regex QueryRx = new Regex(@"\b[a-zA-Z_][a-zA-Z0-9_]{1,24}=[^&""'\s]{1,80}(&[a-zA-Z_][a-zA-Z0-9_]{1,24}=[^&""'\s]{1,80}){1,8}", RegexOptions.Compiled);

        private const long MaxScanBytes = 96L * 1024 * 1024;

        private static readonly string[] BadChannel =
        {
            "api.telegram.org", "discord.com/api/webhooks", "hooks.slack.com", "oapi.dingtalk.com/robot",
            "qyapi.weixin.qq.com/cgi-bin/webhook", "webhook.office.com", "open.feishu.cn/open-apis/bot",
            "pastebin.com", "ghostbin", "transfer.sh", "0x0.st", "catbox.moe", "termbin.com"
        };
        private static readonly string[] DynDns =
        {
            "bit.ly", "tinyurl.com", "t.cn", "duckdns.org", "ngrok.io", "ngrok-free.app", "no-ip.org",
            "ddns.net", "serveo.net", "trycloudflare.com", "ngrok.app"
        };
        private static readonly string[] RemoteOps = { "/cmd", "/shell", "/exec", "/execute", "/payload", "/gate", "/c2", "/beacon" };
        private static readonly string[] ExfilOps = { "/upload", "/collect", "/report", "/track", "/log", "/stat", "/heartbeat", "/register", "/active", "/api/report", "/data/report" };
        private static readonly string[] TransportOps = { "/download", "/update", "/install", "/apk", "/dex", "/patch" };

        private static readonly (string Key, string Cat, string Meaning, string Risk)[] PrivacyKeys =
        {
            ("idcard", "身份证号", "公民身份号码", "高"),
            ("id_card", "身份证号", "公民身份号码", "高"),
            ("idnumber", "身份证号", "证件号码", "高"),
            ("bankcard", "银行卡", "银行卡号", "高"),
            ("card_no", "银行卡", "银行卡号", "高"),
            ("cvn", "银行卡", "卡验证码", "高"),
            ("passport", "证件", "护照号", "高"),
            ("imei", "设备标识", "IMEI 设备串号", "高"),
            ("imsi", "设备标识", "IMSI 用户标识", "高"),
            ("android_id", "设备标识", "Android ID", "中"),
            ("androidid", "设备标识", "Android ID", "中"),
            ("oaid", "设备标识", "OAID 广告标识", "中"),
            ("idfa", "设备标识", "IDFA 广告标识", "中"),
            ("deviceid", "设备标识", "设备唯一号", "中"),
            ("device_id", "设备标识", "设备唯一号", "中"),
            ("macaddress", "设备标识", "MAC 地址", "中"),
            ("mac_addr", "设备标识", "MAC 地址", "中"),
            ("serial", "设备标识", "设备序列号", "中"),
            ("latitude", "地理位置", "纬度", "高"),
            ("longitude", "地理位置", "经度", "高"),
            ("lat", "地理位置", "纬度", "中"),
            ("lng", "地理位置", "经度", "中"),
            ("location", "地理位置", "位置信息", "高"),
            ("gps", "地理位置", "GPS 坐标", "高"),
            ("lbs", "地理位置", "基站定位", "高"),
            ("address", "个人资料", "住址/收货地址", "中"),
            ("phone", "手机号", "手机号码", "高"),
            ("mobile", "手机号", "手机号码", "高"),
            ("msisdn", "手机号", "手机号码", "高"),
            ("telephone", "手机号", "电话号码", "高"),
            ("contacts", "通讯录", "联系人读取", "高"),
            ("contactlist", "通讯录", "联系人列表", "高"),
            ("calllog", "通话记录", "通话记录读取", "高"),
            ("sms", "短信", "短信内容/发送", "高"),
            ("album", "相册", "相册访问", "高"),
            ("photo", "相册", "照片访问/上传", "中"),
            ("camera", "摄像头", "摄像头调用", "中"),
            ("record_audio", "麦克风", "录音权限", "高"),
            ("microphone", "麦克风", "麦克风调用", "中"),
            ("clipboard", "剪贴板", "剪贴板读取", "中"),
            ("screenshot", "屏幕", "屏幕截取", "中"),
            ("password", "凭据", "口令字段", "高"),
            ("passwd", "凭据", "口令字段", "高"),
            ("pwd", "凭据", "口令字段", "高"),
            ("privatekey", "凭据", "私钥", "高"),
            ("secret", "凭据", "密钥/口令", "高"),
            ("apikey", "凭据", "API 密钥", "中"),
            ("api_key", "凭据", "API 密钥", "中"),
            ("access_token", "凭据", "访问令牌", "中"),
            ("sessionid", "凭据", "会话标识", "中"),
            ("cookie", "凭据", "Cookie 内容", "中"),
            ("openid", "账户标识", "微信 OpenID", "中"),
            ("unionid", "账户标识", "微信 UnionID", "中"),
            ("userid", "账户标识", "用户 ID", "低"),
            ("uid", "账户标识", "用户 ID", "低"),
        };

        private static readonly string[] KnownServices =
        {
            "umeng.com|友盟统计", "jpush.cn|极光推送", "getui|个推推送", "bugly|腾讯 Bugly", "sentry|Sentry 错误上报",
            "firebase|Firebase", "google-analytics|Google Analytics", "app-measurement|Firebase 分析",
            "facebook.com|Facebook SDK", "appsflyer|AppsFlyer", "adjust.com|Adjust 归因", "talkingdata|TalkingData",
            "baidu.com|百度统计", "cnzz|CNZZ 统计", "growingio|GrowingIO", "sensorsdata|神策数据",
            "alipay|支付宝 SDK", "wechat|微信 SDK", "qq.com|腾讯服务", "amap|高德地图", "map.baidu|百度地图",
            "okhttp|OkHttp 客户端", "retrofit2|Retrofit 客户端", "volley|Volley 客户端", "axios|Axios 客户端"
        };

        public static NetworkReport AnalyzeFile(string path)
        {
            var report = new NetworkReport { Target = path };
            var strings = new List<string>();
            try
            {
                if (Directory.Exists(path))
                {
                    var files = Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Take(400);
                    foreach (var f in files) strings.AddRange(ExtractStrings(ReadCapped(f), 5));
                }
                else if (File.Exists(path))
                {
                    var bytes = ReadCapped(path);
                    strings.AddRange(ExtractStrings(bytes, 5));
                    var ext = (Path.GetExtension(path) ?? "").ToLowerInvariant();
                    if (ext == ".apk" || ext == ".jar" || ext == ".aab" || ext == ".zip" || ext == ".xapk")
                        strings.AddRange(ExtractArchiveStrings(path));
                }
                else
                {
                    report.Error = "目标不存在: " + path;
                    return report;
                }
            }
            catch (Exception ex)
            {
                report.Error = ex.Message;
                return report;
            }

            var result = Core(strings, path);
            result.Target = path;
            return result;
        }

        public static NetworkReport AnalyzeText(string text, string label)
        {
            var strings = ExtractStrings(Encoding.UTF8.GetBytes(text ?? ""), 4);
            if (strings.Count == 0) strings.Add(text ?? "");
            var r = Core(strings, label);
            r.Target = label;
            return r;
        }

        /// <summary>隐私键匹配：要求词边界，避免 allocation→location、GetProcAddress→address 这类子串误报。</summary>
        private static bool HasPrivacyKey(string s, string key)
        {
            var idx = 0;
            while (true)
            {
                idx = s.IndexOf(key, idx, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) return false;
                var end = idx + key.Length;
                var leftOk = idx == 0 || !char.IsLetterOrDigit(s[idx - 1]);
                var rightOk = end >= s.Length || !char.IsLetterOrDigit(s[end]);
                var camel = idx > 0 && char.IsLower(s[idx - 1]) && char.IsUpper(s[idx]);
                if (leftOk && rightOk && !camel) return true;
                idx = end;
            }
        }

        private static NetworkReport Core(List<string> strings, string label)
        {
            var report = new NetworkReport { Ok = true, Target = label, Strings = strings.Count };
            // 去重并限制规模，避免超长文件拖慢
            var uniq = new HashSet<string>(StringComparer.Ordinal);
            var endpoints = new Dictionary<string, Endpoint>(StringComparer.OrdinalIgnoreCase);
            var privacy = new Dictionary<string, PrivacyHit>(StringComparer.OrdinalIgnoreCase);
            var packets = new List<PacketSample>();
            var uas = new HashSet<string>(StringComparer.Ordinal);
            var services = new HashSet<string>(StringComparer.Ordinal);

            int urlCount = 0, ipCount = 0, httpUrls = 0, totalUrls = 0;
            int scanned = 0;

            foreach (var s in strings)
            {
                if (s == null || s.Length < 4) continue;
                if (++scanned > 1500000) break;
                if (!uniq.Add(s)) continue;

                // ---- URL ----
                foreach (Match m in UrlRx.Matches(s))
                {
                    var scheme = m.Groups[1].Value.ToLowerInvariant();
                    var host = m.Groups[2].Value;
                    if (NonNetworkHosts.Contains(host)) continue;   // 命名空间/规范 URI，非真实请求
                    urlCount++; totalUrls++;
                    int port = 0;
                    if (m.Groups[4].Success) int.TryParse(m.Groups[4].Value, out port);
                    if (port == 0) port = scheme == "https" ? 443 : 80;
                    if (scheme == "http") httpUrls++;
                    var ep = GetEp(endpoints, scheme, host, port);
                    ep.Hits++;
                    var p = m.Groups[5].Value;
                    if (!string.IsNullOrEmpty(p) && p.Length > 1 && ep.Paths.Count < 6 && !ep.Paths.Contains(p)) ep.Paths.Add(p);
                }
                // ---- 裸 IP ----
                foreach (Match m in IpRx.Matches(s))
                {
                    var ip = m.Value;
                    if (ip.StartsWith("0.") || ip.StartsWith("127.") || ip.StartsWith("169.254.")
                        || ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "255.255.255.255") continue;
                    // 排除版本号风格（如 5.1.0.0 / 6.0.0.0）与嵌在更长点分串中的片段
                    var seg = ip.Split('.');
                    if (seg.Length == 4 && seg[2] == "0" && seg[3] == "0") continue;
                    var prevCh = m.Index > 0 ? s[m.Index - 1] : '\0';
                    var nextIdx = m.Index + m.Length;
                    var nextCh = nextIdx < s.Length ? s[nextIdx] : '\0';
                    if (prevCh == '.' || nextCh == '.' || (char.IsDigit(prevCh) && char.IsDigit(nextCh))) continue;
                    ipCount++;
                    var ep = GetEp(endpoints, "tcp", ip, 0);
                    ep.Hits++;
                    if (ep.Paths.Count == 0) ep.Paths.Add("(直连 IP，无域名)");
                }
                // ---- UA ----
                if (s.StartsWith("Mozilla/") && s.Length < 400) uas.Add(s.Length > 160 ? s.Substring(0, 160) : s);

                // ---- 数据包体 ----
                foreach (Match m in JsonRx.Matches(s))
                {
                    var body = m.Value;
                    if (body.Count(c => c == ':') < 1) continue;
                    if (body.Contains("http://") || body.Contains("https://")) continue;
                    if (packets.Count >= 60) break;
                    var keys = Regex.Matches(body, "\"([A-Za-z_][A-Za-z0-9_ ]{1,30})\"\\s*:").Select(x => x.Groups[1].Value).Distinct().ToList();
                    if (keys.Count == 0) continue;
                    var pk = new PacketSample { Kind = "JSON", Content = body.Length > 220 ? body.Substring(0, 220) + "..." : body, Fields = keys };
                    ScorePacket(pk, keys, body);
                    packets.Add(pk);
                }
                if (packets.Count < 60)
                {
                    foreach (Match m in QueryRx.Matches(s))
                    {
                        var q = m.Value;
                        var keys = q.Split('&').Select(kv => kv.Split('=')[0]).Distinct().ToList();
                        var pk = new PacketSample { Kind = "Query", Content = q.Length > 220 ? q.Substring(0, 220) + "..." : q, Fields = keys };
                        ScorePacket(pk, keys, q);
                        packets.Add(pk);
                        if (packets.Count >= 60) break;
                    }
                }

                // ---- 隐私键 ----
                foreach (var pk in PrivacyKeys)
                {
                    if (!HasPrivacyKey(s, pk.Key)) continue;
                    if (!privacy.TryGetValue(pk.Cat, out var hit))
                    {
                        hit = new PrivacyHit { Category = pk.Cat, Key = pk.Key, Meaning = pk.Meaning, Risk = pk.Risk };
                        privacy[pk.Cat] = hit;
                    }
                    hit.Hits++;
                    if (hit.Samples.Count < 4)
                    {
                        var ctx = s.Length > 120 ? s.Substring(0, 120) : s;
                        if (!hit.Samples.Contains(ctx)) hit.Samples.Add(ctx);
                    }
                }

                // ---- 第三方服务 ----
                foreach (var svc in KnownServices)
                {
                    var kv = svc.Split('|');
                    if (s.IndexOf(kv[0], StringComparison.OrdinalIgnoreCase) >= 0) services.Add(kv[1]);
                }
            }

            // ---- 端点打分 ----
            foreach (var ep in endpoints.Values)
            {
                ScoreEndpoint(ep, privacy.Keys.ToList(), services);
            }
            var ordered = endpoints.Values.OrderByDescending(e => e.Score).ThenByDescending(e => e.Hits).ToList();
            report.TotalEndpoints = ordered.Count;
            report.TotalDangerous = ordered.Count(e => e.Score >= 3);
            report.Endpoints = ordered.Take(80).ToList();
            report.Dangerous = ordered.Where(e => e.Score >= 3).Take(60).ToList();
            report.Packets = packets.OrderByDescending(p => p.Score).Take(24).ToList();
            report.Privacy = privacy.Values.OrderByDescending(p => RiskWeight(p.Risk)).ThenByDescending(p => p.Hits).ToList();
            report.UserAgents = uas.Take(10).ToList();
            report.Services = services.OrderBy(x => x).ToList();
            report.UrlCount = urlCount;
            report.IpCount = ipCount;
            report.PlainHttpShare = totalUrls == 0 ? "-" : (httpUrls * 100 / totalUrls) + "%（" + httpUrls + "/" + totalUrls + " 为明文 http）";

            int high = report.Dangerous.Count(d => d.Level == "高");
            int mid = report.Dangerous.Count(d => d.Level == "中");
            int pHigh = report.Privacy.Count(p => p.Risk == "高");
            var verdict = new StringBuilder();
            if (high > 0) verdict.Append("发现 " + high + " 个高危外发端点；");
            if (mid > 0) verdict.Append("发现 " + mid + " 个中危外发端点；");
            if (pHigh > 0) verdict.Append("涉及 " + pHigh + " 类高敏个人数据字段；");
            if (report.Dangerous.Count == 0 && pHigh == 0) verdict.Append("未见明显危险外发行为；");
            if (totalUrls > 0 && httpUrls * 100 / totalUrls >= 30) verdict.Append("明文 http 占比偏高，存在传输窃听风险；");
            report.Verdict = verdict.ToString().TrimEnd('；');
            return report;
        }

        /// <summary>非网络请求用途的命名空间/规范 URI 主机，不计为外发端点。</summary>
        private static readonly HashSet<string> NonNetworkHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "schemas.android.com", "w3.org", "www.w3.org", "purl.org", "xmlns.com", "ns.adobe.com",
            "java.sun.com", "json-schema.org", "apache.org", "xml.org", "openxmlformats.org",
            "commons.apache.org", "xml.apache.org", "logging.apache.org", "json.org",
            "schemas.openxmlformats.org", "schemas.microsoft.com", "microsoft.com/office" 
        };

        /// <summary>公共 DNS / 探测类固定地址：属基础设施访问，不按 C2 直连计分。</summary>
        private static readonly HashSet<string> PublicDnsHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "114.114.114.114", "114.114.115.115",
            "119.29.29.29", "182.254.116.116", "223.5.5.5", "223.6.6.6", "180.76.76.76",
            "9.9.9.9", "208.67.222.222", "208.67.220.220"
        };

        /// <summary>内网 / 保留 / 环回地址：属局域网通信，不按规避溯源的公网直连计分。</summary>
        private static bool IsPrivateIp(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            var h = host.Trim('[', ']');
            var parts = h.Split('.');
            if (parts.Length != 4) return false;
            if (!int.TryParse(parts[0], out var a)) return false;
            if (!int.TryParse(parts[1], out var b)) return false;
            if (a == 10 || a == 127 || a == 0) return true;
            if (a == 192 && b == 168) return true;
            if (a == 172 && b >= 16 && b <= 31) return true;
            if (a == 169 && b == 254) return true;
            if (a == 100 && b >= 64 && b <= 127) return true;
            if (a == 192 && b == 0) return true;
            return false;
        }

        private static void ScoreEndpoint(Endpoint ep, List<string> privacyCats, HashSet<string> services)
        {
            var reasons = ep.Reasons;
            int score = 0;
            bool isIpHost = Regex.IsMatch(ep.Host, @"^(\d{1,3}\.){3}\d{1,3}$") || ep.Host.StartsWith("[");
            bool isPrivate = isIpHost && IsPrivateIp(ep.Host);
            if (ep.Scheme == "http") { score += 2; reasons.Add("明文 HTTP 传输"); }
            bool isDns = PublicDnsHosts.Contains(ep.Host.Trim('[', ']'));
            if (isIpHost && !isPrivate && !isDns) { score += 2; reasons.Add("域名缺失，IP 直连（规避域名溯源与封禁）"); }
            else if (isDns) { AddReason(reasons, "公共 DNS / 基础设施地址"); }
            else if (isPrivate) { AddReason(reasons, "内网/局域网地址（调试或内网服务，非公网外发）"); }
            if (ep.Port != 0 && ep.Port != 80 && ep.Port != 443 && ep.Port != 8080 && ep.Port != 8443)
            { score += 1; reasons.Add("非常规端口 " + ep.Port); }
            foreach (var p in ep.Paths)
            {
                var low = p.ToLowerInvariant();
                if (BadChannel.Any(b => (ep.Host + low).ToLowerInvariant().Contains(b)))
                { score += 4; AddReason(reasons, "命中已知外传通道（IM/网盘/paste 服务）"); }
                var op = RemoteOps.FirstOrDefault(x => low.Contains(x));
                if (op != null) { score += 3; AddReason(reasons, "疑似远程指令/载荷通道 " + op); }
                var ex = ExfilOps.FirstOrDefault(x => low.Contains(x));
                if (ex != null) { score += 1; AddReason(reasons, "疑似埋点/数据回传路径 " + ex); }
                var tr = TransportOps.FirstOrDefault(x => low.Contains(x));
                if (tr != null) { score += 1; AddReason(reasons, "含更新/下载分发路径 " + tr); }
            }
            if (DynDns.Any(d => ep.Host.ToLowerInvariant().Contains(d))) { score += 2; AddReason(reasons, "动态域名/短链，指向可随时切换"); }
            if (ep.Scheme == "tcp" && isIpHost && !isPrivate) { score += 1; AddReason(reasons, "裸 IP 直连，非标准客户端流量"); }
            if (services.Contains("友盟统计") || services.Contains("Google Analytics")) { }
            if (isPrivate) score = Math.Min(score, 2);   // 内网通信不计入危险发包，仅作提示
            ep.Score = Math.Min(score, 12);
            ep.Level = ep.Score >= 6 ? "高" : ep.Score >= 3 ? "中" : "低";
            if (reasons.Count == 0) reasons.Add("常规 https 域名访问");
        }

        private static void ScorePacket(PacketSample pk, List<string> keys, string content)
        {
            int score = 0;
            foreach (var k in keys)
            {
                var hit = PrivacyKeys.FirstOrDefault(p => k.IndexOf(p.Key, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!string.IsNullOrEmpty(hit.Key))
                {
                    score += hit.Risk == "高" ? 3 : 1;
                    AddReason(pk.Reasons, "携带敏感字段 " + k + "（" + hit.Meaning + "）");
                }
                if (k.IndexOf("cmd", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    k.IndexOf("shell", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    k.IndexOf("exec", StringComparison.OrdinalIgnoreCase) >= 0)
                { score += 3; AddReason(pk.Reasons, "含指令下发字段 " + k); }
                if (k.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    k.IndexOf("upload", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    k.IndexOf("data", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    k.IndexOf("content", StringComparison.OrdinalIgnoreCase) >= 0)
                { score += 1; AddReason(pk.Reasons, "含数据回传字段 " + k); }
            }
            if (content.Contains("base64") || content.Contains("AES") || content.Contains("encrypt"))
            { score += 1; AddReason(pk.Reasons, "载荷提及加密/编码"); }
            pk.Score = Math.Min(score, 10);
            if (pk.Reasons.Count == 0) pk.Reasons.Add("常规业务参数");
        }

        private static void AddReason(List<string> list, string r)
        {
            if (!list.Contains(r) && list.Count < 6) list.Add(r);
        }

        private static int RiskWeight(string risk) => risk == "高" ? 3 : risk == "中" ? 2 : 1;

        private static Endpoint GetEp(Dictionary<string, Endpoint> map, string scheme, string host, int port)
        {
            var key = scheme + "://" + host.ToLowerInvariant() + ":" + port;
            if (!map.TryGetValue(key, out var ep))
            {
                ep = new Endpoint { Scheme = scheme, Host = host, Port = port };
                map[key] = ep;
            }
            return ep;
        }

        private static byte[] ReadCapped(string path)
        {
            try
            {
                using var fs = File.OpenRead(path);
                var len = (int)Math.Min(fs.Length, MaxScanBytes);
                var buf = new byte[len];
                int read = 0;
                while (read < len)
                {
                    int n = fs.Read(buf, read, len - read);
                    if (n <= 0) break;
                    read += n;
                }
                if (read == buf.Length) return buf;
                var trimmed = new byte[read];
                Array.Copy(buf, trimmed, read);
                return trimmed;
            }
            catch { return Array.Empty<byte>(); }
        }

        private static int EntryRank(string name)
        {
            var n = name.ToLowerInvariant();
            if (n.EndsWith(".dex")) return 0;                       // 代码与常量池，最高价值
            if (n.EndsWith(".arsc")) return 1;                      // 资源索引
            if (n.EndsWith(".json") || n.EndsWith(".js") || n.EndsWith(".xml")) return 2;
            if (n.EndsWith(".html") || n.EndsWith(".txt") || n.EndsWith(".properties")
                || n.EndsWith(".cfg") || n.EndsWith(".ini") || n.EndsWith(".yml")
                || n.EndsWith(".yaml") || n.EndsWith(".map") || n.EndsWith(".smali")) return 3;
            if (n.EndsWith(".dat")) return 4;
            if (n.EndsWith(".so")) return 6;                        // 原生库，噪音多，最后处理
            return 5;
        }

        /// <summary>抽取压缩包（APK/JAR/ZIP）内的字符串：按价值排序并给出更大预算。</summary>
        private static List<string> ExtractArchiveStrings(string path)
        {
            var list = new List<string>();
            try
            {
                using var za = System.IO.Compression.ZipFile.OpenRead(path);
                long budget = 160L * 1024 * 1024;
                var entries = za.Entries
                    .Where(e => e.Length > 0)
                    .OrderBy(e => EntryRank(e.FullName))
                    .ThenByDescending(e => e.Length)
                    .ToList();

                foreach (var e in entries)
                {
                    if (budget <= 0) break;
                    var name = e.FullName.ToLowerInvariant();
                    if (name.EndsWith(".so"))
                    {
                        if (e.Length > 2L * 1024 * 1024) continue;      // 过大的原生库跳过
                    }
                    else if (e.Length > 40L * 1024 * 1024) continue;     // dex 可到数十 MB

                    bool text = name.EndsWith(".xml") || name.EndsWith(".json") || name.EndsWith(".js") || name.EndsWith(".txt")
                        || name.EndsWith(".properties") || name.EndsWith(".html") || name.EndsWith(".smali") || name.EndsWith(".so")
                        || name.EndsWith(".dex") || name.EndsWith(".arsc") || name.EndsWith(".dat") || name.EndsWith(".cfg")
                        || name.EndsWith(".ini") || name.EndsWith(".yml") || name.EndsWith(".yaml") || name.EndsWith(".map");
                    if (!text && e.Length > 4L * 1024 * 1024) continue;

                    try
                    {
                        using var es = e.Open();
                        var ms = new MemoryStream();
                        es.CopyTo(ms);
                        budget -= ms.Length;
                        list.AddRange(ExtractStrings(ms.ToArray(), 5));
                    }
                    catch { }
                }
            }
            catch { }
            return list;
        }

        /// <summary>同时抽取 ASCII 与 UTF-16LE 字符串。</summary>
        public static List<string> ExtractStrings(byte[] data, int minLen)
        {
            var result = new List<string>();
            if (data == null || data.Length == 0) return result;
            var sb = new StringBuilder(256);
            foreach (var b in data)
            {
                if (b >= 32 && b < 127) sb.Append((char)b);
                else
                {
                    if (sb.Length >= minLen) result.Add(sb.ToString());
                    sb.Clear();
                }
                if (result.Count > 600000) break;
            }
            if (sb.Length >= minLen) result.Add(sb.ToString());
            sb.Clear();
            // UTF-16LE
            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                byte lo = data[i], hi = data[i + 1];
                if (hi == 0 && lo >= 32 && lo < 127) sb.Append((char)lo);
                else
                {
                    if (sb.Length >= minLen) result.Add(sb.ToString());
                    sb.Clear();
                }
                if (result.Count > 800000) break;
            }
            if (sb.Length >= minLen) result.Add(sb.ToString());
            return result;
        }
    }
}
