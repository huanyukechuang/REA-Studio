using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    internal sealed class WebSiteReport
    {
        public string Url { get; set; } = "";
        public string FinalUrl { get; set; } = "";
        public bool Ok { get; set; }
        public string Error { get; set; } = "";
        public int Status { get; set; }
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public long HtmlBytes { get; set; }
        public bool IsHttps { get; set; }
        public List<string> Scripts { get; set; } = new List<string>();
        public List<string> ExternalHosts { get; set; } = new List<string>();
        public List<string> SameHosts { get; set; } = new List<string>();
        public List<string> Forms { get; set; } = new List<string>();
        public List<string> Signals { get; set; } = new List<string>();
        public List<string> Cookies { get; set; } = new List<string>();
        public NetworkReport Network { get; set; } = new NetworkReport();
        public string Verdict { get; set; } = "";
    }

    /// <summary>网站逆向：抓取站点静态资源并复用网络情报引擎做流量/隐私/外发评估。</summary>
    internal static class WebRecon
    {
        private static readonly HttpClient Client = Sandbox.CreateHttpClient(18);

        public static async Task<WebSiteReport> ReconAsync(string rawUrl)
        {
            var r = new WebSiteReport { Url = rawUrl };
            string url = (rawUrl ?? "").Trim();
            if (url.Length == 0) { r.Error = "URL 为空"; return r; }
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                url = "https://" + url;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) { r.Error = "URL 无法解析"; return r; }
            r.IsHttps = uri.Scheme == "https";

            string body = "";
            try
            {
                using var resp = await Client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
                r.Status = (int)resp.StatusCode;
                r.FinalUrl = resp.RequestMessage?.RequestUri?.ToString() ?? url;
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                r.HtmlBytes = bytes.Length;
                if (bytes.Length > 4 * 1024 * 1024) bytes = bytes.Take(4 * 1024 * 1024).ToArray();
                body = Encoding.UTF8.GetString(bytes);
                if (resp.Headers.TryGetValues("Set-Cookie", out var sc)) r.Cookies.AddRange(sc.Take(30));
            }
            catch (Exception ex)
            {
                r.Error = ex.Message;
                return r;
            }

            r.Ok = true;
            var baseUri = new Uri(r.FinalUrl.Length > 0 ? r.FinalUrl : url);
            r.Title = Unescape(Regex.Match(body, @"<title[^>]*>(.*?)</title>", RegexOptions.Singleline | RegexOptions.IgnoreCase).Groups[1].Value).Trim();
            r.Description = Unescape(Regex.Match(body, @"<meta[^>]+name\s*=\s*[""']description[""'][^>]*content\s*=\s*[""']([^""']*)", RegexOptions.IgnoreCase).Groups[1].Value).Trim();

            var scriptSrcs = Regex.Matches(body, @"<script[^>]+src\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase)
                .Select(m => m.Groups[1].Value).Distinct().ToList();
            var links = Regex.Matches(body, @"<(link|iframe|img)[^>]+(src|href)\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase)
                .Select(m => m.Groups[3].Value).ToList();
            var forms = Regex.Matches(body, @"<form[^>]*>", RegexOptions.IgnoreCase)
                .Select(m => Regex.Match(m.Value, @"action\s*=\s*[""']([^""']*)", RegexOptions.IgnoreCase).Groups[1].Value).ToList();

            var hostSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in scriptSrcs)
            {
                var abs = Absolute(baseUri, s);
                r.Scripts.Add(abs);
                if (Uri.TryCreate(abs, UriKind.Absolute, out var u)) hostSet.Add(u.Host);
            }
            foreach (var l in links)
            {
                var abs = Absolute(baseUri, l);
                if (Uri.TryCreate(abs, UriKind.Absolute, out var u)) hostSet.Add(u.Host);
            }
            foreach (var h in hostSet)
            {
                if (string.Equals(h, baseUri.Host, StringComparison.OrdinalIgnoreCase)) r.SameHosts.Add(h);
                else r.ExternalHosts.Add(h);
            }
            foreach (var f in forms.Where(x => x.Length > 0).Distinct().Take(10)) r.Forms.Add(f);

            // 站点合规/风险信号
            if (Regex.IsMatch(body, @"隐私政策|privacy\s*policy|个人信息保护", RegexOptions.IgnoreCase)) r.Signals.Add("页面声明隐私政策");
            if (Regex.IsMatch(body, "ICP|备案号|公安备案", RegexOptions.IgnoreCase)) r.Signals.Add("含 ICP/备案信息");
            if (Regex.IsMatch(body, "用户协议|terms of service", RegexOptions.IgnoreCase)) r.Signals.Add("含用户协议");
            if (!r.IsHttps) r.Signals.Add("站点未使用 HTTPS（明文传输）");
            if (r.Cookies.Any(c => !c.Contains("Secure", StringComparison.OrdinalIgnoreCase))) r.Signals.Add("存在未标记 Secure 的 Cookie");
            if (r.Cookies.Any(c => c.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase) == false) && r.Cookies.Count > 0) r.Signals.Add("存在未标记 HttpOnly 的 Cookie（可被脚本读取）");
            if (r.ExternalHosts.Count >= 8) r.Signals.Add("第三方外部域偏多（" + r.ExternalHosts.Count + " 个），存在数据外流面");
            if (Regex.IsMatch(body, @"console\.log\(|debugger", RegexOptions.IgnoreCase)) r.Signals.Add("页面残留调试代码");

            // 采样同源 JS，补充到网络情报
            var sb = new StringBuilder(body);
            int fetched = 0;
            foreach (var s in r.Scripts.Take(6))
            {
                if (fetched >= 4) break;
                if (!Uri.TryCreate(s, UriKind.Absolute, out var su)) continue;
                if (!string.Equals(su.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var js = await Client.GetStringAsync(s);
                    if (js.Length > 1500000) js = js.Substring(0, 1500000);
                    sb.Append('\n').Append(js);
                    fetched++;
                }
                catch { }
            }

            r.Network = NetworkIntel.AnalyzeText(sb.ToString(), uri.Host);
            var v = new StringBuilder();
            if (r.Network.Dangerous.Count > 0) v.Append("识别到 " + r.Network.Dangerous.Count + " 个可疑外发端点；");
            if (r.Network.Privacy.Count > 0) v.Append("命中 " + r.Network.Privacy.Count + " 类个人数据字段；");
            v.Append("外部第三方域 " + r.ExternalHosts.Count + " 个；");
            if (!r.IsHttps) v.Append("未启用 HTTPS；");
            r.Verdict = v.ToString().TrimEnd('；');
            return r;
        }

        private static string Absolute(Uri baseUri, string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            if (s.StartsWith("//")) return baseUri.Scheme + ":" + s;
            if (Uri.TryCreate(s, UriKind.Absolute, out var abs)) return abs.ToString();
            if (Uri.TryCreate(baseUri, s, out var rel)) return rel.ToString();
            return s;
        }

        private static string Unescape(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return System.Net.WebUtility.HtmlDecode(s).Trim();
        }
    }
}
