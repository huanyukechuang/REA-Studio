using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    /// <summary>一项站点分析证据（结构与静态分析的 evidence 项对齐，便于统一在证据页展示）。</summary>
    internal sealed class SiteEvidenceItem
    {
        public string Module { get; set; } = "";
        public string Title { get; set; } = "";
        public string Group { get; set; } = "";
        public string Json { get; set; } = "";
        public string EvidenceFile { get; set; } = "";
        public long Size { get; set; }
        public long Elapsed { get; set; }
    }

    internal sealed class SiteSummary
    {
        public string FinalUrl { get; set; } = "";
        public int Status { get; set; }
        public string Title { get; set; } = "";
        public bool IsHttps { get; set; }
        public long HtmlBytes { get; set; }
        public int JsFiles { get; set; }
        public long JsBytes { get; set; }
        public int InlineScripts { get; set; }
        public int ApiEndpoints { get; set; }
        public int Secrets { get; set; }
        public int ExternalHosts { get; set; }
        public int MissingHeaders { get; set; }
        public int UnsafeCookies { get; set; }
        public int Forms { get; set; }
        public List<string> Tech { get; set; } = new List<string>();
        public List<string> Signals { get; set; } = new List<string>();
        public string Verdict { get; set; } = "";
    }

    internal sealed class SiteStaticReport
    {
        public bool Ok { get; set; }
        public string Error { get; set; } = "";
        public string Url { get; set; } = "";
        public string FinalUrl { get; set; } = "";
        public int Status { get; set; }
        public string Title { get; set; } = "";
        public string Mode { get; set; } = "site-static";
        public long Elapsed { get; set; }
        public SiteSummary Summary { get; set; } = new SiteSummary();
        public List<SiteEvidenceItem> Evidence { get; set; } = new List<SiteEvidenceItem>();
    }

    /// <summary>站点静态分析：不执行页面脚本，仅由 HTML/JS 文本还原站点结构、接口面、凭据泄露与配置弱点。</summary>
    internal static class SiteAnalyzer
    {
        private static readonly HttpClient Client = Sandbox.CreateHttpClient(20);

        internal static readonly JsonSerializerOptions J = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public static async Task<SiteStaticReport> AnalyzeAsync(string rawUrl, Action<string>? log)
        {
            var sw = Stopwatch.StartNew();
            var rep = new SiteStaticReport();
            string url = Normalize(rawUrl);
            if (url.Length == 0) { rep.Error = "URL 为空"; return rep; }
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) { rep.Error = "URL 无法解析"; return rep; }
            rep.Url = uri.ToString();
            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");

            try
            {
                log?.Invoke("站点静态分析：抓取 " + uri.Host);
                using var req = new HttpRequestMessage(HttpMethod.Get, uri);
                using var resp = await Client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
                var bytes = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                if (bytes.Length > 6 * 1024 * 1024) bytes = bytes.Take(6 * 1024 * 1024).ToArray();
                var html = Decode(bytes, resp.Content.Headers.ContentType?.CharSet);

                rep.Ok = true;
                rep.Status = (int)resp.StatusCode;
                rep.FinalUrl = (resp.RequestMessage?.RequestUri ?? uri).ToString();
                var baseUri = resp.RequestMessage?.RequestUri ?? uri;
                var head = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var h in resp.Headers) head[h.Key] = string.Join(" ; ", h.Value);
                // Content-* 头挂在 Content 上，需要单独合并
                foreach (var h in resp.Content.Headers) head[h.Key] = string.Join(" ; ", h.Value);

                var title = Clean(One(html, @"<title[^>]*>(.*?)</title>"));
                rep.Title = title;
                rep.Summary.FinalUrl = rep.FinalUrl;
                rep.Summary.Status = rep.Status;
                rep.Summary.Title = title;
                rep.Summary.IsHttps = string.Equals(baseUri.Scheme, "https", StringComparison.OrdinalIgnoreCase);
                rep.Summary.HtmlBytes = bytes.Length;

                log?.Invoke("解析页面结构…");
                AddEvidence(rep, stamp, "site-meta", "站点页面概况", "站点静态", JsonSerializer.Serialize(BuildMeta(html, head, baseUri, bytes.Length), J), sw);

                log?.Invoke("解析脚本与资源…");
                var res = BuildResources(html, baseUri);
                AddEvidence(rep, stamp, "site-resources", "脚本与资源清单", "站点静态", res.Json, sw);

                log?.Invoke("下载同源脚本用于接口与凭据提取…");
                var js = await FetchScriptsAsync(res.SameOriginScripts, log).ConfigureAwait(false);
                rep.Summary.JsFiles = js.Fetched.Count;
                rep.Summary.JsBytes = js.Bytes;
                rep.Summary.InlineScripts = res.InlineScripts.Count;

                log?.Invoke("解析 DOM 与表单面…");
                var dom = BuildDom(html, res);
                rep.Summary.Forms = dom.Forms.Count;
                AddEvidence(rep, stamp, "site-dom", "DOM 结构与表单提交面", "站点静态", dom.Json, sw);

                log?.Invoke("提取接口与端点…");
                var api = BuildApi(html, res, js, baseUri);
                rep.Summary.ApiEndpoints = api.Total;
                AddEvidence(rep, stamp, "site-api", "接口与端点提取", "站点静态", api.Json, sw);

                log?.Invoke("扫描敏感信息…");
                var secrets = BuildSecrets(html, res, js);
                rep.Summary.Secrets = secrets.Total;
                AddEvidence(rep, stamp, "site-secrets", "敏感信息与凭据", "站点静态", secrets.Json, sw);

                log?.Invoke("检查安全响应头与 Cookie…");
                var hdr = BuildHeaders(head, html);
                rep.Summary.MissingHeaders = hdr.Missing.Count;
                rep.Summary.UnsafeCookies = hdr.UnsafeCount;
                AddEvidence(rep, stamp, "site-headers", "安全响应头与 Cookie 属性", "站点静态", hdr.Json, sw);

                log?.Invoke("识别技术栈与合规信号…");
                var tech = BuildTech(html, head, res, js);
                rep.Summary.Tech = tech.Tech;
                rep.Summary.Signals = tech.Signals;
                rep.Summary.ExternalHosts = res.ExternalHosts.Count;
                AddEvidence(rep, stamp, "site-tech", "技术指纹与合规信号", "站点静态", tech.Json, sw);

                rep.Summary.Verdict = string.Format(
                    "识别 {0} 个接口端点、{1} 处疑似敏感信息；第三方域 {2} 个；缺失 {3} 项安全响应头；{4} 个 Cookie 属性不全；同源脚本 {5} 个（{6}）",
                    rep.Summary.ApiEndpoints, rep.Summary.Secrets, rep.Summary.ExternalHosts,
                    rep.Summary.MissingHeaders, rep.Summary.UnsafeCookies, rep.Summary.JsFiles, Human(rep.Summary.JsBytes));
            }
            catch (Exception ex)
            {
                rep.Ok = false;
                rep.Error = ex.Message;
                Log.Write("site.static: " + ex);
            }
            rep.Elapsed = sw.ElapsedMilliseconds;
            log?.Invoke("站点静态分析完成：" + rep.Evidence.Count + " 项证据");
            return rep;
        }

        // ---------------- 模块构建 ----------------

        private static object BuildMeta(string html, Dictionary<string, string> head, Uri baseUri, long bytes)
        {
            var metas = new Dictionary<string, string>();
            foreach (Match m in Regex.Matches(html, @"(?is)<meta[^>]+name\s*=\s*[""']([^""']+)[""'][^>]*>"))
            {
                var name = m.Groups[1].Value.Trim().ToLowerInvariant();
                var cm = Regex.Match(m.Value, @"(?is)content\s*=\s*[""']([^""']*)[""']");
                if (!metas.ContainsKey(name)) metas[name] = Clean(cm.Success ? cm.Groups[1].Value : "");
            }
            foreach (Match m in Regex.Matches(html, @"(?is)<meta[^>]+property\s*=\s*[""'](og:[^""']+)[""'][^>]*>"))
            {
                var cm = Regex.Match(m.Value, @"(?is)content\s*=\s*[""']([^""']*)[""']");
                if (cm.Success) metas[m.Groups[1].Value.Trim().ToLowerInvariant()] = Clean(cm.Groups[1].Value);
            }
            var canonical = Clean(AttrValue(html, @"<link[^>]+rel\s*=\s*[""'][^""']*canonical[^""']*[""'][^>]*>", "href"));
            var lang = Clean(AttrValue(html, @"<html[^>]*>", "lang"));
            var charset = One(html, @"(?i)<meta[^>]+charset\s*=\s*[""']?([a-zA-Z0-9\-]+)");
            return new
            {
                url = baseUri.ToString(),
                status = (int?)null,
                htmlBytes = bytes,
                title = Clean(One(html, @"<title[^>]*>(.*?)</title>")),
                lang,
                charset,
                canonical,
                meta = metas,
                serverHeaders = head.Where(k => k.Key.Equals("server", StringComparison.OrdinalIgnoreCase)
                    || k.Key.Equals("x-powered-by", StringComparison.OrdinalIgnoreCase)
                    || k.Key.Equals("via", StringComparison.OrdinalIgnoreCase)
                    || k.Key.StartsWith("x-aspnet", StringComparison.OrdinalIgnoreCase)
                    || k.Key.StartsWith("x-generator", StringComparison.OrdinalIgnoreCase))
                    .ToDictionary(k => k.Key, v => v.Value),
                allHeaders = head
            };
        }

        private sealed class ResourceSet
        {
            public List<string> Scripts { get; } = new List<string>();
            public List<string> SameOriginScripts { get; } = new List<string>();
            public List<string> Styles { get; } = new List<string>();
            public List<string> InlineScripts { get; } = new List<string>();
            public List<string> Iframes { get; } = new List<string>();
            public List<string> Images { get; } = new List<string>();
            public List<string> ExternalHosts { get; set; } = new List<string>();
            public List<string> SameHosts { get; } = new List<string>();
            public string Json { get; set; } = "";
        }

        private static ResourceSet BuildResources(string html, Uri baseUri)
        {
            var r = new ResourceSet();
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Match m in Regex.Matches(html, @"(?is)<script[^>]+src\s*=\s*[""']([^""']+)[""']"))
            {
                var abs = Absolute(baseUri, m.Groups[1].Value);
                r.Scripts.Add(abs);
                if (Uri.TryCreate(abs, UriKind.Absolute, out var u))
                {
                    hosts.Add(u.Host);
                    if (string.Equals(u.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)) r.SameOriginScripts.Add(abs);
                    else r.ExternalHosts.Add(u.Host);
                }
            }
            foreach (Match m in Regex.Matches(html, @"(?is)<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>"))
            {
                var code = m.Groups[1].Value;
                if (string.IsNullOrWhiteSpace(code)) continue;
                r.InlineScripts.Add(code.Length > 20000 ? code.Substring(0, 20000) : code);
            }
            foreach (Match m in Regex.Matches(html, @"(?is)<link[^>]+rel\s*=\s*[""'][^""']*stylesheet[^""']*[""'][^>]*>"))
            {
                var href = AttrValue(m.Value, "<link[^>]*>", "href");
                if (string.IsNullOrEmpty(href)) continue;
                var abs = Absolute(baseUri, href);
                r.Styles.Add(abs);
                if (Uri.TryCreate(abs, UriKind.Absolute, out var u)) hosts.Add(u.Host);
            }
            foreach (Match m in Regex.Matches(html, @"(?is)<iframe[^>]+src\s*=\s*[""']([^""']+)[""']"))
            {
                var abs = Absolute(baseUri, m.Groups[1].Value);
                r.Iframes.Add(abs);
                if (Uri.TryCreate(abs, UriKind.Absolute, out var u) && !string.Equals(u.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)) r.ExternalHosts.Add(u.Host);
            }
            foreach (Match m in Regex.Matches(html, @"(?is)<img[^>]+src\s*=\s*[""']([^""']+)[""']"))
            {
                var abs = Absolute(baseUri, m.Groups[1].Value);
                if (r.Images.Count < 200) r.Images.Add(abs);
                if (Uri.TryCreate(abs, UriKind.Absolute, out var u) && !string.Equals(u.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)) r.ExternalHosts.Add(u.Host);
            }
            foreach (var h in hosts)
            {
                if (string.Equals(h, baseUri.Host, StringComparison.OrdinalIgnoreCase)) r.SameHosts.Add(h);
            }
            r.ExternalHosts = r.ExternalHosts.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();

            r.Json = JsonSerializer.Serialize(new
            {
                scriptCount = r.Scripts.Count,
                sameOriginScripts = r.Scripts.Count,
                externalScripts = r.Scripts.Count(s => r.ExternalHosts.Any(h => s.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0)),
                inlineScriptCount = r.InlineScripts.Count,
                scripts = r.Scripts.Take(80).ToList(),
                sameOrigin = r.SameOriginScripts.Take(40).ToList(),
                styles = r.Styles.Take(60).ToList(),
                iframes = r.Iframes.Take(40).ToList(),
                images = r.Images.Take(60).ToList(),
                externalHosts = r.ExternalHosts,
                inlineScriptPreview = r.InlineScripts.Take(6).Select((s, i) => new { index = i, length = s.Length, head = s.Length > 600 ? s.Substring(0, 600) : s }).ToList()
            }, J);
            return r;
        }

        private sealed class JsBundle
        {
            public Dictionary<string, string> Fetched { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public long Bytes { get; set; }
        }

        private static async Task<JsBundle> FetchScriptsAsync(List<string> scripts, Action<string>? log)
        {
            var b = new JsBundle();
            var targets = scripts.Take(10).ToList();
            foreach (var s in targets)
            {
                try
                {
                    using var resp = await Client.GetAsync(s, HttpCompletionOption.ResponseContentRead).ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode) continue;
                    var buf = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                    if (buf.Length > 1500000) buf = buf.Take(1500000).ToArray();
                    b.Bytes += buf.Length;
                    b.Fetched[s] = Encoding.UTF8.GetString(buf);
                }
                catch { /* 单个脚本失败不影响整体 */ }
            }
            log?.Invoke("已分析同源脚本 " + b.Fetched.Count + " 个（" + Human(b.Bytes) + "）");
            return b;
        }

        private sealed class DomInfo
        {
            public List<object> Forms { get; } = new List<object>();
            public string Json { get; set; } = "";
        }

        private static DomInfo BuildDom(string html, ResourceSet res)
        {
            var d = new DomInfo();
            var tags = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in Regex.Matches(html, @"(?is)<([a-zA-Z][a-zA-Z0-9]*)"))
            {
                var t = m.Groups[1].Value.ToLowerInvariant();
                tags[t] = tags.TryGetValue(t, out var c) ? c + 1 : 1;
            }
            var dangerous = new List<string>();
            if (Regex.IsMatch(html, @"(?i)\beval\s*\(")) dangerous.Add("存在 eval() 动态执行");
            if (Regex.IsMatch(html, @"(?i)document\.write\s*\(")) dangerous.Add("存在 document.write()");
            if (Regex.IsMatch(html, @"(?i)new\s+Function\s*\(")) dangerous.Add("存在 new Function() 动态构造");
            if (Regex.IsMatch(html, @"(?i)innerHTML\s*=")) dangerous.Add("存在 innerHTML 赋值（XSS 注入面）");
            if (Regex.IsMatch(html, @"(?i)postMessage\s*\(")) dangerous.Add("使用 postMessage 跨窗口通信");
            if (Regex.IsMatch(html, @"(?i)atob\s*\(|unescape\s*\(|fromCharCode")) dangerous.Add("存在编码解码/字符串混淆调用");

            foreach (Match m in Regex.Matches(html, @"(?is)<form[^>]*>"))
            {
                var action = AttrValue(m.Value, "<form[^>]*>", "action");
                var method = AttrValue(m.Value, "<form[^>]*>", "method");
                var start = m.Index;
                var end = html.IndexOf("</form>", start, StringComparison.OrdinalIgnoreCase);
                var seg = end > start ? html.Substring(start, Math.Min(end - start, 20000)) : "";
                var inputs = Regex.Matches(seg, @"(?is)<input[^>]*>").Cast<Match>()
                    .Select(x => new
                    {
                        name = Clean(AttrValue(x.Value, "<input[^>]*>", "name")),
                        type = Clean(AttrValue(x.Value, "<input[^>]*>", "type")).ToLowerInvariant(),
                        autocomplete = Clean(AttrValue(x.Value, "<input[^>]*>", "autocomplete"))
                    })
                    .Where(x => !string.IsNullOrEmpty(x.name))
                    .Take(30).ToList();
                d.Forms.Add(new
                {
                    action = string.IsNullOrEmpty(action) ? "(当前页)" : action,
                    method = string.IsNullOrEmpty(method) ? "get" : method.ToLowerInvariant(),
                    enctype = Clean(AttrValue(m.Value, "<form[^>]*>", "enctype")),
                    hasPassword = inputs.Any(i => i.type == "password"),
                    hasFileUpload = inputs.Any(i => i.type == "file"),
                    hasCsrfToken = inputs.Any(i => i.name.ToLowerInvariant().Contains("csrf") || i.name.ToLowerInvariant().Contains("token")),
                    inputs
                });
            }

            d.Json = JsonSerializer.Serialize(new
            {
                nodeCount = tags.Values.Sum(),
                tagTop = tags.OrderByDescending(k => k.Value).Take(24).Select(k => new { tag = k.Key, count = k.Value }).ToList(),
                counts = new
                {
                    script = tags.TryGetValue("script", out var sc) ? sc : 0,
                    form = tags.TryGetValue("form", out var fm) ? fm : 0,
                    iframe = tags.TryGetValue("iframe", out var ifr) ? ifr : 0,
                    img = tags.TryGetValue("img", out var im) ? im : 0,
                    a = tags.TryGetValue("a", out var a) ? a : 0,
                    input = tags.TryGetValue("input", out var ip) ? ip : 0,
                    video = tags.TryGetValue("video", out var vd) ? vd : 0,
                    canvas = tags.TryGetValue("canvas", out var cv) ? cv : 0
                },
                forms = d.Forms,
                hiddenElements = Regex.Matches(html, @"(?is)<input[^>]+type\s*=\s*[""']hidden[""']").Count,
                comments = Regex.Matches(html, @"(?s)<!--(.*?)-->").Count,
                inlineEventHandlers = Regex.Matches(html, @"(?i)\son(click|load|error|mouseover)\s*=").Count,
                dangerousPatterns = dangerous,
                iframes = res.Iframes.Take(20).ToList()
            }, J);
            return d;
        }

        private sealed class ApiInfo
        {
            public int Total { get; set; }
            public string Json { get; set; } = "";
        }

        private static ApiInfo BuildApi(string html, ResourceSet res, JsBundle js, Uri baseUri)
        {
            var endpoints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // url -> 来源

            void Scan(string text, string origin)
            {
                if (string.IsNullOrEmpty(text)) return;
                void Add(string v)
                {
                    v = Clean(v);
                    if (v.Length < 2 || v.Length > 400) return;
                    if (v.StartsWith("data:", StringComparison.OrdinalIgnoreCase) || v.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)) return;
                    if (v.EndsWith(".png") || v.EndsWith(".jpg") || v.EndsWith(".gif") || v.EndsWith(".svg") || v.EndsWith(".woff") || v.EndsWith(".woff2") || v.EndsWith(".ttf") || v.EndsWith(".css")) return;
                    if (!endpoints.ContainsKey(v)) endpoints[v] = origin;
                }
                foreach (Match m in Regex.Matches(text, @"(?i)(?:fetch|axios(?:\.\w+)?|\$\.ajax|\$\.get|\$\.post|XMLHttpRequest|request)\s*\(\s*['""`]([^'""`\s]{2,400})['""`]"))
                    Add(m.Groups[1].Value);
                foreach (Match m in Regex.Matches(text, @"(?i)['""`](/api/[A-Za-z0-9_\-/{}.$:]{1,180})['""`]"))
                    Add(m.Groups[1].Value);
                foreach (Match m in Regex.Matches(text, @"['""`](/(?:v\d|rest|graphql|service|gateway|admin|user|auth|login|upload)[A-Za-z0-9_\-/]{1,120})['""`]"))
                    Add(m.Groups[1].Value);
                foreach (Match m in Regex.Matches(text, @"(?i)['""`](https?://[a-z0-9\.\-]{4,80}(?::\d{2,5})?/[^'""`\s]{0,200})['""`]"))
                    Add(m.Groups[1].Value);
                foreach (Match m in Regex.Matches(text, @"(?i)(wss?://[^'""`\s]{4,200})"))
                    Add(m.Groups[1].Value);
                foreach (Match m in Regex.Matches(text, @"\.open\s*\(\s*['""](GET|POST|PUT|DELETE|PATCH)['""]\s*,\s*['""]([^'""\s]{2,300})['""]", RegexOptions.IgnoreCase))
                    Add(m.Groups[2].Value);
            }

            Scan(html, "页面 HTML");
            foreach (var item in res.InlineScripts) Scan(item, "内联脚本");
            foreach (var kv in js.Fetched) Scan(kv.Value, ShortName(kv.Key));

            var list = endpoints.Select(kv => new
            {
                value = kv.Key,
                source = kv.Value,
                kind = kv.Key.StartsWith("ws", StringComparison.OrdinalIgnoreCase) ? "websocket"
                    : (kv.Key.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? "absolute" : "path"),
                thirdParty = kv.Key.StartsWith("http", StringComparison.OrdinalIgnoreCase) &&
                             Uri.TryCreate(kv.Key, UriKind.Absolute, out var u) &&
                             !string.Equals(u.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase),
                sensitive = Regex.IsMatch(kv.Key, @"(?i)(admin|debug|export|backup|internal|test|upload|delete|token|key|passwd|password|login|auth)")
            })
            .OrderByDescending(x => x.sensitive).ThenBy(x => x.value)
            .Take(400).ToList();

            return new ApiInfo
            {
                Total = endpoints.Count,
                Json = JsonSerializer.Serialize(new
                {
                    total = endpoints.Count,
                    absolute = list.Count(x => x.kind == "absolute"),
                    relative = list.Count(x => x.kind == "path"),
                    websocket = list.Count(x => x.kind == "websocket"),
                    thirdParty = list.Count(x => x.thirdParty),
                    sensitive = list.Count(x => x.sensitive),
                    endpoints = list
                }, J)
            };
        }

        private sealed class SecretInfo
        {
            public int Total { get; set; }
            public string Json { get; set; } = "";
        }

        private static SecretInfo BuildSecrets(string html, ResourceSet res, JsBundle js)
        {
            var hits = new List<object>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var patterns = new (string kind, string pattern, int group, string risk)[]
            {
                ("AWS AccessKey", @"AKIA[0-9A-Z]{16}", 0, "高"),
                ("Google API Key", @"AIza[0-9A-Za-z\-_]{35}", 0, "高"),
                ("私钥块", @"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0, "高"),
                ("JWT", @"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}", 0, "中"),
                ("阿里云 AccessKey", @"LTAI[0-9A-Za-z]{12,20}", 0, "高"),
                ("腾讯云 SecretId", @"AKID[0-9A-Za-z]{13,40}", 0, "高"),
                ("通用密钥赋值", @"(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|app[_-]?secret|secret|token|password|passwd|pwd)\s*[:=]\s*['""]([^'""\s]{6,120})['""]", 1, "中"),
                ("内网地址", @"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?::\d{2,5})?\b", 0, "中"),
                ("Bearer 头", @"(?i)bearer\s+[A-Za-z0-9\-_\.=]{12,200}", 0, "中"),
                ("邮箱", @"[A-Za-z0-9._%\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", 0, "低"),
                ("手机号", @"(?<!\d)1[3-9]\d{9}(?!\d)", 0, "低"),
                ("身份证号", @"(?<!\d)\d{17}[\dXx](?!\d)", 0, "高")
            };

            void Scan(string text, string origin)
            {
                if (string.IsNullOrEmpty(text)) return;
                foreach (var p in patterns)
                {
                    foreach (Match m in Regex.Matches(text, p.pattern))
                    {
                        var val = m.Groups[p.group].Value;
                        if (string.IsNullOrWhiteSpace(val)) continue;
                        var key = p.kind + "|" + val;
                        if (!seen.Add(key)) continue;
                        if (hits.Count >= 200) return;
                        var idx = m.Index;
                        var ctx = text.Substring(Math.Max(0, idx - 40), Math.Min(80, text.Length - Math.Max(0, idx - 40))).Replace("\r", " ").Replace("\n", " ");
                        hits.Add(new
                        {
                            kind = p.kind,
                            value = Mask(val),
                            length = val.Length,
                            risk = p.risk,
                            origin,
                            context = Clean(ctx)
                        });
                    }
                }
            }

            Scan(html, "页面 HTML");
            foreach (var item in res.InlineScripts) Scan(item, "内联脚本");
            foreach (var kv in js.Fetched) Scan(kv.Value, ShortName(kv.Key));

            return new SecretInfo
            {
                Total = hits.Count,
                Json = JsonSerializer.Serialize(new
                {
                    total = hits.Count,
                    high = hits.Count(h => (string)h.GetType().GetProperty("risk")!.GetValue(h)! == "高"),
                    medium = hits.Count(h => (string)h.GetType().GetProperty("risk")!.GetValue(h)! == "中"),
                    low = hits.Count(h => (string)h.GetType().GetProperty("risk")!.GetValue(h)! == "低"),
                    note = "命中值为掩码后的片段，仅用于定位与复核，不代表可直接使用的凭据",
                    hits
                }, J)
            };
        }

        private sealed class HeaderInfo
        {
            public List<string> Missing { get; set; } = new List<string>();
            public List<object> Cookies { get; set; } = new List<object>();
            public int UnsafeCount { get; set; }
            public string Json { get; set; } = "";
        }

        private static HeaderInfo BuildHeaders(Dictionary<string, string> head, string html)
        {
            var expected = new[]
            {
                ("content-security-policy", "缺少 CSP，页面注入面缺少兜底限制"),
                ("x-frame-options", "缺少 X-Frame-Options，存在被 iframe 嵌入风险"),
                ("x-content-type-options", "缺少 X-Content-Type-Options，存在 MIME 嗅探风险"),
                ("strict-transport-security", "缺少 HSTS，可被降级到明文传输"),
                ("referrer-policy", "缺少 Referrer-Policy，外链会携带来源信息"),
                ("permissions-policy", "缺少 Permissions-Policy，摄像头/麦克风等能力未显式限制")
            };
            var info = new HeaderInfo();
            var items = new List<object>();
            foreach (var (name, desc) in expected)
            {
                var has = head.TryGetValue(name, out var val);
                if (!has) info.Missing.Add(desc);
                items.Add(new { header = name, present = has, value = has ? val : "" });
            }

            if (head.TryGetValue("set-cookie", out var sc) && !string.IsNullOrWhiteSpace(sc))
            {
                // WebView/HttpClient 把多个 Set-Cookie 合并成一串，用属性名白名单切回单条 Cookie
                var attrNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "path","domain","expires","max-age","secure","httponly","samesite","priority","partitioned","version","comment" };
                string? curName = null;
                var flags = new Dictionary<string, (bool secure, bool httpOnly, string sameSite)>(StringComparer.OrdinalIgnoreCase);
                foreach (var seg in sc.Split(';'))
                {
                    var line = seg.Trim();
                    if (line.Length == 0) continue;
                    var nv = line.Split('=', 2);
                    var key = nv[0].Trim();
                    if (!attrNames.Contains(key) && nv.Length >= 2)
                    {
                        curName = key;
                        if (!flags.ContainsKey(key)) flags[key] = (false, false, "");
                        continue;
                    }
                    if (curName == null) continue;
                    var f = flags[curName];
                    if (key.Equals("secure", StringComparison.OrdinalIgnoreCase)) f.secure = true;
                    else if (key.Equals("httponly", StringComparison.OrdinalIgnoreCase)) f.httpOnly = true;
                    else if (key.Equals("samesite", StringComparison.OrdinalIgnoreCase) && nv.Length >= 2) f.sameSite = nv[1].Trim();
                    flags[curName] = f;
                }
                foreach (var kv in flags)
                {
                    if (!kv.Value.secure || !kv.Value.httpOnly) info.UnsafeCount++;
                    info.Cookies.Add(new
                    {
                        name = kv.Key,
                        secure = kv.Value.secure,
                        httpOnly = kv.Value.httpOnly,
                        sameSite = kv.Value.sameSite
                    });
                }
            }
            info.Json = JsonSerializer.Serialize(new
            {
                missingCount = info.Missing.Count,
                missing = info.Missing,
                unsafeCookies = info.UnsafeCount,
                headers = items,
                cookies = info.Cookies,
                server = head.TryGetValue("server", out var sv) ? sv : "",
                poweredBy = head.TryGetValue("x-powered-by", out var pb) ? pb : "",
                hasHttpsHint = html.Contains("https://", StringComparison.OrdinalIgnoreCase)
            }, J);
            return info;
        }

        private sealed class TechInfo
        {
            public List<string> Tech { get; set; } = new List<string>();
            public List<string> Signals { get; set; } = new List<string>();
            public string Json { get; set; } = "";
        }

        private static TechInfo BuildTech(string html, Dictionary<string, string> head, ResourceSet res, JsBundle js)
        {
            var t = new TechInfo();
            var all = html.Length > 2000000 ? html.Substring(0, 2000000) : html;
            void Hit(string name, bool cond) { if (cond && !t.Tech.Contains(name)) t.Tech.Add(name); }

            Hit("React", all.Contains("data-reactroot") || all.Contains("react.production.min.js") || all.Contains("__REACT_DEVTOOLS"));
            Hit("Vue", all.Contains("vue.min.js") || all.Contains("vue.global") || Regex.IsMatch(all, @"data-v-[0-9a-f]{6}"));
            Hit("Angular", all.Contains("ng-version") || all.Contains("angular.min.js"));
            Hit("jQuery", all.Contains("jquery"));
            Hit("Bootstrap", all.Contains("bootstrap.min.css") || all.Contains("bootstrap.min.js"));
            Hit("Next.js", all.Contains("_next/static"));
            Hit("Nuxt", all.Contains("__NUXT__") || all.Contains("_nuxt/"));
            Hit("Vite", all.Contains("/@vite/") || all.Contains("type=\"module\""));
            Hit("WordPress", all.Contains("wp-content") || all.Contains("wp-includes"));
            Hit("Element UI", all.Contains("el-button") || all.Contains("element-ui"));
            Hit("Ant Design", all.Contains("ant-btn") || all.Contains("antd"));
            Hit("Tailwind CSS", all.Contains("tailwind"));
            Hit("Google Analytics", all.Contains("googletagmanager") || all.Contains("gtag(") || all.Contains("ga("));
            Hit("百度统计", all.Contains("hm.baidu.com"));
            Hit("Sentry", all.Contains("sentry"));
            Hit("webpack", all.Contains("__webpack_require__") || all.Contains("webpackJsonp"));
            Hit("axios", all.Contains("axios"));
            Hit("ECharts", all.Contains("echarts"));
            Hit("Swagger/OpenAPI", all.Contains("swagger-ui") || all.Contains("openapi"));

            if (head.TryGetValue("server", out var sv) && sv.Length > 0) t.Tech.Add("Server: " + sv);
            if (head.TryGetValue("x-powered-by", out var pb) && pb.Length > 0) t.Tech.Add("X-Powered-By: " + pb);
            var gen = One(all, @"(?is)<meta[^>]+name\s*=\s*[""']generator[""'][^>]+content\s*=\s*[""']([^""']*)");
            if (!string.IsNullOrEmpty(gen)) t.Tech.Add("Generator: " + Clean(gen));

            var s = t.Signals;
            if (Regex.IsMatch(all, @"(?i)(隐私政策|privacy policy|个人信息保护)")) s.Add("页面声明隐私政策");
            if (Regex.IsMatch(all, @"(?i)(ICP|备案号|公安备案)")) s.Add("含 ICP/备案信息");
            if (Regex.IsMatch(all, @"(?i)(用户协议|terms of service)")) s.Add("含用户协议");
            if (Regex.IsMatch(all, @"(?i)(console\.log|debugger)")) s.Add("页面残留调试代码");
            if (Regex.IsMatch(all, @"(?i)(\.map[""'`\s])|sourceMappingURL")) s.Add("发布环境残留 SourceMap 引用");
            if (Regex.IsMatch(all, @"(?i)内部|仅供内部|test\.html|测试环境")) s.Add("页面出现内部/测试环境字样");
            if (res.ExternalHosts.Count >= 8) s.Add("第三方外部域偏多（" + res.ExternalHosts.Count + " 个）");
            if (js.Fetched.Count == 0 && res.Scripts.Count > 0) s.Add("外链脚本未能取回，接口/凭据结论仅覆盖页面内联部分");

            t.Json = JsonSerializer.Serialize(new
            {
                techCount = t.Tech.Count,
                tech = t.Tech,
                signals = s,
                externalHostCount = res.ExternalHosts.Count,
                externalHosts = res.ExternalHosts,
                analyzedScripts = js.Fetched.Keys.Select(ShortName).ToList()
            }, J);
            return t;
        }

        // ---------------- 工具 ----------------

        private static void AddEvidence(SiteStaticReport rep, string stamp, string module, string title, string group, string json, Stopwatch sw)
        {
            var item = new SiteEvidenceItem
            {
                Module = module,
                Title = title,
                Group = group,
                Json = json,
                Size = Encoding.UTF8.GetByteCount(json ?? ""),
                Elapsed = sw.ElapsedMilliseconds
            };
            try
            {
                var dir = Path.Combine(Storage.OutputRoot, stamp + "-" + module);
                Directory.CreateDirectory(dir);
                var f = Path.Combine(dir, "evidence.json");
                File.WriteAllText(f, json ?? "{}", new UTF8Encoding(false));
                item.EvidenceFile = f;
                if (item.Size > 400_000) item.Json = "";   // 超大证据只留文件，前端用 evidence.peek 按需读取
            }
            catch (Exception ex) { Log.Write("site.evidence persist: " + ex.Message); }
            rep.Evidence.Add(item);
        }

        private static string Normalize(string raw)
        {
            var url = (raw ?? "").Trim();
            if (url.Length == 0) return "";
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                url = "https://" + url;
            return url;
        }

        private static string Decode(byte[] bytes, string? charset)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(charset))
                {
                    var enc = Encoding.GetEncoding(charset.Trim('"', '\'', ' '));
                    return enc.GetString(bytes);
                }
            }
            catch { }
            var utf8 = Encoding.UTF8.GetString(bytes);
            var m = Regex.Match(utf8, @"(?i)charset\s*=\s*[""']?([a-zA-Z0-9\-]+)");
            if (m.Success)
            {
                try { return Encoding.GetEncoding(m.Groups[1].Value).GetString(bytes); } catch { }
            }
            return utf8;
        }

        private static string One(string text, string pattern)
        {
            var m = Regex.Match(text ?? "", pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
            return m.Success ? m.Groups[1].Value : "";
        }

        private static string AttrValue(string tag, string tagPattern, string attr)
        {
            if (string.IsNullOrEmpty(tag)) return "";
            var m = Regex.Match(tag, @"(?is)\b" + attr + @"\s*=\s*(?:""([^""]*)""|'([^']*)')");
            if (!m.Success) return "";
            return m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
        }

        private static string Absolute(Uri baseUri, string value)
        {
            var v = (value ?? "").Trim();
            if (v.Length == 0) return "";
            if (v.StartsWith("data:", StringComparison.OrdinalIgnoreCase) || v.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)) return "";
            try
            {
                if (v.StartsWith("//", StringComparison.Ordinal)) return baseUri.Scheme + ":" + v;
                if (Uri.TryCreate(baseUri, v, out var abs)) return abs.ToString();
            }
            catch { }
            return v;
        }

        private static string Clean(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var t = Regex.Replace(s, @"\s+", " ").Trim();
            if (t.Length > 2000) t = t.Substring(0, 2000);
            return t.Replace("<", "‹").Replace(">", "›");
        }

        private static string Mask(string v)
        {
            if (string.IsNullOrEmpty(v)) return "";
            if (v.Length <= 8) return v.Substring(0, 1) + "****";
            return v.Substring(0, 4) + "****" + v.Substring(v.Length - 4);
        }

        private static string ShortName(string url)
        {
            try
            {
                var u = new Uri(url);
                var name = Path.GetFileName(u.AbsolutePath);
                return string.IsNullOrEmpty(name) ? u.Host : u.Host + "/" + name;
            }
            catch { return url.Length > 90 ? url.Substring(0, 90) : url; }
        }

        private static string Human(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return v.ToString("0.##") + " " + units[i];
        }
    }
}
