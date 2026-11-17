using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace ReaStudio.Services
{
    internal sealed class SiteDynRequest
    {
        public string Url { get; set; } = "";
        public string Host { get; set; } = "";
        public string Method { get; set; } = "";
        public string Context { get; set; } = "";
        public int Status { get; set; }
        public bool ThirdParty { get; set; }
        public bool PlainHttp { get; set; }
        public bool SuspiciousPort { get; set; }
    }

    internal sealed class SiteDynConnection
    {
        public string Host { get; set; } = "";
        public int Count { get; set; }
        public bool ThirdParty { get; set; }
        public bool PlainHttp { get; set; }
        public bool SuspiciousPort { get; set; }
        public List<string> Contexts { get; set; } = new List<string>();
        public List<string> SampleUrls { get; set; } = new List<string>();
    }

    internal sealed class SiteDynApiCall
    {
        public string Method { get; set; } = "";
        public string Url { get; set; } = "";
        public string Host { get; set; } = "";
        public string Via { get; set; } = "";
        public long AtMs { get; set; }
        public string Body { get; set; } = "";
        public bool ThirdParty { get; set; }
        public bool HasCredential { get; set; }
    }

    internal sealed class SiteDynStorageItem
    {
        public string Area { get; set; } = "";
        public string Key { get; set; } = "";
        public string ValuePreview { get; set; } = "";
        public bool LooksSecret { get; set; }
    }

    internal sealed class SiteDynConsoleItem
    {
        public string Level { get; set; } = "";
        public long AtMs { get; set; }
        public string Text { get; set; } = "";
    }

    internal sealed class SiteDynSummary
    {
        public string FinalUrl { get; set; } = "";
        public string Title { get; set; } = "";
        public int DurationSec { get; set; }
        public long LoadMs { get; set; }
        public int Requests { get; set; }
        public int ThirdPartyHosts { get; set; }
        public int ApiCalls { get; set; }
        public int ConsoleErrors { get; set; }
        public int Cookies { get; set; }
        public int StorageKeys { get; set; }
        public int DangerousCount { get; set; }
        public long TransferBytes { get; set; }
        public List<string> Tech { get; set; } = new List<string>();
        public List<string> Signals { get; set; } = new List<string>();
        public string Verdict { get; set; } = "";
    }

    internal sealed class SiteDynReport
    {
        public bool Ok { get; set; }
        public string Error { get; set; } = "";
        public string Url { get; set; } = "";
        public string FinalUrl { get; set; } = "";
        public int Status { get; set; }
        public string Title { get; set; } = "";
        public string Mode { get; set; } = "site-dynamic";
        public int DurationSec { get; set; }
        public long Elapsed { get; set; }
        public SiteDynSummary Summary { get; set; } = new SiteDynSummary();
        public List<SiteDynConnection> Connections { get; set; } = new List<SiteDynConnection>();
        public List<SiteDynRequest> Requests { get; set; } = new List<SiteDynRequest>();
        public List<SiteDynApiCall> ApiCalls { get; set; } = new List<SiteDynApiCall>();
        public List<SiteDynStorageItem> Storage { get; set; } = new List<SiteDynStorageItem>();
        public List<SiteDynConsoleItem> Console { get; set; } = new List<SiteDynConsoleItem>();
        public List<string> Scripts { get; set; } = new List<string>();
        public List<string> Timeline { get; set; } = new List<string>();
        public List<string> Dangerous { get; set; } = new List<string>();
        public object? Dom { get; set; }
        public List<SiteEvidenceItem> Evidence { get; set; } = new List<SiteEvidenceItem>();
    }

    /// <summary>站点动态分析：在受控的内置浏览器内核中真实加载页面，记录网络请求、运行时接口调用、存储与脚本行为。</summary>
    internal static class SiteDynamic
    {
        public static bool IsRunning { get; private set; }
        private static CancellationTokenSource? _cts;

        public static void Stop()
        {
            try { _cts?.Cancel(); } catch { }
        }

        public static async Task<SiteDynReport> RunAsync(string rawUrl, int seconds, Action<string>? log)
        {
            var rep = new SiteDynReport { Url = Normalize(rawUrl) };
            if (!Uri.TryCreate(rep.Url, UriKind.Absolute, out var uri)) { rep.Error = "URL 无法解析"; return rep; }
            if (IsRunning) { rep.Error = "已有站点动态分析在执行"; return rep; }
            seconds = Math.Max(5, Math.Min(seconds, 120));
            rep.DurationSec = seconds;

            var app = Application.Current;
            if (app == null) { rep.Error = "缺少 UI 线程，无法启动内置浏览器引擎"; return rep; }

            IsRunning = true;
            var cts = new CancellationTokenSource();
            _cts = cts;
            var sw = Stopwatch.StartNew();
            var tcs = new TaskCompletionSource<SiteDynReport>(TaskCreationOptions.RunContinuationsAsynchronously);

            app.Dispatcher.InvokeAsync(new Action(async () =>
            {
                Window? win = null;
                WebView2? wv = null;
                try
                {
                    log?.Invoke("启动内置浏览器内核（隐身窗口）…");
                    win = new Window
                    {
                        Width = 1360,
                        Height = 900,
                        WindowStyle = WindowStyle.None,
                        ShowInTaskbar = false,
                        ShowActivated = false,
                        Left = -30000,
                        Top = -30000,
                        Background = Brushes.White
                    };
                    wv = new WebView2();
                    win.Content = wv;
                    win.Show();

                    var env = await Sandbox.CreateWebEnvironmentAsync();
                    await wv.EnsureCoreWebView2Async(env);
                    var core = wv.CoreWebView2;
                    // 沙箱守卫：会话级隔离数据目录、下载重定向、权限拒绝、弹窗阻断、越界协议 403
                    Sandbox.Guard(core, log);
                    core.Settings.IsStatusBarEnabled = false;
                    core.Settings.AreBrowserAcceleratorKeysEnabled = false;

                    var host = uri.Host;
                    var reqs = new List<SiteDynRequest>();
                    var statusMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var scripts = new List<string>();
                    var timeline = new List<string>();
                    long t0 = sw.ElapsedMilliseconds;
                    void Mark(string s) { if (timeline.Count < 300) timeline.Add(sw.ElapsedMilliseconds - t0 + "ms  " + s); }

                    // 过滤器已由 Sandbox.Guard 统一注册，此处只做取证记录，避免重复触发
                    core.WebResourceRequested += (s, e) =>
                    {
                        try
                        {
                            var u = e.Request.Uri;
                            if (!seenUrls.Add(u)) { }
                            var ru = new Uri(u);
                            var item = new SiteDynRequest
                            {
                                Url = u.Length > 500 ? u.Substring(0, 500) : u,
                                Host = ru.Host,
                                Method = string.IsNullOrEmpty(e.Request.Method) ? "GET" : e.Request.Method,
                                Context = e.ResourceContext.ToString(),
                                ThirdParty = !string.Equals(ru.Host, host, StringComparison.OrdinalIgnoreCase),
                                PlainHttp = ru.Scheme == "http",
                                SuspiciousPort = ru.Port != 80 && ru.Port != 443 && ru.IsDefaultPort == false
                            };
                            if (reqs.Count < 800) reqs.Add(item);
                            if (item.Context == "Script" && !scripts.Contains(ru.Host + "/" + Path.GetFileName(ru.AbsolutePath)) && scripts.Count < 60)
                                scripts.Add(ru.Host + "/" + Path.GetFileName(ru.AbsolutePath));
                        }
                        catch { }
                    };
                    core.WebResourceResponseReceived += (s, e) =>
                    {
                        try { statusMap[e.Request.Uri] = (int)e.Response.StatusCode; } catch { }
                    };

                    log?.Invoke("注入运行时探针…");
                    await core.AddScriptToExecuteOnDocumentCreatedAsync(HookScript);

                    var nav = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    core.NavigationCompleted += (s, e) =>
                    {
                        try
                        {
                            rep.Status = (int)e.HttpStatusCode;
                            Mark("导航完成 http=" + (int)e.HttpStatusCode + " success=" + e.IsSuccess);
                        }
                        catch { }
                        nav.TrySetResult(e.IsSuccess);
                    };
                    Mark("开始加载 " + rep.Url);
                    core.Navigate(rep.Url);
                    var loaded = await Task.WhenAny(nav.Task, Task.Delay(25000, cts.Token)) == nav.Task && nav.Task.Result;
                    rep.Ok = true;
                    if (!loaded) Mark("导航未在 25 秒内完成，使用当前页面状态继续");

                    // 观测阶段：让页面自己跑脚本、发请求
                    try
                    {
                        for (int i = 0; i < seconds; i++)
                        {
                            await Task.Delay(1000, cts.Token);
                            if (i == 0) log?.Invoke("持续观测页面行为…");
                        }
                    }
                    catch (TaskCanceledException) { Mark("用户停止观测"); }

                    log?.Invoke("采集运行时数据…");
                    rep.FinalUrl = core.Source;
                    var raw = await core.ExecuteScriptAsync(CaptureScript);
                    var payloadJson = JsonSerializer.Deserialize<string>(raw);
                    using var doc = JsonDocument.Parse(payloadJson ?? "{}");
                    var root = doc.RootElement;

                    rep.Title = Str(root, "title");
                    rep.FinalUrl = Str(root, "url");
                    // 注意：不能直接保存 JsonElement，其生命周期绑定在 using 的 JsonDocument 上，
                    // 文档释放后再序列化会抛 ObjectDisposedException(JsonDocument)。此处 Clone 成独立副本。
                    if (root.TryGetProperty("dom", out var domEl)) rep.Dom = domEl.Clone();

                    // 请求补齐状态码与统计
                    foreach (var r in reqs)
                        if (statusMap.TryGetValue(r.Url, out var sc)) r.Status = sc;
                    rep.Requests = reqs;
                    rep.Connections = reqs
                        .GroupBy(r => r.Host, StringComparer.OrdinalIgnoreCase)
                        .Select(g => new SiteDynConnection
                        {
                            Host = g.Key,
                            Count = g.Count(),
                            ThirdParty = g.First().ThirdParty,
                            PlainHttp = g.Any(x => x.PlainHttp),
                            SuspiciousPort = g.Any(x => x.SuspiciousPort),
                            Contexts = g.Select(x => x.Context).Distinct().Take(8).ToList(),
                            SampleUrls = g.Select(x => x.Url).Distinct().Take(3).ToList()
                        })
                        .OrderByDescending(c => c.ThirdParty).ThenByDescending(c => c.Count)
                        .Take(120).ToList();
                    rep.Scripts = scripts;

                    // 运行时接口调用
                    if (root.TryGetProperty("api", out var apiEl) && apiEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var a in apiEl.EnumerateArray())
                        {
                            var u = Str(a, "u");
                            var call = new SiteDynApiCall
                            {
                                Method = Str(a, "m"),
                                Url = u.Length > 500 ? u.Substring(0, 500) : u,
                                Via = Str(a, "via"),
                                Body = Str(a, "body"),
                                AtMs = Long(a, "t"),
                                Host = SafeHost(u),
                                ThirdParty = !string.Equals(SafeHost(u), host, StringComparison.OrdinalIgnoreCase),
                                HasCredential = RegexCredential(u) || RegexCredential(Str(a, "body"))
                            };
                            if (rep.ApiCalls.Count < 300) rep.ApiCalls.Add(call);
                        }
                    }

                    // 存储与 Cookie
                    var cookie = Str(root, "cookie");
                    foreach (var kv in WalkStorage(root, "ls", "localStorage")) rep.Storage.Add(kv);
                    foreach (var kv in WalkStorage(root, "ss", "sessionStorage")) rep.Storage.Add(kv);
                    if (!string.IsNullOrWhiteSpace(cookie))
                    {
                        foreach (var c in cookie.Split(';'))
                        {
                            var line = c.Trim();
                            if (line.Length == 0) continue;
                            var nv = line.Split('=', 2);
                            rep.Storage.Add(new SiteDynStorageItem
                            {
                                Area = "cookie(JS可见)",
                                Key = nv[0],
                                ValuePreview = nv.Length > 1 ? Preview(nv[1]) : "",
                                LooksSecret = nv[0].ToLowerInvariant().Contains("token") || nv[0].ToLowerInvariant().Contains("session") || nv[0].ToLowerInvariant().Contains("auth")
                            });
                        }
                    }

                    // 控制台与异常
                    if (root.TryGetProperty("console", out var conEl) && conEl.ValueKind == JsonValueKind.Array)
                        foreach (var c in conEl.EnumerateArray())
                            if (rep.Console.Count < 200)
                                rep.Console.Add(new SiteDynConsoleItem { Level = Str(c, "level"), AtMs = Long(c, "t"), Text = Str(c, "text") });
                    if (root.TryGetProperty("errors", out var errEl) && errEl.ValueKind == JsonValueKind.Array)
                        foreach (var c in errEl.EnumerateArray())
                            if (rep.Console.Count < 260)
                                rep.Console.Add(new SiteDynConsoleItem { Level = "uncaught", AtMs = Long(c, "t"), Text = Str(c, "msg") + " @" + Str(c, "src") });

                    // 技术指纹
                    if (root.TryGetProperty("globals", out var gEl))
                    {
                        if (Bool(gEl, "react")) rep.Summary.Tech.Add("React");
                        if (Bool(gEl, "vue")) rep.Summary.Tech.Add("Vue");
                        var jq = Str(gEl, "jquery");
                        if (!string.IsNullOrEmpty(jq)) rep.Summary.Tech.Add("jQuery " + jq);
                        if (Bool(gEl, "angular")) rep.Summary.Tech.Add("Angular");
                        if (Bool(gEl, "next")) rep.Summary.Tech.Add("Next.js");
                        if (Bool(gEl, "nuxt")) rep.Summary.Tech.Add("Nuxt");
                        if (Bool(gEl, "webpack")) rep.Summary.Tech.Add("webpack");
                        if (Bool(gEl, "gtag")) rep.Summary.Tech.Add("gtag/GA");
                        if (Bool(gEl, "sentry")) rep.Summary.Tech.Add("Sentry");
                    }

                    // 危险/可疑面
                    foreach (var r in reqs.Where(x => x.PlainHttp).Take(20)) rep.Dangerous.Add("明文 HTTP 请求：" + r.Url);
                    foreach (var a in rep.ApiCalls.Where(x => x.HasCredential).Take(20)) rep.Dangerous.Add("请求携带凭据字段：" + a.Method + " " + a.Url);
                    foreach (var a in rep.ApiCalls.Where(x => x.ThirdParty && x.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)).Take(20)) rep.Dangerous.Add("向第三方域提交数据：" + a.Host + " " + a.Url);
                    foreach (var s in rep.Storage.Where(x => x.LooksSecret).Take(20)) rep.Dangerous.Add("浏览器存储中存在敏感键：" + s.Area + "/" + s.Key);
                    foreach (var r in reqs.Where(x => x.SuspiciousPort).Take(10)) rep.Dangerous.Add("非常规端口通信：" + r.Url);
                    if (rep.Console.Any(c => c.Level == "error" || c.Level == "uncaught")) rep.Dangerous.Add("页面运行时存在脚本错误（见控制台证据）");

                    // 汇总
                    var sum = rep.Summary;
                    sum.FinalUrl = rep.FinalUrl;
                    sum.Title = rep.Title;
                    sum.DurationSec = seconds;
                    sum.LoadMs = timeline.Count > 0 ? 0 : 0;
                    sum.Requests = rep.Requests.Count;
                    sum.ThirdPartyHosts = rep.Connections.Count(c => c.ThirdParty);
                    sum.ApiCalls = rep.ApiCalls.Count;
                    sum.ConsoleErrors = rep.Console.Count(c => c.Level == "error" || c.Level == "uncaught");
                    sum.Cookies = rep.Storage.Count(s => s.Area.StartsWith("cookie"));
                    sum.StorageKeys = rep.Storage.Count(s => !s.Area.StartsWith("cookie"));
                    sum.DangerousCount = rep.Dangerous.Count;
                    sum.TransferBytes = root.TryGetProperty("res", out var resEl) && resEl.ValueKind == JsonValueKind.Array
                        ? resEl.EnumerateArray().Sum(x => Long(x, "s")) : 0;
                    sum.Signals.Add("运行时发出请求 " + sum.Requests + " 条，第三方域 " + sum.ThirdPartyHosts + " 个");
                    if (sum.ApiCalls > 0) sum.Signals.Add("脚本主动发起接口调用 " + sum.ApiCalls + " 次");
                    if (sum.Cookies > 0) sum.Signals.Add("存在 JS 可读 Cookie " + sum.Cookies + " 个（未设 HttpOnly）");
                    if (sum.StorageKeys > 0) sum.Signals.Add("localStorage/sessionStorage 共 " + sum.StorageKeys + " 个键可被脚本读取");
                    if (sum.ConsoleErrors > 0) sum.Signals.Add("控制台错误/未捕获异常 " + sum.ConsoleErrors + " 条");
                    sum.Verdict = string.Format("观测 {0} 秒：请求 {1} 条、第三方域 {2} 个、脚本接口调用 {3} 次、可疑项 {4} 项",
                        seconds, sum.Requests, sum.ThirdPartyHosts, sum.ApiCalls, sum.DangerousCount);
                    rep.Timeline = timeline;

                    BuildEvidence(rep, log);
                    Mark("采集完成");
                    log?.Invoke("站点动态分析完成");
                }
                catch (Exception ex)
                {
                    rep.Ok = false;
                    rep.Error = ex.Message;
                    Log.Write("site.dynamic: " + ex);
                    log?.Invoke("站点动态分析失败：" + ex.Message);
                }
                finally
                {
                    rep.Elapsed = sw.ElapsedMilliseconds;
                    try { wv?.Dispose(); } catch { }
                    try { win?.Close(); } catch { }
                    IsRunning = false;
                    cts.Dispose();
                    tcs.TrySetResult(rep);
                }
            }));

            return await tcs.Task.ConfigureAwait(true);
        }

        // ---------------- 证据 ----------------

        private static void BuildEvidence(SiteDynReport rep, Action<string>? log)
        {
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            void Add(string module, string title, object payload)
            {
                var json = JsonSerializer.Serialize(payload, SiteAnalyzer.J);
                var item = new SiteEvidenceItem
                {
                    Module = module,
                    Title = title,
                    Group = "站点动态",
                    Json = json,
                    Size = Encoding.UTF8.GetByteCount(json)
                };
                try
                {
                    var dir = Path.Combine(Storage.OutputRoot, stamp + "-" + module);
                    Directory.CreateDirectory(dir);
                    var f = Path.Combine(dir, "evidence.json");
                    File.WriteAllText(f, json, new UTF8Encoding(false));
                    item.EvidenceFile = f;
                    if (item.Size > 400_000) item.Json = "";
                }
                catch (Exception ex) { Log.Write("site.dyn evidence persist: " + ex.Message); }
                rep.Evidence.Add(item);
            }

            Add("site-dyn-meta", "动态观测概览", new
            {
                url = rep.Url,
                finalUrl = rep.FinalUrl,
                status = rep.Status,
                title = rep.Title,
                durationSec = rep.DurationSec,
                elapsedMs = rep.Elapsed,
                summary = new
                {
                    requests = rep.Summary.Requests,
                    thirdPartyHosts = rep.Summary.ThirdPartyHosts,
                    apiCalls = rep.Summary.ApiCalls,
                    consoleErrors = rep.Summary.ConsoleErrors,
                    transferBytes = rep.Summary.TransferBytes,
                    dangerous = rep.Summary.DangerousCount
                },
                tech = rep.Summary.Tech,
                signals = rep.Summary.Signals,
                verdict = rep.Summary.Verdict,
                timeline = rep.Timeline
            });

            Add("site-dyn-net", "动态网络请求与第三方外联", new
            {
                total = rep.Requests.Count,
                thirdPartyHosts = rep.Connections.Count(c => c.ThirdParty),
                connections = rep.Connections,
                requests = rep.Requests.Take(500).ToList()
            });

            Add("site-dyn-api", "运行时接口调用（脚本触发）", new
            {
                total = rep.ApiCalls.Count,
                withCredential = rep.ApiCalls.Count(a => a.HasCredential),
                thirdParty = rep.ApiCalls.Count(a => a.ThirdParty),
                calls = rep.ApiCalls
            });

            Add("site-dyn-storage", "浏览器存储与 Cookie（运行时可见）", new
            {
                total = rep.Storage.Count,
                cookies = rep.Storage.Count(s => s.Area.StartsWith("cookie")),
                secrets = rep.Storage.Count(s => s.LooksSecret),
                items = rep.Storage
            });

            Add("site-dyn-console", "控制台输出与运行时异常", new
            {
                total = rep.Console.Count,
                errors = rep.Console.Count(c => c.Level == "error" || c.Level == "uncaught"),
                items = rep.Console
            });

            Add("site-dyn-dom", "运行时 DOM 结构", new
            {
                dom = rep.Dom,
                scripts = rep.Scripts
            });
            log?.Invoke("已生成站点动态证据 " + rep.Evidence.Count + " 项");
        }

        // ---------------- 脚本 ----------------

        private const string HookScript = @"(function(){
  if (window.__rea_hook) return;
  var h = window.__rea_hook = { api: [], ws: [], console: [], errors: [], t0: Date.now() };
  function push(a, v){ if (a.length < 400) a.push(v); }
  function now(){ return Date.now() - h.t0; }
  try {
    var of = window.fetch;
    if (of) window.fetch = function(input, init){
      try {
        var url = typeof input === 'string' ? input : ((input && input.url) || '');
        var body = '';
        try { if (init && init.body) body = typeof init.body === 'string' ? init.body.slice(0,300) : '[non-text]'; } catch(e){}
        push(h.api, { m: ((init && init.method) || 'GET'), u: String(url), t: now(), via: 'fetch', body: body });
      } catch(e){}
      return of.apply(this, arguments);
    };
  } catch(e){}
  try {
    var ox = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(m, u){
      try { push(h.api, { m: String(m), u: String(u), t: now(), via: 'xhr', body: '' }); } catch(e){}
      return ox.apply(this, arguments);
    };
    var os = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(b){
      try { if (b && typeof b === 'string') { var last = h.api[h.api.length-1]; if (last && !last.body) last.body = b.slice(0,300); } } catch(e){}
      return os.apply(this, arguments);
    };
  } catch(e){}
  try {
    var ows = window.WebSocket;
    if (ows) {
      var nws = function(u, p){
        try { push(h.ws, { u: String(u), t: now() }); push(h.api, { m: 'WS', u: String(u), t: now(), via: 'websocket', body: '' }); } catch(e){}
        return (p === undefined) ? new ows(u) : new ows(u, p);
      };
      nws.prototype = ows.prototype;
      window.WebSocket = nws;
    }
  } catch(e){}
  try {
    ['log','warn','error','info'].forEach(function(k){
      var o = console[k];
      console[k] = function(){
        try {
          var parts = [];
          for (var i=0;i<arguments.length;i++){
            var a = arguments[i];
            if (typeof a === 'string') parts.push(a);
            else { try { parts.push(JSON.stringify(a)); } catch(e){ parts.push(String(a)); } }
          }
          push(h.console, { level: k, t: now(), text: parts.join(' ').slice(0,400) });
        } catch(e){}
        return o && o.apply(console, arguments);
      };
    });
  } catch(e){}
  try {
    window.addEventListener('error', function(e){
      try { push(h.errors, { t: now(), msg: String((e && e.message) || ''), src: String((e && e.filename) || '') }); } catch(_){}
    });
  } catch(e){}
})();";

        private const string CaptureScript = @"(function(){
  var h = window.__rea_hook || { api: [], ws: [], console: [], errors: [] };
  var ls = {}, ss = {};
  try { for (var i=0;i<localStorage.length;i++){ var k=localStorage.key(i); ls[k]=String(localStorage.getItem(k)||'').slice(0,200); } } catch(e){}
  try { for (var j=0;j<sessionStorage.length;j++){ var k2=sessionStorage.key(j); ss[k2]=String(sessionStorage.getItem(k2)||'').slice(0,200); } } catch(e){}
  var res = [];
  try {
    res = performance.getEntriesByType('resource').map(function(r){ return { n: r.name, t: r.initiatorType, s: r.transferSize||0, d: Math.round(r.duration||0) }; }).slice(0,400);
  } catch(e){}
  var g = {
    react: !!(window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__),
    vue: !!window.Vue,
    jquery: window.jQuery ? String((window.jQuery.fn && window.jQuery.fn.jquery) || '') : '',
    angular: !!window.angular,
    next: !!window.__NEXT_DATA__,
    nuxt: !!window.__NUXT__,
    webpack: !!(window.webpackJsonp || window.__webpack_require__),
    gtag: !!window.gtag,
    sentry: !!window.Sentry
  };
  return JSON.stringify({
    url: location.href,
    title: document.title,
    dom: { nodes: document.getElementsByTagName('*').length, scripts: document.scripts.length, iframes: document.getElementsByTagName('iframe').length, forms: document.forms.length, inputs: document.getElementsByTagName('input').length, images: document.images.length, links: document.links.length },
    cookie: document.cookie,
    ls: ls, ss: ss, res: res,
    api: h.api.slice(0,300), ws: h.ws.slice(0,50),
    console: h.console.slice(0,200), errors: h.errors.slice(0,50),
    globals: g
  });
})()";

        // ---------------- 工具 ----------------

        private static IEnumerable<SiteDynStorageItem> WalkStorage(JsonElement root, string prop, string area)
        {
            var list = new List<SiteDynStorageItem>();
            if (!root.TryGetProperty(prop, out var el) || el.ValueKind != JsonValueKind.Object) return list;
            foreach (var p in el.EnumerateObject())
            {
                var lower = p.Name.ToLowerInvariant();
                list.Add(new SiteDynStorageItem
                {
                    Area = area,
                    Key = p.Name.Length > 120 ? p.Name.Substring(0, 120) : p.Name,
                    ValuePreview = Preview(p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.ToString()),
                    LooksSecret = (lower.Contains("token") || lower.Contains("secret") || lower.Contains("auth") || lower.Contains("password") || lower.Contains("key") || lower.Contains("session") || lower.Contains("jwt"))
                });
            }
            return list;
        }

        private static string Preview(string v)
        {
            if (string.IsNullOrEmpty(v)) return "";
            var s = v.Length > 160 ? v.Substring(0, 160) + "…" : v;
            // 形似 JSON Web Token 或长凭据时只保留头尾
            if (s.Length > 40 && (s.Count(c => c == '.') >= 2 || s.Length > 80))
                s = s.Substring(0, 6) + "****" + s.Substring(s.Length - 4);
            return s.Replace("\r", " ").Replace("\n", " ");
        }

        private static bool RegexCredential(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            return System.Text.RegularExpressions.Regex.IsMatch(s,
                @"(?i)(token|access_token|api[_-]?key|secret|password|passwd|pwd|auth|session|sign|signature|appkey|app_key)");
        }

        private static string SafeHost(string url)
        {
            try { return new Uri(url).Host; } catch { return ""; }
        }

        private static string Normalize(string raw)
        {
            var url = (raw ?? "").Trim();
            if (url.Length == 0) return "";
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                url = "https://" + url;
            return url;
        }

        private static string Str(JsonElement el, string name)
        {
            if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v))
            {
                if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "";
                if (v.ValueKind == JsonValueKind.Number) return v.ToString();
            }
            return "";
        }

        private static long Long(JsonElement el, string name)
        {
            if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number)
                return (long)v.GetDouble();
            return 0;
        }

        private static bool Bool(JsonElement el, string name)
        {
            if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False))
                return v.GetBoolean();
            return false;
        }
    }
}
