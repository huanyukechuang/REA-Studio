using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Web.WebView2.Core;

namespace ReaStudio.Services
{
    /// <summary>一次沙箱会话：文件、网页内核数据、下载与产出全部收敛在本目录下，可整体焚毁。</summary>
    internal sealed class SandboxSession
    {
        public string Id = "";
        public string Scope = "";
        public string Root = "";
        public DateTime CreatedAt = DateTime.Now;

        public string Inbox => Path.Combine(Root, "inbox");
        public string Web => Path.Combine(Root, "web");
        public string Downloads => Path.Combine(Root, "downloads");
        public string Out => Path.Combine(Root, "out");
        public string Logs => Path.Combine(Root, "logs");
        public string LogFile => Path.Combine(Logs, "sandbox.log");
        public string MetaFile => Path.Combine(Root, "session.json");

        public void EnsureDirs()
        {
            Directory.CreateDirectory(Root);
            foreach (var d in new[] { Inbox, Web, Downloads, Out, Logs }) Directory.CreateDirectory(d);
            if (!File.Exists(MetaFile))
            {
                try
                {
                    File.WriteAllText(MetaFile,
                        "{\n  \"id\": \"" + Id + "\",\n  \"scope\": \"" + Scope + "\",\n  \"created\": \"" + CreatedAt.ToString("yyyy-MM-dd HH:mm:ss") + "\",\n  \"policy\": \"样本只读副本／网页内核数据独立／下载重定向／危险协议拦截／产出限本目录\"\n}\n");
                }
                catch { }
            }
        }
    }

    /// <summary>
    /// 应用级沙箱：为文件分析与网站分析提供隔离作业面。
    /// 1) 文件：原始样本只复制副本入沙箱，分析全程只处理副本；
    /// 2) 链接：WebView2 使用会话级独立 UserDataFolder，Cookie/缓存/存储随会话焚毁，下载强制重定向进沙箱；
    /// 3) 越界：file:// 只允许访问沙箱内文件，其余非 http(s)/data/blob 协议一律 403；
    /// 4) 产出：临时与中间文件统一落沙箱，可一键清空。
    /// </summary>
    internal static class Sandbox
    {
        private static readonly object Sync = new object();
        private static SandboxSession? _current;
        private static int _seq;

        public const int KeepSessions = 3;
        public const long StageLimitBytes = 512L * 1024 * 1024;

        /// <summary>沙箱开关；关闭时退回旧行为（不推荐）。</summary>
        public static bool Enabled { get; set; } = true;

        public static string RootDir
        {
            get
            {
                var d = Path.Combine(Storage.AppRoot, "sandbox");
                Directory.CreateDirectory(d);
                return d;
            }
        }

        public static SandboxSession? Current { get { lock (Sync) return _current; } }

        /// <summary>取当前会话；作用域不同或尚未建立时新建。</summary>
        public static SandboxSession Ensure(string scope)
        {
            lock (Sync)
            {
                if (_current != null && string.Equals(_current.Scope, scope, StringComparison.OrdinalIgnoreCase)) return _current;
                return Rotate(scope);
            }
        }

        /// <summary>强制开始新会话（旧会话目录保留，供事后回看）。</summary>
        public static SandboxSession Begin(string scope)
        {
            lock (Sync) return Rotate(scope);
        }

        private static SandboxSession Rotate(string scope)
        {
            var id = DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + (++_seq).ToString("D2");
            var s = new SandboxSession { Id = id, Scope = scope, Root = Path.Combine(RootDir, id) };
            s.EnsureDirs();
            _current = s;
            Prune();
            return s;
        }

        /// <summary>只保留最近若干会话，避免沙箱目录无限增长。</summary>
        private static void Prune()
        {
            try
            {
                var dirs = new DirectoryInfo(RootDir).GetDirectories()
                    .OrderByDescending(d => d.CreationTimeUtc).ToList();
                foreach (var d in dirs.Skip(KeepSessions))
                {
                    if (_current != null && PathsEqual(d.FullName, _current.Root)) continue;
                    try { d.Delete(true); } catch { }
                }
            }
            catch { }
        }

        /// <summary>把样本复制进沙箱，返回副本路径；失败或关闭沙箱时回退原路径。</summary>
        public static string StageFile(string path)
        {
            if (!Enabled || string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return path;
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length > StageLimitBytes)
                {
                    Log.Write("sandbox: 样本 " + fi.Length + " 字节超过暂存上限，改为原位只读分析");
                    return path;
                }
                var s = Ensure("file");
                var dst = UniquePath(s.Inbox, fi.Name);
                File.Copy(path, dst, true);
                Note(s, "样本入箱 " + path + " -> inbox\\" + Path.GetFileName(dst) + " (" + fi.Length + " B)");
                return dst;
            }
            catch (Exception ex)
            {
                Log.Write("sandbox stage: " + ex.Message);
                return path;
            }
        }

        /// <summary>把字符串内容写入沙箱（如报告 HTML、代码片段），返回沙箱内路径。</summary>
        public static string StageText(string name, string content, string sub = "")
        {
            var s = Ensure(string.IsNullOrEmpty(sub) ? "web" : sub);
            var dir = string.IsNullOrEmpty(sub) ? s.Out : Path.Combine(s.Root, sub);
            Directory.CreateDirectory(dir);
            var dst = UniquePath(dir, name);
            File.WriteAllText(dst, content, new System.Text.UTF8Encoding(false));
            return dst;
        }

        /// <summary>会话日志追加。</summary>
        public static void Note(SandboxSession? s, string text)
        {
            try
            {
                s ??= _current;
                if (s == null) return;
                lock (Sync)
                {
                    Directory.CreateDirectory(s.Logs);
                    File.AppendAllText(s.LogFile, DateTime.Now.ToString("HH:mm:ss.fff") + "  " + text + Environment.NewLine);
                }
            }
            catch { }
        }

        public static void Note(string text) => Note(_current, text);

        /// <summary>网页内核环境：会话级独立数据目录，关闭扩展/同步/后台联网。</summary>
        public static Task<CoreWebView2Environment> CreateWebEnvironmentAsync()
        {
            var s = Ensure("web");
            var opts = new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments =
                    "--disable-extensions --disable-sync --disable-background-networking --disable-component-update " +
                    "--no-first-run --disable-breakpad --disable-features=MediaRouter,OptimizationHints,Translate,AutofillServerCommunication --blink-settings=preferredColorScheme=1"
            };
            return CoreWebView2Environment.CreateAsync(null, s.Web, opts);
        }

        /// <summary>给网页内核挂隔离守卫：下载重定向、权限拒绝、弹窗阻断、危险协议拦截。</summary>
        public static void Guard(CoreWebView2 core, Action<string>? log)
        {
            var s = Ensure("web");
            try
            {
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.AreHostObjectsAllowed = false;
                core.Settings.IsWebMessageEnabled = false;
                core.Settings.IsStatusBarEnabled = false;
                core.Settings.AreBrowserAcceleratorKeysEnabled = false;
            }
            catch { }

            core.DownloadStarting += (o, e) =>
            {
                try
                {
                    var name = string.IsNullOrEmpty(e.ResultFilePath) ? "download.bin" : Path.GetFileName(e.ResultFilePath);
                    var target = UniquePath(s.Downloads, name);
                    e.ResultFilePath = target;
                    e.Handled = true; // 由沙箱接管落盘，不在宿主任意位置留文件
                    Note(s, "接管下载 downloads\\" + Path.GetFileName(target) + " <- " + Clip(e.DownloadOperation?.Uri, 200));
                    log?.Invoke("沙箱接管下载：" + Path.GetFileName(target));
                }
                catch (Exception ex)
                {
                    try { e.Cancel = true; } catch { }
                    Log.Write("sandbox download: " + ex.Message);
                }
            };

            core.PermissionRequested += (o, e) =>
            {
                try
                {
                    e.State = CoreWebView2PermissionState.Deny;
                    Note(s, "拒绝权限 " + e.PermissionKind + " <- " + Clip(e.Uri, 160));
                }
                catch { }
            };

            core.NewWindowRequested += (o, e) =>
            {
                try
                {
                    e.Handled = true; // 不开宿主窗口，避免逃逸出沙箱会话
                    Note(s, "阻断弹窗 " + Clip(e.Uri, 160));
                    log?.Invoke("沙箱阻断弹窗：" + Clip(e.Uri, 120));
                }
                catch { }
            };

            try
            {
                core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
                core.WebResourceRequested += (o, e) => BlockUnsafe(core, e, s, log);
            }
            catch (Exception ex) { Log.Write("sandbox filter: " + ex.Message); }
        }

        private static void BlockUnsafe(CoreWebView2 core, CoreWebView2WebResourceRequestedEventArgs e, SandboxSession s, Action<string>? log)
        {
            try
            {
                var uri = new Uri(e.Request.Uri);
                var scheme = uri.Scheme.ToLowerInvariant();
                bool allowed = scheme == "http" || scheme == "https" || scheme == "data" || scheme == "blob" || scheme == "about";
                if (!allowed && scheme == "file") allowed = IsInsideSandbox(uri.LocalPath);
                if (allowed) return;

                e.Response = core.Environment.CreateWebResourceResponse(null, 403, "Blocked by REA Sandbox", "Content-Type: text/plain");
                Note(s, "拦截越界请求 " + Clip(e.Request.Uri, 220));
                log?.Invoke("沙箱拦截越界协议：" + scheme);
            }
            catch { }
        }

        /// <summary>沙箱内的 HTTP 客户端：禁代理残留、限超时，供静态抓取复用。</summary>
        public static HttpClient CreateHttpClient(int timeoutSec = 20)
        {
            var h = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                AutomaticDecompression = DecompressionMethods.All,
                UseCookies = true,
                CookieContainer = new CookieContainer()
            };
            var c = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(timeoutSec) };
            c.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36");
            c.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            c.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
            return c;
        }

        /// <summary>清空全部沙箱会话目录，返回释放的会话数与字节数。</summary>
        public static (int removed, long freed) Purge()
        {
            int n = 0; long freed = 0;
            try
            {
                lock (Sync)
                {
                    foreach (var d in new DirectoryInfo(RootDir).GetDirectories())
                    {
                        try
                        {
                            var size = SizeOf(d.FullName);
                            d.Delete(true);
                            n++; freed += size;
                        }
                        catch { }
                    }
                    _current = null;
                }
                Log.Write("sandbox purged: " + n + " sessions, " + freed + " bytes");
            }
            catch (Exception ex) { Log.Write("sandbox purge: " + ex.Message); }
            return (n, freed);
        }

        public static object Status()
        {
            var s = _current;
            long total = SizeOf(RootDir);
            int sessions = 0;
            try { sessions = new DirectoryInfo(RootDir).GetDirectories().Length; } catch { }
            return new
            {
                enabled = Enabled,
                active = s != null,
                id = s?.Id ?? "",
                scope = s?.Scope ?? "",
                root = s?.Root ?? RootDir,
                inbox = s?.Inbox ?? "",
                web = s?.Web ?? "",
                downloads = s?.Downloads ?? "",
                output = s?.Out ?? "",
                created = s?.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                files = s == null ? 0 : CountFiles(s.Root),
                bytes = s == null ? 0L : SizeOf(s.Root),
                sessions,
                totalBytes = total,
                keep = KeepSessions
            };
        }

        public static bool IsInsideSandbox(string fullPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(fullPath)) return false;
                var root = Path.GetFullPath(RootDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                var p = Path.GetFullPath(fullPath);
                return p.StartsWith(root, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static bool PathsEqual(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar), Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }

        private static string UniquePath(string dir, string fileName)
        {
            Directory.CreateDirectory(dir);
            if (string.IsNullOrWhiteSpace(fileName)) fileName = "file.bin";
            foreach (var ch in Path.GetInvalidFileNameChars()) fileName = fileName.Replace(ch, '_');
            var name = Path.GetFileNameWithoutExtension(fileName);
            var ext = Path.GetExtension(fileName);
            var candidate = Path.Combine(dir, fileName);
            int i = 1;
            while (File.Exists(candidate) || Directory.Exists(candidate))
            {
                candidate = Path.Combine(dir, name + "-" + i.ToString("D2") + ext);
                i++;
            }
            return candidate;
        }

        private static int CountFiles(string dir)
        {
            try { return Directory.Exists(dir) ? Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Length : 0; }
            catch { return 0; }
        }

        private static long SizeOf(string dir)
        {
            try
            {
                if (!Directory.Exists(dir)) return 0;
                long sum = 0;
                foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                {
                    try { sum += new FileInfo(f).Length; } catch { }
                }
                return sum;
            }
            catch { return 0; }
        }

        private static string Clip(string? s, int n)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s!.Length <= n ? s : s.Substring(0, n) + "…";
        }
    }
}
