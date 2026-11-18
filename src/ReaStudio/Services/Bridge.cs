using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace ReaStudio.Services
{
    internal sealed class Bridge
    {
        private readonly MainWindow _window;
        private readonly CoreWebView2 _core;
        private CancellationTokenSource? _analysisCts;
        private static readonly SemaphoreSlim Throttle = new SemaphoreSlim(4);

        public Bridge(MainWindow window, CoreWebView2 core)
        {
            _window = window;
            _core = core;
        }

        private void Send(object payload) => _window.PostJson(payload);

        // WebView2 铺满客户区，鼠标按下发生在子 HWND 内，WPF 侧没有左键捕获状态，
        // 直接调用 Window.DragMove() 必然抛异常并被吞掉（表现为窗口拖不动）。
        // 改为交还 Win32：ReleaseCapture + WM_NCLBUTTONDOWN/HTCAPTION 由系统接管拖动。
        [DllImport("user32.dll")]
        private static extern bool ReleaseCapture();
        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
        private const int WM_NCLBUTTONDOWN = 0x00A1;
        private const int HTCAPTION = 0x0002;

        private void BeginSystemDrag()
        {
            _window.Dispatcher.Invoke(() =>
            {
                try
                {
                    var hwnd = new System.Windows.Interop.WindowInteropHelper(_window).Handle;
                    if (hwnd == IntPtr.Zero) return;
                    ReleaseCapture();
                    SendMessage(hwnd, WM_NCLBUTTONDOWN, (IntPtr)HTCAPTION, IntPtr.Zero);
                }
                catch (Exception ex) { Log.Write("drag: " + ex.Message); }
            });
        }

        /// <summary>切换最大化/还原；最大化时切换回普通状态并保持标题栏比例。</summary>
        private void ToggleMaximize()
        {
            _window.Dispatcher.Invoke(() =>
            {
                _window.WindowState = _window.WindowState == WindowState.Maximized
                    ? WindowState.Normal : WindowState.Maximized;
            });
        }

        private void Reply(string id, object? result) => Send(new { id, ok = true, result });
        private void Fail(string id, string error) => Send(new { id, ok = false, error });
        private void Event(string name, object? data) => Send(new { @event = name, data });

        public async void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            string raw;
            try { raw = e.WebMessageAsJson; }
            catch { return; }

            string id = "", method = "";
            JsonElement paramsEl = default;
            try
            {
                using var doc = JsonDocument.Parse(string.IsNullOrEmpty(raw) ? "{}" : raw);
                var root = doc.RootElement;
                if (root.TryGetProperty("id", out var idEl)) id = idEl.GetString() ?? "";
                if (root.TryGetProperty("method", out var mEl)) method = mEl.GetString() ?? "";
                if (root.TryGetProperty("params", out var pEl)) paramsEl = pEl.Clone();
            }
            catch (Exception ex) { Log.Write("bad message: " + ex.Message); return; }

            try
            {
                switch (method)
                {
                    case "app.status":
                        Reply(id, AppStatus());
                        break;
                    case "target.pick":
                        Reply(id, PickFile());
                        break;
                    case "target.info":
                        Reply(id, DescribePath(Str(paramsEl, "path")));
                        break;
                    case "target.paths":
                        // 拖入/粘贴文件时由 postMessageWithAdditionalObjects 附带 File 对象，
                        // 从 e.AdditionalObjects 取 CoreWebView2File.Path（不依赖已移除的 File.path）
                        Reply(id, AdditionalPaths(e));
                        break;
                    case "modules.list":
                        Reply(id, Modules.ForFile(Str(paramsEl, "path")).Select(m => m.ToDto()).ToArray());
                        break;
                    case "analysis.run":
                        await StartAnalysis(id, paramsEl).ConfigureAwait(false);
                        break;
                    case "analysis.cancel":
                        _analysisCts?.Cancel();
                        Reply(id, new { cancelled = true });
                        break;
                    case "settings.get":
                        Reply(id, AiService.Load());
                        break;
                    case "settings.set":
                        {
                            // 前端提交的是 camelCase（localModel / contextSize …）。System.Text.Json 默认大小写敏感，
                            // 直接 Deserialize<AiSettings> 会把所有字段丢成默认值（LocalModel 被清空），
                            // 于是"用户已选择模型"变成"未检测到模型"。这里必须用 camelCase + 大小写不敏感，
                            // 并且只在请求里出现过的键上覆盖，避免部分提交把其它设置冲掉。
                            try
                            {
                                var merged = MergeSettings(AiService.Load(), paramsEl);
                                AiService.Save(merged);
                                Log.Write("[settings] saved model=\"" + merged.LocalModel + "\" mode=" + merged.Mode);
                                Reply(id, AiService.Settings);
                            }
                            catch (Exception ex) { Fail(id, "设置保存失败：" + ex.Message); }
                            break;
                        }
                    case "model.status":
                        Reply(id, ModelStore.Status());
                        break;
                    case "model.catalog":
                        Reply(id, await ModelStore.CatalogAsync().ConfigureAwait(false));
                        break;
                    case "model.repo":
                        {
                            try { Reply(id, await ModelStore.RepoFilesAsync(Str(paramsEl, "repo")).ConfigureAwait(false)); }
                            catch (Exception ex) { Fail(id, ex.Message); }
                            break;
                        }
                    case "model.download":
                        {
                            var repo = Str(paramsEl, "repo");
                            var file = Str(paramsEl, "file");
                            Log.Write("[model] download " + repo + " / " + file);
                            ModelStore.StartDownload(repo, file, data => Event("model.progress", data));
                            Reply(id, new { started = true });
                            break;
                        }
                    case "model.cancel":
                        ModelStore.Cancel();
                        Reply(id, new { cancelled = true });
                        break;
                    case "model.apply":
                        {
                            try { Reply(id, ModelStore.Apply(Str(paramsEl, "path"))); }
                            catch (Exception ex) { Fail(id, ex.Message); }
                            break;
                        }
                    case "model.remove":
                        {
                            try { Reply(id, ModelStore.Remove(Str(paramsEl, "file"))); }
                            catch (Exception ex) { Fail(id, ex.Message); }
                            break;
                        }
                    case "model.openDir":
                        {
                            var d = ModelStore.UserModelDir;
                            try { Directory.CreateDirectory(d); System.Diagnostics.Process.Start("explorer.exe", "\"" + d + "\""); } catch { }
                            Reply(id, d);
                            break;
                        }
                    case "model.pick":
                        {
                            var dlg = new Microsoft.Win32.OpenFileDialog
                            {
                                Title = "选择本地 GGUF 模型文件",
                                Filter = "GGUF 模型 (*.gguf)|*.gguf|所有文件 (*.*)|*.*",
                                CheckFileExists = true,
                                Multiselect = false
                            };
                            var modelDir = Storage.ModelDir;
                            if (!string.IsNullOrEmpty(modelDir) && Directory.Exists(modelDir)) dlg.InitialDirectory = modelDir;
                            if (dlg.ShowDialog() != true) { Reply(id, new { cancelled = true }); break; }
                            var fi = new FileInfo(dlg.FileName);
                            Reply(id, new
                            {
                                cancelled = false,
                                path = dlg.FileName,
                                name = fi.Name,
                                size = fi.Length,
                                sizeText = (fi.Length / 1048576.0).ToString("F1") + " MB"
                            });
                            break;
                        }
                    case "ai.start":
                        {
                            Log.Write("[ai] start: engine=" + Storage.LlamaServer + " | modelDir=" + Storage.ModelDir + " | model=" + AiService.Settings.LocalModel);
                            var ok = await AiService.StartLocalAsync(t => { Event("ai.log", t); Log.Write("[ai] " + t); }).ConfigureAwait(false);
                            Log.Write("[ai] start result=" + ok);
                            Reply(id, new { ok, status = AiStatus() });
                            break;
                        }
                    case "ai.stop":
                        AiService.StopLocal();
                        Reply(id, AiStatus());
                        break;
                    case "ai.status":
                        Reply(id, AiStatus());
                        break;
                    case "ai.chat":
                        {
                            var msgs = new List<ChatMsg>();
                            if (paramsEl.TryGetProperty("messages", out var arr))
                                foreach (var m in arr.EnumerateArray())
                                    msgs.Add(new ChatMsg
                                    {
                                        Role = m.TryGetProperty("role", out var r) ? r.GetString() ?? "user" : "user",
                                        Content = m.TryGetProperty("content", out var c) ? c.GetString() ?? "" : ""
                                    });
                            // 流式：正文增量走 ai.delta，实时 token 统计走 ai.stats，结束后再回整体结果
                            Action<string> onDelta = t => Event("ai.delta", new { text = t });
                            Action<AiService.ChatStats> onStats = s => Event("ai.stats", new
                            {
                                promptTokens = s.PromptTokens,
                                completionTokens = s.CompletionTokens,
                                prefillMs = Math.Round(s.PrefillMs, 1),
                                decodeMs = Math.Round(s.DecodeMs, 1),
                                prefillTps = Math.Round(s.PrefillTps, 1),
                                decodeTps = Math.Round(s.DecodeTps, 1),
                                finish = s.Finish
                            });
                            var streamed = await AiService.ChatStreamAsync(msgs, onDelta, onStats).ConfigureAwait(false);
                            Log.Write("[ai] chat ok len=" + (streamed.Content ?? "").Length);
                            Reply(id, new
                            {
                                content = streamed.Content,
                                stats = new
                                {
                                    promptTokens = streamed.Stats.PromptTokens,
                                    completionTokens = streamed.Stats.CompletionTokens,
                                    prefillMs = Math.Round(streamed.Stats.PrefillMs, 1),
                                    decodeMs = Math.Round(streamed.Stats.DecodeMs, 1),
                                    prefillTps = Math.Round(streamed.Stats.PrefillTps, 1),
                                    decodeTps = Math.Round(streamed.Stats.DecodeTps, 1),
                                    finish = streamed.Stats.Finish
                                }
                            });
                            break;
                        }
                    case "log.write":
                        {
                            var uiMsg = Str(paramsEl, "msg");
                            if (!string.IsNullOrEmpty(uiMsg)) Log.Write("[ui] " + uiMsg);
                            Reply(id, true);
                            break;
                        }
                    case "window.min":
                        _window.Dispatcher.Invoke(() => _window.WindowState = WindowState.Minimized);
                        Reply(id, true); break;
                    case "window.max":
                        ToggleMaximize();
                        Reply(id, true); break;
                    case "window.close":
                        _window.Dispatcher.Invoke(() => _window.Close());
                        break;
                    case "window.drag":
                        BeginSystemDrag();
                        Reply(id, true); break;
                    case "shell.reveal":
                        {
                            var p = Str(paramsEl, "path");
                            if (File.Exists(p)) { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + p + "\""); Reply(id, true); }
                            else if (Directory.Exists(p)) { System.Diagnostics.Process.Start("explorer.exe", "\"" + p + "\""); Reply(id, true); }
                            else Fail(id, "路径不存在");
                            break;
                        }
                    case "report.export":
                        {
                            var input = new ReportInput
                            {
                                TargetPath = Str(paramsEl, "path"),
                                ItemsJson = paramsEl.TryGetProperty("items", out var itemsEl) ? itemsEl.GetRawText() : "[]",
                                TypesJson = RawOrString(paramsEl, "types"),
                                NetworkJson = RawOrString(paramsEl, "network"),
                                SiteJson = RawOrString(paramsEl, "site"),
                                AiText = Str(paramsEl, "ai"),
                                DynamicJson = RawOrString(paramsEl, "dynamic"),
                                VirusJson = BuildVirusJson(paramsEl),
                                VulnJson = BuildVulnJson(paramsEl),
                                Format = Str(paramsEl, "format"),
                                Scope = Str(paramsEl, "scope")
                            };
                            if (string.IsNullOrEmpty(input.Format)) input.Format = "md";
                            var file = await Reports.ExportAsync(input).ConfigureAwait(true);
                            if (file == null) { Fail(id, "报告生成失败，请检查目标与分析结果"); break; }
                            Reply(id, new { path = file, name = Path.GetFileName(file), format = Path.GetExtension(file).TrimStart('.').ToLowerInvariant() });
                            break;
                        }
                    case "types.detect":
                        {
                            var list = BinaryTypes.Detect(Str(paramsEl, "path"));
                            Reply(id, Camel(list.Select(t => new { id = t.Id, name = t.Name, confidence = t.Confidence, evidence = t.Evidence, modules = t.Modules }).ToArray()));
                            break;
                        }
                    case "net.analyze":
                        Reply(id, Camel(NetworkIntel.AnalyzeFile(Str(paramsEl, "path"))));
                        break;
                    case "dynamic.run":
                        {
                            var dp = Str(paramsEl, "path");
                            var secs = paramsEl.TryGetProperty("seconds", out var se) ? se.GetInt32() : 12;
                            if (DynamicAnalyzer.IsRunning) { Fail(id, "已有动态分析在执行，请先停止"); break; }
                            Event("dynamic.isolation", new { level = DynIsolation.CurrentLevel() == DynIsolation.LevelRestricted ? "L2 受限级" : "L1 受控级" });
                            var res = await Task.Run(() => DynamicAnalyzer.Run(dp, secs, t => Event("dynamic.log", t))).ConfigureAwait(true);
                            if (res.Ok) Event("dynamic.done", new { ok = true, isolation = res.IsolationLevel, work = res.WorkDirectory, connections = res.Connections.Count, files = res.Files.Count, registry = res.Registry.Count, chain = res.Chain.Count, dangerous = res.DangerousCount });
                            Reply(id, Camel(res));
                            break;
                        }
                    case "dynamic.stop":
                        DynamicAnalyzer.Stop();
                        Reply(id, new { stopped = true });
                        break;
                    case "dynamic.status":
                        Reply(id, new { running = DynamicAnalyzer.IsRunning });
                        break;
                    case "dynamic.capability":
                        Reply(id, Camel(DynIsolation.Capability()));
                        break;
                    case "web.recon":
                        {
                            var url = Str(paramsEl, "url");
                            if (!IsWebTarget(url)) { Fail(id, "仅支持 http/https 目标"); break; }
                            Sandbox.Ensure("site");
                            Reply(id, Camel(await WebRecon.ReconAsync(url).ConfigureAwait(true)));
                            break;
                        }
                    case "site.static":
                        {
                            var url = Str(paramsEl, "url");
                            if (string.IsNullOrWhiteSpace(url)) { Fail(id, "请先填写站点 URL"); break; }
                            if (!IsWebTarget(url)) { Fail(id, "仅支持 http/https 目标"); break; }
                            Sandbox.Ensure("site");
                            var rep = await SiteAnalyzer.AnalyzeAsync(url, t => Event("site.log", t)).ConfigureAwait(true);
                            if (!rep.Ok) { Reply(id, Camel(rep)); break; }
                            Event("site.done", new { mode = "static", evidence = rep.Evidence.Count, endpoints = rep.Summary.ApiEndpoints });
                            Reply(id, Camel(rep));
                            break;
                        }
                    case "site.dynamic":
                        {
                            var url = Str(paramsEl, "url");
                            if (string.IsNullOrWhiteSpace(url)) { Fail(id, "请先填写站点 URL"); break; }
                            if (!IsWebTarget(url)) { Fail(id, "仅支持 http/https 目标"); break; }
                            Sandbox.Ensure("site");
                            var secs = paramsEl.TryGetProperty("seconds", out var se) ? se.GetInt32() : 12;
                            if (SiteDynamic.IsRunning) { Fail(id, "已有站点动态分析在执行，请先停止"); break; }
                            var rep = await SiteDynamic.RunAsync(url, secs, t => Event("site.log", t)).ConfigureAwait(true);
                            if (rep.Ok) Event("site.done", new { mode = "dynamic", evidence = rep.Evidence.Count, requests = rep.Summary.Requests });
                            Reply(id, Camel(rep));
                            break;
                        }
                    case "site.dynamic.stop":
                        SiteDynamic.Stop();
                        Reply(id, new { stopped = true });
                        break;
                    case "site.dynamic.status":
                        Reply(id, new { running = SiteDynamic.IsRunning });
                        break;
                    case "sandbox.status":
                        Reply(id, Sandbox.Status());
                        break;
                    case "sandbox.begin":
                        {
                            var scope = Str(paramsEl, "scope");
                            if (string.IsNullOrWhiteSpace(scope)) scope = "web";
                            Sandbox.Begin(scope);
                            Reply(id, Sandbox.Status());
                            break;
                        }
                    case "sandbox.toggle":
                        {
                            var on = !paramsEl.TryGetProperty("enabled", out var enEl) || enEl.ValueKind == JsonValueKind.True;
                            Sandbox.Enabled = on;
                            Reply(id, Sandbox.Status());
                            break;
                        }
                    case "sandbox.purge":
                        {
                            var (removed, freed) = Sandbox.Purge();
                            Reply(id, new { removed, freed, status = Sandbox.Status() });
                            break;
                        }
                    case "sandbox.open":
                        {
                            var dir = Sandbox.Current?.Root ?? Sandbox.RootDir;
                            Directory.CreateDirectory(dir);
                            try
                            {
                                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", "\"" + dir + "\"") { UseShellExecute = true });
                            }
                            catch (Exception ex) { Log.Write("sandbox open: " + ex.Message); }
                            Reply(id, new { path = dir });
                            break;
                        }
                    case "virus.status":
                        Reply(id, Camel(VirusDb.Status()));
                        break;
                    case "virus.rules":
                        {
                            var take = paramsEl.TryGetProperty("take", out var tr) ? tr.GetInt32() : 200;
                            Reply(id, Camel(VirusDb.TopRules(take)));
                            break;
                        }
                    case "virus.hashes":
                        {
                            var take = paramsEl.TryGetProperty("take", out var th) ? th.GetInt32() : 200;
                            Reply(id, Camel(VirusDb.TopHashes(take)));
                            break;
                        }
                    case "virus.import":
                        {
                            var files = PickFiles("导入病毒库（哈希清单 / YARA 规则）", "病毒库文件 (*.json;*.csv;*.txt;*.yar;*.yara)|*.json;*.csv;*.txt;*.yar;*.yara|全部文件 (*.*)|*.*");
                            if (files.Length == 0) { Reply(id, new { cancelled = true, status = VirusDb.Status() }); break; }
                            var (hashes, rules, err) = VirusDb.ImportFiles(files);
                            Reply(id, new { cancelled = false, hashes, rules, error = err, files = files.Length, status = VirusDb.Status() });
                            break;
                        }
                    case "virus.online":
                        {
                            var url = Str(paramsEl, "url");
                            if (string.IsNullOrWhiteSpace(url)) { Fail(id, "请填写威胁情报地址"); break; }
                            if (!IsWebTarget(url)) { Fail(id, "仅支持 http/https 地址"); break; }
                            var label = Str(paramsEl, "label");
                            var r = await VirusDb.UpdateFromUrlAsync(url, label).ConfigureAwait(true);
                            Reply(id, new { added = r.added, total = r.total, error = r.error, status = VirusDb.Status() });
                            break;
                        }
                    case "virus.threatbook":
                        {
                            var apiKey = Str(paramsEl, "apiKey");
                            if (string.IsNullOrWhiteSpace(apiKey)) { Fail(id, "请填写微步 API Key"); break; }
                            var hashText = Str(paramsEl, "hashes") ?? "";
                            var hashes = hashText.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();
                            if (hashes.Count == 0 && LastVirus != null)
                            {
                                if (!string.IsNullOrWhiteSpace(LastVirus.Sha256)) hashes.Add(LastVirus.Sha256);
                                if (!string.IsNullOrWhiteSpace(LastVirus.Md5)) hashes.Add(LastVirus.Md5);
                            }
                            var tr2 = await VirusDb.SyncFromThreatBookAsync(apiKey, hashes, t => Event("virus.log", t)).ConfigureAwait(true);
                            Reply(id, new { queried = tr2.queried, added = tr2.added, total = tr2.total, error = tr2.error, status = VirusDb.Status() });
                            break;
                        }
                    case "virus.clear":
                        {
                            var n = VirusDb.ClearImported();
                            Reply(id, new { removed = n, status = VirusDb.Status() });
                            break;
                        }
                    case "virus.open":
                        {
                            var dir = VirusDb.Dir;
                            try
                            {
                                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", "\"" + dir + "\"") { UseShellExecute = true });
                            }
                            catch (Exception ex) { Log.Write("virus open: " + ex.Message); }
                            Reply(id, new { path = dir });
                            break;
                        }
                    case "virus.scan":
                        {
                            var vp = Str(paramsEl, "path");
                            if (string.IsNullOrWhiteSpace(vp) || !File.Exists(vp)) { Fail(id, "样本不存在"); break; }
                            var vr = await VirusDb.ScanAsync(vp, t => Event("virus.log", t)).ConfigureAwait(true);
                            if (vr.Ok) LastVirus = vr;
                            Reply(id, Camel(vr));
                            break;
                        }
                    case "vuln.status":
                        Reply(id, Camel(VulnDb.Status()));
                        break;
                    case "vuln.rules":
                        {
                            var take = paramsEl.TryGetProperty("take", out var tr) ? tr.GetInt32() : 200;
                            Reply(id, Camel(VulnDb.TopRules(take)));
                            break;
                        }
                    case "vuln.import":
                        {
                            var files = PickFiles("导入 CVE 库（CSV / JSON）", "CVE 库文件 (*.json;*.csv;*.txt)|*.json;*.csv;*.txt|全部文件 (*.*)|*.*");
                            if (files.Length == 0) { Reply(id, new { cancelled = true, status = VulnDb.Status() }); break; }
                            var (added, total, err) = VulnDb.ImportFiles(files);
                            Reply(id, new { cancelled = false, added, total, error = err, files = files.Length, status = VulnDb.Status() });
                            break;
                        }
                    case "vuln.online":
                        {
                            var source = (Str(paramsEl, "source") ?? "").Trim().ToLowerInvariant();
                            // 默认采用国家信息安全漏洞库（CNNVD），NVD 作为备选
                            var isCnnvd = source != "nvd";
                            var kw = Str(paramsEl, "keyword");
                            if (!isCnnvd && string.IsNullOrWhiteSpace(kw)) { Fail(id, "请填写组件关键词，多个用逗号分隔"); break; }
                            var apiKey = Str(paramsEl, "apiKey");
                            var max = 200;
                            var maxRaw = Str(paramsEl, "max");
                            if (!string.IsNullOrWhiteSpace(maxRaw)) int.TryParse(maxRaw.Trim(), out max);
                            if (max <= 0) max = 200;
                            if (max > 500) max = 500;
                            var r = await VulnDb.UpdateFromSourceAsync(isCnnvd ? "cnnvd" : "nvd", kw, apiKey, max, t => Event("vuln.log", t)).ConfigureAwait(true);
                            Reply(id, new { added = r.added, total = r.total, error = r.error, status = VulnDb.Status() });
                            break;
                        }
                    case "vuln.clear":
                        {
                            var n = VulnDb.ClearImported();
                            Reply(id, new { removed = n, status = VulnDb.Status() });
                            break;
                        }
                    case "vuln.open":
                        {
                            var dir = VulnDb.Dir;
                            try
                            {
                                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", "\"" + dir + "\"") { UseShellExecute = true });
                            }
                            catch (Exception ex) { Log.Write("vuln open: " + ex.Message); }
                            Reply(id, new { path = dir });
                            break;
                        }
                    case "vuln.scan":
                        {
                            var vp = Str(paramsEl, "path");
                            if (string.IsNullOrWhiteSpace(vp) || !File.Exists(vp)) { Fail(id, "样本不存在"); break; }
                            var vr = await VulnDb.ScanAsync(vp, t => Event("vuln.log", t)).ConfigureAwait(true);
                            if (vr.Ok) LastVuln = vr;
                            Reply(id, Camel(vr));
                            break;
                        }
                    case "evidence.peek":
                        {
                            var p = Str(paramsEl, "path");
                            var max = paramsEl.TryGetProperty("maxChars", out var mc) ? mc.GetInt32() : 300000;
                            if (!File.Exists(p)) { Fail(id, "证据文件不存在"); break; }
                            using var fs = File.OpenRead(p);
                            var buf = new byte[Math.Min(max, fs.Length)];
                            var n = fs.Read(buf, 0, buf.Length);
                            Reply(id, new { total = fs.Length, text = System.Text.Encoding.UTF8.GetString(buf, 0, n) });
                            break;
                        }
                    default:
                        Fail(id, "未知方法: " + method);
                        break;
                }
            }
            catch (Exception ex)
            {
                Log.Write("bridge " + method + ": " + ex);
                Fail(id, ex.Message);
            }
        }

        /// <summary>最近一次病毒检测结果，供报告导出兜底引用。</summary>
        public static VirusScanResult? LastVirus;

        /// <summary>最近一次漏洞（CVE）检测结果，供报告导出兜底引用。</summary>
        public static VulnScanResult? LastVuln;

        private static readonly JsonSerializerOptions CamelOpt = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, IncludeFields = true };
        private static JsonElement Camel(object o) => JsonSerializer.SerializeToElement(o, CamelOpt);

        /// <summary>前端设置补丁的读取选项：camelCase 且大小写不敏感，防止 camelCase 提交被静默丢弃。</summary>
        private static readonly JsonSerializerOptions PatchOpt = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };

        /// <summary>
        /// 把前端提交的设置补丁合并到当前设置上：只覆盖补丁里真实出现过的键，
        /// 未提交的字段保留磁盘原值。规避"保存一次就丢模型路径"这类致命问题。
        /// </summary>
        private static AiSettings MergeSettings(AiSettings current, JsonElement patch)
        {
            current ??= new AiSettings();
            JsonObject node;
            try { node = JsonSerializer.SerializeToNode(current, PatchOpt)?.AsObject() ?? new JsonObject(); }
            catch { node = new JsonObject(); }

            if (patch.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in patch.EnumerateObject())
                {
                    if (p.Value.ValueKind == JsonValueKind.Null) continue;
                    try { node[p.Name] = JsonNode.Parse(p.Value.GetRawText()); }
                    catch { /* 单个字段异常不影响整体保存 */ }
                }
            }

            try { return node.Deserialize<AiSettings>(PatchOpt) ?? current; }
            catch { return current; }
        }

        /// <summary>报告所需的病毒检测结果：优先取前端传入的本次结果，缺失时回退最近一次检测。</summary>
        private static string BuildVirusJson(JsonElement p)
        {
            try
            {
                if (p.TryGetProperty("virus", out var v) && v.ValueKind == JsonValueKind.Object) return v.GetRawText();
            }
            catch { }
            var last = LastVirus;
            return last == null ? "" : JsonSerializer.Serialize(last, CamelOpt);
        }

        /// <summary>报告所需的漏洞检测结果：优先取前端传入的本次结果，缺失时回退最近一次检测。</summary>
        private static string BuildVulnJson(JsonElement p)
        {
            try
            {
                if (p.TryGetProperty("vuln", out var v) && v.ValueKind == JsonValueKind.Object) return v.GetRawText();
            }
            catch { }
            var last = LastVuln;
            return last == null ? "" : JsonSerializer.Serialize(last, CamelOpt);
        }

        private static string RawOrString(JsonElement el, string name)
        {
            if (!el.TryGetProperty(name, out var v)) return "";
            if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "";
            if (v.ValueKind == JsonValueKind.Null || v.ValueKind == JsonValueKind.Undefined) return "";
            return v.GetRawText();
        }

        private object AppStatus() => new
        {
            app = "REA Studio",
            version = typeof(Bridge).Assembly.GetName().Version?.ToString(3) ?? "1.1.0",
            payloadReady = Storage.PayloadReady,
            payloadKind = Storage.PayloadKind,
            runtimeRoot = Storage.RuntimeRoot,
            node = Storage.NodeExe,
            rea = Storage.ReaEntry,
            llama = Storage.LlamaServer,
            modelDir = Storage.ModelDir,
            evidenceDir = Storage.OutputRoot,
            sandbox = Sandbox.Status(),
            ai = AiStatus()
        };

        private object AiStatus() => new
        {
            mode = AiService.Settings.Mode,
            localRunning = AiService.LocalReady,
            engine = File.Exists(Storage.LlamaServer),
            model = AiService.ResolveModelPath(),
            endpoint = AiService.LocalEndpoint
        };

        public static object? DescribePath(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
                var fi = new FileInfo(path);
                return new
                {
                    path = fi.FullName,
                    name = fi.Name,
                    ext = fi.Extension.ToLowerInvariant(),
                    size = fi.Length,
                    modified = fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                };
            }
            catch { return null; }
        }

        /// <summary>
        /// 拖放取路径。Chromium 137 起移除了非标准 File.path，新版 WebView2 拖入文件时
        /// dataTransfer 里也不再提供 text/uri-list，前端只能把 File 对象交给宿主，
        /// 由 CoreWebView2File.Path 取真实本地路径（postMessageWithAdditionalObjects）。
        /// </summary>
        private static string[] AdditionalPaths(CoreWebView2WebMessageReceivedEventArgs e)
        {
            var list = new List<string>();
            try
            {
                var objs = e.AdditionalObjects;
                Log.Write("[drop] additional=" + (objs == null ? "null" : objs.Count.ToString()));
                if (objs == null) return Array.Empty<string>();
                foreach (var obj in objs)
                {
                    if (obj is CoreWebView2File file && !string.IsNullOrWhiteSpace(file.Path))
                        list.Add(file.Path);
                    else
                        Log.Write("[drop] 未取到路径, 对象类型=" + (obj == null ? "null" : obj.GetType().Name));
                }
            }
            catch (Exception ex) { Log.Write("[drop] 读取附加对象失败: " + ex.Message); }
            return list.ToArray();
        }

        private object? PickFile()
        {
            object? result = null;
            _window.Dispatcher.Invoke(() =>
            {
                var dlg = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "选择逆向目标",
                    Filter = "所有文件 (*.*)|*.*|可执行文件 (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|.NET 程序集 (*.dll;*.exe)|*.dll;*.exe|Android 包 (*.apk)|*.apk|模型文件 (*.gguf;*.safetensors)|*.gguf;*.safetensors"
                };
                if (dlg.ShowDialog() == true)
                {
                    var fi = new FileInfo(dlg.FileName);
                    result = new
                    {
                        path = fi.FullName,
                        name = fi.Name,
                        ext = fi.Extension.ToLowerInvariant(),
                        size = fi.Length,
                        modified = fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm"),
                        sha256 = ""
                    };
                }
            });
            return result;
        }

        private string[] PickFiles(string title, string filter)
        {
            var result = Array.Empty<string>();
            _window.Dispatcher.Invoke(() =>
            {
                var dlg = new Microsoft.Win32.OpenFileDialog
                {
                    Title = title,
                    Filter = filter,
                    Multiselect = true,
                    CheckFileExists = true
                };
                if (dlg.ShowDialog() == true) result = dlg.FileNames;
            });
            return result;
        }

        private async Task StartAnalysis(string id, JsonElement p)
        {
            var path = Str(p, "path");
            var ids = new List<string>();
            if (p.TryGetProperty("modules", out var arr))
                foreach (var m in arr.EnumerateArray()) ids.Add(m.GetString() ?? "");

            var modules = Modules.ForFile(path).Where(m => ids.Count == 0 || ids.Contains(m.Id)).ToList();
            if (modules.Count == 0) { Fail(id, "没有可执行的分析模块"); return; }

            _analysisCts?.Cancel();
            _analysisCts = new CancellationTokenSource();
            var ct = _analysisCts.Token;
            Reply(id, new { total = modules.Count });
            Event("analysis.begin", new { total = modules.Count, target = path });

            // 沙箱作业：样本只复制副本进沙箱，全部分析只处理副本，原文件不被触碰
            var workPath = Sandbox.StageFile(path);
            if (!string.Equals(workPath, path, StringComparison.OrdinalIgnoreCase))
                Event("analysis.log", "样本已入沙箱：" + workPath);

            // 沙箱内病毒检测：与静态分析并行执行，只在副本上读取比对，样本不运行
            _ = Task.Run(async () =>
            {
                try
                {
                    Event("virus.begin", new { target = path });
                    var vr = await VirusDb.ScanAsync(path, t => Event("virus.log", t)).ConfigureAwait(false);
                    LastVirus = vr;
                    Event("virus.result", Camel(vr));
                    if (!vr.Ok) Event("virus.log", "病毒检测失败：" + vr.Error);
                }
                catch (Exception ex) { Log.Write("virus auto: " + ex); }
            });

            // 沙箱内漏洞检测（CVE 库比对）：与病毒检测并行，只读副本，样本不运行
            _ = Task.Run(async () =>
            {
                try
                {
                    Event("vuln.begin", new { target = path });
                    var vu = await VulnDb.ScanAsync(path, t => Event("vuln.log", t)).ConfigureAwait(false);
                    LastVuln = vu;
                    Event("vuln.result", Camel(vu));
                    if (!vu.Ok) Event("vuln.log", "漏洞检测失败：" + vu.Error);
                }
                catch (Exception ex) { Log.Write("vuln auto: " + ex); }
            });

            var tasks = modules.Select(async m =>
            {
                await Throttle.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    Event("analysis.progress", new { module = m.Id, title = m.Title, state = "running" });
                    ReaResult r;
                    try { r = await ReaRunner.RunAsync(m.Id, m.Command, workPath, null, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { Event("analysis.progress", new { module = m.Id, state = "cancelled" }); return; }
                    Event("analysis.result", new
                    {
                        module = m.Id,
                        title = m.Title,
                        group = m.Group,
                        ok = r.Ok,
                        code = r.ErrorCode,
                        message = r.ErrorMessage,
                        elapsed = Math.Round(r.ElapsedMs),
                        json = r.Json.Length <= 400_000 ? r.Json : "",
                        size = r.Json.Length,
                        evidenceFile = r.EvidenceFile
                    });
                }
                finally { Throttle.Release(); }
            }).ToArray();

            try { await Task.WhenAll(tasks).ConfigureAwait(false); }
            catch (Exception ex) { Log.Write("analysis: " + ex); }
            Event("analysis.done", new { total = modules.Count });
        }

        /// <summary>仅接受 http/https 目标，防止 file://、ftp:// 等协议把作业面拉出沙箱。</summary>
        private static bool IsWebTarget(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return false;
            var s = url.Trim();
            if (s.IndexOf("://", StringComparison.Ordinal) < 0) s = "https://" + s;
            if (!Uri.TryCreate(s, UriKind.Absolute, out var u)) return false;
            return u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps;
        }

        private static string Str(JsonElement el, string key)
        {
            try
            {
                if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String)
                    return v.GetString() ?? "";
            }
            catch { }
            return "";
        }
    }
}
