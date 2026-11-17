using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    /// <summary>
    /// 本地 GGUF 模型的检测、模型库目录拉取与下载。
    /// 模型来源：魔搭社区（ModelScope）公开仓库，走其 repo 文件接口取真实体积，
    /// 下载走 https://www.modelscope.cn/api/v1/models/{repo}/repo?Revision=master&amp;FilePath=xxx（支持 Range）。
    /// </summary>
    internal static class ModelStore
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromMinutes(120) };
        private static CancellationTokenSource? _cts;
        private static int _downloading;
        private static object? _catalogCache;
        private static DateTime _catalogAt = DateTime.MinValue;
        private static readonly object CatalogLock = new object();

        public static bool IsDownloading => Volatile.Read(ref _downloading) == 1;

        /// <summary>用户自备模型目录：数据根下 models，下载与手动放置都在这里。</summary>
        public static string UserModelDir
        {
            get
            {
                var d = Path.Combine(Storage.AppRoot, "models");
                try { Directory.CreateDirectory(d); } catch { }
                return d;
            }
        }

        static ModelStore()
        {
            try
            {
                Http.DefaultRequestHeaders.TryAddWithoutValidation(
                    "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) REAStudio/1.0");
                Http.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json");
            }
            catch { }
        }

        /// <summary>
        /// 内置精选仓库：均为魔搭社区（ModelScope）上实测可访问的公开 GGUF 仓库，取不到的静默跳过。
        /// 覆盖阿里通义 Qwen（0.6B→32B 全规格 + Qwen2.5/Coder）、DeepSeek（1.5B→32B）、谷歌 Gemma、微软 Phi、
        /// Meta Llama、智谱 GLM、面壁 MiniCPM、Mistral、书生 InternLM、百度文心 ERNIE、字节 Seed、IBM Granite。
        /// </summary>
        private static readonly CuratedRepo[] Curated =
        {
            // —— 阿里通义 Qwen3 / Qwen2.5 全规格 ——
            new CuratedRepo("unsloth/Qwen3-0.6B-GGUF", "阿里通义 Qwen", "Qwen3 0.6B", "超轻量 · 内存占用极小，低配机应急可用"),
            new CuratedRepo("unsloth/Qwen3-1.7B-GGUF", "阿里通义 Qwen", "Qwen3 1.7B", "轻量 · 2GB 内存可跑，响应快"),
            new CuratedRepo("unsloth/Qwen3-4B-Instruct-2507-GGUF", "阿里通义 Qwen", "Qwen3 4B Instruct 2507", "推荐 · 中文理解与报告生成均衡，4B 档质量最好"),
            new CuratedRepo("unsloth/Qwen3-8B-GGUF", "阿里通义 Qwen", "Qwen3 8B", "主力档 · 判读与长文总结明显强于 4B，需 8GB 以上空闲内存"),
            new CuratedRepo("unsloth/Qwen3-14B-GGUF", "阿里通义 Qwen", "Qwen3 14B", "高质量 · 需 16GB 以上空闲内存"),
            new CuratedRepo("Qwen/Qwen3-32B-GGUF", "阿里通义 Qwen", "Qwen3 32B", "旗舰档 · 需 24GB 以上空闲内存，Q4 约 18.8GB"),
            new CuratedRepo("Qwen/Qwen2.5-1.5B-Instruct-GGUF", "阿里通义 Qwen", "Qwen2.5 1.5B Instruct", "经典小模型 · 稳定省内存"),
            new CuratedRepo("Qwen/Qwen2.5-3B-Instruct-GGUF", "阿里通义 Qwen", "Qwen2.5 3B Instruct", "均衡 · 通用中文问答稳定"),
            new CuratedRepo("unsloth/Qwen2.5-Coder-7B-Instruct-GGUF", "阿里通义 Qwen", "Qwen2.5 Coder 7B", "代码向 · 读反编译代码、写脚本更稳"),
            // —— 阿里通义 Qwen3.5（新一代，0.8B 超轻量档可离线秒开）——
            new CuratedRepo("unsloth/Qwen3.5-0.8B-GGUF", "阿里通义 Qwen", "Qwen3.5 0.8B", "超轻量 · 与内置模型同档，低配机首选，Q4_K_M 约 0.5GB"),
            new CuratedRepo("unsloth/Qwen3.5-2B-GGUF", "阿里通义 Qwen", "Qwen3.5 2B", "轻量 · 2GB 内存可跑，研判质量优于 0.8B"),
            new CuratedRepo("unsloth/Qwen3.5-4B-GGUF", "阿里通义 Qwen", "Qwen3.5 4B", "均衡 · 4B 档质量最好，需 4GB 以上空闲内存"),
            // —— 深度求索 DeepSeek ——
            new CuratedRepo("unsloth/DeepSeek-R1-Distill-Qwen-1.5B-GGUF", "深度求索 DeepSeek", "DeepSeek-R1 蒸馏 1.5B", "推理型 · 体积小，适合做判读总结"),
            new CuratedRepo("unsloth/DeepSeek-R1-Distill-Qwen-7B-GGUF", "深度求索 DeepSeek", "DeepSeek-R1 蒸馏 7B", "推理型 · 长链思考，需 8GB 以上空闲内存"),
            new CuratedRepo("unsloth/DeepSeek-R1-0528-Qwen3-8B-GGUF", "深度求索 DeepSeek", "DeepSeek-R1-0528 8B", "强推理 · 需要约 8GB 以上空闲内存"),
            new CuratedRepo("unsloth/DeepSeek-R1-Distill-Llama-8B-GGUF", "深度求索 DeepSeek", "DeepSeek-R1 蒸馏 Llama 8B", "非千问基座 · 与 Qwen 系结果互为对照"),
            new CuratedRepo("unsloth/DeepSeek-R1-Distill-Qwen-14B-GGUF", "深度求索 DeepSeek", "DeepSeek-R1 蒸馏 14B", "高质量推理 · 需 16GB 以上空闲内存"),
            new CuratedRepo("unsloth/DeepSeek-R1-Distill-Qwen-32B-GGUF", "深度求索 DeepSeek", "DeepSeek-R1 蒸馏 32B", "旗舰推理 · 需 24GB 以上空闲内存"),
            // —— 谷歌 Gemma ——
            new CuratedRepo("unsloth/gemma-3-1b-it-GGUF", "谷歌 Gemma", "Gemma 3 1B Instruct", "极轻量 · 500MB 级，先跑通链路用"),
            new CuratedRepo("unsloth/gemma-3-4b-it-GGUF", "谷歌 Gemma", "Gemma 3 4B Instruct", "多语言 · 指令跟随稳，长上下文"),
            new CuratedRepo("unsloth/gemma-3-12b-it-GGUF", "谷歌 Gemma", "Gemma 3 12B Instruct", "高质量多语言 · 需 16GB 以上空闲内存"),
            // —— 微软 Phi ——
            new CuratedRepo("unsloth/Phi-4-mini-instruct-GGUF", "微软 Phi", "Phi-4 mini Instruct", "小体积 · 数学与逻辑推理见长"),
            new CuratedRepo("unsloth/phi-4-GGUF", "微软 Phi", "Phi-4 14B", "推理强 · 需 16GB 以上空闲内存"),
            // —— Meta Llama ——
            new CuratedRepo("unsloth/Llama-3.2-1B-Instruct-GGUF", "Meta Llama", "Llama 3.2 1B Instruct", "最小档 · 只做基础摘要"),
            new CuratedRepo("unsloth/Llama-3.2-3B-Instruct-GGUF", "Meta Llama", "Llama 3.2 3B Instruct", "生态通用 · 资料与工具链最全"),
            new CuratedRepo("unsloth/Llama-3.1-8B-Instruct-GGUF", "Meta Llama", "Llama 3.1 8B Instruct", "通用主力 · 需 8GB 以上空闲内存"),
            // —— 智谱 GLM ——
            new CuratedRepo("unsloth/GLM-4-9B-0414-GGUF", "智谱 GLM", "GLM-4 9B 0414", "中文强 · 需要约 8GB 以上空闲内存"),
            new CuratedRepo("unsloth/GLM-4-32B-0414-GGUF", "智谱 GLM", "GLM-4 32B 0414", "中文旗舰 · 需 24GB 以上空闲内存"),
            // —— 面壁 MiniCPM ——
            new CuratedRepo("OpenBMB/MiniCPM3-4B-GGUF", "面壁 MiniCPM", "MiniCPM3 4B", "端侧高效 · 4B 档里推理密度高"),
            new CuratedRepo("OpenBMB/MiniCPM4-8B-GGUF", "面壁 MiniCPM", "MiniCPM4 8B", "端侧旗舰 · 需 8GB 以上空闲内存"),
            // —— Mistral AI ——
            new CuratedRepo("unsloth/Mistral-Nemo-Instruct-2407-GGUF", "Mistral AI", "Mistral Nemo 12B", "12B 高质量 · 需要约 12GB 以上空闲内存"),
            new CuratedRepo("unsloth/Mistral-Small-24B-Instruct-2501-GGUF", "Mistral AI", "Mistral Small 24B", "欧洲语种强 · 需 24GB 以上空闲内存"),
            // —— 书生 InternLM ——
            new CuratedRepo("lmstudio-community/internlm3-8b-instruct-GGUF", "书生 InternLM", "InternLM3 8B Instruct", "中文长文 · 需 8GB 以上空闲内存"),
            // —— 百度文心 ERNIE ——
            new CuratedRepo("unsloth/ERNIE-4.5-0.3B-PT-GGUF", "百度文心 ERNIE", "ERNIE 4.5 0.3B", "极小档 · 400MB 级，秒级加载"),
            // —— 字节 Seed ——
            new CuratedRepo("unsloth/Seed-OSS-36B-Instruct-GGUF", "字节 Seed", "Seed-OSS 36B Instruct", "超大规模 · 需 32GB 以上空闲内存"),
            // —— IBM Granite ——
            new CuratedRepo("unsloth/granite-3.3-8b-instruct-GGUF", "IBM Granite", "Granite 3.3 8B Instruct", "企业向 · 结构化输出稳定，需 8GB 以上空闲内存")
        };

        private sealed class CuratedRepo
        {
            public CuratedRepo(string repo, string vendor, string title, string note)
            {
                Repo = repo; Vendor = vendor; Title = title; Note = note;
            }
            public string Repo { get; }
            public string Vendor { get; }
            public string Title { get; }
            public string Note { get; }
        }

        /// <summary>常用量化档，出现在列表里的优先展示；其余档位归为“其它量化”。</summary>
        private static readonly string[] PreferredQuants = { "Q4_K_M", "Q5_K_M", "Q8_0", "IQ4_XS", "Q6_K", "Q4_K_S" };

        /* ---------------- 检测 ---------------- */

        public static object Status()
        {
            // 一律以磁盘上的 settings.json 为准：内存里的旧值会让"刚选好模型"被误判成"未检测到"
            try { AiService.Load(); } catch { }

            bool engine = !string.IsNullOrEmpty(Storage.LlamaServer) && File.Exists(Storage.LlamaServer);
            var configured = (AiService.Settings.LocalModel ?? "").Trim();
            var resolved = AiService.ResolveModelPath() ?? "";
            var activeFile = SafeResolveFile(resolved);
            var active = activeFile == null ? null : Describe(activeFile, "active");

            var all = new List<object>();
            if (activeFile != null) all.Add(Describe(activeFile, "active"));
            foreach (var f in ScanDir(UserModelDir)) if (!SamePath(f, resolved)) all.Add(Describe(f, "user"));
            if (!string.IsNullOrEmpty(Storage.ModelDir)) foreach (var f in ScanDir(Storage.ModelDir)) if (!SamePath(f, resolved)) all.Add(Describe(f, "builtin"));

            bool found = active != null;
            // 是否随程序内置了本地大模型（含模型版为 true；no model 版 runtime\model 目录为空或不存在）
            bool builtinModel = false;
            try
            {
                var bdir = Storage.ModelDir ?? "";
                if (bdir.Length > 0 && Directory.Exists(bdir)) builtinModel = ScanDir(bdir).Any();
            }
            catch { }
            Log.Write("[model.status] configured=\"" + configured + "\" resolved=\"" + resolved + "\" found=" + found + " count=" + all.Count);

            return new
            {
                engine,
                enginePath = Storage.LlamaServer ?? "",
                userDir = UserModelDir,
                builtinDir = Storage.ModelDir ?? "",
                configured,
                resolved,
                active,
                found,
                builtinModel,
                // 配置了模型但文件已经不在了：前端要明确告诉用户"路径失效"，而不是笼统说没有模型
                missing = !found && configured.Length > 0,
                searched = new[] { UserModelDir, Storage.ModelDir ?? "" }.Where(d => !string.IsNullOrEmpty(d)).ToArray(),
                models = all
            };
        }

        private static bool SamePath(FileInfo f, string path)
        {
            try
            {
                return !string.IsNullOrEmpty(path) &&
                       string.Equals(Path.GetFullPath(f.FullName), Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static FileInfo? SafeResolveFile(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
                var fi = new FileInfo(path);
                return fi.Length > 0 ? fi : null;
            }
            catch { return null; }
        }

        private static IEnumerable<FileInfo> ScanDir(string dir)
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return Array.Empty<FileInfo>();
                // 递归一层以上：用户可能把模型放进子文件夹分类存放，不该因此判定"没有模型"
                return Directory.GetFiles(dir, "*.gguf", SearchOption.AllDirectories)
                    .Select(f => new FileInfo(f))
                    .Where(f => f.Length > 1024 * 1024)
                    .OrderByDescending(f => f.Length)
                    .ToArray();
            }
            catch { return Array.Empty<FileInfo>(); }
        }

        private static object Describe(FileInfo fi, string where) => new
        {
            name = fi.Name,
            path = fi.FullName,
            size = fi.Length,
            sizeText = Mb(fi.Length),
            where
        };

        /* ---------------- 模型库 ---------------- */

        /// <summary>拉取精选仓库的文件清单（只保留单文件 GGUF 的常用量化档）；多厂商仓库并发拉取以缩短等待，结果缓存 10 分钟。</summary>
        public static async Task<object> CatalogAsync(CancellationToken ct = default)
        {
            lock (CatalogLock)
            {
                if (_catalogCache != null && (DateTime.UtcNow - _catalogAt).TotalMinutes < 10) return _catalogCache;
            }

            var gate = new SemaphoreSlim(6);
            var tasks = Curated.Select(async c =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var files = await RepoFilesAsync(c.Repo, ct).ConfigureAwait(false);
                    if (files.Count == 0) return null;
                    return (object)new { repo = c.Repo, vendor = c.Vendor, title = c.Title, note = c.Note, files };
                }
                catch (Exception ex)
                {
                    Log.Write("catalog skip " + c.Repo + ": " + ex.Message);
                    return null;
                }
                finally { gate.Release(); }
            }).ToArray();

            var all = await Task.WhenAll(tasks).ConfigureAwait(false);
            var list = all.Where(o => o != null).ToList();
            var result = new { source = "魔搭 ModelScope", repos = list };

            lock (CatalogLock)
            {
                // 全部仓库都拉失败（断网等）不写缓存，避免把空列表锁死 10 分钟
                if (list.Count > 0) { _catalogCache = result; _catalogAt = DateTime.UtcNow; }
            }
            Log.Write("[catalog] repos=" + list.Count + " / " + Curated.Length);
            return result;
        }

        /// <summary>读取单个仓库的 GGUF 文件列表，返回 name/size 等。</summary>
        public static async Task<List<object>> RepoFilesAsync(string repo, CancellationToken ct = default)
        {
            var result = new List<object>();
            repo = (repo ?? "").Trim().Trim('/');
            if (repo.Length < 3 || !repo.Contains('/')) throw new InvalidOperationException("仓库名格式应为 owner/name");

            var url = "https://modelscope.cn/api/v1/models/" + repo + "/repo/files?Revision=master&Root=";
            using var resp = await Http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) throw new InvalidOperationException("仓库不可访问（HTTP " + (int)resp.StatusCode + "）");
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("Data", out var data) ||
                !data.TryGetProperty("Files", out var files) || files.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var f in files.EnumerateArray())
            {
                var name = f.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
                if (!name.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.IndexOf("-of-", StringComparison.OrdinalIgnoreCase) >= 0) continue;   // 跳过分卷
                long size = 0;
                if (f.TryGetProperty("Size", out var s) && s.ValueKind == JsonValueKind.Number) size = s.GetInt64();
                if (size > 0 && size < 256L * 1024 * 1024) continue;                          // 过小的非模型文件
                var quant = QuantOf(name);
                if (string.IsNullOrEmpty(quant)) continue;
                result.Add(new { name, size, quant });
            }

            return ((List<object>)result)
                .Select(o => new
                {
                    name = (string)o.GetType().GetProperty("name")!.GetValue(o)!,
                    size = (long)o.GetType().GetProperty("size")!.GetValue(o)!,
                    quant = (string)o.GetType().GetProperty("quant")!.GetValue(o)!
                })
                .OrderBy(o => QuantRank(o.quant))
                .ThenBy(o => o.size)
                .Select(o => (object)new
                {
                    o.name,
                    o.size,
                    sizeText = Mb(o.size),
                    o.quant,
                    recommended = PreferredQuants.Take(3).Contains(o.quant, StringComparer.OrdinalIgnoreCase)
                })
                .ToList();
        }

        private static string QuantOf(string fileName)
        {
            var m = System.Text.RegularExpressions.Regex.Match(
                fileName, @"(UD-)?(IQ\d+_[A-Z]+|Q\d+_K_[A-Z]+|Q\d+_K|Q\d+_\d|Q\d+|F16|BF16|FP16)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Value.ToUpperInvariant() : "";
        }

        private static int QuantRank(string quant)
        {
            for (int i = 0; i < PreferredQuants.Length; i++)
                if (string.Equals(PreferredQuants[i], quant, StringComparison.OrdinalIgnoreCase)) return i;
            return 99;
        }

        /* ---------------- 下载 ---------------- */

        /// <summary>后台下载指定仓库文件到用户模型目录，完成后写入本地模型设置。</summary>
        public static void StartDownload(string repo, string file, Action<object> push)
        {
            if (Interlocked.CompareExchange(ref _downloading, 1, 0) == 1)
            {
                push(new { state = "busy", message = "已有下载任务在进行" });
                return;
            }

            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            Task.Run(async () =>
            {
                var dir = UserModelDir;
                var target = Path.Combine(dir, Path.GetFileName(file));
                var part = target + ".part";
                try
                {
                    var url = "https://www.modelscope.cn/api/v1/models/" + repo.Trim().Trim('/') +
                              "/repo?Revision=master&FilePath=" + Uri.EscapeDataString(file);
                    push(new { state = "begin", file = Path.GetFileName(file), target });

                    using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode)
                        throw new InvalidOperationException("下载失败 HTTP " + (int)resp.StatusCode);

                    long total = resp.Content.Headers.ContentLength ?? 0;
                    long received = 0;
                    var started = DateTime.UtcNow;
                    var lastPush = DateTime.MinValue;

                    using (var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                    using (var dst = new FileStream(part, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024, true))
                    {
                        var buf = new byte[1024 * 1024];
                        while (true)
                        {
                            ct.ThrowIfCancellationRequested();
                            int n = await src.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                            if (n <= 0) break;
                            await dst.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
                            received += n;

                            if ((DateTime.UtcNow - lastPush).TotalMilliseconds > 400)
                            {
                                lastPush = DateTime.UtcNow;
                                double sec = Math.Max(0.5, (DateTime.UtcNow - started).TotalSeconds);
                                push(new
                                {
                                    state = "progress",
                                    file = Path.GetFileName(file),
                                    received,
                                    total,
                                    percent = total > 0 ? (int)(received * 100 / total) : 0,
                                    receivedText = Mb(received),
                                    totalText = total > 0 ? Mb(total) : "未知",
                                    speed = Mb((long)(received / sec)) + "/s"
                                });
                            }
                        }
                    }

                    if (File.Exists(target)) File.Delete(target);
                    File.Move(part, target);

                    var st = AiService.Load();
                    st.LocalModel = Path.GetFileName(target);
                    AiService.Save(st);

                    push(new
                    {
                        state = "done",
                        file = Path.GetFileName(target),
                        path = target,
                        sizeText = Mb(new FileInfo(target).Length),
                        applied = true
                    });
                }
                catch (OperationCanceledException)
                {
                    TryDelete(part);
                    push(new { state = "cancelled", message = "下载已取消" });
                }
                catch (Exception ex)
                {
                    TryDelete(part);
                    Log.Write("model download: " + ex);
                    push(new { state = "error", message = ex.Message });
                }
                finally
                {
                    Volatile.Write(ref _downloading, 0);
                    _cts?.Dispose();
                    _cts = null;
                }
            }, ct);
        }

        public static void Cancel()
        {
            try { _cts?.Cancel(); } catch { }
        }

        /// <summary>把已有模型文件设为当前本地模型。</summary>
        public static object Apply(string pathOrName)
        {
            var p = (pathOrName ?? "").Trim();
            if (string.IsNullOrWhiteSpace(p)) throw new InvalidOperationException("未指定模型");

            var full = AiService.ResolveConfiguredPath(p);
            if (string.IsNullOrEmpty(full)) throw new InvalidOperationException("模型文件不存在：" + p);

            var st = AiService.Load();
            // 位于用户模型目录时只存文件名，跟随目录迁移；外部路径则存绝对路径
            st.LocalModel = full.StartsWith(UserModelDir, StringComparison.OrdinalIgnoreCase)
                ? Path.GetFileName(full) : full;
            AiService.Save(st);
            return new { ok = true, active = Describe(new FileInfo(full), "active") };
        }

        /// <summary>删除用户目录下的模型（内置模型不允许删）。</summary>
        public static object Remove(string name)
        {
            var full = Path.Combine(UserModelDir, Path.GetFileName(name ?? ""));
            if (!File.Exists(full)) throw new InvalidOperationException("模型不存在");
            File.Delete(full);
            var st = AiService.Load();
            if (string.Equals(st.LocalModel, Path.GetFileName(full), StringComparison.OrdinalIgnoreCase))
            {
                st.LocalModel = "";
                AiService.Save(st);
            }
            return new { ok = true };
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        private static string Mb(long bytes) => (bytes / 1048576.0).ToString(bytes > 10L * 1024 * 1024 * 1024 ? "F0" : "F1") + " MB";
    }
}
