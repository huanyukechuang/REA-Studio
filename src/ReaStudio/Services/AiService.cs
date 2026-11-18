using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    public sealed class AiSettings
    {
        public string Mode { get; set; } = "local";         // local | cloud | off
        public string LocalModel { get; set; } = "";        // 相对 model 目录或绝对路径
        public int LocalPort { get; set; } = 8791;
        public int ContextSize { get; set; } = 8192;
        public int Threads { get; set; } = 0;
        public string CloudBaseUrl { get; set; } = "https://api.deepseek.com/v1";
        public string CloudApiKey { get; set; } = "";
        public string CloudModel { get; set; } = "deepseek-chat";
        public double Temperature { get; set; } = 0.2;
        // Qwen3.x 等思考型模型会先输出 reasoning_content 再输出正文，768 会被思考链吃光导致正文为空
        public int MaxTokens { get; set; } = 2048;
    }

    public sealed class ChatMsg
    {
        [JsonPropertyName("role")] public string Role { get; set; } = "user";
        [JsonPropertyName("content")] public string Content { get; set; } = "";
    }

    internal static class AiService
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        private static Process? _llama;
        private static readonly object Gate = new object();
        public static AiSettings Settings { get; private set; } = new AiSettings();

        private static string SettingsFile => Path.Combine(Storage.AppRoot, "settings.json");

        public static AiSettings Load()
        {
            try
            {
                if (File.Exists(SettingsFile))
                {
                    var json = File.ReadAllText(SettingsFile, Encoding.UTF8);
                    Settings = JsonSerializer.Deserialize<AiSettings>(json) ?? new AiSettings();
                }
            }
            catch (Exception ex) { Log.Write("settings load: " + ex.Message); }
            return Settings;
        }

        public static void Save(AiSettings s)
        {
            Settings = s;
            Directory.CreateDirectory(Storage.AppRoot);
            File.WriteAllText(SettingsFile, JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
        }

        /// <summary>
        /// 解析用户配置的模型（settings.LocalModel）。支持：绝对路径文件、绝对路径目录、相对 AppRoot 的路径、
        /// 纯文件名（在用户模型目录 / 内置模型目录里按名查找）。找不到返回 null，便于上层区分"没配置"与"配置了但文件丢了"。
        /// </summary>
        public static string? ResolveConfiguredPath(string? raw)
        {
            var m = (raw ?? "").Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(m)) return null;
            // 支持 %USERPROFILE%\models\x.gguf 这类写法
            try { if (m.IndexOf('%') >= 0) m = Environment.ExpandEnvironmentVariables(m).Trim().Trim('"'); } catch { }
            if (string.IsNullOrWhiteSpace(m)) return null;

            var candidates = new List<string>();
            if (Path.IsPathRooted(m))
            {
                candidates.Add(m);
            }
            else
            {
                candidates.Add(Path.Combine(Storage.AppRoot, m));
                candidates.Add(Path.Combine(Storage.AppRoot, "models", m));
                if (!string.IsNullOrEmpty(Storage.ModelDir)) candidates.Add(Path.Combine(Storage.ModelDir, m));
                candidates.Add(m);
            }
            // 忘写扩展名时补一次，避免用户手填 "qwen3-4b" 就判定失败
            if (!m.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase))
                candidates.AddRange(candidates.ToArray().Select(c => c + ".gguf"));

            foreach (var c in candidates)
            {
                try
                {
                    if (File.Exists(c)) return Path.GetFullPath(c);
                    if (Directory.Exists(c))
                    {
                        var pick = Directory.GetFiles(c, "*.gguf", SearchOption.TopDirectoryOnly)
                            .Select(f => new FileInfo(f))
                            .Where(f => f.Length > 1024 * 1024)
                            .OrderByDescending(f => f.Length)
                            .FirstOrDefault();
                        if (pick != null) return pick.FullName;
                    }
                }
                catch { }
            }
            return null;
        }

        public static string ResolveModelPath()
        {
            var byConfig = ResolveConfiguredPath(Settings.LocalModel);
            if (!string.IsNullOrEmpty(byConfig)) return byConfig;

            // 名称未指定或对不上时：用户目录 → 内置目录，各自优先 4B 级别模型（质量优先），其次取体积最大的 GGUF
            foreach (var dir in new[] { Path.Combine(Storage.AppRoot, "models"), Storage.ModelDir })
            {
                try
                {
                    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                    var any = Directory.GetFiles(dir, "*.gguf", SearchOption.TopDirectoryOnly);
                    if (any.Length == 0) continue;
                    var four = any.Where(f => Path.GetFileName(f).IndexOf("4b", StringComparison.OrdinalIgnoreCase) >= 0).ToArray();
                    var pool = four.Length > 0 ? four : any;
                    return pool.OrderByDescending(f => new FileInfo(f).Length).First();
                }
                catch { }
            }
            return "";
        }

        public static bool LocalReady => _llama != null && !_llama.HasExited;
        public static string LocalEndpoint => "http://127.0.0.1:" + Settings.LocalPort;

        /// <summary>Qwen3.x 系（含内置 model.gguf）的模板把 &lt;think&gt; 写死，需要外部模板强制关闭思考。</summary>
        private static bool IsThinkingModel(string modelPath)
        {
            var name = Path.GetFileNameWithoutExtension(modelPath ?? "");
            if (string.IsNullOrEmpty(name)) return false;
            var lower = name.ToLowerInvariant();
            if (lower.Contains("qwen3")) return true;
            if (lower == "model") return true;          // 内置模型即 Qwen3.5-0.8B
            return false;
        }

        /// <summary>把内置的"空思考"模板释放到数据目录，返回模板路径；失败返回 null 表示沿用模型自带模板。</summary>
        private static string? EnsureNoThinkTemplate()
        {
            try
            {
                var dir = Path.Combine(Storage.DataRoot, "ai");
                Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, "qwen-nothink.jinja");
                if (File.Exists(path) && new FileInfo(path).Length > 1000) return path;

                var asm = typeof(AiService).Assembly;
                var res = asm.GetManifestResourceNames()
                    .FirstOrDefault(n => n.EndsWith("qwen-nothink.jinja", StringComparison.OrdinalIgnoreCase));
                if (res == null) return null;
                using var st = asm.GetManifestResourceStream(res);
                if (st == null) return null;
                using var fs = File.Create(path);
                st.CopyTo(fs);
                Log.Write("[ai] 已释放禁用思考模板：" + path);
                return path;
            }
            catch (Exception ex)
            {
                Log.Write("[ai] 释放禁用思考模板失败：" + ex.Message);
                return null;
            }
        }

        /// <summary>探测当前端口上是否已经有一个可用的推理引擎（含其它实例遗留的进程）。</summary>
        public static bool EndpointAlive()
        {
            try
            {
                using (var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(3) })
                {
                    var r = probe.GetAsync(LocalEndpoint + "/health").GetAwaiter().GetResult();
                    if (!r.IsSuccessStatusCode) return false;
                    // 旧实例（老版本程序遗留）可能仍启用思考模板，或上下文只有 4096：
                    // 这类引擎会让正文被思考链挤空，宁可不复用，另起一个干净引擎。
                    try
                    {
                        var props = probe.GetStringAsync(LocalEndpoint + "/props").GetAwaiter().GetResult() ?? "";
                        if (props.IndexOf("<think>", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            Log.Write("[ai] 端口上的旧引擎仍启用思考链，改为另起干净引擎");
                            return false;
                        }
                        var mm = System.Text.RegularExpressions.Regex.Match(props, "\"n_ctx\"\\s*:\\s*(\\d+)");
                        if (mm.Success && int.TryParse(mm.Groups[1].Value, out var nctx) && nctx < Math.Max(4096, Settings.ContextSize / 2))
                        {
                            Log.Write("[ai] 端口上的旧引擎上下文仅 " + nctx + "，改为另起干净引擎");
                            return false;
                        }
                    }
                    catch { }
                    return true;
                }
            }
            catch { return false; }
        }

        /// <summary>端口是否被任何进程占用（不含探测协议，只判可连接）。</summary>
        private static bool PortInUse(int port)
        {
            try
            {
                using (var cli = new System.Net.Sockets.TcpClient())
                {
                    var t = cli.ConnectAsync("127.0.0.1", port);
                    if (!t.Wait(800)) return false;
                    return cli.Connected;
                }
            }
            catch { return false; }
        }

        public static async Task<bool> StartLocalAsync(Action<string>? log = null, CancellationToken ct = default, bool allowTemplate = true)
        {
            if (LocalReady) return true;

            // 端口上已有可用引擎（上个实例未退出 / 另一实例已拉起）：直接复用。
            // 否则新进程会因端口被抢占而绑定失败，聊天请求继续打到旧引擎（旧引擎上下文可能是 4096），表现为"空响应"。
            if (EndpointAlive())
            {
                Log.Write("[ai] 复用已运行的推理引擎 " + LocalEndpoint);
                log?.Invoke("已连接运行中的本地模型：" + LocalEndpoint);
                return true;
            }
            // 端口被非推理程序占用：自动顺延到一个空闲端口，避免启动必然失败
            if (PortInUse(Settings.LocalPort))
            {
                var old = Settings.LocalPort;
                for (var p = old + 1; p <= old + 20; p++)
                {
                    if (!PortInUse(p)) { Settings.LocalPort = p; break; }
                }
                if (Settings.LocalPort != old)
                {
                    try { Save(Settings); } catch { }
                    Log.Write("[ai] 端口 " + old + " 被占用，改用 " + Settings.LocalPort);
                    log?.Invoke("端口 " + old + " 被占用，已切换到 " + Settings.LocalPort);
                }
            }

            var exe = Storage.LlamaServer;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            {
                log?.Invoke("未内置推理引擎（llama-server）");
                return false;
            }
            var model = ResolveModelPath();
            if (string.IsNullOrEmpty(model))
            {
                log?.Invoke("未找到本地模型文件（GGUF）");
                return false;
            }

            // 实测本机 12 逻辑核：8 线程最快（3.8 t/s），满核反而下降（3.1 t/s），故默认上限取 8
            var threads = Settings.Threads > 0 ? Settings.Threads : Math.Min(8, Math.Max(2, Environment.ProcessorCount));
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exe)!
            };
            psi.ArgumentList.Add("-m"); psi.ArgumentList.Add(model);
            psi.ArgumentList.Add("--host"); psi.ArgumentList.Add("127.0.0.1");
            psi.ArgumentList.Add("--port"); psi.ArgumentList.Add(Settings.LocalPort.ToString());
            psi.ArgumentList.Add("-c"); psi.ArgumentList.Add(Settings.ContextSize.ToString());
            psi.ArgumentList.Add("-t"); psi.ArgumentList.Add(threads.ToString());
            psi.ArgumentList.Add("-ngl"); psi.ArgumentList.Add("0");
            // 单请求独占全部上下文：默认多 slot 会把 -c 的上下文切分，长证据极易触发 exceed_context_size
            psi.ArgumentList.Add("--parallel"); psi.ArgumentList.Add("1");
            psi.ArgumentList.Add("--no-webui");
            // Qwen3.x 的 chat template 把 <think> 写死在 generation prompt 里，enable_thinking 无效，
            // 思考链会无限复发并吃光 max_tokens 导致正文为空 —— 只能替换模板强制空思考
            var tplPath = (allowTemplate && IsThinkingModel(model)) ? EnsureNoThinkTemplate() : null;
            if (allowTemplate && !string.IsNullOrEmpty(tplPath))
            {
                psi.ArgumentList.Add("--chat-template-file");
                psi.ArgumentList.Add(tplPath);
                Log.Write("[ai] 已禁用思考链（模板：" + tplPath + "）");
            }

            try
            {
                lock (Gate)
                {
                    _llama = new Process { StartInfo = psi, EnableRaisingEvents = true };
                    _llama.OutputDataReceived += (s, e) => { if (e.Data != null) Log.Write("[llama] " + e.Data); };
                    _llama.ErrorDataReceived += (s, e) => { if (e.Data != null) Log.Write("[llama!] " + e.Data); };
                    _llama.Start();
                    _llama.BeginOutputReadLine();
                    _llama.BeginErrorReadLine();
                }
            }
            catch (Exception ex)
            {
                log?.Invoke("推理引擎启动失败：" + ex.Message);
                return false;
            }

            log?.Invoke("正在加载本地模型…");
            for (int i = 0; i < 180; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (_llama == null || _llama.HasExited)
                {
                    // 个别模型不接受外部模板，去掉模板再试一次，保证至少能跑起来
                    if (allowTemplate && !string.IsNullOrEmpty(tplPath))
                    {
                        Log.Write("[ai] 外部模板不可用，回退为模型内置模板");
                        StopLocal();
                        return await StartLocalAsync(log, ct, false).ConfigureAwait(false);
                    }
                    log?.Invoke("推理引擎异常退出");
                    return false;
                }
                try
                {
                    var r = await Http.GetAsync(LocalEndpoint + "/health", ct).ConfigureAwait(false);
                    if (r.IsSuccessStatusCode) { log?.Invoke("本地模型就绪"); return true; }
                }
                catch { }
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
            log?.Invoke("等待模型加载超时");
            return false;
        }

        public static void StopLocal()
        {
            try
            {
                lock (Gate)
                {
                    if (_llama != null && !_llama.HasExited) _llama.Kill(true);
                    _llama = null;
                }
            }
            catch { }
        }

        /// <summary>单次模型调用的结构化结果，reasoning_content 与 finish_reason 是判定"空响应"的关键。</summary>
        private sealed class ChatOutcome
        {
            public string Content = "";
            public string Reasoning = "";
            public string Finish = "";
            public int PromptTokens;
            public int CompletionTokens;
        }

        public static async Task<string> ChatAsync(IEnumerable<ChatMsg> messages, CancellationToken ct = default)
        {
            var msgs = NormalizeMessages(messages);
            var budget = Settings.MaxTokens > 0 ? Settings.MaxTokens : 2048;
            // 思考型模型（Qwen3.x 等）思考链动辄上千 token，预算过小必然把正文挤成空串，本地模式强制下限
            if (Settings.Mode != "cloud" && budget < 2048) budget = 2048;

            ChatOutcome r;
            try
            {
                r = await CallOnceAsync(msgs, budget, ct).ConfigureAwait(false);
            }
            catch (InvalidOperationException ex) when (IsContextOverflow(ex.Message))
            {
                // 证据过长超出 n_ctx：截断首条 system（证据体）后重试一次
                Log.Write("[ai] 提示超出上下文，裁剪证据后重试");
                r = await CallOnceAsync(TrimForContext(msgs, 0.5), budget, ct).ConfigureAwait(false);
            }

            Log.Write("[ai] chat prompt=" + r.PromptTokens + " completion=" + r.CompletionTokens
                      + " finish=" + r.Finish + " content=" + r.Content.Length + " reasoning=" + r.Reasoning.Length);

            if (!string.IsNullOrWhiteSpace(r.Content)) return r.Content;

            // 正文为空且 finish=length：预算被思考链吃光，提高预算重试一次
            if (r.Finish == "length")
            {
                var retryBudget = Math.Min(6144, Math.Max(3072, budget * 2));
                if (retryBudget > budget)
                {
                    try
                    {
                        var retry = await CallOnceAsync(msgs, retryBudget, ct).ConfigureAwait(false);
                        Log.Write("[ai] 空正文重试 prompt=" + retry.PromptTokens + " completion=" + retry.CompletionTokens
                                  + " finish=" + retry.Finish + " content=" + retry.Content.Length);
                        if (!string.IsNullOrWhiteSpace(retry.Content)) return retry.Content;
                        if (string.IsNullOrWhiteSpace(r.Reasoning)) r = retry;
                    }
                    catch (Exception ex) { Log.Write("[ai] 空正文重试失败：" + ex.Message); }
                }
            }

            // 仍然只有推理过程：把它作为结论兜底返回，绝不让前端拿到空串显示"(空响应)"
            if (!string.IsNullOrWhiteSpace(r.Reasoning))
            {
                Log.Write("[ai] 正文为空，回退使用 reasoning_content");
                return r.Reasoning;
            }

            throw new InvalidOperationException("模型未返回正文（finish=" + r.Finish + "，prompt=" + r.PromptTokens
                + " tokens）。请重试，或在设置中调大“最大输出”后再次提问。");
        }

        private static bool IsContextOverflow(string message)
        {
            if (string.IsNullOrEmpty(message)) return false;
            return message.IndexOf("exceed_context_size", StringComparison.OrdinalIgnoreCase) >= 0
                || message.IndexOf("exceeds the available context size", StringComparison.OrdinalIgnoreCase) >= 0
                || message.IndexOf("context size", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static List<ChatMsg> TrimForContext(List<ChatMsg> msgs, double ratio)
        {
            var copy = new List<ChatMsg>(msgs);
            for (var i = 0; i < copy.Count; i++)
            {
                if (copy[i].Role == "system" && copy[i].Content != null && copy[i].Content.Length > 400)
                {
                    var keep = Math.Max(400, (int)(copy[i].Content.Length * ratio));
                    copy[i] = new ChatMsg
                    {
                        Role = "system",
                        Content = copy[i].Content.Substring(0, keep) + "\n（证据已按模型上下文长度截断）"
                    };
                    break;
                }
            }
            return copy;
        }

        private static async Task<ChatOutcome> CallOnceAsync(List<ChatMsg> msgs, int maxTokens, CancellationToken ct)
        {
            var baseUrl = Settings.Mode == "cloud" ? Settings.CloudBaseUrl.TrimEnd('/') : LocalEndpoint;
            var key = Settings.Mode == "cloud" ? Settings.CloudApiKey : "local";
            var model = Settings.Mode == "cloud" ? Settings.CloudModel : Path.GetFileNameWithoutExtension(ResolveModelPath());

            var payload = new Dictionary<string, object?>
            {
                ["model"] = string.IsNullOrEmpty(model) ? "local" : model,
                ["messages"] = msgs,
                ["temperature"] = Settings.Temperature,
                ["stream"] = false,
                ["max_tokens"] = maxTokens
            };
            // 本地 Qwen3.x 系列默认开"思考链"，会显著拖慢响应且污染报告正文，这里显式关闭
            if (Settings.Mode != "cloud")
                payload["chat_template_kwargs"] = new Dictionary<string, object?> { ["enable_thinking"] = false };

            using var req = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/chat/completions")
            {
                Content = JsonContent.Create(payload)
            };
            if (!string.IsNullOrEmpty(key)) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + key);

            var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false);
            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException("模型调用失败 HTTP " + (int)resp.StatusCode + ": " + Trunc(text, 400));

            using var doc = JsonDocument.Parse(text);
            if (!doc.RootElement.TryGetProperty("choices", out var choices) || choices.GetArrayLength() == 0)
                throw new InvalidOperationException("模型返回格式异常：" + Trunc(text, 300));

            var o = new ChatOutcome();
            if (doc.RootElement.TryGetProperty("usage", out var usage))
            {
                if (usage.TryGetProperty("prompt_tokens", out var pt) && pt.TryGetInt32(out var pv)) o.PromptTokens = pv;
                if (usage.TryGetProperty("completion_tokens", out var ctok) && ctok.TryGetInt32(out var cv)) o.CompletionTokens = cv;
            }

            var c0 = choices[0];
            if (c0.TryGetProperty("finish_reason", out var fr) && fr.ValueKind == JsonValueKind.String)
                o.Finish = fr.GetString() ?? "";
            if (c0.TryGetProperty("message", out var msg))
            {
                if (msg.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.String)
                    o.Content = StripThinking(content.GetString() ?? "");
                // llama-server 会把思考链单独放进 reasoning_content，正文可能因此为空
                if (msg.TryGetProperty("reasoning_content", out var rc) && rc.ValueKind == JsonValueKind.String)
                    o.Reasoning = StripThinking(rc.GetString() ?? "");
            }
            return o;
        }

        /// <summary>
        /// 规范化消息队列：Qwen 系列 chat template 要求 system 必须且只能位于首条，
        /// 否则 llama-server 直接返回 500（Jinja: "System message must be at the beginning"）。
        /// 这里把所有 system 合并到最前一条，并剔除空消息与非法角色，任何调用方都安全。
        /// </summary>
        private static List<ChatMsg> NormalizeMessages(IEnumerable<ChatMsg> messages)
        {
            var list = new List<ChatMsg>();
            var systems = new List<string>();
            if (messages != null)
            {
                foreach (var m in messages)
                {
                    if (m == null) continue;
                    var content = m.Content ?? "";
                    if (string.IsNullOrWhiteSpace(content)) continue;
                    var role = (m.Role ?? "").Trim().ToLowerInvariant();
                    if (role == "system") { systems.Add(content); continue; }
                    if (role != "user" && role != "assistant") role = "user";
                    list.Add(new ChatMsg { Role = role, Content = content });
                }
            }
            if (systems.Count > 0)
                list.Insert(0, new ChatMsg { Role = "system", Content = string.Join("\n\n", systems) });
            return list;
        }

        /// <summary>剔除模型输出中的思考块，仅保留结论正文。</summary>
        private static string StripThinking(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            var e = s.IndexOf("</think>", StringComparison.OrdinalIgnoreCase);
            if (e >= 0) s = s.Substring(e + "</think>".Length);
            s = s.Replace("<think>", "").Replace("</think>", "");
            return s.Trim();
        }

        private static string Trunc(string s, int n) => s.Length <= n ? s : s.Substring(0, n) + "…";
    }
}
