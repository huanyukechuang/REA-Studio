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
        public int MaxTokens { get; set; } = 768;
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

        public static async Task<bool> StartLocalAsync(Action<string>? log = null, CancellationToken ct = default)
        {
            if (LocalReady) return true;
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
            psi.ArgumentList.Add("--no-webui");

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

        public static async Task<string> ChatAsync(IEnumerable<ChatMsg> messages, CancellationToken ct = default)
        {
            var baseUrl = Settings.Mode == "cloud" ? Settings.CloudBaseUrl.TrimEnd('/') : LocalEndpoint;
            var key = Settings.Mode == "cloud" ? Settings.CloudApiKey : "local";
            var model = Settings.Mode == "cloud" ? Settings.CloudModel : Path.GetFileNameWithoutExtension(ResolveModelPath());

            var payload = new Dictionary<string, object?>
            {
                ["model"] = string.IsNullOrEmpty(model) ? "local" : model,
                ["messages"] = NormalizeMessages(messages),
                ["temperature"] = Settings.Temperature,
                ["stream"] = false,
                ["max_tokens"] = Settings.MaxTokens > 0 ? Settings.MaxTokens : 1024
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
            if (doc.RootElement.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
            {
                var c0 = choices[0];
                if (c0.TryGetProperty("message", out var msg) && msg.TryGetProperty("content", out var content))
                    return StripThinking(content.GetString() ?? "");
            }
            return Trunc(text, 800);
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
