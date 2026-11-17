using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    public sealed class ReaResult
    {
        public string ModuleId { get; set; } = "";
        public string Command { get; set; } = "";
        public bool Ok { get; set; }
        public string Json { get; set; } = "";
        public string ErrorCode { get; set; } = "";
        public string ErrorMessage { get; set; } = "";
        public double ElapsedMs { get; set; }
        public string EvidenceFile { get; set; } = "";
    }

    internal static class ReaRunner
    {
        public static async Task<ReaResult> RunAsync(string moduleId, string command, string target,
            IEnumerable<string>? extra, CancellationToken ct)
        {
            var result = new ReaResult { ModuleId = moduleId, Command = command };
            if (!Storage.PayloadReady || !File.Exists(Storage.NodeExe) || !File.Exists(Storage.ReaEntry))
            {
                result.ErrorCode = "runtime_missing";
                result.ErrorMessage = "本地运行时未就绪";
                return result;
            }

            var args = new List<string> { Storage.ReaEntry, command, target, "--format", "json" };
            if (extra != null) args.AddRange(extra);

            var psi = new ProcessStartInfo(Storage.NodeExe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = Path.GetDirectoryName(Storage.ReaEntry)!
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            var sw = Stopwatch.StartNew();
            try
            {
                using var proc = new Process { StartInfo = psi };
                var stdout = new StringBuilder();
                var stderr = new StringBuilder();
                proc.OutputDataReceived += (s, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
                proc.ErrorDataReceived += (s, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };
                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                using var reg = ct.Register(() => { try { if (!proc.HasExited) proc.Kill(true); } catch { } });
                await proc.WaitForExitAsync(ct).ConfigureAwait(false);
                sw.Stop();

                result.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                result.Json = stdout.ToString();

                if (result.Json.Length == 0)
                {
                    result.ErrorCode = "empty_output";
                    result.ErrorMessage = stderr.ToString();
                    return result;
                }

                var idx = result.Json.IndexOf("\"code\":", StringComparison.Ordinal);
                if (proc.ExitCode != 0 && idx >= 0)
                {
                    result.Ok = false;
                    result.ErrorCode = Json.Str(result.Json, "code");
                    result.ErrorMessage = Json.Str(result.Json, "message");
                }
                else
                {
                    result.Ok = true;
                    // 大结果落盘，避免 IPC 传输过大
                    if (result.Json.Length > 400_000)
                    {
                        var dir = Path.Combine(Storage.OutputRoot, DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + moduleId);
                        Directory.CreateDirectory(dir);
                        var f = Path.Combine(dir, "evidence.json");
                        await File.WriteAllTextAsync(f, result.Json, Encoding.UTF8, ct).ConfigureAwait(false);
                        result.EvidenceFile = f;
                    }
                }
                return result;
            }
            catch (OperationCanceledException)
            {
                result.ErrorCode = "cancelled";
                result.ErrorMessage = "已取消";
                return result;
            }
            catch (Exception ex)
            {
                result.ErrorCode = "exec_failed";
                result.ErrorMessage = ex.Message;
                return result;
            }
        }
    }

    internal static class Json
    {
        public static string Str(string json, string key)
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object &&
                    doc.RootElement.TryGetProperty(key, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String)
                    return v.GetString() ?? "";
            }
            catch { }
            return "";
        }
    }
}
