using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace ReaStudio
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            DispatcherUnhandledException += OnUnhandled;
            AppDomain.CurrentDomain.UnhandledException += (s, ex) =>
            {
                try
                {
                    Services.Log.Write("FATAL " + ex.ExceptionObject);
                }
                catch { }
            };

            var args = e.Args ?? Array.Empty<string>();
            var si = Array.IndexOf(args, "--selftest");
            if (si >= 0 && si + 1 < args.Length)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Dispatcher.InvokeAsync(new Action(async () =>
                {
                    await RunSelfTestAsync(args[si + 1]).ConfigureAwait(true);
                    Shutdown(0);
                }));
            }
        }

        /// <summary>诊断模式：对指定样本跑类型识别、网络分析与报告导出（md/pdf），结果写入 selftest.txt。</summary>
        private static async Task RunSelfTestAsync(string file)
        {
            var sb = new StringBuilder();
            try
            {
                await Services.Storage.EnsureRuntimeAsync().ConfigureAwait(true);
                sb.AppendLine("PAYLOAD kind=" + Services.Storage.PayloadKind + " ready=" + Services.Storage.PayloadReady
                    + " root=" + Services.Storage.RuntimeRoot);
                if (!File.Exists(file))
                {
                    sb.AppendLine("ERR file not found: " + file);
                }
                else
                {
                    var types = Services.BinaryTypes.Detect(file);
                    sb.AppendLine("TYPES(" + types.Count + ")=" + string.Join(" | ", types.Select(t => t.Id + ":" + t.Name + ":" + t.Confidence)));

                    var net = Services.NetworkIntel.AnalyzeFile(file);
                    sb.AppendLine("NET ok=" + net.Ok + " strings=" + net.Strings + " urls=" + net.UrlCount + " ips=" + net.IpCount
                        + " endpoints=" + net.Endpoints.Count + " dangerous=" + net.Dangerous.Count
                        + " privacy=" + net.Privacy.Count + " packets=" + net.Packets.Count);
                    sb.AppendLine("VERDICT=" + net.Verdict);
                    foreach (var d in net.Dangerous.Take(5))
                        sb.AppendLine("  DANGER " + d.Host + " score=" + d.Score + " level=" + d.Level + " " + string.Join(";", d.Reasons ?? new System.Collections.Generic.List<string>()));

                    var opt = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
                    var input = new Services.ReportInput
                    {
                        TargetPath = file,
                        TypesJson = JsonSerializer.Serialize(types, opt),
                        NetworkJson = JsonSerializer.Serialize(net, opt),
                        Format = "md"
                    };
                    sb.AppendLine("MD=" + (await Services.Reports.ExportAsync(input).ConfigureAwait(true)));
                    input.Format = "pdf";
                    sb.AppendLine("PDF=" + (await Services.Reports.ExportAsync(input).ConfigureAwait(true)));

                    // 本地模型冒烟测试：确认内置 GGUF 可加载可生成
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    if (await Services.AiService.StartLocalAsync(m => sb.AppendLine("[ai] " + m)).ConfigureAwait(true))
                    {
                        sb.AppendLine("AI model=" + Path.GetFileName(Services.AiService.ResolveModelPath())
                            + " ctx=" + Services.AiService.Load().ContextSize
                            + " threads=" + Services.AiService.Load().Threads);
                        var sw2 = System.Diagnostics.Stopwatch.StartNew();
                        var ans = await Services.AiService.ChatAsync(new[]
                        {
                            new Services.ChatMsg { Role = "system", Content = "你是安卓安全分析助手，用中文回答，不超过80字。" },
                            // 回归验证：第二条 system 曾触发 llama-server 500（Jinja: System message must be at the beginning）
                            new Services.ChatMsg { Role = "system", Content = "当前分析证据：APK 使用明文 HTTP，目的端口 8095。" },
                            new Services.ChatMsg { Role = "user", Content = "该 APK 用明文 HTTP 向 IP 直连端口 8095 外发 IMEI 与位置，风险是什么？" }
                        }).ConfigureAwait(true);
                        sw2.Stop();
                        sb.AppendLine("AI ok 耗时=" + sw2.Elapsed.TotalSeconds.ToString("F1") + "s");
                        sb.AppendLine("AI out=" + ans.Replace("\n", " ").Replace("\r", " ").Trim());
                    }
                    else
                    {
                        sb.AppendLine("AI 启动失败");
                    }
                    Services.AiService.StopLocal();
                    sb.AppendLine("AI total=" + sw.Elapsed.TotalSeconds.ToString("F1") + "s");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("EX " + ex);
            }

            try
            {
                var outFile = Path.Combine(Services.Storage.AppRoot, "selftest.txt");
                File.WriteAllText(outFile, sb.ToString(), new UTF8Encoding(false));
                Services.Log.Write("[selftest] " + sb.ToString());
            }
            catch { }
        }

        private void OnUnhandled(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            Services.Log.Write("UI-EX " + e.Exception);
            MessageBox.Show(e.Exception.Message, "REA Studio", MessageBoxButton.OK, MessageBoxImage.Warning);
            e.Handled = true;
        }
    }
}
