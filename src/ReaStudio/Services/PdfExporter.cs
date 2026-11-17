using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace ReaStudio.Services
{
    /// <summary>用离屏 WebView2 将报告 HTML 打印为 PDF；渲染环境跑在沙箱会话内。</summary>
    internal static class PdfExporter
    {
        // A4 版心：上 16mm、下 16mm、左右 14mm（mm = 1/25.4in），与 Reports.cs 的 @page 保持一致
        public const double MarginTopMm = 16.0;
        public const double MarginBottomMm = 16.0;
        public const double MarginLeftMm = 14.0;
        public const double MarginRightMm = 14.0;

        private const double MmPerInch = 25.4;

        public static async Task<(bool ok, string error)> ExportAsync(string html, string outPath)
        {
            if (string.IsNullOrWhiteSpace(outPath)) return (false, "输出路径为空");
            var app = Application.Current;
            if (app == null) return (false, "缺少 UI 线程，无法渲染 PDF");

            // 渲染用的 HTML 也落在沙箱内，不留宿主临时文件
            var tmpHtml = Sandbox.StageText("report-" + Guid.NewGuid().ToString("N") + ".html", html, "out");

            var tcs = new TaskCompletionSource<(bool, string)>(TaskCreationOptions.RunContinuationsAsynchronously);

            // 不等待 UI 队列本身，结果由 tcs 回传（避免 CS4014）
            var uiOp = app.Dispatcher.InvokeAsync(new Action(async () =>
            {
                Window? win = null;
                WebView2? wv = null;
                try
                {
                    win = new Window
                    {
                        Width = 1240,
                        Height = 1754,
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
                    Sandbox.Guard(wv.CoreWebView2, null);
                    // 强制浅色配色：避免宿主深色主题把 A4 画布渲染成深色，导致 PDF 页边出现深色边框
                    try { wv.CoreWebView2.Profile.PreferredColorScheme = CoreWebView2PreferredColorScheme.Light; } catch { }

                    var nav = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    wv.NavigationCompleted += (s, e) => nav.TrySetResult(e.IsSuccess);
                    wv.CoreWebView2.Navigate(new Uri(tmpHtml).AbsoluteUri);
                    await Task.WhenAny(nav.Task, Task.Delay(20000));
                    await Task.Delay(700); // 等待布局与字体就绪

                    var ps = wv.CoreWebView2.Environment.CreatePrintSettings();
                    ps.PageWidth = 8.27;   // A4 纵向 210mm
                    ps.PageHeight = 11.69; // A4 纵向 297mm
                    ps.ScaleFactor = 1.0;
                    ps.ShouldPrintBackgrounds = false; // 页面画布在深色主题下为深色，打印背景会形成深色页边；报告本身白底黑字无需背景色
                    ps.ShouldPrintHeaderAndFooter = false;
                    // 页边距以 CSS @page 为准，此处 PrintSettings 仅作兜底
                    ps.MarginTop = MarginTopMm / MmPerInch;
                    ps.MarginBottom = MarginBottomMm / MmPerInch;
                    ps.MarginLeft = MarginLeftMm / MmPerInch;
                    ps.MarginRight = MarginRightMm / MmPerInch;
                    await wv.CoreWebView2.PrintToPdfAsync(outPath, ps);

                    var ok = File.Exists(outPath) && new FileInfo(outPath).Length > 1024;
                    Sandbox.Note("PDF 导出 " + outPath + " ok=" + ok);
                    tcs.TrySetResult((ok, ok ? "" : "打印未生成有效文件"));
                }
                catch (Exception ex)
                {
                    tcs.TrySetResult((false, ex.Message));
                }
                finally
                {
                    try { wv?.Dispose(); } catch { }
                    try { win?.Close(); } catch { }
                    try { if (File.Exists(tmpHtml) && Sandbox.IsInsideSandbox(tmpHtml)) File.Delete(tmpHtml); } catch { }
                }
            }));

            var result = await tcs.Task.ConfigureAwait(true);
            GC.KeepAlive(uiOp);
            return result;
        }
    }
}
