using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;
using ReaStudio.Services;

namespace ReaStudio
{
    public partial class MainWindow : Window
    {
        private Bridge? _bridge;

        public MainWindow()
        {
            InitializeComponent();
            SourceInitialized += OnSourceInitialized;
            Loaded += OnLoaded;
        }

        private void OnSourceInitialized(object? sender, EventArgs e)
        {
            try
            {
                var hwnd = new WindowInteropHelper(this).Handle;
                int dark = 1;
                DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int));      // DWMWA_USE_IMMERSIVE_DARK_MODE
                int corner = 2;                                              // DWMWCP_ROUND
                DwmSetWindowAttribute(hwnd, 33, ref corner, sizeof(int));    // DWMWA_WINDOW_CORNER_PREFERENCE
                int backdrop = 2;                                            // DWMSBT_MAINWINDOW (Mica)
                DwmSetWindowAttribute(hwnd, 38, ref backdrop, sizeof(int));  // DWMWA_SYSTEMBACKDROP_TYPE
            }
            catch (Exception ex) { Log.Write("dwm: " + ex.Message); }
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            try
            {
                Storage.Progress += t => Dispatcher.Invoke(() => SplashText.Text = t);
                SplashText.Text = "正在准备本地运行时…";
                await Storage.EnsureRuntimeAsync();

                SplashText.Text = "正在解出界面资源…";
                var uiDir = UiAssets.ExtractToCache();
                var userData = WebViewEnvironment.UserDataFolder;
                var core = await CoreWebView2Environment.CreateAsync(null, userData).ConfigureAwait(true);
                await Web.EnsureCoreWebView2Async(core);
                Web.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
                Web.CoreWebView2.Settings.IsStatusBarEnabled = false;
                Web.CoreWebView2.Settings.AreDevToolsEnabled = true;
                Web.CoreWebView2.SetVirtualHostNameToFolderMapping("reastudio.local", uiDir,
                    CoreWebView2HostResourceAccessKind.Allow);

                _bridge = new Bridge(this, Web.CoreWebView2);
                Web.CoreWebView2.WebMessageReceived += _bridge.OnWebMessage;
                Web.CoreWebView2.NavigationCompleted += async (s, a) =>
                {
                    Splash.Visibility = Visibility.Collapsed;
                    TryOpenCommandLineTarget();
                    // 调试钩子：REASTUDIO_PAGE=settings 直接进入指定页面（便于界面自动化核验）
                    var startPage = Environment.GetEnvironmentVariable("REASTUDIO_PAGE");
                    if (!string.IsNullOrEmpty(startPage))
                    {
                        await Task.Delay(600);
                        await Web.CoreWebView2.ExecuteScriptAsync(
                            "typeof navigate==='function'&&navigate('" + startPage.Replace("'", "") + "')");
                    }
                    // 调试钩子：REASTUDIO_EVAL 在页面加载后执行一段脚本，结果写入调试日志
                    var evalScript = Environment.GetEnvironmentVariable("REASTUDIO_EVAL");
                    if (!string.IsNullOrEmpty(evalScript))
                    {
                        await Task.Delay(1500);
                        var evalResult = await Web.CoreWebView2.ExecuteScriptAsync(evalScript);
                        Log.Write("eval: " + evalResult);
                    }
                    if (Environment.GetEnvironmentVariable("REASTUDIO_AUTORUN") == "1")
                    {
                        await Task.Delay(1200);
                        await Web.CoreWebView2.ExecuteScriptAsync(
                            "document.getElementById('btnGotoAnalysis')&&document.getElementById('btnGotoAnalysis').click()");
                    }
                };
                Web.CoreWebView2.Navigate("https://reastudio.local/index.html");
            }
            catch (Exception ex)
            {
                Log.Write("webview init: " + ex);
                SplashText.Text = "WebView2 初始化失败：" + ex.Message;
            }
        }

        /// <summary>支持 rea-studio.exe "D:\sample.exe" 直接带着目标启动。</summary>
        private void TryOpenCommandLineTarget()
        {
            try
            {
                var args = Environment.GetCommandLineArgs();
                for (int i = 1; i < args.Length; i++)
                {
                    var p = args[i];
                    if (string.IsNullOrWhiteSpace(p) || p.StartsWith("-")) continue;
                    var dto = Services.Bridge.DescribePath(p);
                    if (dto != null)
                    {
                        PostJson(new { @event = "open.target", data = dto });
                        return;
                    }
                }
            }
            catch (Exception ex) { Log.Write("cmdline: " + ex.Message); }
        }

        public void PostJson(object payload)
        {
            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(payload);
                Dispatcher.Invoke(() => Web.CoreWebView2?.PostWebMessageAsJson(json));
            }
            catch (Exception ex) { Log.Write("post: " + ex.Message); }
        }

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    }
}
