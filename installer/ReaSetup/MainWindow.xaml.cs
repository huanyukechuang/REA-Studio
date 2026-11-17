using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace ReaSetup
{
    public partial class MainWindow : Window
    {
        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        private int _step = 1;
        private bool _busy;
        private bool _done;
        private bool _ok;
        private string _dir;

        public MainWindow()
        {
            InitializeComponent();

            var size = SetupCore.PayloadBytes;
            var hasModel = SetupCore.HasLocalModel;
            TxtVersion.Text = "版本 " + SetupCore.AppVersion + " · 本地逆向分析工作台";
            TxtPackageInfo.Text = size > 0
                ? (hasModel
                    ? "安装包约 " + SetupCore.FormatSize(size) + "（已含本地大模型），安装过程需复制全部文件，请预留足够空间。"
                    : "安装包约 " + SetupCore.FormatSize(size) + "（不含本地大模型），安装完成后可在软件「设置 · 本地模型」中在线下载模型。")
                : "安装包缺少随包载荷，请重新获取完整安装程序。";
            TxtSpace.Text = "所需磁盘空间：约 " + SetupCore.FormatSize(size);
            if (!hasModel)
                TxtModelLine.Text = "· 本地大模型（需在软件「设置 · 本地模型」中按需下载）";

            _dir = SetupCore.DefaultInstallDir;
            TxtPath.Text = _dir;

            SourceInitialized += (s, e) => ApplyCorners();
        }

        private void ApplyCorners()
        {
            try
            {
                var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                int pref = 2; // DWMWCP_ROUND
                DwmSetWindowAttribute(hwnd, 33, ref pref, sizeof(int));
            }
            catch { }
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed)
            {
                try { DragMove(); } catch { }
            }
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();
        private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();

        private void BtnBack_Click(object sender, RoutedEventArgs e)
        {
            if (_busy || _done) return;
            if (_step == 2) ShowStep(1);
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            if (_busy) return;
            using var dlg = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "选择 REA Studio 的安装位置",
                UseDescriptionForTitle = true,
                SelectedPath = Directory.Exists(TxtPath.Text) ? TxtPath.Text : SetupCore.DefaultInstallDir,
                ShowNewFolderButton = true
            };
            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(dlg.SelectedPath))
            {
                _dir = dlg.SelectedPath;
                TxtPath.Text = _dir;
            }
        }

        private void BtnNext_Click(object sender, RoutedEventArgs e)
        {
            if (_done)
            {
                if (_ok && ChkLaunchDone.IsChecked == true)
                {
                    try { SetupCore.Launch(_dir); } catch (Exception ex) { Log("启动失败：" + ex.Message); }
                }
                Close();
                return;
            }
            if (_busy) return;
            if (_step == 1) { ShowStep(2); return; }
            if (_step == 2) StartInstall();
        }

        private void ShowStep(int step)
        {
            _step = step;
            Page1.Visibility = step == 1 ? Visibility.Visible : Visibility.Collapsed;
            Page2.Visibility = step == 2 ? Visibility.Visible : Visibility.Collapsed;
            Page3.Visibility = step == 3 ? Visibility.Visible : Visibility.Collapsed;
            BtnBack.Visibility = step == 2 ? Visibility.Visible : Visibility.Collapsed;
            BtnNext.Content = step == 2 ? "安装" : "下一步";
        }

        private void StartInstall()
        {
            var dir = (TxtPath.Text ?? "").Trim();
            if (string.IsNullOrWhiteSpace(dir))
            {
                System.Windows.MessageBox.Show(this, "请选择安装位置。", "REA Studio", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!SetupCore.CheckSpace(dir, out var spaceMsg))
            {
                System.Windows.MessageBox.Show(this, spaceMsg, "REA Studio", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _dir = dir;
            var desktop = ChkDesktop.IsChecked == true;
            var startMenu = ChkStartMenu.IsChecked == true;

            ShowStep(3);
            _busy = true;
            BtnNext.IsEnabled = false;
            BtnCancel.IsEnabled = false;
            BtnBack.Visibility = Visibility.Collapsed;
            SetProgress(0, "正在准备安装目录…");
            Log("开始安装到 " + dir);

            Task.Run(() =>
            {
                try
                {
                    SetupCore.Install(_dir, desktop, startMenu,
                        (p, s) => Dispatcher.Invoke(() => SetProgress(p, s)),
                        m => Dispatcher.Invoke(() => Log(m)));
                    Dispatcher.Invoke(() => OnInstalled(true, null));
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => OnInstalled(false, ex.Message));
                }
            });
        }

        private void SetProgress(double ratio, string status)
        {
            if (ratio < 0) ratio = 0;
            if (ratio > 1) ratio = 1;
            var w = ProgHost.ActualWidth;
            if (w <= 0) w = 560;
            ProgFill.Width = Math.Max(0, w * ratio);
            TxtPercent.Text = ((int)(ratio * 100)) + "%  " + status;
        }

        private void OnInstalled(bool ok, string? error)
        {
            _busy = false;
            _done = true;
            _ok = ok;
            BtnCancel.IsEnabled = true;
            BtnNext.IsEnabled = true;
            BtnNext.Content = "关闭";

            if (ok)
            {
                SetProgress(1.0, "安装完成");
                TxtStepTitle.Text = "安装完成";
                TxtStepSub.Text = "REA Studio 已成功安装，可直接启动使用。";
                DoneBadge.Visibility = Visibility.Visible;
                TxtStepTitle.Margin = new Thickness(12, 0, 0, 0);
                DonePanel.Visibility = Visibility.Visible;
                TxtInstallDir.Text = "安装位置：" + _dir;
                BtnCancel.Content = "关闭";
                BtnNext.Content = "完成";
                Log("安装完成");
            }
            else
            {
                SetProgress(1.0, "安装失败");
                ProgFill.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xC4, 0x2B, 0x1C));
                TxtStepTitle.Text = "安装未完成";
                TxtStepSub.Text = error ?? "未知错误";
                Log("安装失败：" + error);
            }
        }

        private void Log(string msg)
        {
            try
            {
                var path = Path.Combine(Path.GetTempPath(), "REASetup.log");
                File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine);
            }
            catch { }
        }
    }
}
