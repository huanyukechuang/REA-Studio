using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace ReaSetup
{
    /// <summary>安装核心：从自身尾部读取随包载荷（含本地模型），释放到目标目录并建立快捷方式与卸载项。</summary>
    public static class SetupCore
    {
        public const string AppName = "REA Studio";
        public const string AppNameNoModel = "REA Studio(no model)";
        public const string AppExeFull = "REAStudio.exe";
        public const string AppExeNoModel = "REA Studio(no model).exe";
        public const string AppVersion = "1.0.0";
        public const string Publisher = "环宇科创 · 科创云玄武安全实验室";
        public const string UninstallKeyFull = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\REAStudio";
        public const string UninstallKeyNoModel = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\REAStudio-NoModel";

        /// <summary>主程序文件名：含模型版 REAStudio.exe，no model 版 REA Studio(no model).exe。</summary>
        public static string AppExe
        {
            get { return HasLocalModel ? AppExeFull : AppExeNoModel; }
        }

        /// <summary>显示名：快捷方式、卸载项、默认安装目录都跟着版本走，避免两版互相覆盖。</summary>
        public static string DisplayName
        {
            get { return HasLocalModel ? AppName : AppNameNoModel; }
        }

        public static string UninstallKey
        {
            get { return HasLocalModel ? UninstallKeyFull : UninstallKeyNoModel; }
        }

        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("REASET01");
        private static readonly byte[] MagicLite = Encoding.ASCII.GetBytes("REASET02");

        [System.Runtime.InteropServices.DllImport("shell32.dll")]
        private static extern bool IsUserAnAdmin();

        public static string DefaultInstallDir
        {
            get
            {
                if (IsUserAnAdmin())
                {
                    var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                    if (!string.IsNullOrWhiteSpace(pf)) return Path.Combine(pf, DisplayName);
                }
                var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrWhiteSpace(local)) local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local");
                return Path.Combine(local, "Programs", DisplayName);
            }
        }

        public static string SelfPath
        {
            get
            {
                var p = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(p) && File.Exists(p)) return p;
                return Process.GetCurrentProcess().MainModule?.FileName ?? "";
            }
        }

        /// <summary>定位随包载荷：读取 EXE 尾部 24 字节尾标（magic + offset + length）。</summary>
        public static bool TryLocatePayload(out long offset, out long length, out string error)
        {
            offset = 0; length = 0; error = "";
            var self = SelfPath;
            if (string.IsNullOrEmpty(self) || !File.Exists(self)) { error = "无法定位安装程序自身路径"; return false; }
            try
            {
                using var fs = new FileStream(self, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (fs.Length < 24) { error = "安装包不完整（缺少载荷）"; return false; }
                fs.Seek(-24, SeekOrigin.End);
                var head = new byte[8];
                fs.Read(head, 0, 8);
                bool isFull = true, isLite = true;
                for (int i = 0; i < 8; i++)
                {
                    if (head[i] != Magic[i]) isFull = false;
                    if (head[i] != MagicLite[i]) isLite = false;
                }
                if (!isFull && !isLite)
                {
                    // 开发调试：同目录存在独立 REAStudio.exe 时直接使用
                    var sibling = Path.Combine(Path.GetDirectoryName(self) ?? "", AppExe);
                    if (File.Exists(sibling))
                    {
                        offset = 0; length = new FileInfo(sibling).Length;
                        error = "";
                        return true;
                    }
                    error = "安装包缺少随包载荷（可能未完成打包）";
                    return false;
                }
                var buf = new byte[16];
                fs.Read(buf, 0, 16);
                offset = BitConverter.ToInt64(buf, 0);
                length = BitConverter.ToInt64(buf, 8);
                if (offset <= 0 || length <= 0 || offset + length > fs.Length)
                {
                    error = "安装包载荷信息损坏";
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public static long PayloadBytes
        {
            get
            {
                return TryLocatePayload(out _, out var len, out _) ? len : 0;
            }
        }

        /// <summary>载荷是否包含本地大模型（尾标 REASET01=含模型，REASET02=不含模型）。</summary>
        public static bool HasLocalModel
        {
            get
            {
                var self = SelfPath;
                try
                {
                    if (string.IsNullOrEmpty(self) || !File.Exists(self)) return true;
                    using var fs = new FileStream(self, FileMode.Open, FileAccess.Read, FileShare.Read);
                    if (fs.Length < 24) return true;
                    fs.Seek(-24, SeekOrigin.End);
                    var head = new byte[8];
                    fs.Read(head, 0, 8);
                    for (int i = 0; i < 8; i++)
                        if (head[i] != MagicLite[i]) return true;
                    return false;
                }
                catch { return true; }
            }
        }

        public static string FormatSize(long bytes)
        {
            if (bytes <= 0) return "未知";
            double mb = bytes / 1048576.0;
            if (mb >= 1024) return (mb / 1024.0).ToString("0.00") + " GB";
            return mb.ToString("0.0") + " MB";
        }

        /// <summary>校验目标目录所在磁盘可用空间是否足够。</summary>
        public static bool CheckSpace(string dir, out string message)
        {
            message = "";
            try
            {
                var root = Path.GetPathRoot(Path.GetFullPath(dir));
                if (string.IsNullOrEmpty(root)) { message = "无法识别目标磁盘"; return false; }
                var di = new DriveInfo(root);
                long need = PayloadBytes;
                if (need <= 0) { message = "无法读取安装包体积"; return false; }
                if (di.AvailableFreeSpace < need + 200L * 1024 * 1024)
                {
                    message = "目标磁盘可用空间不足：需要 " + FormatSize(need) + "，当前可用 " + FormatSize(di.AvailableFreeSpace);
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        /// <summary>执行安装。progress 回调参数为 0~1 的进度与状态文案。</summary>
        public static void Install(string targetDir, bool desktopShortcut, bool startMenuShortcut, Action<double, string> progress, Action<string> log)
        {
            progress(0.0, "正在准备安装目录…");
            Directory.CreateDirectory(targetDir);

            if (!TryLocatePayload(out var offset, out var length, out var perr))
                throw new InvalidOperationException(perr);

            var self = SelfPath;
            var sibling = Path.Combine(Path.GetDirectoryName(self) ?? "", AppExe);
            var src = offset == 0 && File.Exists(sibling) ? sibling : self;

            var dstExe = Path.Combine(targetDir, AppExe);
            log("释放程序与本地模型：" + FormatSize(length));

            using (var sfs = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
            using (var dfs = new FileStream(dstExe, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
            {
                if (offset > 0) sfs.Seek(offset, SeekOrigin.Begin);
                var buffer = new byte[4 << 20];
                long done = 0;
                int lastPct = -1;
                while (done < length)
                {
                    int want = (int)Math.Min(buffer.Length, length - done);
                    int n = sfs.Read(buffer, 0, want);
                    if (n <= 0) break;
                    dfs.Write(buffer, 0, n);
                    done += n;
                    int pct = (int)(done * 100 / Math.Max(1, length));
                    if (pct != lastPct)
                    {
                        lastPct = pct;
                        progress(0.02 + 0.88 * (double)done / length, "正在写入 " + FormatSize(done) + " / " + FormatSize(length));
                    }
                }
                dfs.Flush(true);
            }

            progress(0.92, "正在建立快捷方式…");
            if (desktopShortcut)
            {
                var desk = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                CreateShortcut(Path.Combine(desk, DisplayName + ".lnk"), dstExe, targetDir);
            }
            if (startMenuShortcut)
            {
                var sm = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
                CreateShortcut(Path.Combine(sm, DisplayName + ".lnk"), dstExe, targetDir);
            }

            progress(0.95, "正在注册卸载信息…");
            WriteUninstall(targetDir, dstExe, length);

            progress(0.99, "正在完成安装…");
            log("安装目录：" + targetDir);
            progress(1.0, "安装完成");
        }

        private static void CreateShortcut(string lnkPath, string targetExe, string workDir)
        {
            try
            {
                var t = Type.GetTypeFromProgID("WScript.Shell");
                if (t == null) return;
                dynamic shell = Activator.CreateInstance(t)!;
                dynamic lnk = shell.CreateShortcut(lnkPath);
                lnk.TargetPath = targetExe;
                lnk.WorkingDirectory = workDir;
                lnk.IconLocation = targetExe + ",0";
                lnk.Description = DisplayName + " 本地逆向分析工作台";
                lnk.Save();
            }
            catch { /* 快捷方式失败不影响主流程 */ }
        }

        private static void WriteUninstall(string dir, string exe, long size)
        {
            var ps = Path.Combine(dir, "uninstall.ps1");
            var script = string.Join("\r\n", new[]
            {
                "$ErrorActionPreference='SilentlyContinue'",
                "$dir = Split-Path -Parent $MyInvocation.MyCommand.Path",
                "Stop-Process -Name '" + Path.GetFileNameWithoutExtension(AppExe) + "' -Force",
                "Remove-Item 'HKCU:\\" + UninstallKey + "' -Recurse -Force",
                "Remove-Item (Join-Path $env:USERPROFILE 'Desktop\\" + DisplayName + ".lnk') -Force",
                "Remove-Item (Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs\\" + DisplayName + ".lnk') -Force",
                "Start-Sleep -Milliseconds 400",
                "Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',(\"Start-Sleep -Seconds 2; Remove-Item -LiteralPath '{0}' -Recurse -Force\" -f $dir)",
            });
            File.WriteAllText(ps, script, new UTF8Encoding(true));

            using var key = Registry.CurrentUser.CreateSubKey(UninstallKey);
            if (key == null) return;
            key.SetValue("DisplayName", DisplayName, RegistryValueKind.String);
            key.SetValue("DisplayVersion", AppVersion, RegistryValueKind.String);
            key.SetValue("Publisher", Publisher, RegistryValueKind.String);
            key.SetValue("DisplayIcon", exe + ",0", RegistryValueKind.String);
            key.SetValue("InstallLocation", dir, RegistryValueKind.String);
            key.SetValue("UninstallString",
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"" + ps + "\"", RegistryValueKind.String);
            key.SetValue("NoModify", 1, RegistryValueKind.DWord);
            key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            key.SetValue("EstimatedSize", (int)Math.Min(int.MaxValue, size / 1024), RegistryValueKind.DWord);
        }

        /// <summary>安装后启动主程序。</summary>
        public static void Launch(string dir)
        {
            var exe = Path.Combine(dir, AppExe);
            if (!File.Exists(exe)) return;
            var psi = new ProcessStartInfo(exe) { WorkingDirectory = dir, UseShellExecute = true };
            Process.Start(psi);
        }
    }
}
