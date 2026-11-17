using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    /// <summary>
    /// 运行时载荷管理：把内嵌的 payload.zip（Node 运行时 + REA + 推理引擎 + 本地模型）
    /// 按版本解出到 %LOCALAPPDATA%\REAStudio\runtime，后续启动直接复用。
    /// </summary>
    internal static class Storage
    {
        public static readonly string AppRoot = ResolveAppRoot();

        /// <summary>数据目录优先级：REASTUDIO_HOME > 程序同级 REAStudio-Data（便携） > LocalAppData。</summary>
        private static string ResolveAppRoot()
        {
            var env = Environment.GetEnvironmentVariable("REASTUDIO_HOME");
            if (!string.IsNullOrWhiteSpace(env))
            {
                try { Directory.CreateDirectory(env); return env; } catch { }
            }
            try
            {
                var portable = Path.Combine(AppContext.BaseDirectory, "REAStudio-Data");
                Directory.CreateDirectory(portable);
                var probe = Path.Combine(portable, ".writable");
                File.WriteAllText(probe, "1");
                File.Delete(probe);
                return portable;
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "REAStudio");
        }

        public static string DataRoot
        {
            get { var d = Path.Combine(AppRoot, "data"); Directory.CreateDirectory(d); return d; }
        }

        public static string OutputRoot
        {
            get { var d = Path.Combine(AppRoot, "evidence"); Directory.CreateDirectory(d); return d; }
        }

        public static string RuntimeRoot { get; private set; } = "";
        public static string NodeExe { get; private set; } = "";
        public static string ReaEntry { get; private set; } = "";
        public static string LlamaServer { get; private set; } = "";
        public static string ModelDir { get; private set; } = "";
        public static bool PayloadReady { get; private set; }
        public static string PayloadKind { get; private set; } = "none";
        public static string PayloadVersion { get; private set; } = "";

        public static event Action<string>? Progress;

        private static void Report(string text)
        {
            try { Progress?.Invoke(text); } catch { }
            Log.Write("[payload] " + text);
        }

        /// <summary>读取自身 EXE 尾部的载荷尾标（REAPAY01 + offset + length）。</summary>
        private static string FindOverlayPayload(out long offset, out long length)
        {
            offset = 0; length = 0;
            try
            {
                var exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return null;
                using var fs = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (fs.Length < 32) return null;
                fs.Seek(-24, SeekOrigin.End);
                var tail = new byte[24];
                var read = 0;
                while (read < 24)
                {
                    var n = fs.Read(tail, read, 24 - read);
                    if (n <= 0) break;
                    read += n;
                }
                if (read != 24) return null;
                if (System.Text.Encoding.ASCII.GetString(tail, 0, 8) != "REAPAY01") return null;
                offset = BitConverter.ToInt64(tail, 8);
                length = BitConverter.ToInt64(tail, 16);
                if (offset <= 0 || length <= 0 || offset + length > fs.Length) return null;
                return exe;
            }
            catch { return null; }
        }

        /// <summary>把 EXE 尾部载荷区段复制成独立 zip 文件。</summary>
        private static void CopyOverlay(string exe, long offset, long length, string dstPath)
        {
            using var src = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            src.Seek(offset, SeekOrigin.Begin);
            using var dst = new FileStream(dstPath, FileMode.Create, FileAccess.Write, FileShare.None, 4 << 20);
            var buf = new byte[4 << 20];
            var left = length;
            while (left > 0)
            {
                var n = src.Read(buf, 0, (int)Math.Min(buf.Length, left));
                if (n <= 0) break;
                dst.Write(buf, 0, n);
                left -= n;
            }
        }

        public static Task EnsureRuntimeAsync()
        {
            return Task.Run(() => EnsureRuntime());
        }

        private static void EnsureRuntime()
        {
            // 1) 开发模式：环境变量直接指向现成目录
            var devNode = Environment.GetEnvironmentVariable("REASTUDIO_NODE");
            var devRea = Environment.GetEnvironmentVariable("REASTUDIO_REA");
            if (!string.IsNullOrEmpty(devNode) && File.Exists(devNode) && !string.IsNullOrEmpty(devRea) && File.Exists(devRea))
            {
                NodeExe = devNode;
                ReaEntry = devRea;
                RuntimeRoot = Path.GetDirectoryName(Path.GetDirectoryName(devNode)) ?? "";
                PayloadKind = "dev";
                PayloadReady = true;
                ResolveOptionalAssets(RuntimeRoot);
                Report("开发模式：使用外部运行时 " + NodeExe);
                return;
            }

            var asm = Assembly.GetExecutingAssembly();
            var resName = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.Equals("payload.zip", StringComparison.OrdinalIgnoreCase));

            long expected = 0;
            string overlayExe = null;
            long overlayOffset = 0, overlayLength = 0;
            if (resName != null)
            {
                using var probe = asm.GetManifestResourceStream(resName)!;
                expected = probe.Length;
            }
            else
            {
                overlayExe = FindOverlayPayload(out overlayOffset, out overlayLength);
                if (overlayExe != null) expected = overlayLength;
            }

            if (expected <= 0)
            {
                PayloadKind = "missing";
                Report("未找到运行时载荷（内嵌资源与 EXE 尾部附加均缺失）");
                return;
            }

            PayloadVersion = expected.ToString("X") + "-" + (asm.GetName().Version?.ToString() ?? "0");
            RuntimeRoot = Path.Combine(AppRoot, "runtime", PayloadVersion);
            var doneFlag = Path.Combine(RuntimeRoot, ".ready");

            if (!File.Exists(doneFlag))
            {
                if (Directory.Exists(RuntimeRoot))
                {
                    try { Directory.Delete(RuntimeRoot, true); } catch { }
                }
                Report("首次运行，正在解压运行时组件（" + (expected / 1048576.0).ToString("F1") + " MB）…");
                Directory.CreateDirectory(RuntimeRoot);

                var stage = Path.Combine(AppRoot, "payload");
                Directory.CreateDirectory(stage);
                var zipPath = Path.Combine(stage, "payload.zip");
                try
                {
                    var staged = File.Exists(zipPath) ? new FileInfo(zipPath).Length : 0;
                    if (staged == expected)
                    {
                        Report("复用已解出的载荷暂存文件（" + (expected / 1048576.0).ToString("F1") + " MB）…");
                    }
                    else
                    {
                        if (resName != null)
                        {
                            using var fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None, 4 << 20);
                            using var rs = asm.GetManifestResourceStream(resName)!;
                            rs.CopyTo(fs, 4 << 20);
                        }
                        else
                        {
                            CopyOverlay(overlayExe, overlayOffset, overlayLength, zipPath);
                        }
                    }

                    using (var fs = File.OpenRead(zipPath))
                    using (var zip = new ZipArchive(fs, ZipArchiveMode.Read))
                    {
                        foreach (var entry in zip.Entries)
                        {
                            if (string.IsNullOrEmpty(entry.Name)) continue;
                            var dest = Path.GetFullPath(Path.Combine(RuntimeRoot, entry.FullName));
                            if (!dest.StartsWith(RuntimeRoot, StringComparison.OrdinalIgnoreCase)) continue;
                            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                            entry.ExtractToFile(dest, true);
                        }
                    }
                }
                finally
                {
                    try { File.Delete(zipPath); } catch { }
                }
                File.WriteAllText(doneFlag, DateTime.Now.ToString("O"));
            }

            NodeExe = Path.Combine(RuntimeRoot, "node", "node.exe");
            ReaEntry = Path.Combine(RuntimeRoot, "node", "modules", "rea-agents", "scripts", "rea.mjs");
            PayloadKind = "embedded";
            PayloadReady = File.Exists(NodeExe) && File.Exists(ReaEntry);
            ResolveOptionalAssets(RuntimeRoot);
            Report(PayloadReady ? "运行时就绪" : "运行时组件不完整");
        }

        private static void ResolveOptionalAssets(string root)
        {
            if (string.IsNullOrEmpty(root)) return;
            var llama = Path.Combine(root, "llama", "llama-server.exe");
            LlamaServer = File.Exists(llama) ? llama : "";
            var model = Path.Combine(root, "model");
            ModelDir = Directory.Exists(model) ? model : "";

            // 开发模式下允许外部指定
            var devLlama = Environment.GetEnvironmentVariable("REASTUDIO_LLAMA");
            if (!string.IsNullOrEmpty(devLlama) && File.Exists(devLlama)) LlamaServer = devLlama;
            var devModel = Environment.GetEnvironmentVariable("REASTUDIO_MODEL_DIR");
            if (!string.IsNullOrEmpty(devModel) && Directory.Exists(devModel)) ModelDir = devModel;
        }

        public static string Sha256(string path)
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
    }

    /// <summary>把内嵌 ui/ 静态资源解到缓存目录，交给 WebView2 虚拟主机映射。</summary>
    internal static class UiAssets
    {
        public static string ExtractToCache()
        {
            var asm = Assembly.GetExecutingAssembly();
            var name = asm.FullName ?? "app";
            var dir = Path.Combine(Storage.AppRoot, "ui", Hash(name));

            var names = asm.GetManifestResourceNames()
                .Where(n => n.StartsWith("ui/", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (names.Length == 0)
            {
                Directory.CreateDirectory(dir);
                return dir;
            }

            Directory.CreateDirectory(dir);
            foreach (var res in names)
            {
                var rel = res.Substring(3).Replace('/', Path.DirectorySeparatorChar);
                var dest = Path.Combine(dir, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                using var s = asm.GetManifestResourceStream(res)!;
                using var f = File.Create(dest);
                s.CopyTo(f);
            }
            return dir;
        }

        private static string Hash(string text)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(text));
            return Convert.ToHexString(bytes).Substring(0, 10).ToLowerInvariant();
        }
    }

}