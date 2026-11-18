using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace ReaStudio.Services
{
    /// <summary>
    /// 动态执行网络隔离：用 Windows 防火墙出站阻断规则，把样本（以及工作区内解包出的可执行文件）
    /// 的出站流量整体拦截，使样本在被观测期间无法外联真实网络或回传数据。
    /// 规则名统一以 REA-DynBlock- 为前缀，会话结束按前缀清理；进程异常退出留下的残留由 CleanupStale 兜底。
    /// 说明：防火墙程序规则按可执行文件绝对路径生效，样本若把自身复制到工作区外运行则不受约束，
    /// 这一限制会写入结果备注，提示结合进程树与落盘记录人工核对。
    /// </summary>
    internal static class DynNetGuard
    {
        public const string Prefix = "REA-DynBlock-";

        static readonly object Sync = new object();
        static readonly List<string> Rules = new();
        static bool _active;

        public static bool Active { get { lock (Sync) { return _active; } } }

        /// <summary>网络阻断需要管理员权限才能写入防火墙规则。</summary>
        public static bool Available { get { try { return DynIsolation.IsAdmin(); } catch { return false; } } }

        /// <summary>对工作区内的可执行文件逐个建立出站阻断规则，返回是否至少成功一条。</summary>
        public static bool Enable(string tag, string workRoot, Action<string>? log = null, params string[]? extraFiles)
        {
            lock (Sync)
            {
                if (_active) return true;
                if (string.IsNullOrWhiteSpace(tag)) tag = "r" + DateTime.Now.ToString("HHmmss");
                tag = new string(tag.Where(ch => char.IsLetterOrDigit(ch) || ch == '-').ToArray());
                if (tag.Length == 0) tag = "sess";

                var targets = new List<string>();
                void AddFile(string? p)
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(p) || !File.Exists(p)) return;
                        var ext = Path.GetExtension(p).ToLowerInvariant();
                        if (ext != ".exe" && ext != ".scr" && ext != ".com" && ext != ".bat" && ext != ".cmd" && ext != ".pif") return;
                        var full = Path.GetFullPath(p);
                        if (targets.Exists(t => string.Equals(t, full, StringComparison.OrdinalIgnoreCase))) return;
                        targets.Add(full);
                    }
                    catch { }
                }

                try
                {
                    if (!string.IsNullOrWhiteSpace(workRoot) && Directory.Exists(workRoot))
                        foreach (var f in Directory.EnumerateFiles(workRoot, "*", SearchOption.AllDirectories))
                        {
                            AddFile(f);
                            if (targets.Count >= 24) break;
                        }
                }
                catch { }
                if (extraFiles != null) foreach (var f in extraFiles) AddFile(f);

                if (targets.Count == 0)
                {
                    Note = "工作区内未发现可执行文件，未建立网络阻断规则";
                    log?.Invoke(Note);
                    return false;
                }

                int ok = 0, i = 0;
                string lastErr = "";
                foreach (var f in targets)
                {
                    i++;
                    var name = Prefix + tag + "-" + i;
                    var args = "advfirewall firewall add rule name=\"" + name + "\" dir=out action=block program=\"" + f + "\" profile=any enable=yes";
                    var r = RunNetsh(args);
                    if (r.Code == 0)
                    {
                        ok++;
                        Rules.Add(name);
                    }
                    else
                    {
                        lastErr = Tail(r.Output);
                    }
                }

                _active = ok > 0;
                if (_active)
                {
                    Note = "已对 " + ok + " 个可执行文件启用出站阻断（规则前缀 " + Prefix + tag + "，会话结束自动清理）";
                    log?.Invoke("网络隔离：" + Note);
                }
                else
                {
                    Note = "未能建立网络阻断规则" + (lastErr.Length > 0 ? "：" + lastErr : "（请确认 Windows 防火墙服务已启用且具备管理员权限）");
                    log?.Invoke("网络隔离：" + Note);
                }
                return _active;
            }
        }

        /// <summary>删除本次会话建立的规则。</summary>
        public static void Disable(Action<string>? log = null)
        {
            lock (Sync)
            {
                if (Rules.Count == 0) { _active = false; return; }
                int ok = 0;
                foreach (var name in Rules.ToArray())
                {
                    var r = RunNetsh("advfirewall firewall delete rule name=\"" + name + "\"");
                    if (r.Code == 0) { Rules.Remove(name); ok++; }
                }
                _active = Rules.Count > 0;
                log?.Invoke("网络隔离已解除：清理规则 " + ok + " 条" + (_active ? "，仍有 " + Rules.Count + " 条未能清理" : ""));
            }
        }

        /// <summary>按前缀清理历史残留规则（进程被强杀时会留下规则）。</summary>
        public static int CleanupStale(Action<string>? log = null)
        {
            lock (Sync)
            {
                var show = RunNetsh("advfirewall firewall show rule name=all");
                if (show.Code != 0) return 0;
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var raw in show.Output.Split('\n'))
                {
                    var line = raw.Trim();
                    int idx = line.IndexOf(Prefix, StringComparison.OrdinalIgnoreCase);
                    if (idx < 0) continue;
                    var tail = line.Substring(idx);
                    int cut = tail.IndexOfAny(new[] { ' ', '\t', '\r' });
                    if (cut > 0) tail = tail.Substring(0, cut);
                    if (tail.Length > Prefix.Length) names.Add(tail);
                }
                int n = 0;
                foreach (var name in names)
                {
                    var del = RunNetsh("advfirewall firewall delete rule name=\"" + name + "\"");
                    if (del.Code == 0) n++;
                }
                if (n > 0) log?.Invoke("已清理 " + n + " 条历史网络阻断规则");
                return n;
            }
        }

        public static string Note = "";

        static (int Code, string Output) RunNetsh(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                if (p == null) return (-1, "无法启动 netsh.exe");
                string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit(8000);
                int code;
                try { code = p.HasExited ? p.ExitCode : -1; } catch { code = -1; }
                return (code, output);
            }
            catch (Exception ex) { return (-1, ex.Message); }
        }

        static string Tail(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return "";
            s = s.Replace("\r", " ").Replace("\n", " ").Trim();
            while (s.IndexOf("  ", StringComparison.Ordinal) >= 0) s = s.Replace("  ", " ");
            return s.Length > 160 ? s.Substring(0, 160) : s;
        }
    }
}
