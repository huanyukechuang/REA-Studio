using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;

namespace ReaStudio.Services
{
    /// <summary>动态分析：在 Job 对象约束下运行样本，采集进程树、网络外联与落盘行为。</summary>
    internal static class DynamicAnalyzer
    {
        public class DynProc
        {
            public int Pid;
            public string Name = "";
            public string FilePath = "";
            public string FirstSeen = "";
            public long WorkingSet;
            public bool Exited;
        }

        public class DynConn
        {
            public string Time = "";
            public string Proto = "TCP";
            public string Local = "";
            public string Remote = "";
            public string State = "";
            public int Pid;
            public string Process = "";
            public bool Dangerous;
            public string Note = "";
        }

        public class DynFile
        {
            public string Time = "";
            public string Path = "";
            public string Kind = "";
        }

        public class DynEvent
        {
            public long Seq;
            public string Time = "";
            public string Kind = "";
            public string Title = "";
            public string Detail = "";
            public bool Dangerous;
        }

        public class DynResult
        {
            public bool Ok;
            public string Error = "";
            public string Target = "";
            public string Sha256 = "";
            public string StartedAt = "";
            public int DurationSec;
            public bool Unlimited;
            public string Verdict = "";
            public List<DynProc> Processes = new();
            public List<DynConn> Connections = new();
            public List<DynFile> Files = new();
            public List<DynEvent> Events = new();
            public List<string> Notes = new();
            public int DangerousCount;
        }

        static IntPtr _job = IntPtr.Zero;
        static volatile bool _stop;
        static int _running;

        public static bool IsRunning => _running == 1;

        public static void Stop()
        {
            _stop = true;
            try { if (_job != IntPtr.Zero) TerminateJobObject(_job, 1); } catch { }
        }

        static readonly int[] DangerPorts = { 21, 22, 23, 25, 53, 69, 135, 137, 139, 445, 1433, 1521, 3306, 3389, 5900, 6379, 8080, 9001 };

        public static DynResult Run(string path, int seconds, Action<string> log)
        {
            var r = new DynResult { Target = path, StartedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") };
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { r.Error = "样本不存在"; return r; }

            // 观测时长：0 表示无限制（直到手动停止或样本自行退出）；正数上限 24 小时
            int sec;
            if (seconds <= 0) { r.Unlimited = true; sec = 0; }
            else sec = Math.Min(86400, Math.Max(1, seconds));
            r.DurationSec = sec;

            try { r.Sha256 = Sha256(path); } catch { }

            // 运行前的目录快照（只做名称级 diff，避免深遍历拖慢启动）
            var watchDirs = new List<string>();
            try { watchDirs.Add(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ""); } catch { }
            watchDirs.Add(Path.GetTempPath());
            watchDirs.Add(SafeEnv("TEMP"));
            watchDirs.Add(SafeEnv("APPDATA"));
            watchDirs.Add(SafeEnv("LOCALAPPDATA"));
            watchDirs.Add(SafeEnv("ProgramData"));
            watchDirs = watchDirs.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).Distinct().ToList();
            var before = Snapshot(watchDirs);

            Process? proc = null;
            try
            {
                var psi = new ProcessStartInfo(path)
                {
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(path) ?? Environment.CurrentDirectory
                };
                proc = Process.Start(psi);
                if (proc == null) { r.Error = "样本启动失败"; return r; }
            }
            catch (Exception ex)
            {
                r.Error = "样本启动失败：" + ex.Message;
                r.Notes.Add("样本未能启动，可能是权限、架构不匹配或被安全软件拦截。");
                return r;
            }

            _running = 1; _stop = false;
            _job = CreateJobObject(IntPtr.Zero, null);
            if (_job != IntPtr.Zero)
            {
                var ext = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                ext.BasicLimitInformation.LimitFlags = 0x2000; // KILL_ON_JOB_CLOSE
                int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr p = Marshal.AllocHGlobal(len);
                try
                {
                    Marshal.StructureToPtr(ext, p, false);
                    SetInformationJobObject(_job, 9, p, len);
                }
                finally { Marshal.FreeHGlobal(p); }
                try { AssignProcessToJobObject(_job, proc.Handle); } catch { }
            }

            long seq = 0;
            void Ev(string kind, string title, string detail, bool danger = false)
            {
                r.Events.Add(new DynEvent
                {
                    Seq = ++seq,
                    Time = DateTime.Now.ToString("HH:mm:ss.fff"),
                    Kind = kind,
                    Title = title,
                    Detail = detail,
                    Dangerous = danger
                });
                if (danger) r.DangerousCount++;
                try { log?.Invoke("[" + kind + "] " + title + (string.IsNullOrEmpty(detail) ? "" : " — " + detail)); } catch { }
            }

            var seenPid = new HashSet<int>();
            var seenConn = new HashSet<string>();
            var procs = new Dictionary<int, DynProc>();

            Ev("start", "启动样本 " + Path.GetFileName(path), path);
            var sw = Stopwatch.StartNew();
            var lastScan = -1000;
            log?.Invoke(r.Unlimited
                ? "观测时长：无限制（样本退出或点击停止结束）"
                : "观测时长：" + sec + " 秒（" + (sec >= 3600 ? (sec / 3600.0).ToString("0.##") + " 小时" : sec >= 60 ? (sec / 60.0).ToString("0.##") + " 分钟" : sec + " 秒") + "）");

            while ((r.Unlimited || sw.Elapsed.TotalSeconds < sec) && !_stop)
            {
                Thread.Sleep(300);
                try { proc.Refresh(); } catch { }
                if (proc.HasExited && sw.Elapsed.TotalSeconds > 1.2) break;

                // 进程树
                foreach (var pid in JobPids())
                {
                    if (!seenPid.Add(pid)) continue;
                    try
                    {
                        var p = Process.GetProcessById(pid);
                        var dp = new DynProc
                        {
                            Pid = pid,
                            Name = p.ProcessName,
                            FilePath = SafeMainModule(p),
                            FirstSeen = DateTime.Now.ToString("HH:mm:ss.fff"),
                            WorkingSet = SafeWs(p)
                        };
                        procs[pid] = dp;
                        r.Processes.Add(dp);
                        Ev("proc", "创建进程 " + dp.Name + " (PID " + pid + ")", dp.FilePath);
                    }
                    catch { }
                }

                // 网络外联
                if (sw.ElapsedMilliseconds - lastScan >= 600)
                {
                    lastScan = (int)sw.ElapsedMilliseconds;
                    var pids = JobPids();
                    if (pids.Count == 0) continue;
                    RefreshPortMap();
                    foreach (var c in TcpConns())
                    {
                        if (!pids.Contains(c.Pid)) continue;
                        var key = c.Proto + "|" + c.Local + "|" + c.Remote + "|" + c.Pid;
                        if (!seenConn.Add(key)) continue;
                        var name = procs.TryGetValue(c.Pid, out var dp2) ? dp2.Name : SafeName(c.Pid);
                        var note = JudgeConn(c.Remote);
                        var dc = new DynConn
                        {
                            Time = DateTime.Now.ToString("HH:mm:ss.fff"),
                            Proto = c.Proto,
                            Local = c.Local,
                            Remote = c.Remote,
                            State = c.State,
                            Pid = c.Pid,
                            Process = name,
                            Dangerous = note.Length > 0,
                            Note = note
                        };
                        r.Connections.Add(dc);
                        Ev("net", dc.Proto + " 外联 " + dc.Remote, name + (string.IsNullOrEmpty(note) ? "" : " · " + note), dc.Dangerous);
                    }
                }
            }

            try { if (!proc.HasExited) TerminateJobObject(_job, 1); } catch { }
            try { proc.WaitForExit(1500); } catch { }
            Ev("stop", "观测结束", "样本进程已终止（实际观测 " + sw.Elapsed.TotalSeconds.ToString("0.0") + " 秒）");
            _running = 0;
            try { if (_job != IntPtr.Zero) CloseHandle(_job); } catch { }
            _job = IntPtr.Zero;

            // 落盘行为
            var after = Snapshot(watchDirs);
            foreach (var f in after.Keys.Where(k => !before.ContainsKey(k)).Take(400))
            {
                var kind = JudgeFile(f);
                r.Files.Add(new DynFile { Time = DateTime.Now.ToString("HH:mm:ss"), Path = f, Kind = kind });
                Ev("file", "新增文件 " + Path.GetFileName(f), f + (kind.Length > 0 ? " · " + kind : ""), kind.Contains("自启动") || kind.Contains("服务"));
            }

            r.Ok = true;
            r.Verdict = BuildVerdict(r);
            r.Notes.Add("动态分析在作业对象约束下运行，观测结束会强制终止样本及其子进程。");
            r.Notes.Add("未使用内核驱动与 API HOOK，行为采集基于进程/连接/目录快照，可能漏采极短命进程。");
            if (r.Connections.Any(c => c.Proto == "UDP")) r.Notes.Add("已包含 UDP 监听端点，UDP 无连接会话无法完整还原。");
            return r;
        }

        static string BuildVerdict(DynResult r)
        {
            if (!r.Ok) return "动态分析未完成";
            int net = r.Connections.Count;
            int dg = r.DangerousCount;
            int files = r.Files.Count;
            int procs = r.Processes.Count;
            string head = procs + " 个进程、" + net + " 条外联、" + files + " 个新增文件";
            if (dg > 0) return head + "；存在 " + dg + " 项高风险行为（敏感端口外联或自启动写入），建议结合静态分析深查。";
            if (net > 0) return head + "；有网络行为但未命中敏感端口特征。";
            if (files > 0) return head + "；无外联行为，存在落盘动作。";
            return head + "；运行期间未见明显外联与落盘行为。";
        }

        static string JudgeConn(string remote)
        {
            try
            {
                var host = remote;
                int idx = host.LastIndexOf(':');
                if (idx > 0) host = host.Substring(0, idx);
                int port = 0;
                if (idx > 0 && int.TryParse(remote.Substring(idx + 1), out var p)) port = p;
                if (DangerPorts.Contains(port)) return "敏感端口 " + port;
                if (port == 80 || port == 8080) return "明文 HTTP";
                if (host == "0.0.0.0" || host == "::") return "监听端口";
                return "";
            }
            catch { return ""; }
        }

        static string JudgeFile(string path)
        {
            var l = path.ToLowerInvariant();
            if (l.Contains("\\start menu\\programs\\startup") || l.Contains("\\startup\\")) return "自启动目录写入";
            if (l.Contains("\\windows\\system32\\tasks") || l.Contains("\\tasks\\")) return "计划任务痕迹";
            if (l.Contains("\\currentversion\\run")) return "注册表导出痕迹";
            if (l.EndsWith(".dll") || l.EndsWith(".exe") || l.EndsWith(".sys")) return "可执行载荷落盘";
            if (l.EndsWith(".bat") || l.EndsWith(".ps1") || l.EndsWith(".vbs") || l.EndsWith(".cmd")) return "脚本落盘";
            if (l.EndsWith(".log") || l.EndsWith(".tmp") || l.EndsWith(".dat")) return "临时数据";
            return "";
        }

        static string SafeEnv(string k)
        {
            try { return Environment.GetEnvironmentVariable(k) ?? ""; } catch { return ""; }
        }

        static string SafeMainModule(Process p)
        {
            try { return p.MainModule == null ? "" : p.MainModule.FileName; } catch { return ""; }
        }

        static long SafeWs(Process p)
        {
            try { return p.WorkingSet64; } catch { return 0; }
        }

        static string SafeName(int pid)
        {
            try { return Process.GetProcessById(pid).ProcessName; } catch { return "unknown"; }
        }

        static Dictionary<string, long> Snapshot(List<string> dirs)
        {
            var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in dirs)
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(d, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (map.Count >= 20000) break;
                        try { map[f] = new FileInfo(f).Length; } catch { }
                    }
                }
                catch { }
            }
            return map;
        }

        struct TcpRow
        {
            public string Proto;
            public string Local;
            public string Remote;
            public string State;
            public int Pid;
        }

        static List<TcpRow> TcpConns()
        {
            var list = new List<TcpRow>();
            try
            {
                foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
                    list.Add(new TcpRow
                    {
                        Proto = "TCP",
                        Local = c.LocalEndPoint.ToString(),
                        Remote = c.RemoteEndPoint.ToString(),
                        State = c.State.ToString(),
                        Pid = SafeOwner(c.LocalEndPoint.Port, false)
                    });
            }
            catch { }
            try
            {
                foreach (var u in IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners())
                    list.Add(new TcpRow
                    {
                        Proto = "UDP",
                        Local = u.ToString(),
                        Remote = "-",
                        State = "Listen",
                        Pid = SafeOwner(u.Port, true)
                    });
            }
            catch { }
            return list;
        }

        /// <summary>取端口所属进程：用 netstat 兜底（GetExtendedTcpTable 需更多 P/Invoke，改用命令行更稳）。</summary>
        static readonly Dictionary<string, int> _portPid = new();

        static int SafeOwner(int port, bool udp)
        {
            try
            {
                var key = (udp ? "UDP:" : "TCP:") + port;
                return _portPid.TryGetValue(key, out var pid) ? pid : 0;
            }
            catch { return 0; }
        }

        static void RefreshPortMap()
        {
            _portPid.Clear();
            try
            {
                var psi = new ProcessStartInfo("netstat.exe", "-ano")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p == null) return;
                string? line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    var t = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (t.Length < 4) continue;
                    var proto = t[0].ToUpperInvariant();
                    if (proto != "TCP" && proto != "UDP") continue;
                    var local = t[1];
                    int idx = local.LastIndexOf(':');
                    if (idx <= 0) continue;
                    if (!int.TryParse(local.Substring(idx + 1), out var port)) continue;
                    if (!int.TryParse(t[t.Length - 1], out var pid)) continue;
                    _portPid[proto + ":" + port] = pid;
                }
            }
            catch { }
        }

        static string Sha256(string path)
        {
            using var fs = File.OpenRead(path);
            using var sha = System.Security.Cryptography.SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }

        static List<int> JobPids()
        {
            var list = new List<int>();
            if (_job == IntPtr.Zero) return list;
            const int max = 512;
            int size = 8 + max * IntPtr.Size;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (QueryInformationJobObject(_job, 3, buf, size, out var ret))
                {
                    int n = Marshal.ReadInt32(buf, 4);
                    int cnt = Math.Min(n, max);
                    for (int i = 0; i < cnt; i++)
                    {
                        IntPtr val = Marshal.ReadIntPtr(buf, 8 + i * IntPtr.Size);
                        int pid = val.ToInt32();
                        if (pid > 0) list.Add(pid);
                    }
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(buf); }
            return list;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, int cbInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool QueryInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, int cbInfo, out int lpReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }
    }
}
