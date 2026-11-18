using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace ReaStudio.Services
{
    /// <summary>动态分析：在 Job 对象约束下运行样本，采集进程树、网络外联与落盘行为。</summary>
    internal static class DynamicAnalyzer
    {
        public class DynProc
        {
            public int Pid;
            public int ParentPid;
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
            public string Change = "";
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

        public class DynReg
        {
            public string Time = "";
            public string Hive = "";
            public string Key = "";
            public string Name = "";
            public string Data = "";
            public string Change = "";
            public bool Dangerous;
            public string Note = "";
        }

        public class DynChain
        {
            public string Time = "";
            public string Stage = "";
            public string Subject = "";
            public string Detail = "";
            public string Attck = "";
            public int Danger;
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
            public List<DynReg> Registry = new();
            public List<DynChain> Chain = new();
            public List<string> Rollback = new();
            public List<string> Notes = new();
            public int DangerousCount;
            public string IsolationLevel = "";
            public int IsolationLevelCode;
            public string WorkDirectory = "";
            public string SandboxSession = "";
            public string Desktop = "";
            public bool LowIntegrity;
            public string Containment = "";
            public bool NetBlocked;
            public string NetBlockNote = "";
        }

        static IntPtr _job = IntPtr.Zero;
        static DynIsolation.LaunchResult? _launch;
        static volatile bool _stop;
        static int _running;

        public static bool IsRunning => _running == 1;

        public static void Stop()
        {
            _stop = true;
            try { if (_launch != null) DynIsolation.Terminate(_launch); } catch { }
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

            // ① 样本入箱：动态执行只在沙箱执行区的副本上进行，原文件不触碰
            SandboxSession? sess = null;
            string staged = path;
            try
            {
                sess = Sandbox.Begin("dyn");
                var fi = new FileInfo(path);
                if (fi.Length <= Sandbox.StageLimitBytes)
                {
                    var dst = Path.Combine(sess.Inbox, fi.Name);
                    File.Copy(path, dst, true);
                    staged = dst;
                    Sandbox.Note(sess, "动态执行样本入箱：" + path + " -> inbox\\" + fi.Name);
                }
            }
            catch (Exception ex) { Sandbox.Note("动态执行入箱失败：" + ex.Message); }

            // ② 隔离等级与执行工作区（TEMP/APPDATA/HOME 全部重定向到 exec 工作区）
            int level = DynIsolation.CurrentLevel();
            var area = DynIsolation.Prepare(sess != null ? sess.Root : Path.GetTempPath(), staged,
                level == DynIsolation.LevelRestricted);
            r.IsolationLevelCode = level;
            r.IsolationLevel = level == DynIsolation.LevelRestricted ? "L2 受限级" : "L1 受控级";
            r.WorkDirectory = area.Root;
            r.LowIntegrity = area.LowIntegrityAcl;
            if (sess != null) r.SandboxSession = sess.Id;

            // ③ 运行前快照：沙箱外目录 + 持久化注册表项
            var watchDirs = new List<string>();
            try { watchDirs.Add(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ""); } catch { }
            watchDirs.Add(SafeEnv("TEMP"));
            watchDirs.Add(SafeEnv("APPDATA"));
            watchDirs.Add(SafeEnv("LOCALAPPDATA"));
            watchDirs.Add(SafeEnv("ProgramData"));
            watchDirs.Add(Path.Combine(SafeEnv("APPDATA"), @"Microsoft\Windows\Start Menu\Programs\Startup"));
            watchDirs.Add(Path.Combine(SafeEnv("ProgramData"), @"Microsoft\Windows\Start Menu\Programs\StartUp"));
            watchDirs = watchDirs.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).Distinct().ToList();
            var before = Snapshot(watchDirs);
            var areaBefore = SnapshotDeep(new[] { area.Root }, 3, 6000);
            var regBefore = RegSnapshot();

            // ④ 隔离启动：私有桌面 + 受限令牌/低完整性 + Job 约束（挂起创建后再入 Job，避免逃逸竞态）
            // ④-a 网络隔离：管理员会话下为工作区可执行文件建立出站阻断，样本无法外联真实网络
            bool netBlocked = false;
            string netNote = "";
            try
            {
                var tag = (r.Sha256.Length >= 8 ? r.Sha256.Substring(0, 8) : "sess") + "-" + DateTime.Now.ToString("HHmmss");
                netBlocked = DynNetGuard.Enable(tag, area.Root, log, area.SamplePath);
                netNote = DynNetGuard.Note;
            }
            catch (Exception ex)
            {
                netNote = "网络隔离初始化失败：" + ex.Message;
            }
            r.NetBlocked = netBlocked;
            r.NetBlockNote = netNote;
            if (!netBlocked) r.Notes.Add(netNote);

            var opt = new DynIsolation.Options();
            var launch = DynIsolation.Launch(area.SamplePath, area, opt, log);
            if (!launch.Ok)
            {
                r.Error = launch.Error;
                foreach (var n in launch.Notes) r.Notes.Add(n);
                try { DynNetGuard.Disable(log); } catch { }
                return r;
            }

            _running = 1; _stop = false;
            _job = launch.Job;
            _launch = launch;
            r.Desktop = launch.DesktopName;
            foreach (var n in launch.Notes) r.Notes.Add(n);
            try { log?.Invoke("隔离等级：" + launch.IsolationName + "；执行区：" + area.Root); } catch { }

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
            var seenAreaFile = new HashSet<string>(areaBefore.Keys, StringComparer.OrdinalIgnoreCase);
            var procs = new Dictionary<int, DynProc>();

            Ev("start", "启动样本 " + Path.GetFileName(path), path + "（副本：" + area.SamplePath + "）");
            Ev("net-guard", netBlocked ? "网络出站已阻断" : "网络出站未阻断", netNote, !netBlocked);
            var sw = Stopwatch.StartNew();
            var lastScan = -1000;
            var lastAreaScan = -1000;
            log?.Invoke(r.Unlimited
                ? "观测时长：无限制（样本退出或点击停止结束）"
                : "观测时长：" + sec + " 秒（" + (sec >= 3600 ? (sec / 3600.0).ToString("0.##") + " 小时" : sec >= 60 ? (sec / 60.0).ToString("0.##") + " 分钟" : sec + " 秒") + "）");

            while ((r.Unlimited || sw.Elapsed.TotalSeconds < sec) && !_stop)
            {
                Thread.Sleep(300);
                var proc = launch.Process;
                try { proc?.Refresh(); } catch { }
                if (proc != null && proc.HasExited && sw.Elapsed.TotalSeconds > 1.2) break;

                // 进程树（Job 内全部进程，含子进程）
                var livePids = JobPids();
                if (livePids.Count == 0 && launch.Pid > 0) livePids.Add(launch.Pid);
                var parents = ParentMap();
                foreach (var pid in livePids)
                {
                    if (!seenPid.Add(pid)) continue;
                    try
                    {
                        var p = Process.GetProcessById(pid);
                        parents.TryGetValue(pid, out var ppid);
                        var dp = new DynProc
                        {
                            Pid = pid,
                            ParentPid = ppid,
                            Name = p.ProcessName,
                            FilePath = SafeMainModule(p),
                            FirstSeen = DateTime.Now.ToString("HH:mm:ss.fff"),
                            WorkingSet = SafeWs(p)
                        };
                        procs[pid] = dp;
                        r.Processes.Add(dp);
                        Ev("proc", "创建进程 " + dp.Name + " (PID " + pid + ")", dp.FilePath + (ppid > 0 ? " · 父进程 " + ppid : ""));
                    }
                    catch { }
                }

                // 网络外联
                if (sw.ElapsedMilliseconds - lastScan >= 600)
                {
                    lastScan = (int)sw.ElapsedMilliseconds;
                    var pids = livePids;
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

                // 沙箱执行区实时落盘（样本写 TEMP/APPDATA 落在 exec 工作区，可即时观察）
                if (sw.ElapsedMilliseconds - lastAreaScan >= 1500)
                {
                    lastAreaScan = (int)sw.ElapsedMilliseconds;
                    var nowArea = SnapshotDeep(new[] { area.Root }, 3, 6000);
                    foreach (var kv in nowArea)
                    {
                        if (!seenAreaFile.Add(kv.Key)) continue;
                        var kind = JudgeFile(kv.Key);
                        r.Files.Add(new DynFile { Time = DateTime.Now.ToString("HH:mm:ss"), Path = kv.Key, Change = "新增", Kind = kind.Length > 0 ? kind : "沙箱内落盘" });
                        Ev("file", "新增文件 " + Path.GetFileName(kv.Key), kv.Key + (kind.Length > 0 ? " · " + kind : ""), kind.Contains("自启动") || kind.Contains("服务"));
                    }
                }
            }

            // ⑤ 收尾：终止作业内全部进程，关闭私有桌面句柄
            var elapsed = sw.Elapsed.TotalSeconds;
            DynIsolation.Terminate(launch);
            try { launch.Process?.WaitForExit(1500); } catch { }
            Ev("stop", "观测结束", "样本及子进程已终止（实际观测 " + elapsed.ToString("0.0") + " 秒）");
            _running = 0;
            try { if (_job != IntPtr.Zero) CloseHandle(_job); } catch { }
            _job = IntPtr.Zero;
            DynIsolation.Release(launch);
            _launch = null;
            try { DynNetGuard.Disable(log); } catch { }

            // ⑥ 沙箱外落盘（目录 diff）
            var after = Snapshot(watchDirs);
            var seenOut = new HashSet<string>(r.Files.Select(f => f.Path), StringComparer.OrdinalIgnoreCase);
            foreach (var kv in after)
            {
                string change = "";
                if (!before.TryGetValue(kv.Key, out var oldSize)) change = "新增";
                else if (oldSize != kv.Value) change = "修改";
                else continue;
                if (!seenOut.Add(kv.Key)) continue;
                if (r.Files.Count >= 600) break;
                var kind = JudgeFile(kv.Key);
                r.Files.Add(new DynFile { Time = DateTime.Now.ToString("HH:mm:ss"), Path = kv.Key, Change = change, Kind = kind });
                Ev("file", change + "文件 " + Path.GetFileName(kv.Key), kv.Key + (kind.Length > 0 ? " · " + kind : ""), kind.Contains("自启动") || kind.Contains("服务"));
            }
            foreach (var f in r.Files.Where(f => !IsInside(area.Root, f.Path))) r.Rollback.Add(f.Path);

            // ⑦ 注册表持久化 diff
            try
            {
                var regAfter = RegSnapshot();
                foreach (var kv in regAfter)
                {
                    if (!regBefore.TryGetValue(kv.Key, out var oldVal))
                        AddReg(r, "新增", kv.Key, kv.Value, Ev);
                    else if (!string.Equals(oldVal, kv.Value, StringComparison.OrdinalIgnoreCase))
                        AddReg(r, "修改", kv.Key, kv.Value, Ev);
                }
                foreach (var kv in regBefore.Where(kv => !regAfter.ContainsKey(kv.Key)))
                    AddReg(r, "删除", kv.Key, kv.Value, Ev);
            }
            catch (Exception ex) { r.Notes.Add("注册表快照失败：" + ex.Message); }

            // ⑧ 行为链与判定
            r.Chain = BuildChain(r);
            r.Ok = true;
            r.Verdict = BuildVerdict(r);
            r.Containment = (level == DynIsolation.LevelRestricted
                ? "受限令牌 + 低完整性 + 私有桌面 + 作业对象约束，样本运行在沙箱 exec 工作区"
                : "私有桌面 + 环境重定向 + 作业对象约束，样本运行在沙箱 exec 工作区")
                + (r.NetBlocked ? "；出站网络已在防火墙层阻断" : "；出站网络未阻断（仅观测）");
            if (r.NetBlocked)
                r.Notes.Add("网络隔离已生效：" + r.NetBlockNote + "。规则按可执行文件路径匹配，样本若将自身复制到工作区外运行则不受该规则约束，需结合进程树与落盘记录核对。");
            else if (!string.IsNullOrEmpty(r.NetBlockNote))
                r.Notes.Add("网络隔离未生效：" + r.NetBlockNote + "。本次为仅观测模式，样本可外联真实网络，建议配合断网/离线环境使用。");
            r.Notes.Add("动态执行使用独立工作区：" + area.Root + "，样本的 TEMP/APPDATA/USERPROFILE 已重定向，界面运行在私有桌面。");
            r.Notes.Add("作业对象约束进程数上限 " + opt.MaxProcesses + "，单进程内存上限 " + opt.ProcessMemoryMb + " MB，观测结束整树终止。");
            r.Notes.Add("未使用内核驱动与 API HOOK，行为采集基于进程/连接/目录/注册表快照，可能漏采极短命进程；注册表仅覆盖常见持久化项。");
            if (r.Rollback.Count > 0)
                r.Notes.Add("有 " + r.Rollback.Count + " 个文件落在沙箱执行区之外的宿主目录，已列入回滚清单，需在报告中确认后清理。");
            if (r.Connections.Any(c => c.Proto == "UDP")) r.Notes.Add("已包含 UDP 监听端点，UDP 无连接会话无法完整还原。");
            return r;
        }

        static void AddReg(DynResult r, string change, string key, string data, Action<string, string, string, bool> ev)
        {
            ParseRegKey(key, out var hive, out var path, out var name);
            bool persist = IsPersistenceKey(path);
            var dr = new DynReg
            {
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Hive = hive,
                Key = path,
                Name = name,
                Data = data,
                Change = change,
                Dangerous = persist && change != "删除",
                Note = persist ? "持久化位置变更" : ""
            };
            r.Registry.Add(dr);
            ev("reg", change + "注册表项 " + name, hive + "\\" + path + " = " + data, dr.Dangerous);
        }

        static void ParseRegKey(string key, out string hive, out string path, out string name)
        {
            hive = "";
            path = "";
            name = "";
            try
            {
                int bar = key.IndexOf('|');
                var left = bar > 0 ? key.Substring(0, bar) : key;
                name = bar > 0 ? key.Substring(bar + 1) : "";
                int sp = left.IndexOf('\\');
                hive = sp > 0 ? left.Substring(0, sp) : left;
                path = sp > 0 ? left.Substring(sp + 1) : "";
            }
            catch { }
        }

        static bool IsPersistenceKey(string path)
        {
            var l = (path ?? "").ToLowerInvariant();
            return l.Contains("\\currentversion\\run") || l.Contains("winlogon") || l.Contains("services\\")
                || l.Contains("image file execution options") || l.Contains("session manager") || l.Contains("policies\\explorer\\run");
        }

        static bool IsInside(string root, string path)
        {
            try
            {
                var a = Path.GetFullPath(root).TrimEnd('\\') + "\\";
                var b = Path.GetFullPath(path);
                return b.StartsWith(a, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        static readonly (string Hive, string Path)[] RegKeys = new (string, string)[]
        {
            ("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            ("HKCU", @"Software\Microsoft\Windows NT\CurrentVersion\Windows"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
            ("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager"),
        };

        /// <summary>持久化位置快照：值名+数据，服务项只记录子键名（服务安装痕迹）。</summary>
        static Dictionary<string, string> RegSnapshot()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (hive, path) in RegKeys)
            {
                try
                {
                    var baseKey = hive == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;
                    using var key = baseKey.OpenSubKey(path);
                    if (key == null) continue;
                    foreach (var name in key.GetValueNames())
                    {
                        string val;
                        try { val = Convert.ToString(key.GetValue(name)) ?? ""; } catch { val = ""; }
                        map[hive + "\\" + path + "|" + name] = val;
                    }
                }
                catch { }
            }
            try
            {
                using var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (svc != null)
                {
                    foreach (var sub in svc.GetSubKeyNames().Take(4000))
                        map["HKLM\\SYSTEM\\CurrentControlSet\\Services|" + sub] = "service";
                }
            }
            catch { }
            return map;
        }

        static Dictionary<string, long> SnapshotDeep(IEnumerable<string> dirs, int maxDepth, int maxFiles)
        {
            var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in dirs) Walk(d, 0, maxDepth, map, maxFiles);
            return map;
        }

        static void Walk(string dir, int depth, int maxDepth, Dictionary<string, long> map, int maxFiles)
        {
            if (depth > maxDepth || map.Count >= maxFiles) return;
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir))
                {
                    if (map.Count >= maxFiles) return;
                    try { map[f] = new FileInfo(f).Length; } catch { }
                }
                foreach (var s in Directory.EnumerateDirectories(dir))
                {
                    if (map.Count >= maxFiles) return;
                    Walk(s, depth + 1, maxDepth, map, maxFiles);
                }
            }
            catch { }
        }

        static Dictionary<int, int> ParentMap()
        {
            var map = new Dictionary<int, int>();
            IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);
            if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return map;
            try
            {
                var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };
                if (Process32First(snap, ref pe))
                {
                    do { map[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID; }
                    while (Process32Next(snap, ref pe));
                }
            }
            catch { }
            finally { CloseHandle(snap); }
            return map;
        }

        static List<DynChain> BuildChain(DynResult r)
        {
            var list = new List<DynChain>();
            foreach (var e in r.Events)
            {
                string stage;
                string attck;
                switch (e.Kind)
                {
                    case "start": stage = "执行"; attck = "T1204 用户执行"; break;
                    case "proc": stage = "子进程"; attck = "T1106 原生 API 调用"; break;
                    case "net": stage = "外联"; attck = "T1071 应用层协议"; break;
                    case "file": stage = "落盘"; attck = StageAttck(e.Detail); break;
                    case "reg": stage = "持久化"; attck = "T1547.001 注册表自启动"; break;
                    default: stage = "结束"; attck = ""; break;
                }
                list.Add(new DynChain
                {
                    Time = e.Time,
                    Stage = stage,
                    Subject = e.Title,
                    Detail = e.Detail,
                    Attck = attck,
                    Danger = e.Dangerous ? 70 : 20
                });
                if (list.Count >= 800) break;
            }
            return list;
        }

        static string StageAttck(string detail)
        {
            var l = (detail ?? "").ToLowerInvariant();
            if (l.Contains("自启动")) return "T1547 启动项";
            if (l.Contains("计划任务")) return "T1053.005 计划任务";
            if (l.Contains("脚本")) return "T1059 命令与脚本";
            if (l.EndsWith(".exe") || l.Contains(".exe ·")) return "T1105 载荷投递";
            if (l.EndsWith(".dll") || l.Contains(".dll ·")) return "T1129 共享模块";
            return "T1105 载荷投递";
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

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
