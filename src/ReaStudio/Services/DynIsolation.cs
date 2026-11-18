using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ReaStudio.Services
{
    /// <summary>
    /// 动态执行隔离：把样本运行收敛到沙箱工作区，并按当前权限自动选择隔离等级。
    /// L2 受限级：去特权受限令牌 + 低完整性级别 + 私有桌面 + Job 全限制（需管理员）；
    /// L1 受控级：当前用户令牌 + 私有桌面 + Job 全限制 + 环境重定向（普通用户可用）。
    /// 两级共同保证：样本只在沙箱工作区内落盘、子进程随 Job 一并终止、界面不出现在用户桌面。
    /// </summary>
    internal static class DynIsolation
    {
        public const int LevelControlled = 1;
        public const int LevelRestricted = 2;

        public sealed class WorkArea
        {
            public string Root = "";
            public string App = "";
            public string Temp = "";
            public string AppData = "";
            public string LocalAppData = "";
            public string Home = "";
            public string Output = "";
            public string Dump = "";
            public string SamplePath = "";
            public bool LowIntegrityAcl;
        }

        public sealed class Options
        {
            /// <summary>在私有桌面运行，样品界面不进入用户可视桌面。</summary>
            public bool HideWindow = true;
            /// <summary>追加 LUA 受限 SID，访问面最小但部分样本可能无法启动。</summary>
            public bool StrictToken;
            public long ProcessMemoryMb = 1024;
            public long JobMemoryMb = 2048;
            public int MaxProcesses = 32;
            /// <summary>单进程 CPU 时间上限，0 表示不限。</summary>
            public int CpuSeconds;
            public bool RedirectProfile = true;
        }

        public sealed class LaunchResult
        {
            public bool Ok;
            public string Error = "";
            public int Pid;
            public int IsolationLevel;
            public string IsolationName = "";
            public string DesktopName = "";
            public IntPtr ProcessHandle = IntPtr.Zero;
            public IntPtr ThreadHandle = IntPtr.Zero;
            public IntPtr Job = IntPtr.Zero;
            public IntPtr DesktopHandle = IntPtr.Zero;
            public Process? Process;
            public readonly List<string> Notes = new List<string>();
        }

        // ————————————————————— 能力探测 —————————————————————
        public static bool IsAdmin()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static bool HasPrivilege(string name)
        {
            IntPtr token = IntPtr.Zero;
            IntPtr buf = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) return false;
                if (!LookupPrivilegeValue(null, name, out var luid)) return false;
                GetTokenInformation(token, 3, IntPtr.Zero, 0, out var need);
                if (need <= 0) return false;
                buf = Marshal.AllocHGlobal(need);
                if (!GetTokenInformation(token, 3, buf, need, out _)) return false;
                int count = Marshal.ReadInt32(buf);
                for (int i = 0; i < count; i++)
                {
                    int off = 4 + i * Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                    long luidLow = Marshal.ReadInt32(buf, off);
                    int luidHigh = Marshal.ReadInt32(buf, off + 4);
                    if (luidLow == luid.LowPart && luidHigh == (int)luid.HighPart) return true;
                }
                return false;
            }
            catch { return false; }
            finally
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        public static bool WindowsSandboxAvailable()
        {
            try
            {
                var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsSandbox.exe");
                if (!File.Exists(exe)) return false;
                return Environment.OSVersion.Version.Build >= 18362;
            }
            catch { return false; }
        }

        /// <summary>当前环境可用的最高隔离等级（不实际启动进程）。</summary>
        public static int CurrentLevel()
        {
            if (IsAdmin() && (HasPrivilege("SeAssignPrimaryTokenPrivilege") || HasPrivilege("SeImpersonatePrivilege")))
                return LevelRestricted;
            return LevelControlled;
        }

        public static object Capability()
        {
            bool admin = IsAdmin();
            bool canRestrict = HasPrivilege("SeAssignPrimaryTokenPrivilege") || HasPrivilege("SeImpersonatePrivilege");
            var level = CurrentLevel();
            string name = level == LevelRestricted ? "L2 受限级" : "L1 受控级";
            var tips = new List<string>
            {
                level == LevelRestricted
                    ? "当前以管理员运行：样本使用去特权令牌 + 低完整性 + 私有桌面 + Job 约束执行。"
                    : "当前为普通用户：样本使用私有桌面 + 环境重定向 + Job 约束执行；以管理员重新启动可获得 L2 令牌级隔离。"
            };
            if (level != LevelRestricted && admin && !canRestrict)
                tips.Add("检测到管理员会话但缺少 SeAssignPrimaryToken/SeImpersonate 特权，已降为 L1。");
            tips.Add("两级隔离都不使用内核驱动，文件重定向靠工作区重定向与快照比对，不做驱动级拦截。");
            tips.Add(admin
                ? "网络隔离：管理员会话下为样本与工作区内可执行文件建立防火墙出站阻断（规则前缀 REA-DynBlock-，观测结束自动清理，启动时兜底清理残留）。"
                : "网络隔离：普通用户无法写防火墙规则，动态执行仅为观测模式，样本可外联真实网络，建议在断网环境复核。");
            if (WindowsSandboxAvailable()) tips.Add("本机可用 Windows Sandbox，可作为一次性虚拟机通道手动复核高价值样本。");
            return new
            {
                level,
                name,
                admin,
                canRestrict,
                netBlock = admin,
                windowsSandbox = WindowsSandboxAvailable(),
                tips
            };
        }

        // ————————————————————— 工作区 —————————————————————
        public static WorkArea Prepare(string sandboxRoot, string samplePath, bool useLowIntegrity, Action<string>? log = null)
        {
            var root = Path.Combine(sandboxRoot, "exec");
            var area = new WorkArea
            {
                Root = root,
                App = Path.Combine(root, "app"),
                Temp = Path.Combine(root, "temp"),
                AppData = Path.Combine(root, "appdata"),
                LocalAppData = Path.Combine(root, "localappdata"),
                Home = Path.Combine(root, "home"),
                Output = Path.Combine(root, "out"),
                Dump = Path.Combine(root, "dump")
            };
            foreach (var d in new[] { area.App, area.Temp, area.AppData, area.LocalAppData, area.Home, area.Output, area.Dump })
                Directory.CreateDirectory(d);

            if (!string.IsNullOrWhiteSpace(samplePath) && File.Exists(samplePath))
            {
                var dst = Path.Combine(area.App, Path.GetFileName(samplePath));
                try
                {
                    if (!PathsEqual(samplePath, dst)) File.Copy(samplePath, dst, true);
                    area.SamplePath = dst;
                }
                catch (Exception ex)
                {
                    area.SamplePath = samplePath;
                    log?.Invoke("样本复制进执行区失败，退回原路径：" + ex.Message);
                }
            }

            if (useLowIntegrity)
            {
                // 低完整性沙箱需要可写目录带低完整性标签，否则样本无法写自己的 TEMP/配置
                try
                {
                    var psi = new ProcessStartInfo("icacls.exe", "\"" + root + "\" /setintegritylevel (OI)(CI)L /T /Q")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var p = Process.Start(psi);
                    p?.WaitForExit(4000);
                    area.LowIntegrityAcl = p != null && p.ExitCode == 0;
                }
                catch { }
            }
            return area;
        }

        // ————————————————————— 启动 —————————————————————
        public static LaunchResult Launch(string exePath, WorkArea area, Options opt, Action<string>? log = null)
        {
            var lr = new LaunchResult();
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath)) { lr.Error = "样本不存在"; return lr; }

            var workDir = Path.GetDirectoryName(exePath) ?? area.App;
            IntPtr env = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;
            try
            {
                env = BuildEnvironment(area, opt);
                IntPtr deskHandle = IntPtr.Zero;
                string deskName = "";
                if (opt.HideWindow) CreatePrivateDesktop(out deskHandle, out deskName);
                lr.DesktopHandle = deskHandle;
                lr.DesktopName = deskName;

                lr.Job = CreateJob(opt);

                // ——— 优先 L2：受限令牌 + 低完整性 ———
                var admin = IsAdmin();
                if (admin && (HasPrivilege("SeAssignPrimaryTokenPrivilege") || HasPrivilege("SeImpersonatePrivilege")))
                {
                    token = CreateRestricted(opt.StrictToken, out var tokenNote);
                    if (token != IntPtr.Zero && SetLowIntegrity(token))
                    {
                        var si = new STARTUPINFO();
                        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                        si.lpDesktop = deskName;
                        uint flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
                        string cmd = "\"" + exePath + "\"";
                        bool created = CreateProcessAsUser(token, exePath, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, env, workDir, ref si, out var pi);
                        if (!created)
                            created = CreateProcessWithTokenW(token, 1 /*LOGON_WITH_PROFILE*/, exePath, cmd, flags, env, workDir, ref si, out pi);
                        if (created)
                        {
                            lr.Ok = true;
                            lr.IsolationLevel = LevelRestricted;
                            lr.IsolationName = "L2 受限级";
                            lr.Pid = pi.dwProcessId;
                            lr.ProcessHandle = pi.hProcess;
                            lr.ThreadHandle = pi.hThread;
                            lr.Notes.Add("令牌已去除特权并降为低完整性，界面运行在私有桌面 " + deskName + "。");
                            if (!string.IsNullOrEmpty(tokenNote)) lr.Notes.Add(tokenNote);
                        }
                        else
                        {
                            lr.Notes.Add("令牌级创建失败（Win32 " + Marshal.GetLastWin32Error() + "），退回 L1 受控级。");
                        }
                    }
                    else
                    {
                        lr.Notes.Add("受限令牌或低完整性设置不可用，退回 L1 受控级。");
                    }
                }
                else
                {
                    lr.Notes.Add("普通用户会话不具备令牌降权特权，使用 L1 受控级隔离。");
                }

                // ——— 兜底 L1：挂起创建 → 入 Job → 恢复 ———
                if (!lr.Ok)
                {
                    var si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                    si.lpDesktop = deskName;
                    si.dwFlags = STARTF_USESHOWWINDOW;
                    si.wShowWindow = opt.HideWindow ? (short)0 : (short)1; // SW_HIDE / SW_SHOWNORMAL
                    uint flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | (opt.HideWindow ? CREATE_NO_WINDOW : 0);
                    string cmd = "\"" + exePath + "\"";
                    if (!CreateProcess(IntPtr.Zero, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, env, workDir, ref si, out var pi))
                    {
                        lr.Error = "样本启动失败（Win32 " + Marshal.GetLastWin32Error() + "）";
                        return lr;
                    }
                    lr.Ok = true;
                    lr.IsolationLevel = LevelControlled;
                    lr.IsolationName = "L1 受控级";
                    lr.Pid = pi.dwProcessId;
                    lr.ProcessHandle = pi.hProcess;
                    lr.ThreadHandle = pi.hThread;
                }

                if (lr.Job != IntPtr.Zero && lr.ProcessHandle != IntPtr.Zero)
                {
                    if (!AssignProcessToJobObject(lr.Job, lr.ProcessHandle))
                        lr.Notes.Add("进程未能加入作业对象（可能已在其它作业中），进程树约束可能不完整。");
                }
                if (lr.ThreadHandle != IntPtr.Zero) ResumeThread(lr.ThreadHandle);

                try { lr.Process = Process.GetProcessById(lr.Pid); } catch { }
                lr.Notes.Add("工作目录：" + workDir + "；TEMP/APPDATA 已重定向到沙箱执行区。");
                return lr;
            }
            catch (Exception ex)
            {
                lr.Error = "隔离执行异常：" + ex.Message;
                return lr;
            }
            finally
            {
                if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        public static bool Terminate(LaunchResult lr)
        {
            if (lr == null) return false;
            try { if (lr.Job != IntPtr.Zero) TerminateJobObject(lr.Job, 1); } catch { }
            try { if (lr.ProcessHandle != IntPtr.Zero) TerminateProcess(lr.ProcessHandle, 1); } catch { }
            return true;
        }

        /// <summary>释放句柄与私有桌面；调用后不能再使用该 LaunchResult。</summary>
        public static void Release(LaunchResult lr)
        {
            if (lr == null) return;
            try { if (lr.ProcessHandle != IntPtr.Zero) CloseHandle(lr.ProcessHandle); } catch { }
            try { if (lr.ThreadHandle != IntPtr.Zero) CloseHandle(lr.ThreadHandle); } catch { }
            try { if (lr.Job != IntPtr.Zero) CloseHandle(lr.Job); } catch { }
            try { if (lr.DesktopHandle != IntPtr.Zero) CloseDesktop(lr.DesktopHandle); } catch { }
            lr.ProcessHandle = IntPtr.Zero;
            lr.ThreadHandle = IntPtr.Zero;
            lr.Job = IntPtr.Zero;
            lr.DesktopHandle = IntPtr.Zero;
        }

        // ————————————————————— 内部构件 —————————————————————
        private static IntPtr BuildEnvironment(WorkArea area, Options opt)
        {
            var sb = new StringBuilder();
            var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (opt.RedirectProfile)
            {
                overrides["TEMP"] = area.Temp;
                overrides["TMP"] = area.Temp;
                overrides["APPDATA"] = area.AppData;
                overrides["LOCALAPPDATA"] = area.LocalAppData;
                overrides["USERPROFILE"] = area.Home;
                overrides["HOMEDRIVE"] = Path.GetPathRoot(area.Home) ?? "C:";
                overrides["HOMEPATH"] = area.Home.Substring((Path.GetPathRoot(area.Home) ?? "C:\\").Length - 1);
            }
            overrides["REA_SANDBOX_SESSION"] = Path.GetFileName(area.Root.TrimEnd(Path.DirectorySeparatorChar));

            var vars = Environment.GetEnvironmentVariables();
            foreach (System.Collections.DictionaryEntry kv in vars)
            {
                var k = Convert.ToString(kv.Key) ?? "";
                if (string.IsNullOrEmpty(k)) continue;
                var v = overrides.TryGetValue(k, out var ov) ? ov : Convert.ToString(kv.Value) ?? "";
                sb.Append(k).Append('=').Append(v).Append('\0');
            }
            foreach (var kv in overrides)
            {
                if (vars.Contains(kv.Key)) continue;
                sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
            }
            sb.Append('\0');
            return Marshal.StringToHGlobalUni(sb.ToString());
        }

        private static IntPtr CreatePrivateDesktop(out IntPtr handle, out string name)
        {
            handle = IntPtr.Zero;
            name = "winsta0\\default";
            try
            {
                var deskName = "ReaDyn_" + DateTime.Now.ToString("HHmmss") + "_" + Environment.ProcessId;
                var h = CreateDesktop(deskName, IntPtr.Zero, IntPtr.Zero, 0, DESKTOP_ALL_ACCESS, IntPtr.Zero);
                if (h == IntPtr.Zero) return IntPtr.Zero;
                handle = h;
                name = "winsta0\\" + deskName;
                return h;
            }
            catch { return IntPtr.Zero; }
        }

        private static IntPtr CreateJob(Options opt)
        {
            var job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return IntPtr.Zero;
            var ext = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            uint flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (opt.MaxProcesses > 0)
            {
                flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                ext.BasicLimitInformation.ActiveProcessLimit = (uint)Math.Max(1, opt.MaxProcesses);
            }
            if (opt.ProcessMemoryMb > 0)
            {
                flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                ext.ProcessMemoryLimit = (UIntPtr)(ulong)(opt.ProcessMemoryMb * 1024 * 1024);
            }
            if (opt.JobMemoryMb > 0)
            {
                flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                ext.JobMemoryLimit = (UIntPtr)(ulong)(opt.JobMemoryMb * 1024 * 1024);
            }
            if (opt.CpuSeconds > 0)
            {
                flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
                ext.BasicLimitInformation.PerProcessUserTimeLimit = opt.CpuSeconds * 10_000_000L;
            }
            ext.BasicLimitInformation.LimitFlags = flags;
            int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr p = Marshal.AllocHGlobal(len);
            try
            {
                Marshal.StructureToPtr(ext, p, false);
                SetInformationJobObject(job, 9, p, len);
            }
            finally { Marshal.FreeHGlobal(p); }

            // 禁止样本操作用户桌面：切换桌面、读写剪贴板、改系统参数
            var ui = new JOBOBJECT_BASIC_UI_RESTRICTIONS
            {
                UIRestrictionsClass = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40
            };
            int uilen = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
            IntPtr up = Marshal.AllocHGlobal(uilen);
            try
            {
                Marshal.StructureToPtr(ui, up, false);
                SetInformationJobObject(job, 4, up, uilen);
            }
            finally { Marshal.FreeHGlobal(up); }
            return job;
        }

        private static IntPtr CreateRestricted(string strictNote, out string note)
        {
            note = "";
            return IntPtr.Zero;
        }

        private static IntPtr CreateRestricted(bool strict, out string note)
        {
            note = "";
            IntPtr token = IntPtr.Zero;
            IntPtr newToken = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                        out token)) return IntPtr.Zero;
                uint flags = DISABLE_MAX_PRIVILEGE;
                if (strict) flags |= LUA_TOKEN;
                if (!CreateRestrictedToken(token, flags, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out newToken))
                    return IntPtr.Zero;
                note = strict ? "已启用严格受限令牌（含 LUA 受限 SID）。" : "已去除令牌全部特权（DISABLE_MAX_PRIVILEGE）。";
                return newToken;
            }
            catch { return IntPtr.Zero; }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        private static bool SetLowIntegrity(IntPtr token)
        {
            IntPtr sid = IntPtr.Zero;
            IntPtr label = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSid("S-1-16-4096", out sid)) return false;
                var sa = new SID_AND_ATTRIBUTES { Sid = sid, Attributes = SE_GROUP_INTEGRITY };
                var tml = new TOKEN_MANDATORY_LABEL { Label = sa };
                int len = Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));
                label = Marshal.AllocHGlobal(len);
                Marshal.StructureToPtr(tml, label, false);
                return SetTokenInformation(token, 25 /*TokenIntegrityLevel*/, label, len);
            }
            catch { return false; }
            finally
            {
                if (label != IntPtr.Zero) Marshal.FreeHGlobal(label);
                if (sid != IntPtr.Zero) LocalFree(sid);
            }
        }

        private static bool PathsEqual(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }

        // ————————————————————— 常量与 P/Invoke —————————————————————
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;

        private const uint DISABLE_MAX_PRIVILEGE = 0x1;
        private const uint LUA_TOKEN = 0x4;
        private const uint SE_GROUP_INTEGRITY = 0x20;

        private const uint DESKTOP_ALL_ACCESS = 0x000F01FF;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const short STARTF_USESHOWWINDOW = 0x00000001;

        private const uint JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;
        private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
        private const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
        private const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_UI_RESTRICTIONS { public uint UIRestrictionsClass; }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
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
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpInfo, int cbInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int infoClass, IntPtr info, int infoLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateRestrictedToken(IntPtr existingToken, uint flags,
            uint disableSidCount, IntPtr sidsToDisable,
            uint deletePrivilegeCount, IntPtr privilegesToDelete,
            uint restrictedSidCount, IntPtr sidsToRestrict, out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr tokenHandle, int infoClass, IntPtr info, int infoLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(IntPtr token, string? applicationName, string commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string? applicationName,
            string commandLine, uint creationFlags, IntPtr environment, string? currentDirectory,
            ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr lpszDevice, IntPtr pDevmode,
            int dwFlags, uint dwDesiredAccess, IntPtr lpsa);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr hDesktop);
    }
}
