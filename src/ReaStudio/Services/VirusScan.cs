using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    /// <summary>单条检测命中（规则命中或哈希命中）。</summary>
    public sealed class VirusHit
    {
        public string RuleId = "";
        public string Name = "";
        public string Family = "";
        public string Type = "";
        public string Severity = "中";
        public string Match = "";
        public string Desc = "";
        public string Source = "规则";
    }

    /// <summary>一次病毒检测的结果（全部在沙箱副本上完成，样本不执行）。</summary>
    public sealed class VirusScanResult
    {
        public bool Ok;
        public string Error = "";
        public string Path = "";
        public string ScanPath = "";
        public bool InSandbox;
        public string Sha256 = "";
        public string Md5 = "";
        public long Size;
        public double Entropy;
        public string PeInfo = "";
        public string Verdict = "未检出";
        public int Score;
        public int High, Medium, Low;
        public List<VirusHit> Matches = new();
        public int RuleCount, HashCount;
        public string DbVersion = "";
        public long ElapsedMs;
        public List<string> Notes = new();
        public string Summary = "";
    }

    /// <summary>病毒库中的一条哈希记录。</summary>
    public sealed class VirusRecord
    {
        public string Hash { get; set; } = "";
        public string Name { get; set; } = "";
        public string Type { get; set; } = "未知";
        public string Severity { get; set; } = "高";
        public string Source { get; set; } = "导入";
        public string AddedAt { get; set; } = "";
    }

    /// <summary>一条检测规则。Kind: text=字节流包含 / all=全部包含 / regex=正则 / hex=十六进制字节序列 / pe=PE结构特征。</summary>
    public sealed class VirusRule
    {
        public string Id = "";
        public string Name = "";
        public string Family = "";
        public string Type = "";
        public string Severity = "中";
        public string Kind = "text";
        public string Pattern = "";
        public string Desc = "";
        public bool Builtin = true;
    }

    /// <summary>
    /// 病毒库与检测引擎。
    /// 库分为两部分：①内置规则库（随程序发布，覆盖勒索/窃密/挖矿/远控/注入/持久化/横移/脚本投放等已知攻击族谱特征，不可删除）；
    /// ②可导入的样本哈希库 + 外置 YARA 规则，支持本地文件导入与从威胁情报 URL 在线同步。
    /// 检测时只读取样本副本，可在沙箱内进行，样本不被执行，不影响主系统。
    /// </summary>
    public static class VirusDb
    {
        private const int MaxScanBytes = 16 * 1024 * 1024;
        private const int MaxHashLines = 400000;

        private static readonly object _lock = new();
        private static List<VirusRecord>? _hashes;
        private static Dictionary<string, VirusRecord>? _index;
        private static List<VirusRule>? _importedRules;
        private static string _lastUpdate = "";
        private static string _lastSource = "";

        public static string Dir
        {
            get { var d = Path.Combine(Storage.DataRoot, "virusdb"); Directory.CreateDirectory(d); return d; }
        }

        private static string HashFile => Path.Combine(Dir, "hashes.json");
        private static string RuleFile => Path.Combine(Dir, "rules.json");
        private static string MetaFile => Path.Combine(Dir, "meta.json");

        // ————————————————————— 内置规则库 —————————————————————
        private static readonly (string Id, string Name, string Family, string Type, string Sev, string Kind, string Pattern, string Desc)[] Defs = new[]
        {
            ("r001","勒索信样本","Locky/Ryuk 类","勒索软件","高","text","ALL YOUR FILES ARE ENCRYPTED","样本内含勒索信正文，典型双重勒索投放物特征"),
            ("r002","勒索信样本","Conti/Phobos 类","勒索软件","高","text","YOUR FILES HAVE BEEN ENCRYPTED","勒索信通用开头，指向文件加密攻击"),
            ("r003","解密说明投放","通用勒索","勒索软件","高","all","HOW_TO_DECRYPT|READ_ME","落盘解密说明文件命名特征"),
            ("r004","卷影副本删除","通用勒索","勒索软件","高","text","vssadmin delete shadows","删除卷影副本以阻断系统还原，勒索前置动作"),
            ("r005","备份目录删除","通用勒索","勒索软件","高","text","wbadmin delete catalog","删除备份目录，阻断恢复路径"),
            ("r006","关闭恢复模式","通用勒索","勒索软件","高","text","bcdedit /set {default} recoveryenabled no","关闭启动恢复，典型勒索加固步骤"),
            ("r007","磁盘擦写","通用勒索","破坏型","高","text","cipher /w:","空闲空间擦写，用于阻止文件恢复"),
            ("r008","勒索扩展名","Locky","勒索软件","中","text",".locky","加密文件后缀特征"),
            ("r009","勒索扩展名","WannaCry","勒索软件","中","text",".wncry","加密文件后缀特征"),
            ("r010","勒索扩展名","Ryuk","勒索软件","中","text",".ryuk","加密文件后缀特征"),
            ("r011","勒索扩展名","Phobos","勒索软件","中","text",".phobos","加密文件后缀特征"),
            ("r012","勒索扩展名","Conti","勒索软件","中","text",".conti","加密文件后缀特征"),
            ("r013","勒索扩展名","STOP/Djvu","勒索软件","低","text",".djvu","加密文件后缀特征"),
            ("r014","暗网通告","通用勒索","勒索软件","低","text",".onion","样本引用暗网支付/谈判页面"),
            ("r015","终止防护进程","通用勒索","勒索软件","中","text","taskkill /f /im","批量强杀进程，常见于加密前终止安全软件"),

            ("r020","矿池协议","通用挖矿","挖矿程序","高","text","stratum+tcp://","矿池通信协议，直接指向挖矿行为"),
            ("r021","矿池协议","通用挖矿","挖矿程序","高","text","stratum+ssl://","加密矿池通信协议"),
            ("r022","挖矿程序标识","XMRig","挖矿程序","高","text","xmrig","已知门罗币挖矿程序标识"),
            ("r023","挖矿程序标识","minerd","挖矿程序","高","text","minerd","经典 cpuminer 挖矿程序标识"),
            ("r024","挖矿算法","通用挖矿","挖矿程序","中","text","cryptonight","门罗币挖矿算法名"),
            ("r025","挖矿算法","通用挖矿","挖矿程序","中","text","randomx","RandomX 挖矿算法名"),
            ("r026","矿池域名","通用挖矿","挖矿程序","中","text","minexmr","公开矿池域名特征"),
            ("r027","矿池域名","NiceHash","挖矿程序","中","text","nicehash","矿池租赁平台域名特征"),

            ("r030","浏览器凭据窃取","通用窃密","窃密木马","高","text","Login Data","Chromium 登录凭据库文件名"),
            ("r031","加密货币钱包窃取","通用窃密","窃密木马","高","text","wallet.dat","钱包私钥文件，典型窃取目标"),
            ("r032","Chromium 主密钥","通用窃密","窃密木马","中","text","Local State","Chromium 加密密钥文件，用于解密凭据"),
            ("r033","Cookie 窃取","通用窃密","窃密木马","中","text","cookies.sqlite","浏览器 Cookie 数据库"),
            ("r034","浏览器历史窃取","通用窃密","窃密木马","中","text","places.sqlite","Firefox 历史/书签数据库"),
            ("r035","Telegram 会话窃取","通用窃密","窃密木马","中","text","tdata","Telegram 会话目录，常用于接管账号"),
            ("r036","凭据抓取工具","LaZagne","窃密木马","高","text","LaZagne","开源凭据抓取工具标识"),
            ("r037","FTP 凭据窃取","通用窃密","窃密木马","高","text","recentservers.xml","FileZilla 保存的 FTP 凭据文件"),
            ("r038","浏览器配置目录","通用窃密","窃密木马","中","text","\\User Data\\Default","Chromium 用户配置目录遍历"),
            ("r039","邮件存储遍历","通用窃密","窃密木马","低","text","Outlook\\","本地邮件存储遍历特征"),

            ("r045","远控框架","Quasar RAT","远控木马","高","text","Quasar.Client","已知开源远控客户端标识"),
            ("r046","远控框架","njRAT","远控木马","高","text","AsyncTaskAction","njRAT 通信分包标识"),
            ("r047","远控框架","DarkComet","远控木马","高","text","DarkComet","已知远控标识"),
            ("r048","远控框架","Remcos","远控木马","高","text","Remcos","已知远控标识"),
            ("r049","远控框架","AsyncRAT","远控木马","高","text","AsyncRAT","已知远控标识"),
            ("r050","键盘记录","通用远控","远控木马","中","text","SetWindowsHookEx","全局键盘钩子，键盘记录常用 API"),
            ("r051","键盘记录","通用远控","远控木马","中","text","GetAsyncKeyState","异步按键状态轮询，键盘记录常用 API"),
            ("r052","屏幕截取","通用远控","远控木马","中","all","GetDC|BitBlt","屏幕抓取 API 组合"),
            ("r053","摄像头采集","通用远控","远控木马","中","text","avicap32","摄像头采集库，隐私窃取特征"),
            ("r054","麦克风录音","通用远控","远控木马","中","text","waveInOpen","录音 API，环境窃听特征"),

            ("r060","远程线程注入","通用注入","进程注入","高","all","VirtualAllocEx|WriteProcessMemory|CreateRemoteThread","经典跨进程注入 API 三段组合"),
            ("r061","进程镂空","通用注入","进程注入","高","text","NtUnmapViewOfSection","进程镂空（Process Hollowing）关键 API"),
            ("r062","APC 注入","通用注入","进程注入","高","text","QueueUserAPC","APC 注入关键 API"),
            ("r063","线程上下文劫持","通用注入","进程注入","高","text","SetThreadContext","线程上下文劫持关键 API"),
            ("r064","内存映射注入","通用注入","进程注入","高","all","MapViewOfFile|CreateRemoteThread","共享映射注入组合"),
            ("r065","调试检测","通用规避","反分析","低","text","IsDebuggerPresent","反调试检测 API"),
            ("r066","虚拟机检测","VMware","反分析","低","text","VMware","虚拟机环境检测字符串"),
            ("r067","虚拟机检测","VirtualBox","反分析","中","text","VBoxService","VirtualBox 服务检测"),
            ("r068","沙箱检测","Sandboxie","反分析","高","text","SbieDll","沙箱环境检测，恶意样本典型规避手段"),
            ("r069","Wine 环境检测","Wine","反分析","中","text","wine_get_unix_file_name","非 Windows 分析环境检测"),
            ("r070","AMSI 绕过","通用规避","反分析","中","text","amsi.dll","加载 AMSI 以打补丁绕过脚本扫描"),
            ("r071","ETW 绕过","通用规避","反分析","中","text","EtwEventWrite","ETW 补丁，常用于隐藏行为"),
            ("r072","关闭 Defender 实时防护","通用规避","安全篡改","高","text","DisableRealtimeMonitoring","关闭杀软实时监控指令"),
            ("r073","添加 Defender 排除","通用规避","安全篡改","高","text","Add-MpPreference -ExclusionPath","为自身添加杀软排除目录"),

            ("r080","注册表自启动","通用持久化","持久化","中","text","\\CurrentVersion\\Run","写入 Run 键实现开机自启"),
            ("r081","计划任务持久化","通用持久化","持久化","中","text","schtasks /create","通过计划任务维持常驻"),
            ("r082","服务注册","通用持久化","持久化","低","text","CreateServiceW","注册系统服务，常用于权限维持"),
            ("r083","启动目录投放","通用持久化","持久化","中","text","\\Start Menu\\Programs\\Startup","投放至启动目录实现自启"),
            ("r084","WMI 事件订阅","通用持久化","持久化","高","text","CommandLineEventConsumer","WMI 永久事件订阅，隐蔽持久化"),
            ("r085","Winlogon 劫持","通用持久化","持久化","中","text","Userinit","Winlogon Userinit 劫持"),
            ("r086","IFEO 劫持","通用持久化","持久化","高","text","Image File Execution Options","映像劫持，用于劫持或阻止程序启动"),
            ("r087","Active Setup 持久化","通用持久化","持久化","中","text","Active Setup","通过 Active Setup 维持执行"),

            ("r095","横向移动工具","PsExec","横向移动","高","text","psexec","PsExec 远程执行工具标识"),
            ("r096","SMB 连接","通用横向","横向移动","中","text","net use \\\\","建立远程共享连接"),
            ("r097","共享创建","通用横向","横向移动","中","text","net share","创建网络共享"),
            ("r098","远程 WMI 执行","通用横向","横向移动","高","text","wmic /node:","远程 WMI 命令执行"),
            ("r099","WinRM 远程执行","通用横向","横向移动","中","text","winrs ","WinRM 远程命令执行"),
            ("r100","开启远程桌面","通用横向","横向移动","中","text","fDenyTSConnections","修改 RDP 开关，开启远程桌面"),

            ("r105","MBR 写入","通用破坏","破坏型","高","text","\\\\.\\PhysicalDrive0","直接写物理磁盘，破坏引导记录"),
            ("r106","格式化命令","通用破坏","破坏型","高","text","format c:","格式化系统盘指令"),
            ("r107","递归强删","通用破坏","破坏型","中","text","del /f /s /q","递归强制删除文件"),
            ("r108","磁盘清理命令","通用破坏","破坏型","中","all","diskpart|clean","diskpart 清盘组合"),

            ("r115","PowerShell 编码执行","通用脚本","脚本投放","高","text","powershell -enc","Base64 编码命令，规避检测的常用手法"),
            ("r116","隐藏窗口执行","通用脚本","脚本投放","中","text","-windowstyle hidden","隐藏窗口运行，逃避用户察觉"),
            ("r117","IEX 内存加载","通用脚本","脚本投放","高","text","IEX(","PowerShell 内存加载执行"),
            ("r118","远程脚本下载","通用脚本","脚本投放","中","text","DownloadString","下载远程脚本内容"),
            ("r119","证书工具解码","LOLBin","脚本投放","高","text","certutil -decode","滥用 certutil 解码释放载荷"),
            ("r120","BITS 传输","LOLBin","脚本投放","高","text","bitsadmin /transfer","滥用 BITS 下载载荷"),
            ("r121","mshta 远程执行","LOLBin","脚本投放","高","text","mshta http","mshta 直接加载远程 HTA"),
            ("r122","regsvr32 远程注册","LOLBin","脚本投放","高","text","regsvr32 /s /u /i:http","Squiblydoo，绕过白名单加载脚本"),
            ("r123","MSBuild 执行","LOLBin","脚本投放","低","text","msbuild.exe","滥用 MSBuild 编译执行内联任务"),
            ("r124","InstallUtil 执行","LOLBin","脚本投放","中","text","installutil","滥用 InstallUtil 执行托管代码"),
            ("r125","COM 脚本对象","通用脚本","脚本投放","中","text","WScript.Shell","脚本创建 Shell 对象执行命令"),
            ("r126","Base64 解码","通用脚本","脚本投放","中","text","FromBase64String","脚本内 Base64 解码，常见载荷解码步骤"),

            ("r130","Office 宏自动执行","通用文档","恶意文档","中","text","AutoOpen","宏自动执行入口"),
            ("r131","Office 宏自动执行","通用文档","恶意文档","中","text","Document_Open","宏文档打开事件"),
            ("r132","OLE 对象执行","通用文档","恶意文档","中","text","Shell.Application","通过 Shell 对象启动外部程序"),
            ("r133","PDF 自动动作","通用文档","恶意文档","低","text","/OpenAction","PDF 打开即执行的动作，钓鱼常用"),

            ("r140","UPX 加壳","UPX","加壳/混淆","中","text","UPX0","UPX 壳节名，常用于压缩规避静态检测"),
            ("r141","ASPack 加壳","ASPack","加壳/混淆","中","text",".aspack","ASPack 壳节名"),
            ("r142","Themida 加壳","Themida","加壳/混淆","中","text",".themida","Themida 强壳节名"),
            ("r143","VMProtect 加壳","VMProtect","加壳/混淆","中","text",".vmp0","VMProtect 虚拟化壳节名"),
            ("r144","Enigma 加壳","Enigma","加壳/混淆","中","text",".enigma1","Enigma 壳节名"),
            ("r145","高熵载荷","通用","加壳/混淆","中","pe","high_entropy","PE 区段熵值极高，疑似加密/压缩载荷"),

            ("r150","U 盘自启动","通用蠕虫","蠕虫","中","text","autorun.inf","U 盘自启动配置文件，蠕虫传播特征"),
            ("r151","快捷方式投放","通用蠕虫","蠕虫","低","text",".lnk","大量快捷方式投放，常见于蠕虫传播"),

            ("r155","IRC 机器人","通用僵尸网络","僵尸网络","高","text","JOIN #","IRC 频道加入指令，僵尸网络控制"),
            ("r156","Tor 代理连接","通用匿名","反溯源","高","text","127.0.0.1:9050","连接本地 Tor 代理隐藏来源"),
            ("r157","Telegram 机器人回传","通用窃密","远控木马","中","text","api.telegram.org","通过 Telegram 机器人接口外传数据"),
            ("r158","Discord Webhook 回传","通用窃密","远控木马","中","text","api/webhooks","通过 Discord Webhook 外传数据"),

            ("r160","Android 可执行载荷","通用安卓","移动恶意","低","text","classes.dex","APK 内 Dalvik 字节码"),
            ("r161","短信权限申请","通用安卓","移动恶意","中","text","android.permission.SEND_SMS","申请发送短信权限，资费消耗类特征"),
            ("r162","无障碍服务滥用","通用安卓","移动恶意","中","text","BIND_ACCESSIBILITY_SERVICE","滥用无障碍服务实现自动操作/窃密"),
            ("r163","设备管理器权限","通用安卓","移动恶意","中","text","DEVICE_ADMIN_ENABLED","申请设备管理器权限，抗卸载"),

            ("r170","凭据抓取工具","Mimikatz","黑客工具","高","text","mimikatz","已知凭据抓取工具标识"),
            ("r171","凭据抓取模块","Mimikatz","黑客工具","高","text","sekurlsa","Mimikatz LSASS 凭据模块名"),
            ("r172","CobaltStrike 信标","CobaltStrike","渗透框架","高","text","beacon.dll","CobaltStrike 信标特征"),
            ("r173","Metasploit 载荷","Meterpreter","渗透框架","高","text","metsrv","Meterpreter 服务端载荷标识"),
            ("r174","密码哈希导出","通用","黑客工具","高","text","pwdump","本地账户哈希导出工具"),
            ("r175","注册表导出 SAM","通用","黑客工具","中","text","reg save hklm\\sam","导出 SAM 数据库，凭据窃取前置"),
            ("r176","注册表导出 SECURITY","通用","黑客工具","中","text","reg save hklm\\security","导出 SECURITY 配置单元"),
            ("r177","扫描爆破","通用","黑客工具","中","text","masscan","大规模端口扫描工具"),
            ("r178","弱口令爆破","通用","黑客工具","中","text","hydra","暴力破解工具标识"),

            // ——— 扩充：主流勒索家族与加密行为 ———
            ("r200","勒索家族标识","LockBit","勒索软件","中","text","LockBit","LockBit 勒索团伙标识"),
            ("r201","勒索家族标识","BlackCat/ALPHV","勒索软件","中","text","ALPHV","BlackCat（ALPHV）勒索家族标识"),
            ("r202","勒索家族标识","Clop","勒索软件","中","text","Clop","Clop 勒索团伙标识"),
            ("r203","勒索家族标识","REvil/Sodinokibi","勒索软件","中","text","Sodinokibi","REvil（Sodinokibi）勒索家族标识"),
            ("r204","勒索家族标识","BlackBasta","勒索软件","中","text","BlackBasta","BlackBasta 勒索家族标识"),
            ("r205","勒索家族标识","Babuk","勒索软件","中","text","Babuk","Babuk 勒索家族标识"),
            ("r206","勒索家族标识","Hive","勒索软件","低","text","HiveLeaks","Hive 勒索数据泄露站点标识"),
            ("r207","勒索家族标识","Royal","勒索软件","低","text","Royal ransomware","Royal 勒索家族标识"),
            ("r208","勒索家族标识","Akira","勒索软件","低","text","akira_readme","Akira 勒索信文件名特征"),
            ("r209","勒索家族标识","Egregor","勒索软件","中","text","Egregor","Egregor 勒索家族标识"),
            ("r210","勒索谈判通道","通用勒索","勒索软件","低","text","Tox chat","勒索谈判使用 Tox 即时通信"),
            ("r211","加密文件后缀","BlackCat","勒索软件","低","text",".phobos.","加密文件复合后缀特征"),
            ("r212","批量加密行为","通用勒索","勒索软件","中","all","FindFirstFile|CryptEncrypt","文件枚举配合加密 API，批量加密典型组合"),
            ("r213","加密后自删除","通用勒索","勒索软件","中","all","DeleteFileW|MoveFileEx","加密后删除原文件痕迹"),

            // ——— 扩充：知名远控 / 后渗透框架 ———
            ("r220","渗透框架","Cobalt Strike","渗透框架","高","text","beacon.dll","Cobalt Strike Beacon 载荷标识"),
            ("r221","渗透框架","Cobalt Strike","渗透框架","中","text","cobaltstrike","Cobalt Strike 团队服务器标识"),
            ("r222","渗透框架","Sliver","渗透框架","中","text","sliver-client","Sliver C2 客户端标识"),
            ("r223","渗透框架","Havoc","渗透框架","中","text","Havoc","Havoc C2 框架标识"),
            ("r224","渗透框架","Brute Ratel","渗透框架","高","text","Brute Ratel","Brute Ratel C4 框架标识"),
            ("r225","远控家族","Gh0st RAT","远控木马","高","text","Gh0st","Gh0st 远控家族标识"),
            ("r226","远控家族","PoisonIvy","远控木马","高","text","PoisonIvy","PoisonIvy 远控家族标识"),
            ("r227","远控家族","PlugX","远控木马","高","text","PlugX","PlugX 远控家族标识"),
            ("r228","远控家族","ShadowPad","远控木马","高","text","ShadowPad","ShadowPad 后门标识"),
            ("r229","远控家族","Winnti","远控木马","高","text","Winnti","Winnti 组织专用后门标识"),
            ("r230","远控家族","NetWire","远控木马","高","text","NetWire","NetWire 远控家族标识"),
            ("r231","远控家族","Warzone RAT","远控木马","中","text","Warzone","Warzone RAT 标识"),
            ("r232","远控家族","XWorm","远控木马","中","text","XWorm","XWorm 远控家族标识"),
            ("r233","远控家族","DCRat","远控木马","中","text","DcRat","DCRat 远控家族标识"),
            ("r234","远控家族","Venom RAT","远控木马","中","text","VenomRAT","Venom RAT 家族标识"),
            ("r235","远控家族","Quasar","远控木马","中","text","QuasarRAT","Quasar RAT 家族标识"),

            // ——— 扩充：银行木马与下载器 ———
            ("r240","银行木马","Emotet","窃密木马","高","text","Emotet","Emotet 银行木马/加载器标识"),
            ("r241","银行木马","TrickBot","窃密木马","高","text","TrickBot","TrickBot 银行木马标识"),
            ("r242","银行木马","QakBot","窃密木马","高","text","QakBot","QakBot 银行木马标识"),
            ("r243","银行木马","Dridex","窃密木马","高","text","Dridex","Dridex 银行木马标识"),
            ("r244","银行木马","IcedID","窃密木马","高","text","IcedID","IcedID 银行木马标识"),
            ("r245","加载器","BazarLoader","窃密木马","中","text","BazarLoader","BazarLoader 下载器标识"),
            ("r246","银行木马","Ursnif/Gozi","窃密木马","高","text","Gozi","Ursnif（Gozi）银行木马标识"),

            // ——— 扩充：信息窃取木马 ———
            ("r250","窃密家族","AgentTesla","窃密木马","高","text","AgentTesla","AgentTesla 窃密木马标识"),
            ("r251","窃密家族","Formbook/XLoader","窃密木马","高","text","Formbook","Formbook（XLoader）窃密木马标识"),
            ("r252","窃密家族","RedLine Stealer","窃密木马","高","text","RedLine Stealer","RedLine 窃密木马标识"),
            ("r253","窃密家族","Raccoon Stealer","窃密木马","高","text","Raccoon Stealer","Raccoon 窃密木马标识"),
            ("r254","窃密家族","LokiBot","窃密木马","高","text","LokiBot","LokiBot 窃密木马标识"),
            ("r255","窃密家族","RisePro","窃密木马","高","text","RisePro","RisePro 窃密木马标识"),
            ("r256","窃密家族","Vidar","窃密木马","高","text","Vidar","Vidar 窃密木马标识"),
            ("r257","窃密家族","Mars Stealer","窃密木马","高","text","Mars Stealer","Mars 窃密木马标识"),
            ("r258","凭据解密","通用窃密","窃密木马","中","text","CryptUnprotectData","调用 DPAPI 解密浏览器保存凭据"),

            // ——— 扩充：蠕虫与大规模破坏 ———
            ("r265","蠕虫家族","WannaCry","蠕虫","高","text","WanaCrypt0r","WannaCry 蠕虫标识"),
            ("r266","蠕虫家族","NotPetya","蠕虫","高","text","NotPetya","NotPetya 破坏性蠕虫标识"),
            ("r267","蠕虫家族","Conficker","蠕虫","高","text","Conficker","Conficker 蠕虫标识"),
            ("r268","蠕虫传播","通用蠕虫","蠕虫","中","text","EternalBlue","永恒之蓝漏洞利用，蠕虫横向传播特征"),
            ("r269","僵尸网络","Mirai","僵尸网络","高","text","Mirai","Mirai 僵尸网络标识"),
            ("r270","僵尸网络","Gafgyt","僵尸网络","高","text","gafgyt","Gafgyt 僵尸网络标识"),
            ("r271","僵尸网络","Kinsing","僵尸网络","高","text","kinsing","Kinsing 挖矿僵尸网络标识"),
            ("r272","云环境攻击","TeamTNT","挖矿程序","高","text","TeamTNT","TeamTNT 挖矿团伙标识"),
            ("r273","挖矿程序","XMRig 配置","挖矿程序","中","text","donate-level","XMRig 配置文件特征字段"),
            ("r274","挖矿程序","Minergate","挖矿程序","中","text","minergate","Minergate 挖矿程序标识"),

            // ——— 扩充：恶意文档与宏投放 ———
            ("r280","宏自动执行","通用文档","恶意文档","中","text","AutoOpen","Office 宏自动执行入口"),
            ("r281","脚本宿主调用","通用文档","恶意文档","中","text","WScript.Shell","VBA 调用脚本宿主执行命令"),
            ("r282","OLE 外链释放","通用文档","恶意文档","中","text","OLE2Link","OLE 外链对象投放载荷"),
            ("r283","模板注入","通用文档","恶意文档","中","text","Template Injection","远程模板注入加载恶意宏"),
            ("r284","PDF 脚本投放","通用文档","恶意文档","低","text","/JavaScript","PDF 内嵌脚本，常见投放入口"),
            ("r285","文档漏洞利用","CVE 利用","恶意文档","高","text","Equation.3","公式编辑器漏洞利用特征"),

            // ——— 扩充：移动端恶意（APK） ———
            ("r290","短信拦截","安卓恶意","移动恶意","中","text","android.provider.Telephony.SMS_RECEIVED","注册短信接收广播，常见验证码窃取"),
            ("r291","无障碍滥用","安卓恶意","移动恶意","中","text","AccessibilityService","滥用无障碍服务模拟点击/窃取界面"),
            ("r292","设备管理器提权","安卓恶意","移动恶意","中","text","BIND_DEVICE_ADMIN","申请设备管理器权限，阻碍卸载"),
            ("r293","静默安装","安卓恶意","移动恶意","低","text","REQUEST_INSTALL_PACKAGES","申请安装未知应用权限，常见投放链"),
            ("r294","安卓银行木马","Cerberus/Anubis","移动恶意","高","text","Cerberus","Cerberus 安卓银行木马标识"),
            ("r295","安卓间谍软件","Joker","移动恶意","中","text","Joker","Joker 订阅欺诈类间谍软件标识"),

            // ——— 扩充：加壳与混淆 ———
            ("r300","可执行壳","UPX","加壳/混淆","低","text","UPX0","UPX 加壳节区特征"),
            ("r301","商业壳","Themida","加壳/混淆","低","text","Themida","Themida 保护壳标识"),
            ("r302","商业壳","VMProtect","加壳/混淆","低","text",".vmp0","VMProtect 虚拟机保护节区"),
            ("r303","商业壳","Enigma","加壳/混淆","低","text","Enigma protector","Enigma 保护壳标识"),

            // ——— 扩充：外联与隧道 ———
            ("r310","反向 Shell","通用后门","远控木马","中","text","nc -e","Netcat 反向 shell 用法"),
            ("r311","反弹 Shell","通用后门","远控木马","中","text","/bin/sh -i","Linux 交互式反弹 shell"),
            ("r312","DNS 隧道","通用隧道","远控木马","中","text","iodine","iodine DNS 隧道工具标识"),
            ("r313","Tor 代理","通用匿名","反溯源","中","text","127.0.0.1:9050","连接本机 Tor 代理端口，隐藏真实出口"),
            ("r314","内网穿透","通用隧道","远控木马","低","text","ngrok.io","使用公网穿透服务建立外联通道"),

            // ——— 扩充：凭据与域渗透工具 ———
            ("r320","凭据提取","Mimikatz 变体","黑客工具","高","text","sekurlsa","Mimikatz 凭据提取模块名"),
            ("r321","域内侦察","SharpHound","黑客工具","高","text","SharpHound","SharpHound 域内信息收集器标识"),
            ("r322","票据攻击","Rubeus","黑客工具","高","text","Rubeus","Rubeus Kerberos 票据工具标识"),
            ("r323","AD CS 滥用","Certipy","黑客工具","中","text","certipy","Certipy 证书服务滥用工具标识"),
            ("r324","协议利用","Impacket","黑客工具","中","text","impacket","Impacket 协议工具集标识"),
            ("r325","关系分析","BloodHound","黑客工具","中","text","bloodhound","BloodHound 域关系分析标识"),
            ("r326","注入测试","SQLMap","黑客工具","中","text","sqlmap","SQLMap 注入测试工具标识"),
            ("r327","端口扫描","Nmap","黑客工具","低","text","nmap","Nmap 端口扫描工具标识"),

            // ——— 扩充：反分析补充 ———
            ("r330","进程信息查询","通用规避","反分析","低","text","NtQueryInformationProcess","查询进程调试端口，常用于反调试"),
            ("r331","延迟规避","通用规避","反分析","低","text","NtDelayExecution","长延时执行，规避沙箱超时判定"),
            ("r332","父进程伪造","通用规避","反分析","中","text","PROC_THREAD_ATTRIBUTE_PARENT_PROCESS","伪造父进程，规避行为链分析"),
            ("r333","时间戳伪造","通用规避","反分析","低","text","SetFileTime","篡改文件时间戳，干扰取证时间线"),
        };

        private static List<VirusRule> BuildBuiltins()
        {
            var list = new List<VirusRule>(Defs.Length);
            foreach (var d in Defs)
            {
                list.Add(new VirusRule
                {
                    Id = d.Id, Name = d.Name, Family = d.Family, Type = d.Type, Severity = d.Sev,
                    Kind = d.Kind, Pattern = d.Pattern, Desc = d.Desc, Builtin = true
                });
            }
            return list;
        }

        private static readonly List<VirusRule> Builtins = BuildBuiltins();

        // ————————————————————— 持久化 —————————————————————
        private static void Load()
        {
            if (_hashes != null && _importedRules != null) return;
            lock (_lock)
            {
                if (_hashes != null && _importedRules != null) return;
                var hs = new List<VirusRecord>();
                try
                {
                    if (File.Exists(HashFile))
                    {
                        var txt = File.ReadAllText(HashFile, Encoding.UTF8);
                        if (!string.IsNullOrWhiteSpace(txt))
                            hs = JsonSerializer.Deserialize<List<VirusRecord>>(txt) ?? new List<VirusRecord>();
                    }
                }
                catch (Exception ex) { Log.Write("virusdb hashes load: " + ex.Message); }

                var rs = new List<VirusRule>();
                try
                {
                    if (File.Exists(RuleFile))
                    {
                        var txt = File.ReadAllText(RuleFile, Encoding.UTF8);
                        if (!string.IsNullOrWhiteSpace(txt))
                            rs = JsonSerializer.Deserialize<List<VirusRule>>(txt) ?? new List<VirusRule>();
                        foreach (var r in rs) r.Builtin = false;
                    }
                }
                catch (Exception ex) { Log.Write("virusdb rules load: " + ex.Message); }

                try
                {
                    if (File.Exists(MetaFile))
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(MetaFile, Encoding.UTF8));
                        if (doc.RootElement.TryGetProperty("lastUpdate", out var lu)) _lastUpdate = lu.GetString() ?? "";
                        if (doc.RootElement.TryGetProperty("lastSource", out var ls)) _lastSource = ls.GetString() ?? "";
                    }
                }
                catch { }

                _hashes = hs;
                _importedRules = rs;
                Reindex();
            }
        }

        private static void Reindex()
        {
            var idx = new Dictionary<string, VirusRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in _hashes ?? new List<VirusRecord>())
            {
                if (string.IsNullOrWhiteSpace(r.Hash)) continue;
                var k = r.Hash.Trim();
                if (!idx.ContainsKey(k)) idx[k] = r;
            }
            _index = idx;
        }

        private static void SaveHashes()
        {
            try { File.WriteAllText(HashFile, JsonSerializer.Serialize(_hashes ?? new List<VirusRecord>()), Encoding.UTF8); }
            catch (Exception ex) { Log.Write("virusdb hashes save: " + ex.Message); }
        }

        private static void SaveRules()
        {
            try { File.WriteAllText(RuleFile, JsonSerializer.Serialize(_importedRules ?? new List<VirusRule>()), Encoding.UTF8); }
            catch (Exception ex) { Log.Write("virusdb rules save: " + ex.Message); }
        }

        private static void SaveMeta()
        {
            try
            {
                File.WriteAllText(MetaFile, JsonSerializer.Serialize(new { lastUpdate = _lastUpdate, lastSource = _lastSource }), Encoding.UTF8);
            }
            catch { }
        }

        public static List<VirusRule> AllRules()
        {
            Load();
            var list = new List<VirusRule>(Builtins);
            list.AddRange(_importedRules ?? new List<VirusRule>());
            return list;
        }

        public static object Status()
        {
            Load();
            var byType = new Dictionary<string, int>();
            foreach (var r in AllRules())
            {
                var t = string.IsNullOrEmpty(r.Type) ? "其他" : r.Type;
                byType[t] = byType.TryGetValue(t, out var n) ? n + 1 : 1;
            }
            var hd = (_hashes ?? new List<VirusRecord>())
                .GroupBy(h => string.IsNullOrEmpty(h.Severity) ? "高" : h.Severity)
                .ToDictionary(g => g.Key, g => g.Count());
            return new
            {
                dir = Dir,
                hashCount = (_hashes ?? new List<VirusRecord>()).Count,
                ruleCount = AllRules().Count,
                builtinRuleCount = Builtins.Count,
                importedRuleCount = (_importedRules ?? new List<VirusRule>()).Count,
                version = VersionText(),
                lastUpdate = _lastUpdate,
                lastSource = _lastSource,
                byType,
                hashBySeverity = hd,
                sandbox = Sandbox.Enabled
            };
        }

        private static string VersionText()
        {
            var n = (_hashes ?? new List<VirusRecord>()).Count;
            return "内置规则 " + Builtins.Count + " 条 / 导入规则 " + (_importedRules ?? new List<VirusRule>()).Count + " 条 / 样本哈希 " + n + " 条";
        }

        public static List<object> TopRules(int take)
        {
            Load();
            return AllRules().Take(Math.Max(1, take)).Select(r => (object)new
            {
                id = r.Id, name = r.Name, family = r.Family, type = r.Type, severity = r.Severity,
                kind = r.Kind, pattern = r.Pattern, desc = r.Desc, builtin = r.Builtin
            }).ToList();
        }

        public static List<object> TopHashes(int take)
        {
            Load();
            return (_hashes ?? new List<VirusRecord>()).Take(Math.Max(1, take)).Select(h => (object)new
            {
                hash = h.Hash, name = h.Name, type = h.Type, severity = h.Severity, source = h.Source, addedAt = h.AddedAt
            }).ToList();
        }

        /// <summary>清空用户导入的哈希与规则（内置规则不可清除）。</summary>
        public static int ClearImported()
        {
            Load();
            int n = (_hashes ?? new List<VirusRecord>()).Count + (_importedRules ?? new List<VirusRule>()).Count;
            _hashes = new List<VirusRecord>();
            _importedRules = new List<VirusRule>();
            _lastUpdate = "";
            _lastSource = "";
            Reindex();
            SaveHashes(); SaveRules(); SaveMeta();
            return n;
        }

        // ————————————————————— 导入 —————————————————————
        private static bool IsHashToken(string s, out string hash)
        {
            hash = "";
            var t = (s ?? "").Trim().Trim('"', '\'', ',');
            if (t.Length != 32 && t.Length != 40 && t.Length != 64) return false;
            foreach (var ch in t)
                if (!Uri.IsHexDigit(ch)) return false;
            hash = t.ToUpperInvariant();
            return true;
        }

        /// <summary>导入本地文件：支持 .json（哈希数组）、.csv/.txt（每行首列为哈希）与 .yar/.yara（外置规则）。</summary>
        public static (int hashes, int rules, string error) ImportFiles(IEnumerable<string> paths)
        {
            Load();
            int addedH = 0, addedR = 0;
            var errs = new List<string>();
            foreach (var p in paths)
            {
                try
                {
                    if (!File.Exists(p)) { errs.Add(Path.GetFileName(p) + "：文件不存在"); continue; }
                    var ext = Path.GetExtension(p).ToLowerInvariant();
                    var text = File.ReadAllText(p, DetectEncoding(p));
                    if (ext == ".yar" || ext == ".yara")
                    {
                        var rs = ParseYara(text);
                        foreach (var r in rs)
                        {
                            r.Builtin = false;
                            if ((_importedRules!).Any(x => x.Id == r.Id)) r.Id = r.Id + "-" + Guid.NewGuid().ToString("N").Substring(0, 6);
                            _importedRules!.Add(r);
                            addedR++;
                        }
                    }
                    else if (ext == ".json")
                    {
                        addedH += ImportJson(text, p);
                    }
                    else
                    {
                        addedH += ImportLines(text, p);
                    }
                }
                catch (Exception ex) { errs.Add(Path.GetFileName(p) + "：" + ex.Message); }
            }
            if (addedH > 0) SaveHashes();
            if (addedR > 0) SaveRules();
            Reindex();
            return (addedH, addedR, string.Join("；", errs));
        }

        private static Encoding DetectEncoding(string path)
        {
            try
            {
                using var fs = File.OpenRead(path);
                var buf = new byte[3];
                var n = fs.Read(buf, 0, 3);
                if (n == 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) return Encoding.UTF8;
            }
            catch { }
            return new UTF8Encoding(false);
        }

        private static int ImportJson(string text, string source)
        {
            int n = 0;
            try
            {
                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) return 0;
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    string h = "";
                    if (el.ValueKind == JsonValueKind.String) h = el.GetString() ?? "";
                    else if (el.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var key in new[] { "hash", "sha256", "md5", "sha1" })
                            if (el.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String) { h = v.GetString() ?? ""; break; }
                    }
                    if (!IsHashToken(h, out var norm)) continue;
                    var rec = ReadRecord(el, norm, Path.GetFileName(source));
                    if (AddRecord(rec)) n++;
                }
            }
            catch { }
            return n;
        }

        private static VirusRecord ReadRecord(JsonElement el, string hash, string source)
        {
            var rec = new VirusRecord { Hash = hash, Source = source, AddedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm") };
            if (el.ValueKind == JsonValueKind.Object)
            {
                foreach (var key in new[] { "name", "signature", "family" })
                    if (el.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String) { rec.Name = v.GetString() ?? ""; break; }
                foreach (var key in new[] { "type", "file_type", "tags" })
                    if (el.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String) { rec.Type = v.GetString() ?? ""; break; }
                if (el.TryGetProperty("severity", out var sv) && sv.ValueKind == JsonValueKind.String) rec.Severity = sv.GetString() ?? "高";
            }
            if (string.IsNullOrEmpty(rec.Name)) rec.Name = "未命名样本";
            if (string.IsNullOrEmpty(rec.Type)) rec.Type = "未知";
            if (rec.Severity != "高" && rec.Severity != "中" && rec.Severity != "低") rec.Severity = "高";
            return rec;
        }

        private static int ImportLines(string text, string source)
        {
            int n = 0;
            var lines = text.Split('\n');
            int limit = Math.Min(lines.Length, MaxHashLines);
            for (int i = 0; i < limit; i++)
            {
                var line = lines[i].Trim().Trim('\r');
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//")) continue;
                var cells = line.Split(new[] { ',', ';', '\t', '|' }, StringSplitOptions.None);
                string hash = "";
                foreach (var c in cells)
                    if (IsHashToken(c, out hash)) break;
                if (string.IsNullOrEmpty(hash)) continue;
                var name = cells.FirstOrDefault(c => !IsHashToken(c, out _) && c.Trim().Length > 1)?.Trim().Trim('"') ?? "未命名样本";
                var rec = new VirusRecord
                {
                    Hash = hash,
                    Name = name.Length > 80 ? name.Substring(0, 80) : name,
                    Type = "未知",
                    Severity = "高",
                    Source = Path.GetFileName(source),
                    AddedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                };
                if (AddRecord(rec)) n++;
            }
            return n;
        }

        private static bool AddRecord(VirusRecord rec)
        {
            if (_hashes == null) _hashes = new List<VirusRecord>();
            if (_hashes.Any(h => string.Equals(h.Hash, rec.Hash, StringComparison.OrdinalIgnoreCase))) return false;
            _hashes.Add(rec);
            return true;
        }

        /// <summary>从威胁情报地址在线同步哈希清单（CSV/TXT，每行含 sha256/md5/sha1）。</summary>
        public static async Task<(int added, int total, string error)> UpdateFromUrlAsync(string url, string label)
        {
            Load();
            try
            {
                var (ok, body) = await FetchTextAsync(url).ConfigureAwait(false);
                if (!ok) return (0, 0, body);
                var added = ImportLines(body, string.IsNullOrWhiteSpace(label) ? url : label);
                if (added > 0)
                {
                    SaveHashes();
                    Reindex();
                }
                _lastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                _lastSource = string.IsNullOrWhiteSpace(label) ? url : label;
                SaveMeta();
                return (added, (_hashes ?? new List<VirusRecord>()).Count, "");
            }
            catch (Exception ex)
            {
                return (0, (_hashes ?? new List<VirusRecord>()).Count, ex.Message);
            }
        }

        /// <summary>
        /// 微步在线威胁情报中心（ThreatBook）文件信誉同步：按样本哈希逐个查询，恶意/可疑样本写入哈希库。
        /// 接口：POST https://api.threatbook.cn/v3/file/report（multipart: apikey + resource）。
        /// </summary>
        public static async Task<(int queried, int added, int total, string error)> SyncFromThreatBookAsync(string apiKey, IEnumerable<string> hashes, Action<string> log)
        {
            Load();
            if (string.IsNullOrWhiteSpace(apiKey))
                return (0, 0, (_hashes ?? new List<VirusRecord>()).Count, "未配置微步 API Key");

            var list = new List<string>();
            foreach (var raw in hashes ?? Enumerable.Empty<string>())
            {
                if (IsHashToken(raw, out var norm) && !list.Contains(norm)) list.Add(norm);
                if (list.Count >= 50) break;
            }
            if (list.Count == 0)
                return (0, 0, (_hashes ?? new List<VirusRecord>()).Count, "未提供可查询的样本哈希（MD5 / SHA1 / SHA256）");

            int added = 0;
            string firstErr = "";
            using var http = Sandbox.CreateHttpClient(25);
            foreach (var hash in list)
            {
                try
                {
                    using var form = new MultipartFormDataContent();
                    form.Add(new StringContent(apiKey.Trim()), "apikey");
                    form.Add(new StringContent(hash), "resource");
                    using var resp = await http.PostAsync("https://api.threatbook.cn/v3/file/report", form).ConfigureAwait(false);
                    var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode)
                    {
                        if (firstErr.Length == 0) firstErr = "HTTP " + (int)resp.StatusCode;
                        continue;
                    }
                    using var doc = JsonDocument.Parse(body);
                    var root = doc.RootElement;
                    int code = root.TryGetProperty("response_code", out var rc) && rc.ValueKind == JsonValueKind.Number ? rc.GetInt32() : -1;
                    if (code != 0)
                    {
                        var msg = root.TryGetProperty("response_msg", out var rm) && rm.ValueKind == JsonValueKind.String ? rm.GetString() : "response_code " + code;
                        if (firstErr.Length == 0) firstErr = msg ?? "微步接口返回异常";
                        continue;
                    }
                    if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object) continue;
                    if (!data.TryGetProperty("summary", out var sum) || sum.ValueKind != JsonValueKind.Object)
                    {
                        log("微步无该样本情报：" + hash);
                        continue;
                    }
                    var level = sum.TryGetProperty("threat_level", out var tl) && tl.ValueKind == JsonValueKind.String ? (tl.GetString() ?? "") : "";
                    var family = sum.TryGetProperty("malware_family", out var mf) && mf.ValueKind == JsonValueKind.String ? (mf.GetString() ?? "") : "";
                    var mtype = sum.TryGetProperty("malware_type", out var mt) && mt.ValueKind == JsonValueKind.String ? (mt.GetString() ?? "") : "";
                    int score = sum.TryGetProperty("threat_score", out var ts) && ts.ValueKind == JsonValueKind.Number ? ts.GetInt32() : 0;
                    if (level != "malicious" && level != "suspicious")
                    {
                        log("微步判定为无害：" + hash);
                        continue;
                    }
                    var name = !string.IsNullOrWhiteSpace(family) ? family : (!string.IsNullOrWhiteSpace(mtype) ? mtype : "微步情报标记样本");
                    var rec = new VirusRecord
                    {
                        Hash = hash,
                        Name = name.Length > 80 ? name.Substring(0, 80) : name,
                        Type = string.IsNullOrWhiteSpace(mtype) ? "未知" : mtype,
                        Severity = level == "malicious" || score >= 60 ? "高" : "中",
                        Source = "微步威胁情报中心",
                        AddedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                    };
                    if (AddRecord(rec))
                    {
                        added++;
                        log("微步情报命中 " + hash.Substring(0, Math.Min(16, hash.Length)) + "… → " + rec.Name + "（" + level + " / 评分 " + score + "）");
                    }
                }
                catch (Exception ex)
                {
                    if (firstErr.Length == 0) firstErr = ex.Message;
                }
                await Task.Delay(180).ConfigureAwait(false);
            }
            if (added > 0) { SaveHashes(); Reindex(); }
            _lastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
            _lastSource = "微步威胁情报中心";
            SaveMeta();
            return (list.Count, added, (_hashes ?? new List<VirusRecord>()).Count, firstErr);
        }

        private static async Task<(bool ok, string body)> FetchTextAsync(string url)
        {
            try
            {
                using var http = Sandbox.CreateHttpClient(30);
                http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "REA-Studio/1.0 (+offline-analysis)");
                using var resp = await http.GetAsync(url).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) return (false, "HTTP " + (int)resp.StatusCode + " " + resp.ReasonPhrase);
                var text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                return (true, text);
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        // ————————————————————— YARA 简化解析 —————————————————————
        private static List<VirusRule> ParseYara(string text)
        {
            var list = new List<VirusRule>();
            var rxRule = new Regex(@"rule\s+([A-Za-z0-9_\-]+)[^{]*\{(.*?)\}", RegexOptions.Singleline);
            foreach (Match m in rxRule.Matches(text))
            {
                var name = m.Groups[1].Value;
                var body = m.Groups[2].Value;
                var meta = Regex.Match(body, @"meta\s*:(.*?)strings\s*:", RegexOptions.Singleline);
                var sev = "中"; var desc = "";
                if (meta.Success)
                {
                    var sm = Regex.Match(meta.Groups[1].Value, @"severity\s*=\s*""?([^\s""]+)", RegexOptions.IgnoreCase);
                    if (sm.Success)
                    {
                        var v = sm.Groups[1].Value.ToLowerInvariant();
                        if (v == "high" || v == "critical") sev = "高";
                        else if (v == "low" || v == "info") sev = "低";
                        else sev = "中";
                    }
                    var dm = Regex.Match(meta.Groups[1].Value, @"description\s*=\s*""([^""]+)""", RegexOptions.IgnoreCase);
                    if (dm.Success) desc = dm.Groups[1].Value;
                }
                var kind = "text"; var pattern = "";
                var hex = Regex.Match(body, @"\$\w*\s*=\s*\{([^}]+)\}");
                if (hex.Success)
                {
                    var bytes = Regex.Replace(hex.Groups[1].Value, @"[\r\n\t]+|//.*", " ").Trim();
                    if (bytes.Length > 0) { kind = "hex"; pattern = Regex.Replace(bytes, @"\s+", " "); }
                }
                if (pattern.Length == 0)
                {
                    var str = Regex.Match(body, @"\$\w*\s*=\s*""([^""]{3,})""");
                    if (str.Success) { kind = "text"; pattern = str.Groups[1].Value; }
                    else
                    {
                        var rx = Regex.Match(body, @"\$\w*\s*=\s*/([^/]{3,})/");
                        if (rx.Success) { kind = "regex"; pattern = rx.Groups[1].Value; }
                    }
                }
                list.Add(new VirusRule
                {
                    Id = "y-" + name, Name = name, Family = "外置规则", Type = "自定义",
                    Severity = sev, Kind = kind, Pattern = pattern, Desc = desc, Builtin = false
                });
            }
            return list;
        }

        // ————————————————————— 检测引擎 —————————————————————
        /// <summary>
        /// 在沙箱内对样本副本执行检测：哈希比对 + 规则匹配 + PE 结构检查。样本不被执行。
        /// </summary>
        public static async Task<VirusScanResult> ScanAsync(string path, Action<string>? log = null)
        {
            Load();
            var sw = Stopwatch.StartNew();
            var res = new VirusScanResult { Path = path };
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    res.Error = "样本不存在";
                    return res;
                }
                var fi = new FileInfo(path);
                res.Size = fi.Length;

                // ——沙箱隔离：把样本以只读副本形式放入本次沙箱会话，检测只在副本上发生——
                var scanPath = path;
                if (Sandbox.Enabled)
                {
                    try
                    {
                        // 复用当前沙箱会话：分析作业已把样本入箱时沿用同一会话，检测过程中不轮换会话
                        if (Sandbox.Current == null) Sandbox.Ensure("virus");
                        var staged = Sandbox.StageFile(path);
                        if (!string.IsNullOrEmpty(staged) && File.Exists(staged))
                        {
                            scanPath = staged;
                            res.InSandbox = true;
                        }
                        Sandbox.Note("virus 检测样本副本：" + (res.InSandbox ? Path.GetFileName(scanPath) : "（未入沙箱）"));
                    }
                    catch (Exception ex) { res.Notes.Add("沙箱暂存失败，退回本地只读扫描：" + ex.Message); }
                }
                res.ScanPath = scanPath;
                log?.Invoke("病毒检测：计算样本指纹（SHA-256 / MD5）…");

                using (var fs = new FileStream(scanPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, false))
                {
                    using var sha = SHA256.Create();
                    res.Sha256 = Convert.ToHexString(sha.ComputeHash(fs)).ToUpperInvariant();
                    fs.Position = 0;
                    using var md5 = MD5.Create();
                    res.Md5 = Convert.ToHexString(md5.ComputeHash(fs)).ToUpperInvariant();
                }

                log?.Invoke("病毒检测：病毒库比对（" + VersionText() + "）…");
                var hits = new List<VirusHit>();
                var idx = _index ?? new Dictionary<string, VirusRecord>(StringComparer.OrdinalIgnoreCase);
                if (idx.TryGetValue(res.Sha256, out var rec) || idx.TryGetValue(res.Md5, out rec))
                {
                    hits.Add(new VirusHit
                    {
                        RuleId = "hash", Name = rec.Name, Family = rec.Name, Type = rec.Type,
                        Severity = rec.Severity, Match = rec.Hash, Desc = "命中病毒库样本指纹（来源：" + rec.Source + "）", Source = "哈希库"
                    });
                }

                // 读取检测窗口（大文件只扫头部，避免拖垮内存）
                int window = (int)Math.Min(fi.Length, MaxScanBytes);
                var buf = new byte[window];
                int read = 0;
                using (var fs = new FileStream(scanPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, false))
                {
                    while (read < window)
                    {
                        var n = fs.Read(buf, read, window - read);
                        if (n <= 0) break;
                        read += n;
                    }
                }
                if (read < window) Array.Resize(ref buf, read);

                res.Entropy = Entropy(buf, 0, buf.Length);
                var pe = ReadPe(buf);
                res.PeInfo = pe.Count == 0 ? "非 PE 文件" : string.Join(" / ", pe.Where(k => !k.StartsWith("_")).Select(k => PeText(k)));
                if (buf.Length < fi.Length) res.Notes.Add("样本较大，仅对前 " + (MaxScanBytes / 1048576) + " MB 做内容匹配，指纹为全文件计算");

                var latin = Encoding.Latin1.GetString(buf);
                var uni = buf.Length > 1 ? Encoding.Unicode.GetString(buf) : "";
                log?.Invoke("病毒检测：规则匹配（" + AllRules().Count + " 条规则）…");

                foreach (var rule in AllRules())
                {
                    if (string.IsNullOrEmpty(rule.Pattern)) continue;
                    string? matched = null;
                    switch (rule.Kind)
                    {
                        case "pe":
                            if (pe.Contains(rule.Pattern)) matched = PeText(rule.Pattern);
                            break;
                        case "all":
                            {
                                var parts = rule.Pattern.Split('|');
                                if (parts.Length > 0 && parts.All(p => FindText(latin, uni, p) != null))
                                    matched = parts[0];
                                break;
                            }
                        case "hex":
                            {
                                var off = FindHex(buf, rule.Pattern);
                                if (off >= 0) matched = "偏移 0x" + off.ToString("X");
                                break;
                            }
                        case "regex":
                            try
                            {
                                var m = Regex.Match(latin, rule.Pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(400));
                                if (m.Success) matched = Snip(m.Value);
                            }
                            catch { }
                            break;
                        default:
                            matched = FindText(latin, uni, rule.Pattern);
                            break;
                    }
                    if (matched == null) continue;
                    hits.Add(new VirusHit
                    {
                        RuleId = rule.Id, Name = rule.Name, Family = rule.Family, Type = rule.Type,
                        Severity = rule.Severity, Match = matched, Desc = rule.Desc, Source = rule.Builtin ? "内置规则" : "导入规则"
                    });
                }

                // 评分：高危 34 / 中危 16 / 低危 6，同类封顶，哈希命中直接判定恶意
                int score = 0;
                var perFamily = new Dictionary<string, int>();
                foreach (var h in hits.OrderByDescending(h => SevWeight(h.Severity)))
                {
                    var fam = string.IsNullOrEmpty(h.Family) ? h.Name : h.Family;
                    perFamily.TryGetValue(fam, out var c);
                    int add = h.Severity == "高" ? 34 : h.Severity == "中" ? 16 : 6;
                    if (c >= 2) add = add / 3;
                    perFamily[fam] = c + 1;
                    score += add;
                    if (h.Severity == "高") res.High++;
                    else if (h.Severity == "中") res.Medium++;
                    else res.Low++;
                }
                if (hits.Any(h => h.Source == "哈希库" && h.Severity == "高")) score = Math.Max(score, 100);
                res.Score = Math.Min(score, 100);
                res.Verdict = res.Score >= 60 ? "恶意" : res.Score >= 22 ? "可疑" : "未检出";
                res.Matches = hits.OrderByDescending(h => SevWeight(h.Severity)).Take(60).ToList();
                res.RuleCount = AllRules().Count;
                res.HashCount = (_hashes ?? new List<VirusRecord>()).Count;
                res.DbVersion = VersionText();
                res.Ok = true;
                if (res.InSandbox) res.Notes.Add("检测在沙箱副本内完成，样本未被加载执行，主系统文件不受影响");
                res.Summary = res.Verdict == "恶意"
                    ? "判定为恶意：命中 " + res.High + " 项高危、" + res.Medium + " 项中危特征"
                    : res.Verdict == "可疑"
                        ? "判定为可疑：命中 " + res.Medium + " 项中危、" + res.Low + " 项低危特征，建议结合动态分析复核"
                        : "病毒库比对未见命中（无签名与行为特征匹配）";
                log?.Invoke("病毒检测完成：判定 " + res.Verdict + "，评分 " + res.Score);
                return res;
            }
            catch (Exception ex)
            {
                res.Error = ex.Message;
                Log.Write("virus scan: " + ex);
                return res;
            }
            finally
            {
                sw.Stop();
                res.ElapsedMs = sw.ElapsedMilliseconds;
            }
        }

        private static int SevWeight(string s) => s == "高" ? 3 : s == "中" ? 2 : 1;

        private static string Snip(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var t = new string(s.Where(ch => ch >= 32 && ch < 127 || ch > 160).ToArray());
            if (t.Length > 64) t = t.Substring(0, 64) + "…";
            return t;
        }

        private static string? FindText(string latin, string uni, string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return null;
            if (pattern.Contains('|')) return null;
            var i = latin.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (i >= 0)
            {
                var s = Math.Max(0, i - 12);
                var len = Math.Min(latin.Length - s, pattern.Length + 24);
                return Snip(latin.Substring(s, len));
            }
            if (uni.Length > 0)
            {
                var j = uni.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                if (j >= 0)
                {
                    var s = Math.Max(0, j - 12);
                    var len = Math.Min(uni.Length - s, pattern.Length + 24);
                    return Snip(uni.Substring(s, len));
                }
            }
            return null;
        }

        private static int FindHex(byte[] data, string pattern)
        {
            var tokens = pattern.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0) return -1;
            var mask = new bool[tokens.Length];
            var val = new byte[tokens.Length];
            for (int i = 0; i < tokens.Length; i++)
            {
                var t = tokens[i].ToUpperInvariant();
                if (t == "??" || t == "?") { mask[i] = false; continue; }
                if (t.Length != 2 || !byte.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out val[i])) return -1;
                mask[i] = true;
            }
            int limit = data.Length - tokens.Length;
            for (int i = 0; i <= limit; i++)
            {
                bool ok = true;
                for (int j = 0; j < tokens.Length; j++)
                {
                    if (mask[j] && data[i + j] != val[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
            return -1;
        }

        private static double Entropy(byte[] data, int offset, int len)
        {
            if (len <= 0) return 0;
            var counts = new int[256];
            for (int i = offset; i < offset + len; i++) counts[data[i]]++;
            double e = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / len;
                e -= p * Math.Log(p, 2);
            }
            return Math.Round(e, 3);
        }

        /// <summary>轻量 PE 结构检查：只解析必要字段，不做完整校验。</summary>
        private static HashSet<string> ReadPe(byte[] b)
        {
            var set = new HashSet<string>();
            try
            {
                if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return set;
                int lfanew = BitConverter.ToInt32(b, 0x3C);
                if (lfanew <= 0 || lfanew + 0x18 > b.Length) return set;
                if (b[lfanew] != 'P' || b[lfanew + 1] != 'E' || b[lfanew + 2] != 0 || b[lfanew + 3] != 0) return set;
                int numSec = BitConverter.ToInt16(b, lfanew + 6);
                int optSize = BitConverter.ToInt16(b, lfanew + 20);
                int optOff = lfanew + 24;
                ushort magic = optOff + 2 <= b.Length ? BitConverter.ToUInt16(b, optOff) : (ushort)0;
                bool pe32plus = magic == 0x20B;
                int ddOff = optOff + (pe32plus ? 112 : 96);
                int ddCount = ddOff + 4 <= b.Length ? BitConverter.ToInt32(b, ddOff - 4) : 0;
                // 签名表
                if (ddCount > 4 && ddOff + 4 * 8 + 4 <= b.Length)
                {
                    int certVa = BitConverter.ToInt32(b, ddOff + 4 * 8);
                    int certSize = BitConverter.ToInt32(b, ddOff + 4 * 8 + 4);
                    if (certVa != 0 && certSize != 0) set.Add("signed");
                }
                // 节表
                int secOff = optOff + optSize;
                if (numSec > 0 && secOff + numSec * 40 <= b.Length)
                {
                    if (numSec > 9) set.Add("many_sections");
                    for (int i = 0; i < numSec; i++)
                    {
                        int o = secOff + i * 40;
                        uint chars = BitConverter.ToUInt32(b, o + 36);
                        bool exec = (chars & 0x20000000) != 0;
                        bool write = (chars & 0x80000000) != 0;
                        if (exec && write) set.Add("wx_section");
                        int rawSize = (int)BitConverter.ToUInt32(b, o + 16);
                        int rawPtr = (int)BitConverter.ToUInt32(b, o + 20);
                        if (rawSize > 4096 && rawPtr > 0 && rawPtr + rawSize <= b.Length)
                        {
                            var e = Entropy(b, rawPtr, Math.Min(rawSize, 4 * 1024 * 1024));
                            if (e > 7.2) set.Add("high_entropy");
                        }
                    }
                }
                if (set.Contains("wx_section") || set.Contains("high_entropy")) { }
                return set;
            }
            catch { return set; }
        }

        private static string PeText(string key)
        {
            switch (key)
            {
                case "high_entropy": return "区段高熵（疑似加密/压缩载荷）";
                case "wx_section": return "存在可写且可执行区段";
                case "many_sections": return "节区数量异常（>9）";
                case "signed": return "含数字签名目录";
                default: return key;
            }
        }
    }
}
