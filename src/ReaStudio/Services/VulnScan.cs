using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    /// <summary>单条漏洞命中记录。</summary>
    public sealed class VulnHit
    {
        public string CveId = "";
        public double Cvss;
        public string Severity = "中";
        /// <summary>命中形态：组件版本 / 版本未知 / 文件指纹 / 利用特征 / 在线参考</summary>
        public string Kind = "组件版本";
        public string Component = "";
        public string Affected = "";
        public string Evidence = "";
        public string Desc = "";
        public string Fix = "";
        public string Refs = "";
        public string Source = "内置库";
    }

    /// <summary>识别到的组件指纹。</summary>
    public sealed class ComponentInfo
    {
        public string Name = "";
        public string Version = "";
        public string Evidence = "";
        public string Source = "";
    }

    /// <summary>一次漏洞检测结果（只读比对，样本不执行）。</summary>
    public sealed class VulnScanResult
    {
        public bool Ok;
        public string Error = "";
        public string Path = "";
        public string ScanPath = "";
        public bool InSandbox;
        public string Sha256 = "";
        public long Size;
        public string Verdict = "未发现已知漏洞";
        public int Score;
        public int Critical, High, Medium, Low, Pending;
        public List<VulnHit> Matches = new();
        public List<ComponentInfo> Components = new();
        public int CveCount;
        public string DbVersion = "";
        public long ElapsedMs;
        public List<string> Notes = new();
        public string Summary = "";
    }

    /// <summary>漏洞库中的一条 CVE 记录。Kind: ver=组件版本区间 / file=文件指纹 / str=利用特征 / name=仅组件名（在线库）。</summary>
    public sealed class VulnRule
    {
        public string CveId = "";
        public string Component = "";
        public string Kind = "ver";
        public string Pattern = "";
        public string MinVer = "";
        public string MaxVer = "";
        public double Cvss = 5.0;
        public string Severity = "中";
        public string Desc = "";
        public string Fix = "";
        public string Refs = "";
        public string Source = "内置库";
        public bool Builtin = true;
        public string Key => CveId + "|" + Kind + "|" + Component;
    }

    /// <summary>
    /// CVE 漏洞库与本地漏洞检测引擎。
    /// 库分三部分：①内置 CVE 库（随程序发布，覆盖主流组件版本型漏洞与常见在野利用特征，不可删除）；
    /// ②导入的 CVE 库（支持 NVD 2.0 JSON / 自定义 CSV / JSON 数组）；
    /// ③在线同步（NVD API 2.0 检索指定组件，仅作组件名匹配，版本需人工核对）。
    /// 检测方式：提取版本资源、导入表与字符串 banner 形成组件指纹，与 CVE 库做版本区间/特征比对，样本不执行。
    /// </summary>
    public static class VulnDb
    {
        private const int MaxStringBytes = 24 * 1024 * 1024;

        private static readonly object _lock = new();
        // VulnRule 字段均为 public 字段，System.Text.Json 默认不序列化字段，必须显式 IncludeFields
        private static readonly JsonSerializerOptions JsonOpt = new() { IncludeFields = true };
        private static List<VulnRule>? _imported;
        private static string _lastUpdate = "";
        private static string _lastSource = "";

        public static string Dir
        {
            get { var d = Path.Combine(Storage.DataRoot, "cvedb"); Directory.CreateDirectory(d); return d; }
        }

        private static string RuleFile => Path.Combine(Dir, "cve.json");
        private static string MetaFile => Path.Combine(Dir, "meta.json");

        // ————————————————————— 内置 CVE 库 —————————————————————
        // 字段：CVE 编号 / 组件 / 匹配方式 / 特征 / 受影响下限 / 受影响上限 / CVSS / 等级 / 说明 / 修复建议
        private static readonly (string Id, string Comp, string Kind, string Pat, string Min, string Max, double Cvss, string Sev, string Desc, string Fix)[] Defs = new[]
        {
            // —— OpenSSL ——
            ("CVE-2014-0160","OpenSSL","ver","","1.0.1","1.0.1f",7.5,"高","TLS 心跳扩展越界读取（Heartbleed），可泄露进程内存中的私钥、会话票据与凭据","升级至 OpenSSL 1.0.1g 及以上并重新签发证书、更换密钥"),
            ("CVE-2015-0204","OpenSSL","ver","","1.0.1","1.0.1j",4.8,"中","RSA export 套件降级（FREAK），可被中间人降级至 512 位出口级密钥","升级至 OpenSSL 1.0.1k 及以上，禁用 EXPORT 级密码套件"),
            ("CVE-2016-2107","OpenSSL","ver","","1.0.1","1.0.1s",5.9,"中","AES-NI 路径下的填充预言（Padding Oracle），可被用于解密流量","升级至 OpenSSL 1.0.1t / 1.0.2h 及以上"),
            ("CVE-2021-3711","OpenSSL","ver","","1.1.1","1.1.1k",7.4,"高","SM2 解密流程缓冲区溢出，可导致内存破坏","升级至 OpenSSL 1.1.1l 及以上"),
            ("CVE-2022-0778","OpenSSL","ver","","1.1.1","1.1.1m",7.5,"高","证书解析中 BN_mod_sqrt 无限循环，可造成拒绝服务","升级至 OpenSSL 1.1.1n / 3.0.2 及以上"),
            ("CVE-2022-1292","OpenSSL","ver","","1.1.1","1.1.1o",9.8,"严重","c_rehash 脚本未转义 shell 元字符，可命令注入","升级至 OpenSSL 1.1.1p / 3.0.4 及以上"),
            ("CVE-2023-0286","OpenSSL","ver","","3.0.0","3.0.7",7.4,"高","X.400 地址类型混淆导致越界读取","升级至 OpenSSL 3.0.8 及以上"),
            // —— 压缩/图像/数据组件 ——
            ("CVE-2018-25032","zlib","ver","","1.2.0","1.2.11",7.5,"高","deflate 压缩时越界写入，可导致内存破坏","升级至 zlib 1.2.12 及以上"),
            ("CVE-2022-37434","zlib","ver","","1.2.12","1.2.12",9.8,"严重","inflateGetHeader 越界写入，可导致代码执行","升级至 zlib 1.2.13 及以上"),
            ("CVE-2015-8126","libpng","ver","","1.6.0","1.6.21",7.5,"高","png_set_PLTE/png_set_tRNS 越界读取，可导致信息泄露或崩溃","升级至 libpng 1.6.22 及以上"),
            ("CVE-2016-10093","libtiff","ver","","4.0.0","4.0.7",7.8,"高","tiffcp 的 PackBits 解码整数溢出，可导致堆溢出","升级至 libtiff 4.0.8 及以上"),
            ("CVE-2022-35737","SQLite","ver","","1.0.0","3.39.1",7.5,"高","特定格式化字符串下数组边界整数溢出，可导致崩溃或代码执行","升级至 SQLite 3.39.2 及以上"),
            ("CVE-2023-38545","curl","ver","","7.69.0","8.3.0",8.8,"高","SOCKS5 代理握手主机名过长导致堆溢出（可远程触发）","升级至 curl 8.4.0 及以上"),
            ("CVE-2020-8177","curl","ver","","7.20.0","7.71.1",7.8,"高","-J 参数与 -i 组合可覆盖本地文件","升级至 curl 7.72.0 及以上"),
            ("CVE-2017-9047","libxml2","ver","","2.9.0","2.9.4",9.8,"严重","xmlSnprintfElementContent 缓冲区溢出","升级至 libxml2 2.9.5 及以上"),
            // —— 远程访问与系统服务 ——
            ("CVE-2016-0777","OpenSSH","ver","","5.4","7.1p1",6.5,"中","客户端 Roaming 功能可被恶意服务端触发内存泄露（含私钥风险）","升级至 OpenSSH 7.1p2 及以上并禁用 UseRoaming"),
            ("CVE-2023-38408","OpenSSH","ver","","5.5","9.3p1",9.8,"严重","ssh-agent 的 PKCS#11 转发可被利用执行远程代码","升级至 OpenSSH 9.3p2 及以上，避免使用 -A 转发"),
            ("CVE-2024-6387","OpenSSH","ver","","8.5","9.7p1",8.1,"高","信号处理器竞争条件（regreSSHion）可导致未经认证的远程代码执行","升级至 OpenSSH 9.8p1 及以上"),
            // —— Shell 与提权 ——
            ("CVE-2014-6271","GNU Bash","ver","","0.1","4.3",9.8,"严重","环境变量解析缺陷（Shellshock），可远程执行命令","升级至 bash 4.3 补丁版及以上"),
            ("CVE-2014-7169","GNU Bash","ver","","0.1","4.3",9.8,"严重","Shellshock 首个补丁不完整，可绕过继续执行命令","升级至 bash 4.3 后续补丁版（≥ patch 25）"),
            ("CVE-2021-3156","sudo","ver","","1.8.2","1.9.5p1",7.8,"高","sudoedit 堆溢出（Baron Samedit），本地用户可提权至 root","升级至 sudo 1.9.5p2 及以上"),
            // —— 归档工具 ——
            ("CVE-2023-38831","WinRAR","ver","","0.1","6.22",7.8,"高","压缩包内同名文件夹欺骗，打开诱饵文件即执行载荷","升级至 WinRAR 6.23 及以上"),
            ("CVE-2024-11477","7-Zip","ver","","0.1","24.07",7.8,"高","Zstandard 解压越界写入，可导致代码执行","升级至 7-Zip 24.08 及以上"),
            // —— Java 生态 ——
            ("CVE-2021-44228","Apache Log4j","ver","","2.0","2.14.1",10.0,"严重","JNDI 查找注入（Log4Shell），日志内容可控即可远程执行代码","升级至 Log4j 2.17.1 及以上，或移除 JndiLookup"),
            ("CVE-2021-45046","Apache Log4j","ver","","2.0","2.15.0",9.0,"严重","2.15.0 修复不完整，特定 PatternLayout 下仍可执行代码","升级至 Log4j 2.16.0 及以上"),
            ("CVE-2021-45105","Apache Log4j","ver","","2.0","2.16.0",5.9,"中","递归查找导致栈溢出拒绝服务","升级至 Log4j 2.17.0 及以上"),
            ("CVE-2017-5638","Apache Struts","ver","","2.3.5","2.5.10",10.0,"严重","Jakarta Multipart 解析器 OGNL 注入（S2-045），可远程执行代码","升级至 Struts 2.3.32 / 2.5.10.1 及以上"),
            ("CVE-2017-9805","Apache Struts","ver","","2.1.2","2.5.12",8.1,"高","REST 插件 XStream 反序列化（S2-052）","升级至 Struts 2.5.13 及以上"),
            ("CVE-2018-11776","Apache Struts","ver","","2.5.0","2.5.16",8.1,"高","命名空间配置不当导致 OGNL 注入（S2-057）","升级至 Struts 2.5.17 及以上"),
            ("CVE-2022-22965","Spring Framework","ver","","5.2.0","5.3.17",9.8,"严重","数据绑定导致 ClassLoader 操纵（Spring4Shell），可写入 webshell","升级至 Spring Framework 5.3.18 / 5.2.20 及以上"),
            ("CVE-2022-25845","fastjson","ver","","1.2.0","1.2.80",9.8,"严重","autoType 绕过导致反序列化远程代码执行","升级至 fastjson 1.2.83 及以上并关闭 autoType"),
            ("CVE-2016-4437","Apache Shiro","ver","","1.0.0","1.2.4",9.8,"严重","rememberMe Cookie 硬编码密钥反序列化，可远程执行代码","升级至 Shiro 1.2.5 及以上并更换密钥"),
            // —— Web 中间件 ——
            ("CVE-2020-1938","Apache Tomcat","ver","","6.0.0","9.0.31",9.8,"严重","AJP 协议文件包含（Ghostcat），可读取应用内任意文件","升级至 Tomcat 9.0.31 及以上并关闭 AJP 或配置 secret"),
            ("CVE-2019-0232","Apache Tomcat","ver","","7.0.0","9.0.14",8.1,"高","Windows 下 CGI Servlet 参数注入，可执行命令","升级至 Tomcat 9.0.15 及以上并关闭 CGI"),
            ("CVE-2020-14882","Oracle WebLogic","ver","","10.3.6.0","14.1.1.0",9.8,"严重","控制台未授权访问可远程执行代码","安装 2020 年 10 月补丁并限制控制台访问"),
            ("CVE-2020-2551","Oracle WebLogic","ver","","10.3.6.0","12.2.1.4",9.8,"严重","IIOP 反序列化漏洞，可远程执行代码","安装 2020 年 1 月补丁（CVE-2020-2551）"),
            ("CVE-2022-26134","Atlassian Confluence","ver","","1.3.0","7.18.1",9.8,"严重","OGNL 注入，未经认证即可远程执行代码","升级至 Confluence 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1 修复版"),
            ("CVE-2023-22515","Atlassian Confluence","ver","","8.0.0","8.5.1",10.0,"严重","权限校验缺陷可创建管理员账户","升级至 Confluence 8.5.2 / 8.4.3 及以上"),
            ("CVE-2019-15107","Webmin","ver","","1.890","1.920",9.8,"严重","password_change.cgi 命令注入，可远程执行代码","升级至 Webmin 1.930 及以上"),
            ("CVE-2024-23897","Jenkins","ver","","2.0","2.441",9.8,"严重","CLI 任意文件读取，可进一步导致远程代码执行","升级至 Jenkins 2.442 / LTS 2.426.3 及以上"),

            // —— 利用特征（样本/文件引用在野漏洞利用代码或攻击载荷痕迹）——
            ("CVE-2017-0144","SMBv1 (MS17-010)","str",@"MS17-010|ETERNALBLUE|ETERNALROMANCE|DOUBLEPULSAR|ETERNALSYNERGY","","",8.1,"高","文件包含永恒之蓝（EternalBlue）等 SMBv1 利用特征字符串，指向 MS17-010 在野利用工具","确认文件用途并排查 SMBv1 是否启用，安装 MS17-010 补丁，关闭 445 端口暴露"),
            ("CVE-2019-0708","RDP (BlueKeep)","str",@"BlueKeep|CVE-2019-0708","","",9.8,"严重","文件包含 BlueKeep（RDP 预认证远程执行）利用特征","安装 MS19-0708 补丁，限制 3389 端口暴露并启用 NLA"),
            ("CVE-2020-0796","SMBv3 (SMBGhost)","str",@"SMBGhost|CVE-2020-0796","","",10.0,"严重","文件包含 SMBv3 压缩漏洞（SMBGhost）利用特征","安装 KB4551762，关闭 SMBv3 压缩"),
            ("CVE-2020-1472","Netlogon (Zerologon)","str",@"Zerologon|CVE-2020-1472","","",10.0,"严重","文件包含 Zerologon 域控提权利用特征","安装 2020 年 8 月补丁并启用强制安全通道"),
            ("CVE-2021-34527","Print Spooler (PrintNightmare)","str",@"PrintNightmare|CVE-2021-34527","","",8.8,"高","文件包含打印后台程序远程执行利用特征","安装 KB5004945 等补丁并禁用不必要的打印服务"),
            ("CVE-2012-0158","MSCOMCTL.OCX","str",@"CVE-2012-0158|MS12-027","","",9.3,"严重","文件包含 MSCOMCTL 控件栈溢出（MS12-027）利用特征","安装 MS12-027 补丁，注销不需要的 MSCOMCTL 控件"),
            ("CVE-2008-4250","Server 服务 (MS08-067)","str",@"MS08-067|CVE-2008-4250","","",9.8,"严重","文件包含 MS08-067 远程溢出利用特征","安装 MS08-067 补丁，关闭 139/445 端口暴露"),
            ("CVE-2017-11882","Office 公式编辑器","str",@"CVE-2017-11882|EQNEDT32\.EXE","","",7.8,"高","文件包含公式编辑器（EQNEDT32）利用特征","安装 Office 2017 年 11 月补丁，禁用公式编辑器"),
            ("CVE-2018-0802","Office 公式编辑器","str",@"CVE-2018-0802","","",7.8,"高","文件包含公式编辑器第二枚漏洞利用特征","安装 Office 2018 年 1 月补丁"),
            ("CVE-2021-40444","MSHTML","str",@"CVE-2021-40444|mhtml:file:|mshtml\.dll","","",8.8,"高","文件包含 MSHTML 远程执行（CVE-2021-40444）利用特征","安装 KB5005565 等补丁，禁用 ActiveX 安装"),
            ("CVE-2022-30190","MSDT (Follina)","str",@"ms-msdt:|CVE-2022-30190","","",7.8,"高","文件包含 MSDT 协议调用（Follina）利用特征","安装 KB5016629 补丁，删除 ms-msdt 协议注册"),
            ("CVE-2021-26855","Exchange (ProxyLogon)","str",@"CVE-2021-26855|ProxyLogon","","",9.8,"严重","文件包含 Exchange SSRF（ProxyLogon）利用特征","安装 2021 年 3 月 Exchange 补丁并排查 webshell"),
            ("CVE-2021-34473","Exchange (ProxyShell)","str",@"CVE-2021-34473|ProxyShell","","",9.8,"严重","文件包含 Exchange（ProxyShell）利用链特征","安装 2021 年 7 月 Exchange 补丁"),
            ("CVE-2018-4878","Adobe Flash Player","str",@"CVE-2018-4878","","",9.8,"严重","文件包含 Flash 释放后重用漏洞利用特征","卸载 Flash Player，或升级至 28.0.0.161 及以上"),
            ("CVE-2017-7269","IIS 6.0 WebDAV","str",@"CVE-2017-7269","","",9.8,"严重","文件包含 IIS WebDAV ScStoragePathFromUrl 溢出利用特征","升级 IIS 或禁用 WebDAV"),
            ("CVE-2020-0601","CryptoAPI (CurveBall)","str",@"CVE-2020-0601","","",8.1,"高","文件包含 CurveBall 证书欺骗利用特征","安装 2020 年 1 月 Windows 补丁"),
            ("CVE-2023-23397","Outlook","str",@"PidLidReminderFileParameter|CVE-2023-23397","","",9.8,"严重","文件包含 Outlook 提醒属性 UNC 路径泄露凭据利用特征","安装 2023 年 3 月 Outlook 补丁，阻断出站 SMB"),
            ("CVE-2023-36884","Office / Windows Search","str",@"CVE-2023-36884","","",7.5,"高","文件包含 Office 与 Windows Search 远程执行利用特征","安装 2023 年 7 月及后续累积更新"),
            ("CVE-2023-28252","CLFS 驱动","str",@"CVE-2023-28252","","",7.8,"高","文件包含公共日志文件系统提权漏洞利用特征","安装 2023 年 4 月 Windows 补丁"),

            // —— 文件指纹（命中文件名即提示，版本需人工核对）——
            ("CVE-2024-3094","xz-utils","file",@"^(liblzma|liblzma5)[^\\/]*\.(so|dll|dylib)(\.[\d\.]+)?$","","",10.0,"严重","该文件为存在上游后门的 liblzma 库，需确认版本是否落在 5.6.0~5.6.1","核对版本并降级/升级，检查 sshd 依赖链"),

            // —— 扩充：Linux / 通用组件 ——
            ("CVE-2019-14287","sudo","ver","","1.8.0","1.8.27",7.8,"高","sudo -u#-1 绕过 Runas 限制提权至 root","升级 sudo 至 1.8.28 及以上"),
            ("CVE-2021-4034","polkit pkexec","str",@"pkexec","","",7.8,"高","pkexec 参数处理越界（PwnKit），本地用户可提权至 root","升级 polkit 至 0.120 补丁版本，或移除 pkexec 的 SUID 位"),
            ("CVE-2016-5195","Linux Kernel","ver","","2.6.22","4.8.3",7.8,"高","写时复制竞态（Dirty COW），本地用户可提权","升级内核至 4.8.3 / 4.4.26 及以上"),
            ("CVE-2022-0847","Linux Kernel","ver","","5.8.0","5.16.11",7.8,"高","pipe 缓冲区标志未初始化（Dirty Pipe），可覆写只读文件提权","升级内核至 5.16.11 / 5.15.25 / 5.10.102 及以上"),
            ("CVE-2015-0235","glibc","ver","","2.2","2.17",10.0,"严重","gethostbyname 系列堆溢出（GHOST），可远程代码执行","升级 glibc 至 2.18 及以上或发行版补丁"),
            ("CVE-2021-33910","systemd","ver","","220","248",5.5,"中","systemd-tmpfiles 栈溢出导致拒绝服务与内存破坏","升级 systemd 至 249 及以上"),
            ("CVE-2022-25636","Linux Kernel","ver","","5.4.0","5.16.12",7.8,"高","netfilter nft_fwd_dup_netdev 越界写，本地提权或容器逃逸","升级内核至 5.16.12 / 5.15.26 及以上"),
            ("CVE-2023-32233","Linux Kernel","ver","","5.0.0","6.3.1",7.8,"高","Netfilter nf_tables 释放后重用，本地提权","升级内核至 6.3.2 / 6.1.30 及以上"),

            // —— 扩充：Web 服务与中间件 ——
            ("CVE-2021-42013","Apache httpd","ver","","2.4.49","2.4.50",9.8,"严重","路径穿越与远程代码执行（CVE-2021-41773 绕过）","升级 httpd 至 2.4.51 及以上"),
            ("CVE-2017-12615","Apache Tomcat","ver","","7.0.0","7.0.79",8.1,"高","PUT 方法任意文件写入导致代码执行","升级 Tomcat 至 7.0.81 及以上，禁用只读初始化参数绕过"),
            ("CVE-2022-22947","Spring Cloud Gateway","ver","","3.0.0","3.1.0",10.0,"严重","Actuator 端点 SpEL 注入导致远程代码执行","升级至 3.1.1 / 3.0.7 及以上，关闭并删除不用的 Actuator 端点"),
            ("CVE-2020-1957","Apache Shiro","ver","","1.5.1","1.5.1",7.5,"高","路径规范化绕过认证","升级 Shiro 至 1.5.2 及以上"),
            ("CVE-2019-2725","Oracle WebLogic","ver","","10.3.6","12.1.3",9.8,"严重","wls9_async 组件反序列化远程代码执行","升级至 12.1.3.0 补丁及 12.2.1.3 及以上，删除 wls9_async 与 wls-wsat"),
            ("CVE-2019-11510","Pulse Secure VPN","str",@"Pulse\s*Secure","","",10.0,"严重","任意文件读取导致凭据泄露，可被用于横向渗透","升级 Pulse Connect Secure 至 9.0R3.4 / 8.3R7.1 及以上"),
            ("CVE-2024-3400","Palo Alto GlobalProtect","str",@"GlobalProtect","","",10.0,"严重","命令注入（未授权），可远程执行代码","升级至 PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 及以上，启用威胁识别"),

            // —— 扩充：数据库与存储 ——
            ("CVE-2019-9193","PostgreSQL","ver","","9.3","11.1",7.2,"高","COPY TO PROGRAM 允许超级用户执行系统命令（功能滥用）","限制超级用户权限，按需禁用 COPY PROGRAM"),
            ("CVE-2021-23222","PostgreSQL libpq","ver","","9.6.0","14.1",5.9,"中","libpq 明文注入中间人攻击","升级至 14.1 / 13.5 / 12.9 / 11.14 / 10.19 及以上"),
            ("CVE-2012-2122","MySQL / MariaDB","ver","","5.0.0","5.5.24",5.9,"中","认证比较缺陷可被暴力绕过登录（重复 256 次成功概率高）","升级 MySQL 至 5.5.25 / 5.1.63 及以上"),
            ("CVE-2016-6662","MySQL / MariaDB","ver","","5.5.0","5.7.14",9.8,"严重","配置文件注入导致以 root 执行代码","升级至 5.7.15 / 5.5.52 / MariaDB 补丁版本"),
            ("CVE-2021-27928","MariaDB","ver","","10.2.0","10.5.9",7.2,"高","wsrep_provider 路径任意库加载导致代码执行","升级至 10.5.10 / 10.4.19 / 10.3.29 / 10.2.38 及以上"),
            ("CVE-2023-34362","Progress MOVEit Transfer","str",@"MOVEit","","",9.8,"严重","SQL 注入导致远程代码执行（Cl0p 勒索利用）","安装 2023 年 6 月补丁并排查 webshell"),
            ("CVE-2017-12635","Apache CouchDB","ver","","1.0.0","2.1.0",9.8,"严重","JSON 解析差异导致权限绕过并提权为管理员","升级至 2.1.1 / 1.7.0 及以上"),

            // —— 扩充：Windows 与常用软件 ——
            ("CVE-2021-1732","Windows Win32k","str",@"CVE-2021-1732","","",7.8,"高","Win32k 提权漏洞利用特征","安装 2021 年 2 月补丁"),
            ("CVE-2023-29357","SharePoint Server","ver","","2019.0.0","2019.0.0",9.8,"严重","JWT 令牌校验缺陷导致权限提升为管理员","安装 2023 年 6 月 SharePoint 补丁"),
            ("CVE-2024-21413","Outlook","str",@"file:///\\\\|CVE-2024-21413","","",9.8,"严重","Outlook 超链接绕过（MonikerLink）可泄露 NTLM 并执行代码","安装 2024 年 2 月 Outlook 补丁"),

            // —— 扩充：浏览器与客户端 ——
            ("CVE-2021-21148","Chrome V8","ver","","88.0.0","88.0.4324.150",8.8,"高","V8 引擎堆溢出，在野利用","升级 Chrome 至 88.0.4324.150 及以上"),
            ("CVE-2023-4863","Chrome / libwebp","ver","","0.0.0","116.0.5845.187",8.8,"高","WebP 解码堆溢出（在野利用）","升级 Chrome 至 116.0.5845.187 及以上，更新 libwebp 至 1.3.2"),
            ("CVE-2023-3079","Chrome V8","ver","","0.0.0","114.0.5735.110",8.8,"高","V8 类型混淆，在野利用","升级 Chrome 至 114.0.5735.110 及以上"),
            ("CVE-2024-0519","Chrome V8","ver","","0.0.0","120.0.6099.224",8.8,"高","V8 越界访问，在野利用","升级 Chrome 至 120.0.6099.224 及以上"),
            ("CVE-2019-11707","Firefox","ver","","60.0","67.0.3",8.8,"高","Array.pop 类型混淆，在野利用","升级 Firefox 至 67.0.3 / 60.7.1 及以上"),
            ("CVE-2020-6819","Firefox","ver","","68.0","74.0",8.8,"高","nsDocShell 释放后重用，在野利用","升级 Firefox 至 74.0.1 / 68.6.1 及以上"),

            // —— 扩充：开源框架与语言运行时 ——
            ("CVE-2019-12384","Jackson-databind","ver","","2.0.0","2.9.9",8.1,"高","logback 反序列化 gadget 导致代码执行","升级 jackson-databind 至 2.9.9.1 及以上并禁用默认类型"),

            // —— 扩充：网络设备与 VPN ——
            ("CVE-2019-1653","Cisco RV320/RV325","str",@"RV32[05]","","",7.5,"高","未授权信息泄露可获取配置与凭据","升级固件 1.4.2.22 及以上"),
            ("CVE-2024-21887","Ivanti Connect Secure","str",@"Ivanti|Pulse\s*Secure","","",9.1,"严重","命令注入（未授权），可远程执行代码","安装 2024 年 1 月缓解措施与补丁"),

            // —— 扩充：供应链与勒索常用 ——
            ("CVE-2020-10189","Zoho ManageEngine","ver","","10.0.0","10.0.479",9.8,"严重","Desktop Central 反序列化远程代码执行","升级至 10.0.479 及以上"),
            ("CVE-2019-19781","Citrix ADC","ver","","10.5.0","13.0.47",9.8,"严重","路径穿越导致远程代码执行（Shitrix）","升级至 13.0.47.24 / 12.1.55.18 / 11.1.63.15 及以上"),
            ("CVE-2021-35464","ForgeRock AM","ver","","6.0.0","7.0.2",9.8,"严重","Jato 反序列化导致远程代码执行","升级至 7.0.3 / 6.5.3 及以上"),
            ("CVE-2022-40684","Fortinet FortiOS","ver","","7.0.0","7.2.1",9.8,"严重","认证绕过可修改管理员配置","升级至 7.2.2 / 7.0.7 / 6.4.11 及以上"),
            ("CVE-2023-27997","Fortinet FortiGate","ver","","6.0.0","7.2.4",9.2,"严重","SSL VPN 堆溢出（XORtigate），可预认证执行代码","升级至 7.2.5 / 7.0.12 / 6.4.13 / 6.2.15 及以上"),
            ("CVE-2023-4966","Citrix NetScaler","ver","","12.1.0","14.1.8.47",9.4,"严重","会话令牌泄露（CitrixBleed），可绕过认证","升级至 14.1-8.50 / 13.1-49.15 / 13.0-92.21 及以上并重置会话"),
            ("CVE-2024-1709","ConnectWise ScreenConnect","ver","","0.0.0","23.9.7",10.0,"严重","认证绕过可创建管理员账户","升级至 23.9.8 及以上并排查异常账户"),
        

            ("CVE-2022-3786","OpenSSL","ver","","3.0.0","3.0.6",7.5,"高",@"X.509 邮件地址名同源缓冲区溢出","升级至 OpenSSL 3.0.7 及以上"),
            ("CVE-2022-3602","OpenSSL","ver","","3.0.0","3.0.6",7.5,"高",@"X.509 证书构造触发 4 字节栈溢出","升级至 OpenSSL 3.0.7 及以上"),
            ("CVE-2022-4450","OpenSSL","ver","","3.0.0","3.0.7",7.5,"高",@"PEM_read_bio_ex 双重释放","升级至 OpenSSL 3.0.8 及以上"),
            ("CVE-2023-0215","OpenSSL","ver","","3.0.0","3.0.7",7.5,"高",@"ASN.1 解析释放后重用（BIO_indef_datafree）","升级至 OpenSSL 3.0.8 及以上"),
            ("CVE-2020-1971","OpenSSL","ver","","1.0.2","1.1.1i",5.9,"中",@"GENERAL_NAME_cmp 空指针解引用导致拒绝服务","升级至 OpenSSL 1.1.1i / 1.0.2x 及以上"),
            ("CVE-2024-0727","OpenSSL","ver","","3.0.0","3.0.12",5.5,"中",@"PKCS12 未校验输入触发空指针解引用","升级至 OpenSSL 3.0.13 及以上"),
            ("CVE-2016-2183","OpenSSL","str",@"SWEET32|DES-CBC3|3DES","","",7.5,"高",@"64 位分组密码（3DES）生日攻击可恢复明文（SWEET32）","禁用 3DES/DES 套件，优先使用 AES-GCM"),
            ("CVE-2014-3566","OpenSSL","str",@"SSLv3|POODLE","","",3.4,"中",@"SSLv3 填充缺陷可致明文泄露（POODLE）","禁用 SSLv3，仅启用 TLS1.2 及以上"),
            ("CVE-2021-22946","curl","ver","","7.20.0","7.77.0",7.5,"高",@"协议降级导致敏感数据以明文发送","升级至 curl 7.77.0 及以上"),
            ("CVE-2022-32221","curl","ver","","7.10.0","7.86.0",9.8,"严重",@"重用连接时方法被改写（POST 变 GET），可能误执行副作用请求","升级至 curl 7.86.0 及以上"),
            ("CVE-2023-27536","curl","ver","","7.10.0","8.0.1",7.5,"高",@"GSS 委派场景错误复用认证句柄导致越权","升级至 curl 8.1.0 及以上"),
            ("CVE-2023-50164","Apache Struts","ver","","2.0.0","6.3.0",9.8,"严重",@"文件上传参数污染导致路径穿越与远程代码执行","升级至 Struts 6.3.0.2 / 2.5.33 及以上"),
            ("CVE-2021-31805","Apache Struts","ver","","2.0.0","2.5.30",9.8,"严重",@"标签属性二次表达式求值导致 OGNL 注入","升级至 Struts 2.5.30 及以上"),
            ("CVE-2020-17530","Apache Struts","ver","","2.0.0","2.5.25",9.8,"严重",@"强制 OGNL 求值（S2-061）可远程代码执行","升级至 Struts 2.5.26 及以上"),
            ("CVE-2019-0230","Apache Struts","ver","","2.0.0","2.5.20",9.8,"严重",@"标签属性 OGNL 二次求值可远程代码执行","升级至 Struts 2.5.22 及以上"),
            ("CVE-2023-46604","Apache ActiveMQ","str",@"ActiveMQ","","",10.0,"严重",@"OpenWire 协议反序列化可远程代码执行","升级至 ActiveMQ 5.18.3 / 5.17.6 / 5.16.7 及以上"),
            ("CVE-2021-4104","Apache Log4j","ver","","1.2.0","1.2.17",7.5,"高",@"Log4j 1.x JMSAppender 不安全反序列化","移除 JMSAppender 或迁移至 Log4j 2.17.1 及以上"),
            ("CVE-2019-17571","Apache Log4j","ver","","1.2.0","1.2.17",9.8,"严重",@"SocketServer 反序列化可远程代码执行","升级至 Log4j 2.x 安全版本"),
            ("CVE-2021-44832","Apache Log4j","ver","","2.0.0","2.17.0",6.6,"中",@"JDBC Appender 配置可控时可远程代码执行","升级至 Log4j 2.17.1 及以上"),
            ("CVE-2022-42889","Apache Commons Text","str",@"commons-text","","",9.8,"严重",@"StringSubstitutor 脚本插值（Text4Shell）可远程代码执行","升级 commons-text 至 1.10.0 及以上"),
            ("CVE-2022-33980","Apache Commons Configuration","str",@"commons-configuration","","",9.8,"严重",@"插值默认值可触发脚本执行","升级 commons-configuration 至 2.8.0 及以上"),
            ("CVE-2022-1471","SnakeYAML","str",@"snakeyaml","","",9.8,"严重",@"Constructor 反序列化可实例化任意类","升级 SnakeYAML 至 2.0 及以上并使用 SafeConstructor"),
            ("CVE-2021-42392","H2 Database","str",@"h2-(\d|\.)+\.jar|org\.h2\.Driver","","",9.8,"严重",@"H2 Console JNDI 注入可远程代码执行","升级 H2 至 2.0.206 及以上并禁用 Console"),
            ("CVE-2020-25649","Jackson Databind","str",@"jackson-databind","","",7.5,"高",@"XML 外部实体注入（XXE）","升级 jackson-databind 至 2.12 及以上并禁用 DTD"),
            ("CVE-2022-22963","Spring Framework","str",@"spring-cloud-function","","",9.8,"严重",@"Spring Cloud Function SpEL 注入可远程代码执行","升级至 3.1.7 / 3.2.3 及以上"),
            ("CVE-2024-22243","Spring Framework","ver","","5.3.0","5.3.33",8.1,"高",@"UriComponentsBuilder 开放重定向与 SSRF","升级至 5.3.34 / 6.1.5 及以上"),
            ("CVE-2022-32532","Apache Shiro","ver","","1.9.0","1.9.0",9.8,"严重",@"正则表达式路径绕过认证","升级 Shiro 至 1.9.1 及以上"),
            ("CVE-2023-21839","Oracle WebLogic","ver","","12.2.1.3","14.1.1.0",7.5,"高",@"T3/IIOP 反序列化可远程代码执行（未授权）","升级至 2023 年 1 月 CPU 补丁版本"),
            ("CVE-2018-2628","Oracle WebLogic","ver","","10.3.6.0","12.2.1.2",9.8,"严重",@"T3 反序列化可远程代码执行","安装 2018 年 4 月 CPU 补丁并限制 T3 协议"),
            ("CVE-2021-2394","Oracle WebLogic","ver","","10.3.6.0","14.1.1.0",9.8,"严重",@"T3/IIOP 反序列化可远程代码执行","安装 2021 年 7 月 CPU 补丁"),
            ("CVE-2021-26084","Atlassian Confluence","ver","","0.0.0","7.4.10",9.8,"严重",@"OGNL 注入可远程执行代码（未授权）","升级至 7.4.11 / 7.13.0 及以上"),
            ("CVE-2022-26138","Atlassian Confluence","str",@"Confluence","","",9.8,"严重",@"Questions for Confluence 硬编码密码可登录后台","卸载应用并轮换受影响账号密码"),
            ("CVE-2023-22518","Atlassian Confluence","ver","","0.0.0","7.19.16",9.1,"严重",@"授权缺陷导致数据破坏（可被利用重置实例）","升级至 7.19.17 / 8.5.2 及以上"),
            ("CVE-2018-1000861","Jenkins","str",@"Jenkins","","",9.8,"严重",@"Stapler 组件路径绕过导致远程代码执行","升级至 Jenkins 2.138.3 / 2.150.1 及以上"),
            ("CVE-2019-1003000","Jenkins","str",@"Jenkins","","",8.8,"高",@"Pipeline 沙箱绕过可执行任意代码","升级至 2.150.2 及以上并更新脚本安全插件"),
            ("CVE-2019-11043","PHP","str",@"php-fpm|PHP/\d","","",9.8,"严重",@"FPM 路径信息处理缺陷可远程代码执行","升级 PHP 至 7.3.11 / 7.2.24 及以上，修正 nginx 配置"),
            ("CVE-2024-4577","PHP","str",@"PHP/\d","","",9.8,"严重",@"Windows 下 CGI 参数注入可远程执行代码","升级至 PHP 8.3.8 / 8.2.20 / 8.1.29 及以上"),
            ("CVE-2012-1823","PHP","ver","","5.0.0","5.4.2",7.5,"高",@"CGI 方式参数注入可远程执行代码","升级 PHP 至 5.4.2 及以上，避免 CGI 模式"),
            ("CVE-2021-3129","Laravel","str",@"laravel","","",9.8,"严重",@"Ignition 调试组件可远程代码执行","关闭 debug 模式，升级 Ignition 至 2.5.2 及以上"),
            ("CVE-2018-7600","Drupal","str",@"Drupal","","",9.8,"严重",@"表单渲染 API 可远程代码执行（Drupalgeddon2）","升级至 7.58 / 8.3.9 / 8.4.6 / 8.5.1 及以上"),
            ("CVE-2019-6340","Drupal","str",@"Drupal","","",8.8,"高",@"REST 模块反序列化可远程代码执行","升级至 8.6.10 / 8.5.11 及以上并限制 REST"),
            ("CVE-2018-13379","Fortinet FortiOS","str",@"FortiOS|FortiGate","","",9.8,"严重",@"SSL VPN 路径穿越可读取会话文件（凭据泄露）","升级至 5.6.8 / 6.0.5 及以上并轮换凭据"),
            ("CVE-2022-42475","Fortinet FortiOS","str",@"FortiOS|FortiGate","","",9.8,"严重",@"SSL VPN 堆溢出可未授权远程代码执行","安装 FG-IR-22-398 补丁并检查入侵痕迹"),
            ("CVE-2022-30525","Zyxel 防火墙","str",@"ZyWALL|USG","","",9.8,"严重",@"管理接口 OS 命令注入（未授权）","升级固件至 5.30 及以上，禁用 WAN 侧管理"),
            ("CVE-2022-1388","F5 BIG-IP","str",@"BIG-IP|BIGIP","","",9.8,"严重",@"iControl REST 认证绕过可远程代码执行","升级至 16.1.2.2 / 15.1.5.1 / 14.1.4.6 及以上"),
            ("CVE-2020-5902","F5 BIG-IP","str",@"BIG-IP|BIGIP","","",9.8,"严重",@"TM UI 路径穿越可远程代码执行","升级至 15.1.0.4 / 14.1.2.1 / 13.1.3.4 及以上"),
            ("CVE-2023-46747","F5 BIG-IP","str",@"BIG-IP|BIGIP","","",9.8,"严重",@"配置接口认证绕过可远程代码执行","安装 2023 年 10 月公告补丁"),
            ("CVE-2023-3519","Citrix ADC","str",@"Citrix|NetScaler","","",9.8,"严重",@"未授权远程代码执行（ADC/Gateway）","升级至 13.1-49.15 / 13.0-92.19 及以上"),
            ("CVE-2021-22893","Pulse Secure","str",@"Pulse\s*Secure","","",10.0,"严重",@"认证绕过可未授权执行代码","升级至 9.1R11.4 及以上并使用 ICT 检测工具"),
            ("CVE-2022-21882","Windows Win32k","str",@"win32k|CVE-2022-21882","","",7.8,"高",@"Win32k 提权漏洞利用特征","安装 2022 年 1 月 Windows 补丁"),
            ("CVE-2022-41040","Microsoft Exchange","str",@"ProxyNotShell|CVE-2022-41040","","",8.8,"高",@"Exchange SSRF（ProxyNotShell）利用特征","安装 2022 年 11 月 Exchange 补丁"),
            ("CVE-2021-42287","Windows AD","str",@"noPac|CVE-2021-42287","","",8.8,"高",@"AD 权限提升（noPac）利用特征","安装 2021 年 11 月补丁并启用 SID 过滤"),
            ("CVE-2020-1350","Windows DNS Server","str",@"SIGRed|CVE-2020-1350","","",10.0,"严重",@"DNS 服务 SIG 记录堆溢出（SIGRed）利用特征","安装 KB4569509 并限制 DNS 服务暴露"),
            ("CVE-2023-21716","Microsoft Office","str",@"rtf|CVE-2023-21716","","",9.8,"严重",@"RTF 解析堆溢出可远程执行代码（Preview 触发）","安装 2023 年 2 月 Office 补丁"),
            ("CVE-2023-36025","Windows SmartScreen","str",@"CVE-2023-36025|SmartScreen","","",8.8,"高",@"SmartScreen 绕过导致安全警告失效","安装 2023 年 11 月 Windows 补丁"),
            ("CVE-2024-21412","Windows SmartScreen","str",@"CVE-2024-21412","","",8.1,"高",@"Internet 快捷方式绕过 SmartScreen 提示","安装 2024 年 2 月 Windows 补丁"),
            ("CVE-2024-2887","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"WebAssembly 类型混淆（在野利用）","升级 Chrome 至 123.0.6312.86 及以上"),
            ("CVE-2024-4947","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"V8 类型混淆（在野利用）","升级 Chrome 至 125.0.6422.60 及以上"),
            ("CVE-2023-2033","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"V8 类型混淆（在野利用）","升级 Chrome 至 112.0.5615.121 及以上"),
            ("CVE-2022-4262","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"V8 类型混淆（在野利用）","升级 Chrome 至 108.0.5359.94 及以上"),
            ("CVE-2023-5217","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"libvpx VP8 编码堆溢出（在野利用）","升级 Chrome 至 117.0.5938.132 及以上"),
            ("CVE-2019-5786","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"FileReader 释放后重用（在野利用）","升级 Chrome 至 72.0.3626.121 及以上"),
            ("CVE-2020-6418","Google Chrome","str",@"Chrome/\d|Chromium/\d","","",8.8,"高",@"V8 类型混淆（在野利用）","升级 Chrome 至 80.0.3987.122 及以上"),
            ("CVE-2022-0185","Linux Kernel","ver","","5.1.0","5.16.2",7.8,"高",@"fs_context 堆溢出（容器逃逸/提权）","升级内核至 5.16.2 / 5.15.16 / 5.10.93 及以上"),
            ("CVE-2023-0386","Linux Kernel","ver","","5.11.0","6.2.0",7.8,"高",@"overlayfs 权限复制缺陷导致本地提权","升级内核至 6.2.1 及以上"),
            ("CVE-2024-1086","Linux Kernel","ver","","5.14.0","6.7.2",7.8,"高",@"nf_tables 释放后重用可本地提权","升级内核至 6.7.3 / 6.6.15 / 6.1.76 及以上"),
            ("CVE-2023-4911","glibc","ver","","2.34","2.38",7.8,"高",@"ld.so GLIBC_TUNABLES 缓冲区溢出（Looney Tunables）","升级发行版 glibc 补丁版本"),
            ("CVE-2021-3493","Ubuntu OverlayFS","str",@"ubuntu.*overlay|CVE-2021-3493","","",7.8,"高",@"overlayfs 未正确校验用户命名空间导致提权","升级 Ubuntu 内核至修复版本"),
            ("CVE-2022-0492","Linux cgroups","str",@"cgroup|CVE-2022-0492","","",7.8,"高",@"cgroups v1 release_agent 可用于容器逃逸","升级内核并限制 CAP_SYS_ADMIN"),
            ("CVE-2024-21626","runc","str",@"runc|libcontainer","","",8.6,"高",@"文件描述符泄露导致容器逃逸","升级 runc 至 1.1.12 及以上"),
            ("CVE-2021-25741","Kubernetes","str",@"kubelet|kubernetes","","",8.1,"高",@"subPath 挂载绕过导致越权访问宿主文件","升级 kubelet 至 1.22.2 / 1.21.5 及以上"),
            ("CVE-2023-7028","GitLab","str",@"GitLab","","",10.0,"严重",@"密码重置邮件可发送至任意邮箱导致账号接管","升级至 16.7.2 / 16.6.4 / 16.5.6 及以上"),
            ("CVE-2021-22205","GitLab","str",@"GitLab","","",10.0,"严重",@"ExifTool 图片解析可远程执行代码","升级至 13.10.3 / 13.9.6 / 13.8.8 及以上"),
            ("CVE-2021-22204","ExifTool","str",@"ExifTool|Image::ExifTool","","",7.8,"高",@"DjVu 解析可执行任意代码","升级 Image::ExifTool 至 12.24 及以上"),
            ("CVE-2022-31197","PostgreSQL","str",@"PostgreSQL|psql","","",8.8,"高",@"ResultSet.refreshRow 导致 SQL 注入","升级 PG JDBC 至 42.4.2 / 42.3.7 及以上"),
            ("CVE-2022-0543","Redis","str",@"Redis|redis-server","","",10.0,"严重",@"Debian 打包 Lua 沙箱逃逸可远程代码执行","升级 Redis 补丁版本并限制访问"),
            ("CVE-2022-24736","Redis","str",@"Redis|redis-server","","",5.5,"中",@"Lua 脚本加载空指针导致拒绝服务","升级 Redis 至 6.2.7 / 7.0.0 及以上"),
            ("CVE-2021-3449","OpenSSL","ver","","1.1.1","1.1.1j",5.9,"中",@"重协商过程中空指针解引用导致拒绝服务","升级至 OpenSSL 1.1.1k 及以上"),
            ("CVE-2021-3712","OpenSSL","ver","","1.1.1","1.1.1l",7.4,"高",@"ASN1_STRING 越界读取可能泄露内存","升级至 OpenSSL 1.1.1l / 3.0.0 及以上"),
            ("CVE-2021-23840","OpenSSL","ver","","1.0.2","1.1.1j",7.5,"高",@"BIO 整数溢出导致越界写","升级至 OpenSSL 1.1.1k 及以上"),
            ("CVE-2022-2068","OpenSSL","ver","","3.0.0","3.0.3",9.8,"严重",@"c_rehash 脚本命令注入","升级至 OpenSSL 3.0.4 及以上"),
            ("CVE-2021-22986","F5 BIG-IP","str",@"BIG-IP|BIGIP","","",9.8,"严重",@"iControl REST 未授权远程命令执行","升级至 16.0.1.1 / 15.1.2.1 / 14.1.3.1 及以上"),
        };

        private static readonly List<VulnRule> Builtins = BuildBuiltins();

        private static List<VulnRule> BuildBuiltins()
        {
            var list = new List<VulnRule>(Defs.Length);
            foreach (var d in Defs)
            {
                list.Add(new VulnRule
                {
                    CveId = d.Id,
                    Component = d.Comp,
                    Kind = d.Kind,
                    Pattern = d.Pat,
                    MinVer = d.Min,
                    MaxVer = d.Max,
                    Cvss = d.Cvss,
                    Severity = d.Sev,
                    Desc = d.Desc,
                    Fix = d.Fix,
                    Refs = "https://nvd.nist.gov/vuln/detail/" + d.Id,
                    Source = "内置库",
                    Builtin = true
                });
            }
            return list;
        }

        // ————————————————————— 组件指纹规则 —————————————————————
        private static readonly (string Name, string Pattern)[] Fingerprints = new[]
        {
            ("OpenSSL", @"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"),
            ("zlib", @"zlib\s*(?:version\s*)?(\d+\.\d+\.\d+)"),
            ("libpng", @"libpng\s+version\s*(\d+\.\d+\.\d+)"),
            ("libtiff", @"LIBTIFF,\s*Version\s*(\d+\.\d+\.\d+)"),
            ("libxml2", @"libxml2?[/ ]\s*(\d+\.\d+\.\d+)"),
            ("curl", @"libcurl/(\d+\.\d+\.\d+)|curl\s+(\d+\.\d+\.\d+)"),
            ("SQLite", @"SQLite\s+version\s+(\d+\.\d+\.\d+)|sqlite_version\s*[:=]?\s*(\d+\.\d+\.\d+)"),
            ("OpenSSH", @"OpenSSH[_ ](\d+\.\d+p\d+)"),
            ("GNU Bash", @"bash,\s*version\s+(\d+\.\d+(?:\.\d+)?)"),
            ("sudo", @"Sudo\s+version\s+(\d+\.\d+\.\d+p?\d*)"),
            ("xz-utils", @"XZ\s+(\d+\.\d+\.\d+)|liblzma[/ ]\s*(\d+\.\d+\.\d+)"),
            ("7-Zip", @"7-Zip\s+(\d+\.\d+)"),
            ("WinRAR", @"WinRAR\s+(\d+\.\d+)"),
            ("Apache Log4j", @"log4j[- ]?(?:core[- ]?)?(\d+\.\d+(?:\.\d+)?)"),
            ("Apache Struts", @"struts2?[^\d]{0,8}(\d+\.\d+\.\d+(?:\.\d+)?)"),
            ("Spring Framework", @"spring[- ]?core[- ](\d+\.\d+\.\d+)"),
            ("Apache Tomcat", @"Apache Tomcat/(\d+\.\d+\.\d+)"),
            ("Oracle WebLogic", @"WebLogic Server\s+(\d+\.\d+(?:\.\d+)?)"),
            ("Atlassian Confluence", @"Confluence\s+(\d+\.\d+\.\d+)"),
            ("Jenkins", @"Jenkins[^\d]{0,12}(\d+\.\d+\.\d+)"),
            ("Webmin", @"Webmin\s+version\s*(\d+\.\d+\.\d+)"),
            ("fastjson", @"fastjson[- ](\d+\.\d+\.\d+)"),
            ("Apache Shiro", @"shiro-(?:core|all)[- ](\d+\.\d+\.\d+)"),
            ("jQuery", @"jQuery\s*v?(\d+\.\d+\.\d+)|jquery[-.](\d+\.\d+\.\d+)"),
            ("Bootstrap", @"Bootstrap\s*v?(\d+\.\d+\.\d+)"),
            ("Linux Kernel", @"Linux version (\d+\.\d+\.\d+)"),
            ("glibc", @"GNU C Library[^\d]{0,40}(\d+\.\d+)"),
            ("PHP", @"PHP/(\d+\.\d+\.\d+)"),
            ("Java", @"Java version .?(\d+\.\d+\.\d+)"),
            ("Redis", @"Redis server v=(\d+\.\d+\.\d+)|redis_version[:=](\d+\.\d+\.\d+)"),
            ("PostgreSQL", @"PostgreSQL (\d+\.\d+)"),
            ("nginx", @"nginx/(\d+\.\d+\.\d+)"),
            ("Apache httpd", @"Apache/(\d+\.\d+\.\d+)"),
            ("Node.js", @"Node\.js v(\d+\.\d+\.\d+)"),
            ("Docker", @"Docker version (\d+\.\d+\.\d+)"),
        };

        private static readonly (string Alias, string Comp)[] Aliases = new[]
        {
            ("openssl", "OpenSSL"), ("libssl", "OpenSSL"), ("libcrypto", "OpenSSL"),
            ("zlib", "zlib"), ("libpng", "libpng"), ("libtiff", "libtiff"),
            ("libxml2", "libxml2"), ("curl", "curl"), ("sqlite", "SQLite"),
            ("openssh", "OpenSSH"), ("bash", "GNU Bash"), ("sudo", "sudo"),
            ("liblzma", "xz-utils"), ("7-zip", "7-Zip"), ("winrar", "WinRAR"),
            ("log4j", "Apache Log4j"), ("struts", "Apache Struts"), ("spring-core", "Spring Framework"),
            ("tomcat", "Apache Tomcat"), ("weblogic", "Oracle WebLogic"), ("confluence", "Atlassian Confluence"),
            ("jenkins", "Jenkins"), ("webmin", "Webmin"), ("fastjson", "fastjson"), ("shiro", "Apache Shiro"),
            ("jquery", "jQuery"), ("bootstrap", "Bootstrap"),
        };

        // ————————————————————— 库管理 —————————————————————
        private static void Ensure()
        {
            if (_imported != null) return;
            lock (_lock)
            {
                if (_imported != null) return;
                try
                {
                    if (File.Exists(RuleFile))
                    {
                        var loaded = JsonSerializer.Deserialize<List<VulnRule>>(File.ReadAllText(RuleFile, Encoding.UTF8), JsonOpt) ?? new();
                        // 兼容旧格式（仅存 Key、字段为空）：空 CveId 的条目丢弃，避免脏规则
                        _imported = loaded.Where(r => !string.IsNullOrWhiteSpace(r.CveId) && !string.IsNullOrWhiteSpace(r.Component)).ToList();
                        if (_imported.Count != loaded.Count)
                            Log.Write("cvedb load: 丢弃旧格式无效条目 " + (loaded.Count - _imported.Count) + " 条");
                    }
                    else _imported = new();
                }
                catch (Exception ex) { Log.Write("cvedb load: " + ex.Message); _imported = new(); }
                try
                {
                    if (File.Exists(MetaFile))
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(MetaFile, Encoding.UTF8));
                        if (doc.RootElement.TryGetProperty("lastUpdate", out var a)) _lastUpdate = a.GetString() ?? "";
                        if (doc.RootElement.TryGetProperty("lastSource", out var b)) _lastSource = b.GetString() ?? "";
                    }
                }
                catch { }
            }
        }

        private static void Save()
        {
            try { File.WriteAllText(RuleFile, JsonSerializer.Serialize(_imported ?? new List<VulnRule>(), JsonOpt), Encoding.UTF8); } catch (Exception ex) { Log.Write("cvedb save: " + ex.Message); }
            try { File.WriteAllText(MetaFile, JsonSerializer.Serialize(new { lastUpdate = _lastUpdate, lastSource = _lastSource }), Encoding.UTF8); } catch { }
        }

        public static List<VulnRule> AllRules()
        {
            Ensure();
            var list = new List<VulnRule>(Builtins.Count + 8);
            list.AddRange(Builtins);
            list.AddRange(_imported ?? new List<VulnRule>());
            return list;
        }

        public static object Status()
        {
            Ensure();
            int imp = (_imported ?? new List<VulnRule>()).Count;
            return new
            {
                cveCount = Builtins.Count + imp,
                builtinCveCount = Builtins.Count,
                importedCveCount = imp,
                lastUpdate = _lastUpdate,
                lastSource = _lastSource,
                dir = Dir,
                version = Version,
                summary = "内置 CVE " + Builtins.Count + " 条 / 导入 CVE " + imp + " 条"
            };
        }

        public static string Version => "CVE 库 v2026.11（内置 " + Builtins.Count + " 条）" + (string.IsNullOrEmpty(_lastUpdate) ? "" : " · 最近同步 " + _lastUpdate);

        public static List<object> TopRules(int take)
        {
            if (take <= 0) take = 60;
            return AllRules().OrderByDescending(r => r.Cvss).ThenBy(r => r.CveId).Take(take)
                .Select(r => (object)new { cveId = r.CveId, component = r.Component, kind = r.Kind, affected = AffectedText(r), cvss = r.Cvss, severity = r.Severity, desc = r.Desc, fix = r.Fix, source = r.Source })
                .ToList();
        }

        public static int ClearImported()
        {
            Ensure();
            int n = (_imported ?? new List<VulnRule>()).Count;
            _imported = new List<VulnRule>();
            _lastUpdate = "";
            _lastSource = "";
            Save();
            return n;
        }

        public static (int added, int total, string error) ImportFiles(IEnumerable<string> paths)
        {
            Ensure();
            int added = 0; string err = "";
            var exist = new HashSet<string>((_imported ?? new List<VulnRule>()).Select(r => r.Key));
            foreach (var p in paths ?? Enumerable.Empty<string>())
            {
                try
                {
                    if (!File.Exists(p)) { err = "文件不存在：" + p; continue; }
                    var text = File.ReadAllText(p, Encoding.UTF8);
                    var list = ParseAny(text);
                    if (list.Count == 0) { err = "未解析到 CVE 记录：" + Path.GetFileName(p); continue; }
                    foreach (var r in list)
                    {
                        if (string.IsNullOrWhiteSpace(r.CveId)) continue;
                        if (!exist.Add(r.Key)) continue;
                        r.Builtin = false;
                        if (string.IsNullOrEmpty(r.Source)) r.Source = "导入";
                        (_imported!).Add(r);
                        added++;
                    }
                    _lastSource = Path.GetFileName(p);
                    _lastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                }
                catch (Exception ex) { err = ex.Message; }
            }
            Save();
            return (added, (_imported ?? new List<VulnRule>()).Count, err);
        }

        // ————————————————————— CNNVD（国家信息安全漏洞库）在线同步 —————————————————————
        private const string CnnvdBase = "https://www.cnnvd.org.cn/cnnvdweb";
        private const string CnnvdAppId = "6i8417579268034679HXvp0Kb6r1C2A9";
        private const string CnnvdReferer = "https://www.cnnvd.org.cn/frontend/loopholeList";
        private static readonly HttpClient CnnvdHttp = CreateCnnvdClient();
        private static readonly Random CnnvdRnd = new Random();

        private static HttpClient CreateCnnvdClient()
        {
            var c = new HttpClient { Timeout = TimeSpan.FromSeconds(45) };
            c.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/157.0.0.0");
            c.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json, text/plain, */*");
            c.DefaultRequestHeaders.TryAddWithoutValidation("Referer", CnnvdReferer);
            return c;
        }

        private static string CnnvdNonce()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var sb = new StringBuilder(32);
            lock (CnnvdRnd)
            {
                for (int i = 0; i < 32; i++) sb.Append(chars[CnnvdRnd.Next(chars.Length)]);
            }
            return sb.ToString();
        }

        /// <summary>统一在线同步入口：source = nvd（默认）/ cnnvd（国家信息安全漏洞库）。</summary>
        public static async Task<(int added, int total, string error)> UpdateFromSourceAsync(string source, string keyword, string apiKey, int maxRecords, Action<string>? log = null)
        {
            var src = (source ?? "").Trim().ToLowerInvariant();
            if (src == "cnnvd") return await UpdateFromCnnvdAsync(keyword, maxRecords, log).ConfigureAwait(false);
            return await UpdateFromUrlAsync(keyword, apiKey, log).ConfigureAwait(false);
        }

        /// <summary>生成关键词的大小写变体（CNNVD 字典大小写敏感，同一名称可能仅某一种写法可命中）。</summary>
        private static IEnumerable<string> CaseVariants(string w)
        {
            var set = new List<string>();
            void Add(string v) { if (!string.IsNullOrWhiteSpace(v) && !set.Contains(v, StringComparer.Ordinal)) set.Add(v); }
            Add(w);
            var lo = w.ToLowerInvariant();
            Add(lo);
            Add(lo.Length > 1 ? char.ToUpperInvariant(lo[0]) + lo.Substring(1) : lo.ToUpperInvariant());
            return set;
        }

        /// <summary>在线同步：从国家信息安全漏洞库（CNNVD）拉取漏洞，仅作组件名匹配，版本需人工核对。</summary>
        public static async Task<(int added, int total, string error)> UpdateFromCnnvdAsync(string keyword, int maxRecords, Action<string>? log = null)
        {
            Ensure();
            if (maxRecords <= 0) maxRecords = 200;
            if (maxRecords > 500) maxRecords = 500;
            var words = (keyword ?? "")
                .Split(new[] { ',', '，', ';', '；', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(w => w.Trim()).Where(w => w.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            int added = 0, fetched = 0;
            try
            {
                var raw = new List<VulnRule>();
                if (words.Count == 0)
                {
                    log?.Invoke("CNNVD：未指定关键词，拉取最新漏洞（上限 " + maxRecords + " 条）");
                    raw.AddRange(await FetchCnnvdAsync("", "", maxRecords, log).ConfigureAwait(false));
                }
                else
                {
                    foreach (var w in words)
                    {
                        var list = new List<VulnRule>();
                        // 站点厂商/产品字典大小写敏感（如 openssl 为小写、Google 为首字母大写），逐个变体试探
                        foreach (var v in CaseVariants(w))
                        {
                            log?.Invoke("CNNVD：按厂商检索「" + v + "」");
                            list = await FetchCnnvdAsync(v, "", maxRecords, log).ConfigureAwait(false);
                            if (list.Count > 0) break;
                        }
                        if (list.Count == 0)
                        {
                            foreach (var v in CaseVariants(w))
                            {
                                log?.Invoke("CNNVD：按产品检索「" + v + "」");
                                list = await FetchCnnvdAsync("", v, maxRecords, log).ConfigureAwait(false);
                                if (list.Count > 0) break;
                            }
                        }
                        if (list.Count == 0)
                        {
                            log?.Invoke("CNNVD：厂商/产品字典未收录「" + w + "」，改为拉取最新漏洞并按关键词本地筛选");
                            var latest = await FetchCnnvdAsync("", "", Math.Min(150, Math.Max(maxRecords, 100)), log).ConfigureAwait(false);
                            list = latest.Where(r => ContainsText(r.Component, w) || ContainsText(r.Desc, w)).ToList();
                        }
                        raw.AddRange(list);
                    }
                }
                fetched = raw.Count;
                if (fetched == 0) return (0, (_imported ?? new List<VulnRule>()).Count, "CNNVD 返回 0 条：建议填写厂商英文名（如 Microsoft、Google、Cisco、Adobe），或稍后重试（接口可能限流）");
                var exist = new HashSet<string>((_imported ?? new List<VulnRule>()).Select(r => r.Key));
                foreach (var r in raw)
                {
                    r.Builtin = false;
                    r.Source = "CNNVD在线";
                    if (!exist.Add(r.Key)) continue;
                    (_imported!).Add(r);
                    added++;
                }
                _lastSource = "CNNVD 国家信息安全漏洞库" + (words.Count > 0 ? " · " + string.Join(",", words) : " · 最新漏洞");
                _lastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                Save();
                log?.Invoke("CNNVD：召回 " + fetched + " 条，新增 " + added + " 条");
            }
            catch (Exception ex) { return (added, (_imported ?? new List<VulnRule>()).Count, "CNNVD 同步失败：" + ex.Message); }
            return (added, (_imported ?? new List<VulnRule>()).Count, "");
        }

        private static bool ContainsText(string? text, string kw)
        {
            return !string.IsNullOrEmpty(text) && !string.IsNullOrEmpty(kw) && text!.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static async Task<List<VulnRule>> FetchCnnvdAsync(string vendor, string product, int maxRecords, Action<string>? log)
        {
            var all = new List<VulnRule>();
            int page = 1;
            const int pageSize = 50;
            while (all.Count < maxRecords && page <= 10)
            {
                var body = "{\"page\":" + page + ",\"pageSize\":" + pageSize + ",\"vendorName\":\"" + EscapeJson(vendor) + "\",\"productName\":\"" + EscapeJson(product) + "\",\"version\":\"\"}";
                int total;
                List<VulnRule> recs;
                try
                {
                    var json = await CnnvdPostAsync("/homePage/filterVul", body).ConfigureAwait(false);
                    (total, recs) = ParseCnnvd(json);
                }
                catch (Exception ex)
                {
                    log?.Invoke("CNNVD：第 " + page + " 页请求失败（" + ex.Message + "），保留已取回 " + all.Count + " 条");
                    break;
                }
                if (recs.Count == 0) break;
                all.AddRange(recs);
                log?.Invoke("CNNVD：第 " + page + " 页取回 " + recs.Count + " 条（匹配总数 " + total + "）");
                if (total > 0 && page * pageSize >= total) break;
                page++;
            }
            return all.Take(maxRecords).ToList();
        }

        private static string EscapeJson(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s!.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
        }

        /// <summary>CNNVD 游客态接口调用：先取签名（signStr = POST + 路径 + 时间戳 + 随机数），再携带 X-Sign 请求。</summary>
        private static async Task<string> CnnvdPostAsync(string path, string bodyJson)
        {
            var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
            var nonce = CnnvdNonce();
            var signStr = "POST/cnnvdweb" + path + ts + nonce;
            string token;
            using (var req = new HttpRequestMessage(HttpMethod.Post, CnnvdBase + "/tourist/sign"))
            {
                req.Headers.TryAddWithoutValidation("X-Appid", CnnvdAppId);
                req.Headers.TryAddWithoutValidation("X-Timestamp", ts);
                req.Headers.TryAddWithoutValidation("X-Nonce", nonce);
                req.Content = new StringContent("{\"signStr\":\"" + EscapeJson(signStr) + "\"}", Encoding.UTF8, "application/json");
                using var res = await CnnvdHttp.SendAsync(req).ConfigureAwait(false);
                var txt = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!res.IsSuccessStatusCode) throw new Exception("CNNVD 签名接口 HTTP " + (int)res.StatusCode);
                using var doc = JsonDocument.Parse(txt);
                if (!doc.RootElement.TryGetProperty("data", out var dEl) || dEl.ValueKind != JsonValueKind.String)
                    throw new Exception("CNNVD 签名获取失败：" + (txt.Length > 120 ? txt.Substring(0, 120) : txt));
                token = dEl.GetString() ?? "";
            }
            using (var req2 = new HttpRequestMessage(HttpMethod.Post, CnnvdBase + path))
            {
                req2.Headers.TryAddWithoutValidation("X-Appid", CnnvdAppId);
                req2.Headers.TryAddWithoutValidation("X-Timestamp", ts);
                req2.Headers.TryAddWithoutValidation("X-Nonce", nonce);
                req2.Headers.TryAddWithoutValidation("X-Sign", token);
                req2.Content = new StringContent(bodyJson ?? "{}", Encoding.UTF8, "application/json");
                using var res2 = await CnnvdHttp.SendAsync(req2).ConfigureAwait(false);
                var txt2 = await res2.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!res2.IsSuccessStatusCode) throw new Exception("CNNVD 接口 HTTP " + (int)res2.StatusCode);
                return txt2;
            }
        }

        private static (int total, List<VulnRule> rules) ParseCnnvd(string json)
        {
            var list = new List<VulnRule>();
            int total = 0;
            if (string.IsNullOrWhiteSpace(json)) return (0, list);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object) return (0, list);
            if (data.TryGetProperty("total", out var tEl) && tEl.ValueKind == JsonValueKind.Number) total = tEl.GetInt32();
            if (!data.TryGetProperty("records", out var recs) || recs.ValueKind != JsonValueKind.Array) return (total, list);
            foreach (var e in recs.EnumerateArray())
            {
                var id = JStr(e, "id");
                var cve = JStr(e, "cveId");
                var cnnvd = JStr(e, "cnnvdId");
                var vulId = cve.Length > 0 ? cve : cnnvd;
                if (vulId.Length == 0) continue;
                var name = JStr(e, "vulName");
                var prod = JStr(e, "productName");
                if (prod.Length == 0) prod = JStr(e, "vendorName");
                var desc = JStr(e, "vulDesc");
                var link = JStr(e, "officialPatchLink");
                var lv = CnnvdLevel(JStr(e, "vulLevel"));
                var full = (name.Length > 0 ? name + "：" : "") + desc;
                list.Add(new VulnRule
                {
                    CveId = vulId,
                    Component = prod,
                    Kind = "name",
                    Pattern = "",
                    Cvss = lv.cvss,
                    Severity = lv.sev,
                    Desc = full.Length > 400 ? full.Substring(0, 400) + "…" : full,
                    Fix = link.Length > 0 ? "官方补丁：" + link : "按 CNNVD 公告升级到修复版本",
                    Refs = "https://www.cnnvd.org.cn/frontend/detail?vulId=" + id,
                    Source = "CNNVD在线",
                    Builtin = false
                });
            }
            return (total, list);
        }

        private static string JStr(JsonElement e, string key)
        {
            if (e.ValueKind != JsonValueKind.Object) return "";
            if (!e.TryGetProperty(key, out var v) || v.ValueKind != JsonValueKind.String) return "";
            return v.GetString() ?? "";
        }

        private static (double cvss, string sev) CnnvdLevel(string? level)
        {
            var l = (level ?? "").Trim().ToLowerInvariant();
            if (l.Length == 0) return (5.0, "中");
            if (l.Contains("超危") || l.Contains("严重") || l.Contains("critical")) return (9.5, "严重");
            if (l.Contains("高危") || l.Contains("high")) return (8.0, "高");
            if (l.Contains("中危") || l.Contains("medium") || l.Contains("moderate")) return (5.5, "中");
            if (l.Contains("低危") || l.Contains("low")) return (2.5, "低");
            return (5.0, "中");
        }

        /// <summary>在线同步：按关键词从 NVD API 2.0 拉取 CVE（需联网，可带 apiKey）。</summary>
        public static async Task<(int added, int total, string error)> UpdateFromUrlAsync(string keyword, string apiKey, Action<string>? log = null)
        {
            Ensure();
            keyword = (keyword ?? "").Trim();
            if (keyword.Length == 0) return (0, (_imported ?? new List<VulnRule>()).Count, "请填写要同步的组件关键词，如 openssl / log4j / apache_struts");
            int added = 0;
            try
            {
                var url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200&keywordSearch=" + Uri.EscapeDataString(keyword);
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
                http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "REAStudio-CVE/1.0");
                if (!string.IsNullOrWhiteSpace(apiKey)) http.DefaultRequestHeaders.TryAddWithoutValidation("apiKey", apiKey.Trim());
                log?.Invoke("正在从 NVD 拉取：" + keyword);
                var json = await http.GetStringAsync(url).ConfigureAwait(false);
                var list = ParseNvd(json);
                if (list.Count == 0) return (0, (_imported ?? new List<VulnRule>()).Count, "NVD 返回 0 条（关键词无匹配或已达速率限制）");
                var exist = new HashSet<string>((_imported ?? new List<VulnRule>()).Select(r => r.Key));
                foreach (var r in list)
                {
                    if (!exist.Add(r.Key)) continue;
                    r.Builtin = false;
                    r.Source = "NVD在线";
                    (_imported!).Add(r);
                    added++;
                }
                _lastSource = "NVD API · " + keyword;
                _lastUpdate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                Save();
                log?.Invoke("已并入 " + added + " 条 CVE");
            }
            catch (Exception ex) { return (added, (_imported ?? new List<VulnRule>()).Count, "同步失败：" + ex.Message); }
            return (added, (_imported ?? new List<VulnRule>()).Count, "");
        }

        private static List<VulnRule> ParseAny(string text)
        {
            var list = new List<VulnRule>();
            var t = (text ?? "").Trim();
            if (t.Length == 0) return list;
            if (t.StartsWith("{") || t.StartsWith("["))
            {
                try
                {
                    if (t.Contains("\"vulnerabilities\"")) return ParseNvd(t);
                    using var doc = JsonDocument.Parse(t);
                    var arr = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement : default;
                    if (arr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var e in arr.EnumerateArray())
                        {
                            var r = FromJson(e);
                            if (r != null) list.Add(r);
                        }
                    }
                    else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        var r = FromJson(doc.RootElement);
                        if (r != null) list.Add(r);
                    }
                    return list;
                }
                catch (Exception ex) { Log.Write("cvedb json: " + ex.Message); }
            }
            // CSV：cveId,component,kind,pattern,minVer,maxVer,cvss,severity,desc,fix
            var lines = t.Split('\n');
            bool first = true;
            foreach (var raw in lines)
            {
                var line = (raw ?? "").Trim().TrimEnd('\r');
                if (line.Length == 0) continue;
                if (first)
                {
                    first = false;
                    if (line.IndexOf("cve", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                }
                var c = SplitCsv(line);
                if (c.Count < 2) continue;
                var r = new VulnRule
                {
                    CveId = c[0].Trim(),
                    Component = c[1].Trim(),
                    Kind = c.Count > 2 && c[2].Trim().Length > 0 ? c[2].Trim().ToLowerInvariant() : "ver",
                    Pattern = c.Count > 3 ? c[3].Trim() : "",
                    MinVer = c.Count > 4 ? c[4].Trim() : "",
                    MaxVer = c.Count > 5 ? c[5].Trim() : "",
                    Cvss = c.Count > 6 ? ToDouble(c[6]) : 5.0,
                    Severity = c.Count > 7 && c[7].Trim().Length > 0 ? c[7].Trim() : "中",
                    Desc = c.Count > 8 ? c[8].Trim() : "",
                    Fix = c.Count > 9 ? c[9].Trim() : "",
                    Source = "导入",
                    Builtin = false
                };
                if (!r.CveId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) continue;
                r.Refs = "https://nvd.nist.gov/vuln/detail/" + r.CveId;
                if (r.Kind == "str" || r.Kind == "file")
                {
                    if (r.Pattern.Length == 0) r.Pattern = r.Component;
                }
                if (r.Kind == "ver" && r.Pattern.Length == 0) r.Pattern = r.Component;
                list.Add(r);
            }
            return list;
        }

        private static VulnRule? FromJson(JsonElement e)
        {
            if (e.ValueKind != JsonValueKind.Object) return null;
            string S(string name)
            {
                foreach (var p in e.EnumerateObject())
                    if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
                        return p.Value.GetString() ?? "";
                return "";
            }
            var id = S("cveId"); if (id.Length == 0) id = S("cve"); if (id.Length == 0) id = S("id");
            if (id.Length == 0) return null;
            if (!id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) id = id.ToUpperInvariant().StartsWith("CVE") ? id.ToUpperInvariant() : "CVE-" + id;
            var r = new VulnRule
            {
                CveId = id,
                Component = S("component"),
                Kind = (S("kind").Length > 0 ? S("kind") : "ver").ToLowerInvariant(),
                Pattern = S("pattern"),
                MinVer = S("minVer"),
                MaxVer = S("maxVer"),
                Cvss = ToDouble(S("cvss")),
                Severity = S("severity").Length > 0 ? S("severity") : "中",
                Desc = S("desc").Length > 0 ? S("desc") : S("description"),
                Fix = S("fix"),
                Source = "导入",
                Builtin = false
            };
            if (r.Component.Length == 0) r.Component = r.Pattern;
            if (r.Kind != "str" && r.Kind != "file" && r.Pattern.Length == 0) r.Pattern = r.Component;
            r.Refs = "https://nvd.nist.gov/vuln/detail/" + r.CveId;
            return r;
        }

        private static List<VulnRule> ParseNvd(string json)
        {
            var list = new List<VulnRule>();
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vs) || vs.ValueKind != JsonValueKind.Array) return list;
            foreach (var item in vs.EnumerateArray())
            {
                if (!item.TryGetProperty("cve", out var cve)) continue;
                var id = cve.TryGetProperty("id", out var idEl) ? (idEl.GetString() ?? "") : "";
                if (id.Length == 0) continue;
                string desc = "";
                if (cve.TryGetProperty("descriptions", out var ds) && ds.ValueKind == JsonValueKind.Array)
                {
                    foreach (var d in ds.EnumerateArray())
                    {
                        var lang = d.TryGetProperty("lang", out var l) ? (l.GetString() ?? "") : "";
                        if (lang == "en") { desc = d.TryGetProperty("value", out var v) ? (v.GetString() ?? "") : ""; break; }
                    }
                }
                double score = 0;
                string sev = "";
                if (cve.TryGetProperty("metrics", out var mx) && mx.ValueKind == JsonValueKind.Object)
                {
                    foreach (var name in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
                    {
                        if (!mx.TryGetProperty(name, out var arr) || arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() == 0) continue;
                        var first = arr[0];
                        if (first.TryGetProperty("cvssData", out var cd))
                        {
                            if (cd.TryGetProperty("baseScore", out var bs) && bs.ValueKind == JsonValueKind.Number) score = bs.GetDouble();
                            if (cd.TryGetProperty("baseSeverity", out var bs2)) sev = bs2.GetString() ?? "";
                        }
                        if (score > 0) break;
                    }
                }
                if (string.IsNullOrEmpty(sev)) sev = score >= 9.0 ? "严重" : score >= 7.0 ? "高" : score >= 4.0 ? "中" : "低";
                else sev = sev.Replace("CRITICAL", "严重").Replace("HIGH", "高").Replace("MEDIUM", "中").Replace("LOW", "低");
                list.Add(new VulnRule
                {
                    CveId = id,
                    Component = "",
                    Kind = "name",
                    Pattern = "",
                    Cvss = score,
                    Severity = sev,
                    Desc = desc.Length > 400 ? desc.Substring(0, 400) + "…" : desc,
                    Fix = "参考 NVD 页面核对受影响版本并升级",
                    Refs = "https://nvd.nist.gov/vuln/detail/" + id,
                    Source = "NVD在线",
                    Builtin = false
                });
            }
            return list;
        }

        private static List<string> SplitCsv(string line)
        {
            var list = new List<string>();
            var sb = new StringBuilder();
            bool q = false;
            foreach (var ch in line)
            {
                if (ch == '"') { q = !q; continue; }
                if (ch == ',' && !q) { list.Add(sb.ToString()); sb.Clear(); continue; }
                sb.Append(ch);
            }
            list.Add(sb.ToString());
            return list;
        }

        private static double ToDouble(string s)
        {
            if (double.TryParse(s, out var d)) return d;
            return 5.0;
        }

        // ————————————————————— 版本比较 —————————————————————
        private static (List<int> nums, string tag) ParseVer(string v)
        {
            var nums = new List<int>();
            var tag = "";
            if (string.IsNullOrWhiteSpace(v)) return (nums, tag);
            v = v.Trim().TrimStart('v', 'V');
            var m = Regex.Match(v, @"(\d+(?:\.\d+)*)([A-Za-z]+)?(\d+)?");
            if (!m.Success) return (nums, tag);
            foreach (var s in m.Groups[1].Value.Split('.'))
                if (int.TryParse(s, out var x)) nums.Add(x);
            tag = (m.Groups[2].Value + m.Groups[3].Value).ToLowerInvariant();
            return (nums, tag);
        }

        public static int CompareVer(string a, string b)
        {
            var pa = ParseVer(a);
            var pb = ParseVer(b);
            int n = Math.Max(pa.nums.Count, pb.nums.Count);
            for (int i = 0; i < n; i++)
            {
                int x = i < pa.nums.Count ? pa.nums[i] : 0;
                int y = i < pb.nums.Count ? pb.nums[i] : 0;
                if (x != y) return x < y ? -1 : 1;
            }
            if (string.Equals(pa.tag, pb.tag, StringComparison.OrdinalIgnoreCase)) return 0;
            return string.CompareOrdinal(pa.tag, pb.tag) < 0 ? -1 : 1;
        }

        /// <summary>版本是否落在 [min,max] 区间；版本为空返回 null（无法判断）。</summary>
        private static bool? InRange(string ver, string min, string max)
        {
            if (string.IsNullOrWhiteSpace(ver)) return null;
            if (!string.IsNullOrWhiteSpace(min) && CompareVer(ver, min) < 0) return false;
            if (!string.IsNullOrWhiteSpace(max) && CompareVer(ver, max) > 0) return false;
            return true;
        }

        private static string AffectedText(VulnRule r)
        {
            if (r.Kind != "ver") return r.Component;
            var a = string.IsNullOrWhiteSpace(r.MinVer) ? "早期版本" : r.MinVer;
            var b = string.IsNullOrWhiteSpace(r.MaxVer) ? "最新版本" : r.MaxVer;
            return a + " ~ " + b;
        }

        // ————————————————————— 扫描 —————————————————————
        public static async Task<VulnScanResult> ScanAsync(string path, Action<string>? log = null)
        {
            return await Task.Run(() => ScanCore(path, log)).ConfigureAwait(false);
        }

        private static VulnScanResult ScanCore(string path, Action<string>? log)
        {
            var sw = Stopwatch.StartNew();
            var res = new VulnScanResult { Path = path, DbVersion = Version, CveCount = AllRules().Count };
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { res.Error = "文件不存在"; return res; }

                // 沙箱内只读副本
                var scanPath = path;
                if (Sandbox.Enabled)
                {
                    try
                    {
                        if (Sandbox.Current == null) Sandbox.Ensure("vuln");
                        var staged = Sandbox.StageFile(path);
                        if (!string.IsNullOrEmpty(staged) && File.Exists(staged)) { scanPath = staged; res.InSandbox = true; }
                    }
                    catch (Exception ex) { res.Notes.Add("沙箱副本创建失败，改在本机只读检测：" + ex.Message); }
                }
                res.ScanPath = scanPath;
                var fi = new FileInfo(scanPath);
                res.Size = fi.Length;
                res.Sha256 = Sha256(scanPath);
                log?.Invoke("正在识别组件指纹：" + Path.GetFileName(scanPath));

                // 读取用于字符串匹配的窗口
                byte[] buf;
                using (var fs = File.OpenRead(scanPath))
                {
                    int want = (int)Math.Min(fi.Length, MaxStringBytes);
                    buf = new byte[want];
                    int read = 0;
                    while (read < want)
                    {
                        int n = fs.Read(buf, read, want - read);
                        if (n <= 0) break;
                        read += n;
                    }
                    if (read < want) Array.Resize(ref buf, read);
                }
                var latin = Encoding.GetEncoding("ISO-8859-1").GetString(buf);
                var uni = Encoding.Unicode.GetString(buf);

                var comps = new List<ComponentInfo>();
                DetectComponents(scanPath, latin, uni, comps);
                res.Components = comps;
                if (comps.Count > 0)
                    log?.Invoke("识别到组件 " + comps.Count + " 个：" + string.Join("、", comps.Take(6).Select(c => c.Name + (c.Version.Length > 0 ? " " + c.Version : ""))));

                var rules = AllRules();
                var hits = new List<VulnHit>();
                var seen = new HashSet<string>();
                string baseName = Path.GetFileName(scanPath);
                int pending = 0;

                foreach (var r in rules)
                {
                    if (r.Kind == "ver")
                    {
                        var cands = comps.Where(c => SameComp(c.Name, r.Component)).ToList();
                        if (cands.Count == 0 && !string.IsNullOrWhiteSpace(r.Pattern))
                            cands = comps.Where(c => SameComp(c.Name, r.Pattern)).ToList();
                        foreach (var c in cands)
                        {
                            var inRange = InRange(c.Version, r.MinVer, r.MaxVer);
                            if (inRange == false) continue;
                            if (inRange == null)
                            {
                                // 版本未知：不下结论，仅提示人工确认
                                pending++;
                                var kh = r.CveId + "|pending|" + c.Name;
                                if (seen.Add(kh))
                                    hits.Add(new VulnHit
                                    {
                                        CveId = r.CveId, Cvss = r.Cvss, Severity = "待确认", Kind = "版本未知",
                                        Component = c.Name, Affected = AffectedText(r),
                                        Evidence = c.Evidence + "（版本无法确定）",
                                        Desc = r.Desc, Fix = r.Fix, Refs = r.Refs, Source = r.Source
                                    });
                                continue;
                            }
                            var key = r.CveId + "|" + c.Name;
                            if (!seen.Add(key)) continue;
                            hits.Add(new VulnHit
                            {
                                CveId = r.CveId, Cvss = r.Cvss, Severity = r.Severity, Kind = "组件版本",
                                Component = c.Name + " " + c.Version, Affected = AffectedText(r),
                                Evidence = c.Evidence, Desc = r.Desc, Fix = r.Fix, Refs = r.Refs, Source = r.Source
                            });
                        }
                    }
                    else if (r.Kind == "file")
                    {
                        try
                        {
                            if (!Regex.IsMatch(baseName, string.IsNullOrWhiteSpace(r.Pattern) ? r.Component : r.Pattern, RegexOptions.IgnoreCase)) continue;
                        }
                        catch { continue; }
                        if (!seen.Add(r.CveId + "|file")) continue;
                        hits.Add(new VulnHit
                        {
                            CveId = r.CveId, Cvss = r.Cvss, Severity = r.Severity, Kind = "文件指纹",
                            Component = r.Component, Affected = AffectedText(r), Evidence = "文件名：" + baseName,
                            Desc = r.Desc, Fix = r.Fix, Refs = r.Refs, Source = r.Source
                        });
                    }
                    else if (r.Kind == "str")
                    {
                        var pat = string.IsNullOrWhiteSpace(r.Pattern) ? Regex.Escape(r.Component) : r.Pattern;
                        string snip = "";
                        try
                        {
                            var m = Regex.Match(latin, pat, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(400));
                            if (!m.Success) m = Regex.Match(uni, pat, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(400));
                            if (m.Success) snip = Snip(m.Value);
                        }
                        catch { }
                        if (snip.Length == 0) continue;
                        if (!seen.Add(r.CveId + "|str")) continue;
                        hits.Add(new VulnHit
                        {
                            CveId = r.CveId, Cvss = r.Cvss, Severity = r.Severity, Kind = "利用特征",
                            Component = r.Component, Affected = "", Evidence = snip,
                            Desc = r.Desc, Fix = r.Fix, Refs = r.Refs, Source = r.Source
                        });
                        log?.Invoke("命中利用特征 " + r.CveId + "（" + r.Component + "）");
                    }
                    else if (r.Kind == "name")
                    {
                        // 在线库条目：仅组件名匹配，版本需人工核对
                        var cands = comps.Where(c => SameComp(c.Name, r.Component)).ToList();
                        if (cands.Count == 0 || string.IsNullOrWhiteSpace(r.Component)) continue;
                        if (!seen.Add(r.CveId + "|name")) continue;
                        pending++;
                        hits.Add(new VulnHit
                        {
                            CveId = r.CveId, Cvss = r.Cvss, Severity = "待确认", Kind = "在线参考",
                            Component = cands[0].Name + (cands[0].Version.Length > 0 ? " " + cands[0].Version : ""),
                            Affected = (r.Source ?? "").IndexOf("CNNVD", StringComparison.OrdinalIgnoreCase) >= 0 ? "见 CNNVD 条目" : "见 NVD 条目", Evidence = cands[0].Evidence,
                            Desc = r.Desc, Fix = r.Fix, Refs = r.Refs, Source = r.Source
                        });
                    }
                }

                // 评分（待确认条目不参与评分，避免虚报）
                int score = 0;
                var counted = new Dictionary<string, int>();
                foreach (var h in hits.Where(h => h.Kind != "版本未知" && h.Kind != "在线参考"))
                {
                    if (h.Severity == "严重") { res.Critical++; score += 40; }
                    else if (h.Severity == "高") { res.High++; score += 26; }
                    else if (h.Severity == "中") { res.Medium++; score += 14; }
                    else { res.Low++; score += 6; }
                }
                res.Pending = hits.Count(h => h.Kind == "版本未知" || h.Kind == "在线参考");
                res.Score = Math.Min(score, 100);
                res.Matches = hits.OrderByDescending(h => SevWeight(h.Severity)).ThenByDescending(h => h.Cvss).Take(80).ToList();
                res.Verdict = res.Critical > 0 || res.High > 0 ? "存在高危漏洞"
                    : res.Medium > 0 ? "存在中危漏洞"
                    : res.Low > 0 ? "存在低危问题"
                    : res.Pending > 0 ? "存在待确认 CVE 关联" : "未发现已知漏洞";

                if (comps.Count > 0)
                    res.Notes.Add("识别组件：" + string.Join("；", comps.Take(12).Select(c => c.Name + (c.Version.Length > 0 ? " " + c.Version : "（版本未知）"))));
                if (res.Pending > 0) res.Notes.Add("另有 " + res.Pending + " 条 CVE 因版本无法精确判定，标记为待人工确认，未计入评分");
                if (comps.Count == 0)
                    res.Notes.Add("未从版本信息/导入表/字符串中识别到受 CVE 覆盖的第三方组件；建议结合 REA 导入表与 PE 结构分析进一步核对");

                var top = res.Matches.Where(m => m.Kind == "组件版本" || m.Kind == "文件指纹").Take(3).Select(m => m.CveId + "（" + m.Component + "）").ToList();
                res.Summary = res.Matches.Count == 0
                    ? "与当前 CVE 库（" + res.CveCount + " 条）比对未发现匹配项。"
                    : res.Verdict + "：共命中 " + res.Matches.Count + " 条，" +
                      (top.Count > 0 ? "主要包括 " + string.Join("、", top) + "。" : "") +
                      " 建议按修复建议升级对应组件后复测。";

                res.Ok = true;
            }
            catch (Exception ex)
            {
                res.Error = ex.Message;
                Log.Write("vuln scan: " + ex);
            }
            finally
            {
                res.ElapsedMs = sw.ElapsedMilliseconds;
            }
            return res;
        }

        private static int SevWeight(string sev)
        {
            switch (sev)
            {
                case "严重": return 4;
                case "高": return 3;
                case "中": return 2;
                case "低": return 1;
                default: return 0;
            }
        }

        private static bool SameComp(string a, string b)
        {
            if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
            a = a.Trim(); b = b.Trim();
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
            if (a.IndexOf(b, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (b.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        // ————————————————————— 组件指纹识别 —————————————————————
        private static void DetectComponents(string path, string latin, string uni, List<ComponentInfo> comps)
        {
            void Add(string name, string ver, string ev, string src)
            {
                if (string.IsNullOrWhiteSpace(name)) return;
                foreach (var c in comps)
                {
                    if (!string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
                    if (c.Version.Length == 0 && !string.IsNullOrWhiteSpace(ver)) { c.Version = CleanVer(ver); c.Evidence = ev; c.Source = src; }
                    return;
                }
                comps.Add(new ComponentInfo { Name = name, Version = CleanVer(ver), Evidence = ev, Source = src });
            }

            // ① 版本资源
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(path);
                var hay = string.Join(" ", new[] { vi.ProductName, vi.FileDescription, vi.CompanyName, vi.InternalName, vi.OriginalFilename, vi.LegalCopyright }.Where(s => !string.IsNullOrWhiteSpace(s)));
                foreach (var al in Aliases)
                {
                    if (hay.IndexOf(al.Alias, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    var ver = !string.IsNullOrWhiteSpace(vi.FileVersion) ? vi.FileVersion : vi.ProductVersion;
                    var ev = "版本资源：" + (string.IsNullOrWhiteSpace(vi.ProductName) ? vi.FileDescription : vi.ProductName) + (string.IsNullOrWhiteSpace(ver) ? "" : " " + ver);
                    Add(al.Comp, ver ?? "", ev.Trim(), "版本信息");
                }
            }
            catch { }

            // ② 字符串 banner
            foreach (var fp in Fingerprints)
            {
                try
                {
                    var m = Regex.Match(latin, fp.Pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(300));
                    if (!m.Success) m = Regex.Match(uni, fp.Pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(300));
                    if (!m.Success) continue;
                    var ver = FirstGroup(m);
                    Add(fp.Name, ver, "字符串特征：" + Snip(m.Value), "字符串");
                }
                catch { }
            }

            // ③ 导入表 DLL
            foreach (var dll in ImportedDlls(path))
            {
                var lower = dll.ToLowerInvariant();
                foreach (var al in Aliases)
                {
                    if (lower.IndexOf(al.Alias, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    Add(al.Comp, "", "导入表：" + dll, "导入表");
                }
            }
        }

        private static string FirstGroup(Match m)
        {
            for (int i = 1; i < m.Groups.Count; i++)
                if (m.Groups[i].Success && m.Groups[i].Value.Length > 0) return m.Groups[i].Value;
            return "";
        }

        private static string CleanVer(string v)
        {
            if (string.IsNullOrWhiteSpace(v)) return "";
            v = v.Trim();
            var m = Regex.Match(v, @"\d+(?:\.\d+){0,3}[a-z]?");
            return m.Success ? m.Value : "";
        }

        private static string Snip(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            s = s.Replace("\r", " ").Replace("\n", " ").Replace("\0", "");
            return s.Length > 80 ? s.Substring(0, 80) + "…" : s;
        }

        private static string Sha256(string path)
        {
            try
            {
                using var sha = System.Security.Cryptography.SHA256.Create();
                using var fs = File.OpenRead(path);
                var hash = sha.ComputeHash(fs);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (var b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
            catch { return ""; }
        }

        // ————————————————————— 轻量 PE 导入表解析 —————————————————————
        private static List<string> ImportedDlls(string path)
        {
            var list = new List<string>();
            try
            {
                byte[] b;
                using (var fs = File.OpenRead(path))
                {
                    int want = (int)Math.Min(fs.Length, 6 * 1024 * 1024);
                    b = new byte[want];
                    int read = 0;
                    while (read < want)
                    {
                        int n = fs.Read(b, read, want - read);
                        if (n <= 0) break;
                        read += n;
                    }
                }
                if (b.Length < 0x40 || b[0] != 0x4D || b[1] != 0x5A) return list; // MZ
                int pe = BitConverter.ToInt32(b, 0x3C);
                if (pe <= 0 || pe + 0x18 > b.Length) return list;
                if (b[pe] != 0x50 || b[pe + 1] != 0x45) return list; // PE
                int numSec = BitConverter.ToInt16(b, pe + 6);
                int optSize = BitConverter.ToInt16(b, pe + 20);
                int opt = pe + 24;
                if (opt + 2 > b.Length) return list;
                ushort magic = BitConverter.ToUInt16(b, opt);
                int ddOff = magic == 0x20B ? opt + 112 : opt + 96;
                if (ddOff + 16 > b.Length) return list;
                int impRva = BitConverter.ToInt32(b, ddOff + 8);
                if (impRva <= 0) return list;

                int secOff = opt + optSize;
                int Rva2Off(int rva)
                {
                    for (int i = 0; i < numSec; i++)
                    {
                        int s = secOff + i * 40;
                        if (s + 40 > b.Length) break;
                        int vsz = BitConverter.ToInt32(b, s + 8);
                        int va = BitConverter.ToInt32(b, s + 12);
                        int rawSize = BitConverter.ToInt32(b, s + 16);
                        int rawPtr = BitConverter.ToInt32(b, s + 20);
                        if (rva >= va && rva < va + Math.Max(vsz, rawSize)) return rawPtr + (rva - va);
                    }
                    return -1;
                }

                int p = Rva2Off(impRva);
                if (p < 0) return list;
                for (int i = 0; i < 256; i++)
                {
                    int d = p + i * 20;
                    if (d + 20 > b.Length) break;
                    int nameRva = BitConverter.ToInt32(b, d + 12);
                    if (nameRva == 0) break;
                    int no = Rva2Off(nameRva);
                    if (no < 0 || no >= b.Length) continue;
                    var sb = new StringBuilder();
                    for (int k = no; k < b.Length && k < no + 256; k++)
                    {
                        if (b[k] == 0) break;
                        sb.Append((char)b[k]);
                    }
                    var name = sb.ToString();
                    if (name.Length > 0 && name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) list.Add(name);
                }
            }
            catch { }
            return list;
        }
    }
}
