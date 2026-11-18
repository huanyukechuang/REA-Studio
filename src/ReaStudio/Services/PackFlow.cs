using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ReaStudio.Services
{
    /// <summary>
    /// 加壳/混淆识别与内层载荷抽取。
    /// 目的：加壳、混淆样本的明文特征被压缩或加密后，静态规则与指纹往往落空；
    /// 这里先判定封装类型，再把可还原的内层载荷（嵌入 PE、压缩流、ZIP 条目）抽到沙箱，
    /// 交由上层扫描器复扫，从而恢复命中率。所有抽取只在沙箱副本上进行，样本不执行。
    /// </summary>
    internal static class PackFlow
    {
        public class PackInfo
        {
            public bool Packed;
            public string Packer = "";
            public string Confidence = "";
            public bool Obfuscated;
            public string ObfuscationKind = "";
            public List<string> Evidence = new List<string>();
            public List<string> Sections = new List<string>();
            public double MaxEntropy;
            public long Overlay;
            public string WeakSign = "";
            public string Installer = "";
            public int InnerCount;
            public string Summary = "";
        }

        public class Payload
        {
            public string Name = "";
            public string Path = "";
            public long Size;
            public string Kind = "";
            public string Source = "";
            public int Depth;
        }

        const long MaxReadBytes = 128L * 1024 * 1024;
        static readonly object _lock = new object();
        static readonly Dictionary<string, Tuple<DateTime, long, PackInfo, List<Payload>>> _cache =
            new Dictionary<string, Tuple<DateTime, long, PackInfo, List<Payload>>>(StringComparer.OrdinalIgnoreCase);

        // ———————————————— 加壳器节名/标记特征 ————————————————
        static readonly (string[] Marks, string Name, string Confidence)[] PackerMarks = new (string[], string, string)[]
        {
            (new[] { "UPX0", "UPX1", "UPX2", "UPX!" }, "UPX", "high"),
            (new[] { ".themida", ".winlice", ".vlizer", "Themida" }, "Themida/WinLicense", "high"),
            (new[] { ".vmp0", ".vmp1", ".vmp2", "VMProtect" }, "VMProtect", "high"),
            (new[] { ".enigma1", ".enigma2", "Enigma" }, "Enigma Protector", "high"),
            (new[] { ".MPRESS1", ".MPRESS2" }, "MPRESS", "high"),
            (new[] { ".aspack", ".adata", "ASPack" }, "ASPack", "high"),
            (new[] { "pec1", "pec2", ".pec", "PECompact" }, "PECompact", "high"),
            (new[] { ".obsidium" }, "Obsidium", "high"),
            (new[] { "_Reactored", ".reactor" }, ".NET Reactor", "high"),
            (new[] { ".petite" }, "Petite", "medium"),
            (new[] { ".mew" }, "MEW", "medium"),
            (new[] { ".fsg" }, "FSG", "medium"),
            (new[] { ".pelock" }, "PELock", "medium"),
            (new[] { ".nsp0", ".nsp1", "NsPack" }, "NsPack", "medium"),
            (new[] { "PELOCKnt" }, "PELock NT", "medium"),
            (new[] { ".y0da" }, "Yoda Cryptor", "medium"),
            (new[] { ".netz", "AgileDotNet" }, "Agile.NET 保护", "high"),
            (new[] { ".maxtocode", "MaxtoCode" }, "MaxtoCode 保护", "high"),
            (new[] { "DNGuard", "HVMProtect" }, "DNGuard HVM", "medium"),
            (new[] { "ILProtector", ".ilp" }, "ILProtector", "medium"),
            (new[] { ".perplex", "Perplex" }, "Perplex 保护", "medium"),
            (new[] { ".spack", "SPack" }, "SPack", "medium"),
            (new[] { "PESpin", ".taz" }, "PESpin", "medium"),
            (new[] { ".ccg", "CCG" }, "CCG 保护", "medium"),
            (new[] { ".boom", "The Boomerang" }, "The Boomerang", "medium"),
            (new[] { "StarForce", ".sforce" }, "StarForce 保护", "medium"),
        };

        // ———————————————— 移动端加固（APK 内 native 库/壳特征） ————————————————
        static readonly (string Mark, string Name, string Tip)[] ApkGuardMarks = new (string, string, string)[]
        {
            ("libjiagu", "360 加固", "需用 frida-dexdump 等动态方式抽取真实 dex"),
            ("libmobisec", "阿里聚安全加固", "dex 已被抽取，需从内存或 so 中还原"),
            ("libshella", "梆梆加固", "壳 so 启动时解密 dex，需内存抽取"),
            ("libDexHelper", "梆梆企业加固", "壳 so 启动时解密 dex，需内存抽取"),
            ("libsecexe", "梆梆安全加固", "壳 so 启动时解密 dex，需内存抽取"),
            ("libexec.so", "爱加密加固", "壳 so 启动时解密 dex，需内存抽取"),
            ("libexecmain", "爱加密加固", "壳 so 启动时解密 dex，需内存抽取"),
            ("libnesec", "网易易盾加固", "dex 保护，需动态抽取"),
            ("libnagain", "娜迦加固", "dex 加密，需动态抽取"),
            ("libkwscmm", "腾讯乐固", "dex 加密，需动态抽取"),
            ("libshell", "通用加固壳", "存在第三方加固壳，dex 可能被加密"),
            ("libapp.so", "Flutter/Dart AOT 或加固", "可能为 Flutter 引擎或加固壳"),
            ("assets/dexopt", "腾讯乐固（dexopt）", "dex 加密，需动态抽取"),
        };

        // ———————————————— 安装器/封装器标识（内层通常可抽） ————————————————
        static readonly (string Mark, string Name)[] InstallerMarks = new (string, string)[]
        {
            ("Inno Setup", "Inno Setup 安装器"),
            ("Nullsoft Install System", "NSIS 安装器"),
            ("InstallShield", "InstallShield 安装器"),
            ("7-Zip SFX", "7-Zip 自解压封装"),
            ("WinRAR SFX", "WinRAR 自解压封装"),
            ("PyInstaller", "PyInstaller 打包"),
            ("AutoIt", "AutoIt 编译脚本"),
            ("AutoHotkey", "AutoHotkey 编译脚本"),
        };

        // ———————————————— 混淆器字符串特征 ————————————————
        static readonly (string Mark, string Name)[] ObfusMarks = new (string, string)[]
        {
            ("ConfusedByAttribute", "ConfuserEx"),
            ("ObfuscatedByGoliath", "Goliath 混淆"),
            ("SmartAssembly", "SmartAssembly"),
            ("DotfuscatorAttribute", "Dotfuscator"),
            ("Eazfuscator", "Eazfuscator"),
            ("BabelAttribute", "Babel 混淆"),
            ("eval(function(p,a,c,k,e,d)", "JS packer（Dean Edwards）"),
            ("_0x", "JS 十六进制混淆"),
        };

        public static PackInfo Detect(string path)
        {
            var info = new PackInfo();
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { info.Summary = "样本不存在"; return info; }
                var data = ReadHead(path, MaxReadBytes);
                if (data.Length == 0) { info.Summary = "空文件"; return info; }

                var latin = Encoding.Latin1.GetString(data);
                bool isPe = data.Length > 0x40 && data[0] == 'M' && data[1] == 'Z';
                bool isDotNet = latin.Contains("BSJB") || latin.Contains("mscoree.dll");
                bool isScript = LooksLikeScript(latin, path);

                foreach (var (marks, name, conf) in PackerMarks)
                {
                    var hit = marks.FirstOrDefault(m => latin.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (hit == null) continue;
                    info.Packed = true;
                    info.Packer = name;
                    info.Confidence = conf;
                    info.Evidence.Add("命中 " + name + " 特征标记 " + hit);
                    break;
                }

                foreach (var (mark, name) in InstallerMarks)
                {
                    if (latin.IndexOf(mark, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    info.Installer = name;
                    info.Evidence.Add("识别为 " + name + "，内层载荷通常可抽取");
                    break;
                }

                if (isPe) AnalyzePe(data, info, isDotNet);
                if (isScript || isDotNet) AnalyzeObfuscation(latin, info);

                // 移动端加固：加固壳的 so 名称通常以 zip 条目形式出现（classes.dex / AndroidManifest.xml 同现）
                bool apkLike = latin.Contains("AndroidManifest.xml") || latin.Contains("classes.dex")
                    || path.EndsWith(".apk", StringComparison.OrdinalIgnoreCase);
                if (apkLike)
                {
                    foreach (var (mark, name, tip) in ApkGuardMarks)
                    {
                        if (latin.IndexOf(mark, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        if (string.Equals(mark, "libapp.so", StringComparison.OrdinalIgnoreCase))
                        {
                            info.Evidence.Add("存在 libapp.so：可能为 Flutter AOT 引擎，需确认是否为加固壳");
                            continue;
                        }
                        info.Packed = true;
                        if (string.IsNullOrEmpty(info.Packer)) info.Packer = name;
                        if (string.IsNullOrEmpty(info.Confidence) || info.Confidence == "medium") info.Confidence = "high";
                        info.Obfuscated = true;
                        if (string.IsNullOrEmpty(info.ObfuscationKind)) info.ObfuscationKind = "移动端加固";
                        info.Evidence.Add("命中移动加固特征 " + mark + "：" + name + "，" + tip);
                        break;
                    }
                }

                // 通用加壳判定（未知壳/自定义壳）
                if (!info.Packed)
                {
                    int score = 0;
                    var reasons = new List<string>();
                    if (info.MaxEntropy >= 7.2) { score += 2; reasons.Add("存在熵 " + info.MaxEntropy.ToString("F2") + " 的区段"); }
                    if (info.Sections.Any(s => s.Contains("WX"))) { score += 2; reasons.Add("存在可写且可执行区段"); }
                    if (info.Evidence.Any(e => e.Contains("入口点"))) { score += 2; reasons.Add("入口点异常"); }
                    if (info.Evidence.Any(e => e.Contains("导入表极简"))) { score += 2; reasons.Add("导入表极简"); }
                    if (info.Evidence.Any(e => e.Contains("原始数据远小于虚拟大小"))) { score += 2; reasons.Add("原始数据远小于虚拟大小"); }
                    if (data.Length > 0 && info.Overlay > data.Length / 4) { score += 1; reasons.Add("尾部附加数据 " + info.Overlay + " 字节"); }
                    if (score >= 6)
                    {
                        info.Packed = true;
                        info.Packer = "未知壳/自定义封装";
                        info.Confidence = score >= 9 ? "high" : "medium";
                        info.Evidence.Add("通用加壳判定（评分 " + score + "）：" + string.Join("、", reasons));
                    }
                }

                if (info.Overlay > 0 && !string.IsNullOrEmpty(info.Installer))
                    info.Evidence.Add("尾部附加数据 " + info.Overlay + " 字节，已纳入内层抽取范围");

                if (isPe) info.WeakSign = WeakSign(info);
                info.Summary = BuildSummary(info);
                return info;
            }
            catch (Exception ex)
            {
                info.Summary = "加壳识别失败：" + ex.Message;
                return info;
            }
        }

        static void AnalyzePe(byte[] data, PackInfo info, bool isDotNet)
        {
            try
            {
                int lfanew = BitConverter.ToInt32(data, 0x3C);
                if (lfanew <= 0 || lfanew + 24 > data.Length) return;
                if (data[lfanew] != 'P' || data[lfanew + 1] != 'E') return;
                int coff = lfanew + 4;
                int numSec = BitConverter.ToUInt16(data, coff + 2);
                int optSize = BitConverter.ToUInt16(data, coff + 16);
                int opt = coff + 20;
                if (opt + optSize > data.Length || numSec <= 0 || numSec > 96) return;

                ushort magic = BitConverter.ToUInt16(data, opt);
                bool pe32Plus = magic == 0x20b;
                uint epRva = BitConverter.ToUInt32(data, opt + 16);
                int ddOff = opt + (pe32Plus ? 112 : 96);
                uint importRva = 0;
                if (ddOff + 8 <= opt + optSize) importRva = BitConverter.ToUInt32(data, ddOff + 8);

                int secOff = opt + optSize;
                long rawEnd = 0;
                var secs = new List<(string Name, uint VSize, uint RawSize, uint RawPtr, uint Chars)>();
                for (int i = 0; i < numSec; i++)
                {
                    int o = secOff + i * 40;
                    if (o + 40 > data.Length) break;
                    var name = Encoding.ASCII.GetString(data, o, 8).TrimEnd('\0');
                    uint vsize = BitConverter.ToUInt32(data, o + 8);
                    uint rawSize = BitConverter.ToUInt32(data, o + 16);
                    uint rawPtr = BitConverter.ToUInt32(data, o + 20);
                    uint chars = BitConverter.ToUInt32(data, o + 36);
                    double ent = 0;
                    if (rawPtr < data.Length && rawSize > 0)
                    {
                        int len = (int)Math.Min(rawSize, Math.Min(4 * 1024 * 1024, (uint)(data.Length - rawPtr)));
                        ent = Entropy(data, (int)rawPtr, len);
                    }
                    if ((long)rawPtr + rawSize > rawEnd) rawEnd = (long)rawPtr + rawSize;
                    secs.Add((string.IsNullOrEmpty(name) ? "(无名)" : name, vsize, rawSize, rawPtr, chars));
                    bool wx = (chars & 0x20000000) != 0 && (chars & 0x80000000) != 0;
                    bool exec = (chars & 0x20000000) != 0;
                    info.Sections.Add(name + " · 熵 " + ent.ToString("F2") + " · " + rawSize + "/" + vsize + (exec ? " · 可执行" : "") + (wx ? " · WX(可写可执行)" : ""));
                    if (ent > info.MaxEntropy) info.MaxEntropy = ent;
                }

                info.Overlay = Math.Max(0, data.LongLength - rawEnd);

                // 入口点归属
                string epSec = "";
                foreach (var s in secs)
                {
                    if (epRva >= s.RawPtr && epRva < (long)s.RawPtr + Math.Max(s.RawSize, s.VSize)) { epSec = s.Name; break; }
                }
                if (!string.IsNullOrEmpty(epSec) && !isDotNet)
                {
                    var lower = epSec.ToLowerInvariant();
                    bool normal = lower.Contains("text") || lower.Contains("code");
                    if (!normal) info.Evidence.Add("入口点不在常规代码段（位于 " + epSec + "）");
                }

                int imports = CountImports(data, importRva, secs.Select(s => (s.Name, s.VSize, s.RawSize, s.RawPtr)).ToList());
                if (imports >= 0)
                {
                    info.Sections.Add("导入函数 " + imports + " 个");
                    if (imports <= 6) info.Evidence.Add("导入表极简（仅 " + imports + " 个导入函数），常见于加壳样本");
                }

                foreach (var s in secs)
                {
                    if (s.VSize > 0x20000 && (long)s.RawSize * 4 < s.VSize)
                    {
                        info.Evidence.Add("区段 " + s.Name + " 原始数据远小于虚拟大小（" + s.RawSize + " vs " + s.VSize + "）");
                        break;
                    }
                }
            }
            catch { }
        }

        static int CountImports(byte[] data, uint importRva, List<(string Name, uint VSize, uint RawSize, uint RawPtr)> secs)
        {
            try
            {
                if (importRva == 0) return 0;
                long off = RvaToOffset(importRva, secs);
                if (off < 0 || off >= data.Length) return -1;
                int count = 0;
                for (int d = 0; d < 64; d++)
                {
                    long p = off + d * 20;
                    if (p + 20 > data.Length) break;
                    uint nameRva = BitConverter.ToUInt32(data, (int)p + 12);
                    uint thunkRva = BitConverter.ToUInt32(data, (int)p + 16);
                    if (nameRva == 0 && thunkRva == 0) break;
                    long t = RvaToOffset(thunkRva, secs);
                    if (t < 0) continue;
                    for (int k = 0; k < 512; k++)
                    {
                        long q = t + k * 4;
                        if (q + 4 > data.Length) break;
                        uint v = BitConverter.ToUInt32(data, (int)q);
                        if (v == 0) break;
                        count++;
                    }
                }
                return count;
            }
            catch { return -1; }
        }

        static long RvaToOffset(uint rva, List<(string Name, uint VSize, uint RawSize, uint RawPtr)> secs)
        {
            foreach (var s in secs)
            {
                if (rva >= s.RawPtr && (long)rva < (long)s.RawPtr + Math.Max(s.RawSize, s.VSize))
                    return (long)s.RawPtr + (rva - s.RawPtr);
            }
            return -1;
        }

        static void AnalyzeObfuscation(string latin, PackInfo info)
        {
            foreach (var (mark, name) in ObfusMarks)
            {
                if (latin.IndexOf(mark, StringComparison.OrdinalIgnoreCase) < 0) continue;
                info.Obfuscated = true;
                info.ObfuscationKind = name;
                info.Evidence.Add("命中混淆特征 " + mark + "（" + name + "）");
                return;
            }

            // 无明确标记时按标识符随机度判定（大量 9 位以上随机字母数字串）
            int rand = 0, run = 0;
            bool hasDigit = false, hasAlpha = false;
            int limit = Math.Min(latin.Length, 4 * 1024 * 1024);
            for (int i = 0; i < limit; i++)
            {
                char c = latin[i];
                bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                if (alnum)
                {
                    run++;
                    if (c >= '0' && c <= '9') hasDigit = true;
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) hasAlpha = true;
                }
                else
                {
                    if (run >= 9 && hasDigit && hasAlpha) rand++;
                    run = 0; hasDigit = false; hasAlpha = false;
                }
            }
            if (rand >= 60)
            {
                info.Obfuscated = true;
                if (info.ObfuscationKind.Length == 0) info.ObfuscationKind = "标识符随机化（疑似自动混淆）";
                info.Evidence.Add("检测到 " + rand + " 个随机化标识符，疑似混淆处理");
            }
            if (latin.IndexOf("FromBase64String", StringComparison.Ordinal) >= 0 && latin.IndexOf("Invoke", StringComparison.Ordinal) >= 0)
            {
                info.Obfuscated = true;
                if (info.ObfuscationKind.Length == 0) info.ObfuscationKind = "反射加载 + Base64 解码";
                info.Evidence.Add("存在 FromBase64String 与 Invoke 组合（反射加载特征）");
            }
        }

        static bool LooksLikeScript(string latin, string path)
        {
            var ext = (Path.GetExtension(path) ?? "").ToLowerInvariant();
            if (ext == ".js" || ext == ".vbs" || ext == ".ps1" || ext == ".hta" || ext == ".jse" || ext == ".vbe") return true;
            return latin.IndexOf("function ", StringComparison.Ordinal) >= 0 && latin.Count(c => c == '{') > 40;
        }

        /// <summary>弱指纹：区段名序列 + 尾部附加规模，用于加壳变体的家族聚类（不依赖字节哈希）。</summary>
        static string WeakSign(PackInfo info)
        {
            try
            {
                var sb = new StringBuilder();
                foreach (var s in info.Sections)
                {
                    var cut = s.IndexOf(' ');
                    sb.Append(cut > 0 ? s.Substring(0, cut) : s).Append('|');
                }
                using var sha = SHA1.Create();
                var h = sha.ComputeHash(Encoding.UTF8.GetBytes(sb + "#" + info.Overlay / 4096));
                return Convert.ToHexString(h).Substring(0, 16);
            }
            catch { return ""; }
        }

        static string BuildSummary(PackInfo i)
        {
            var parts = new List<string>();
            if (i.Packed) parts.Add("加壳：" + i.Packer + "（置信度 " + (i.Confidence == "high" ? "高" : "中") + "）");
            if (i.Obfuscated) parts.Add("混淆：" + i.ObfuscationKind);
            if (!string.IsNullOrEmpty(i.Installer)) parts.Add("封装：" + i.Installer);
            if (parts.Count == 0) parts.Add("未见加壳或混淆特征");
            if (i.MaxEntropy > 0) parts.Add("最高区段熵 " + i.MaxEntropy.ToString("F2"));
            if (i.Overlay > 0) parts.Add("尾部附加 " + i.Overlay + " 字节");
            return string.Join("　", parts);
        }

        // ———————————————— 内层载荷抽取 ————————————————
        /// <summary>
        /// 抽取可还原的内层载荷到沙箱 out\inner 目录（结果按 路径+修改时间+大小 缓存，避免同一次分析重复解包）。
        /// </summary>
        public static List<Payload> Unpack(string path, Action<string>? log, int maxPayloads = 8)
        {
            var list = new List<Payload>();
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return list;
                var fi = new FileInfo(path);
                lock (_lock)
                {
                    if (_cache.TryGetValue(path, out var c) && c.Item1 == fi.LastWriteTimeUtc && c.Item2 == fi.Length)
                    {
                        log?.Invoke("复用已抽取的内层载荷 " + c.Item4.Count + " 个");
                        return c.Item4;
                    }
                }

                var info = Detect(path);
                if (!info.Packed && !info.Obfuscated && string.IsNullOrEmpty(info.Installer)) return list;

                var data = ReadHead(path, MaxReadBytes);
                if (data.Length == 0) return list;

                var dir = InnerDir(path);
                Directory.CreateDirectory(dir);

                ExtractZip(data, dir, list, log, maxPayloads);
                ExtractEmbeddedPe(data, dir, list, log, maxPayloads);
                ExtractCompressed(data, dir, list, log, maxPayloads);

                info.InnerCount = list.Count;
                foreach (var p in list) log?.Invoke("抽取内层载荷：" + p.Kind + " · " + p.Name + "（" + p.Size + " 字节，来源 " + p.Source + "）");

                lock (_lock)
                {
                    if (_cache.Count > 64) _cache.Clear();
                    _cache[path] = Tuple.Create(fi.LastWriteTimeUtc, fi.Length, info, list);
                }
            }
            catch (Exception ex)
            {
                log?.Invoke("内层载荷抽取失败：" + ex.Message);
            }
            return list;
        }

        static string InnerDir(string path)
        {
            try
            {
                var sess = Sandbox.Current;
                if (sess != null) return Path.Combine(sess.Out, "inner");
            }
            catch { }
            try
            {
                var tag = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(path))).Substring(0, 8);
                return Path.Combine(Path.GetTempPath(), "rea_inner", tag);
            }
            catch { return Path.Combine(Path.GetTempPath(), "rea_inner"); }
        }

        static void ExtractZip(byte[] data, string dir, List<Payload> list, Action<string>? log, int max)
        {
            try
            {
                int sig = IndexOf(data, new byte[] { 0x50, 0x4B, 0x03, 0x04 }, 0);
                if (sig < 0) return;
                using var ms = new MemoryStream(data, sig, data.Length - sig, false);
                using var zip = new ZipArchive(ms, ZipArchiveMode.Read, false);
                int n = 0;
                int got = 0;
                foreach (var e in zip.Entries)
                {
                    if (list.Count >= max || n >= 160) break;
                    n++;
                    if (e.Length <= 0 || e.Length > 64L * 1024 * 1024) continue;
                    var name = Path.GetFileName(e.FullName);
                    if (string.IsNullOrEmpty(name)) continue;
                    var ext = Path.GetExtension(name).ToLowerInvariant();
                    bool interesting = ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".bat"
                        || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".jar" || ext == ".py" || ext == ".cpl";
                    if (!interesting) continue;
                    var dst = UniquePath(Path.Combine(dir, Sanitize(name)));
                    try
                    {
                        using var es = e.Open();
                        using var fs = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None);
                        es.CopyTo(fs);
                        list.Add(new Payload { Name = name, Path = dst, Size = e.Length, Kind = "ZIP 条目 " + ext, Source = "zip@0x" + sig.ToString("X") });
                        got++;
                    }
                    catch { }
                }
                if (got > 0) Sandbox.Note("内层抽取（ZIP）：" + got + " 个可执行条目");
            }
            catch (Exception ex) { log?.Invoke("ZIP 抽取跳过：" + ex.Message); }
        }

        static void ExtractEmbeddedPe(byte[] data, string dir, List<Payload> list, Action<string>? log, int max)
        {
            try
            {
                int from = 1;
                int found = 0;
                while (list.Count < max && found < 4)
                {
                    int mz = IndexOf(data, new byte[] { 0x4D, 0x5A }, from);
                    if (mz < 0 || mz + 0x40 >= data.Length) break;
                    from = mz + 2;
                    int lfanew = BitConverter.ToInt32(data, mz + 0x3C);
                    if (lfanew <= 0 || mz + 0x40 + lfanew + 4 >= data.Length) continue;
                    int peOff = mz + 0x40 + lfanew;
                    if (data[peOff] != 'P' || data[peOff + 1] != 'E' || data[peOff + 2] != 0 || data[peOff + 3] != 0) continue;

                    int numSec = BitConverter.ToUInt16(data, peOff + 4 + 2);
                    int optSize = BitConverter.ToUInt16(data, peOff + 4 + 16);
                    int opt = peOff + 24;
                    if (numSec <= 0 || numSec > 96 || opt + optSize > data.Length) continue;
                    int secOff = opt + optSize;
                    long end = opt;
                    for (int i = 0; i < numSec; i++)
                    {
                        int o2 = secOff + i * 40;
                        if (o2 + 40 > data.Length) break;
                        uint rawSize = BitConverter.ToUInt32(data, o2 + 16);
                        uint rawPtr = BitConverter.ToUInt32(data, o2 + 20);
                        long e2 = mz + (long)rawPtr + rawSize;
                        if (e2 > end) end = e2;
                    }
                    long len = Math.Min(end - mz, data.Length - (long)mz);
                    if (len <= 0x1000 || len > 64L * 1024 * 1024) continue;
                    if (mz == 0) continue; // 主样本自身

                    var bytes = new byte[len];
                    Array.Copy(data, mz, bytes, 0, (int)len);
                    found++;
                    var name = "embedded_pe_" + found + "_0x" + mz.ToString("X") + ".exe";
                    var dst = UniquePath(Path.Combine(dir, name));
                    File.WriteAllBytes(dst, bytes);
                    list.Add(new Payload { Name = name, Path = dst, Size = len, Kind = "嵌入 PE", Source = "offset 0x" + mz.ToString("X") });
                    log?.Invoke("解出嵌入 PE：偏移 0x" + mz.ToString("X") + "，长度 " + len);
                }
                if (found > 0) Sandbox.Note("内层抽取（嵌入 PE）：" + found + " 个");
            }
            catch (Exception ex) { log?.Invoke("嵌入 PE 抽取跳过：" + ex.Message); }
        }

        static void ExtractCompressed(byte[] data, string dir, List<Payload> list, Action<string>? log, int max)
        {
            try
            {
                var sigs = new (byte[] Sig, string Kind)[]
                {
                    (new byte[] { 0x1F, 0x8B }, "gzip"),
                    (new byte[] { 0x78, 0x9C }, "zlib"),
                    (new byte[] { 0x78, 0x01 }, "zlib"),
                    (new byte[] { 0x78, 0xDA }, "zlib")
                };
                int got = 0;
                foreach (var (sig, kind) in sigs)
                {
                    if (list.Count >= max) break;
                    int at = IndexOf(data, sig, 0);
                    int tries = 0;
                    while (at > 0 && list.Count < max && tries < 3)
                    {
                        tries++;
                        var outBuf = TryDecompress(data, at, kind, 64 * 1024 * 1024);
                        if (outBuf == null || outBuf.Length < 0x400)
                        {
                            at = IndexOf(data, sig, at + 2);
                            continue;
                        }
                        bool pe = outBuf.Length > 0x40 && outBuf[0] == 'M' && outBuf[1] == 'Z';
                        var name = "inflate_" + kind + "_0x" + at.ToString("X") + (pe ? ".exe" : ".bin");
                        var dst = UniquePath(Path.Combine(dir, name));
                        File.WriteAllBytes(dst, outBuf);
                        list.Add(new Payload
                        {
                            Name = name,
                            Path = dst,
                            Size = outBuf.Length,
                            Kind = kind + (pe ? " 解压得 PE" : " 解压数据"),
                            Source = "offset 0x" + at.ToString("X")
                        });
                        got++;
                        log?.Invoke("解压 " + kind + "（偏移 0x" + at.ToString("X") + "）得到 " + outBuf.Length + " 字节" + (pe ? "，含 PE 头" : ""));
                        at = IndexOf(data, sig, at + 2);
                    }
                }
                if (got > 0) Sandbox.Note("内层抽取（压缩流）：" + got + " 个");
            }
            catch (Exception ex) { log?.Invoke("压缩流抽取跳过：" + ex.Message); }
        }

        static byte[]? TryDecompress(byte[] data, int offset, string kind, int maxOut)
        {
            try
            {
                using var input = new MemoryStream(data, offset, Math.Min(data.Length - offset, 32 * 1024 * 1024), false);
                using Stream dec = kind == "gzip" ? new GZipStream(input, CompressionMode.Decompress) : new ZLibStream(input, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                var buf = new byte[81920];
                int total = 0;
                while (total < maxOut)
                {
                    int n = dec.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    outMs.Write(buf, 0, n);
                    total += n;
                }
                return outMs.Length > 0 ? outMs.ToArray() : null;
            }
            catch { return null; }
        }

        static byte[] ReadHead(string path, long max)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            long len = Math.Min(fs.Length, max);
            var buf = new byte[len];
            int read = 0;
            while (read < len)
            {
                int n = fs.Read(buf, read, (int)len - read);
                if (n <= 0) break;
                read += n;
            }
            if (read < len) Array.Resize(ref buf, read);
            return buf;
        }

        static int IndexOf(byte[] hay, byte[] needle, int start)
        {
            if (start < 0) start = 0;
            int limit = hay.Length - needle.Length;
            for (int i = start; i <= limit; i++)
            {
                if (hay[i] != needle[0]) continue;
                bool ok = true;
                for (int j = 1; j < needle.Length; j++)
                {
                    if (hay[i + j] != needle[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
            return -1;
        }

        static string Sanitize(string name)
        {
            foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
            return name.Length > 120 ? name.Substring(0, 120) : name;
        }

        static string UniquePath(string path)
        {
            if (!File.Exists(path)) return path;
            var dir = Path.GetDirectoryName(path) ?? "";
            var name = Path.GetFileNameWithoutExtension(path);
            var ext = Path.GetExtension(path);
            for (int i = 1; i < 1000; i++)
            {
                var p = Path.Combine(dir, name + "_" + i + ext);
                if (!File.Exists(p)) return p;
            }
            return path;
        }

        static double Entropy(byte[] data, int offset, int len)
        {
            if (len <= 0) return 0;
            var hist = new int[256];
            for (int i = 0; i < len; i++) hist[data[offset + i]]++;
            double e = 0;
            for (int i = 0; i < 256; i++)
            {
                if (hist[i] == 0) continue;
                double p = (double)hist[i] / len;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }
    }
}
