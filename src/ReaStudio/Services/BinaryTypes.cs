using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ReaStudio.Services
{
    /// <summary>九大逆向类型识别结果。</summary>
    internal sealed class SampleType
    {
        public string Id { get; init; } = "";
        public string Name { get; init; } = "";
        public string Confidence { get; init; } = "low";     // high / medium / low
        public string Evidence { get; init; } = "";
        public string Modules { get; init; } = "";           // 建议启用的分析模块 id，逗号分隔
    }

    /// <summary>基于文件头与结构特征做九大逆向类型识别，不执行样本。</summary>
    internal static class BinaryTypes
    {
        public static readonly (string Id, string Name, string Modules)[] Catalog =
        {
            ("windows-pe",  "Windows PE 可执行/驱动", "imports,exports,resources,hardening,loadcfg"),
            ("dotnet",      ".NET 托管程序集",        "managed-artifact,managed-members,managed-native"),
            ("elf",         "Linux ELF 可执行/共享库", "exports,hardening,layout"),
            ("macho",       "macOS Mach-O 可执行/动态库", "exports,layout"),
            ("android-apk", "Android APK/DEX 安装包",  "imports,il2cpp"),
            ("java",        "Java 字节码/JAR 包",      "managed-artifact"),
            ("script",      "脚本/解释型代码",         "entropy"),
            ("firmware",    "固件/裸二进制镜像",       "entropy,layout"),
            ("unity-il2cpp","Unity/IL2CPP 游戏包",     "il2cpp,managed-members"),
        };

        public static List<SampleType> Detect(string path)
        {
            var hits = new List<SampleType>();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return hits;
            byte[] head;
            long size;
            try
            {
                using var fs = File.OpenRead(path);
                size = fs.Length;
                head = new byte[(int)Math.Min(8192, fs.Length)];
                fs.Read(head, 0, head.Length);
            }
            catch { return hits; }

            var ext = (Path.GetExtension(path) ?? "").ToLowerInvariant();
            bool isMz = head.Length > 1 && head[0] == 0x4D && head[1] == 0x5A;                  // MZ
            bool isElf = head.Length > 4 && head[0] == 0x7F && head[1] == 0x45 && head[2] == 0x4C && head[3] == 0x46;
            uint magic = head.Length >= 4 ? BitConverter.ToUInt32(head, 0) : 0;
            bool isMach = magic == 0xFEEDFACF || magic == 0xFEEDFACE || magic == 0xCFFAEDFE || magic == 0xCEFAEDFE;
            bool isFat = magic == 0xCAFEBABE || magic == 0xBEBAFECA;
            bool isZip = head.Length > 3 && head[0] == 0x50 && head[1] == 0x4B && (head[2] == 3 || head[2] == 5 || head[2] == 7);
            bool isDex = head.Length > 7 && head[0] == 0x64 && head[1] == 0x65 && head[2] == 0x78 && head[3] == 0x0A;
            var headText = Encoding.ASCII.GetString(head, 0, Math.Min(head.Length, 512));

            // 1) PE
            bool isPe = false;
            uint clrRva = 0;
            int peOff = 0;
            if (isMz && head.Length > 0x40)
            {
                peOff = (int)BitConverter.ToInt32(head, 0x3C);
                if (peOff > 0 && peOff + 0x18 < head.Length &&
                    head[peOff] == 0x50 && head[peOff + 1] == 0x45 && head[peOff + 2] == 0 && head[peOff + 3] == 0)
                {
                    isPe = true;
                    int optOff = peOff + 24;
                    ushort magicOpt = BitConverter.ToUInt16(head, optOff);
                    int nrvaOff = optOff + (magicOpt == 0x20B ? 108 : 92);
                    int dirOff = nrvaOff + 4;
                    if (dirOff + 14 * 8 + 8 <= head.Length)
                        clrRva = BitConverter.ToUInt32(head, dirOff + 14 * 8);
                }
            }
            if (isPe)
            {
                hits.Add(new SampleType
                {
                    Id = "windows-pe", Name = "Windows PE 可执行/驱动", Confidence = "high",
                    Evidence = "MZ 头 + PE 签名（e_lfanew=0x" + peOff.ToString("X") + "，可选头 0x" + (head.Length > peOff + 24 ? BitConverter.ToUInt16(head, peOff + 24).ToString("X") : "?") + "）",
                    Modules = "imports,exports,resources,hardening,layout"
                });
                if (clrRva > 0)
                    hits.Add(new SampleType
                    {
                        Id = "dotnet", Name = ".NET 托管程序集", Confidence = "high",
                        Evidence = "数据目录[14] CLR Runtime Header RVA=0x" + clrRva.ToString("X"),
                        Modules = "managed-artifact,managed-members,managed-native"
                    });
            }

            // 2) ELF
            if (isElf)
            {
                bool pie = head.Length > 16 && head[16] == 3;
                bool bit64 = head.Length > 4 && head[4] == 2;
                hits.Add(new SampleType
                {
                    Id = "elf", Name = "Linux ELF 可执行/共享库", Confidence = "high",
                    Evidence = "ELF 魔数 7F 45 4C 46，" + (bit64 ? "64" : "32") + " 位，" + (pie ? "PIE/共享对象" : "可执行") + "，机器 0x" + (head.Length > 19 ? head[18].ToString("X2") : "?"),
                    Modules = "exports,hardening,layout"
                });
            }

            // 3) Mach-O / Fat
            if (isMach)
                hits.Add(new SampleType
                {
                    Id = "macho", Name = "macOS Mach-O 可执行/动态库", Confidence = "high",
                    Evidence = "Mach-O 魔数 0x" + magic.ToString("X8") + (magic == 0xFEEDFACF ? "（64 位）" : "（32 位）"),
                    Modules = "exports,layout"
                });
            if (isFat)
                hits.Add(new SampleType
                {
                    Id = "macho", Name = "macOS Mach-O 可执行/动态库", Confidence = "medium",
                    Evidence = "0xCAFEBABE 通用二进制（Fat Mach-O 或 Java class 需结合包结构判定）",
                    Modules = "exports,layout"
                });

            // 4) APK/DEX
            if (isDex)
                hits.Add(new SampleType
                {
                    Id = "android-apk", Name = "Android APK/DEX 安装包", Confidence = "high",
                    Evidence = "DEX 头 dex\\n" + (head.Length > 7 ? Encoding.ASCII.GetString(head, 4, 4) : ""),
                    Modules = "imports,il2cpp"
                });
            else if (isZip && (ext == ".apk" || ext == ".aab" || ext == ".zip"))
            {
                string inner = ZipListing(path);
                bool hasManifest = inner.Contains("AndroidManifest.xml");
                bool hasClasses = inner.Contains("classes.dex");
                if (hasManifest || hasClasses)
                    hits.Add(new SampleType
                    {
                        Id = "android-apk", Name = "Android APK/DEX 安装包", Confidence = hasClasses ? "high" : "medium",
                        Evidence = "ZIP 容器，" + (hasManifest ? "含 AndroidManifest.xml " : "") + (hasClasses ? "含 classes.dex" : ""),
                        Modules = "imports,il2cpp"
                    });
                if (inner.Contains("global-metadata.dat") || inner.Contains("libil2cpp.so"))
                    hits.Add(new SampleType
                    {
                        Id = "unity-il2cpp", Name = "Unity/IL2CPP 游戏包", Confidence = "high",
                        Evidence = "包内含 " + (inner.Contains("libil2cpp.so") ? "libil2cpp.so " : "") + (inner.Contains("global-metadata.dat") ? "global-metadata.dat" : ""),
                        Modules = "il2cpp,managed-members"
                    });
                if (!hasManifest && !hasClasses && inner.Contains(".class"))
                    hits.Add(new SampleType
                    {
                        Id = "java", Name = "Java 字节码/JAR 包", Confidence = "medium",
                        Evidence = "ZIP 容器内含 .class 条目",
                        Modules = "managed-artifact"
                    });
            }

            // 5) 单文件 Java class
            if (isFat && ext == ".class")
                hits.Add(new SampleType
                {
                    Id = "java", Name = "Java 字节码/JAR 包", Confidence = "high",
                    Evidence = "CAFEBABE 魔数 + .class 扩展名",
                    Modules = "managed-artifact"
                });

            // 6) 脚本
            if (IsScript(ext, head, headText))
                hits.Add(new SampleType
                {
                    Id = "script", Name = "脚本/解释型代码", Confidence = "high",
                    Evidence = "文本形态代码，" + ScriptEvidence(ext, headText),
                    Modules = "entropy"
                });

            // 7) Unity/IL2CPP 单文件（global-metadata.dat 本体）
            if (ext == ".dat" && headText.Contains("Metadata"))
                hits.Add(new SampleType
                {
                    Id = "unity-il2cpp", Name = "Unity/IL2CPP 游戏包", Confidence = "medium",
                    Evidence = "疑似 global-metadata.dat（含 Metadata 头）",
                    Modules = "il2cpp,managed-members"
                });

            // 8) 固件/裸二进制
            if (hits.Count == 0)
            {
                double entropy = Entropy(head);
                hits.Add(new SampleType
                {
                    Id = "firmware", Name = "固件/裸二进制镜像", Confidence = entropy > 7.2 ? "medium" : "low",
                    Evidence = "无已知可执行文件头，前 8KB 熵 " + entropy.ToString("F2") + "，" + (ext == "" ? "无扩展名" : "扩展名 " + ext),
                    Modules = "entropy,layout"
                });
            }

            return hits;
        }

        private static bool IsScript(string ext, byte[] head, string headText)
        {
            if (ext == ".js" || ext == ".mjs" || ext == ".py" || ext == ".ps1" || ext == ".bat" || ext == ".cmd"
                || ext == ".vbs" || ext == ".sh" || ext == ".lua" || ext == ".rb" || ext == ".php" || ext == ".hta")
                return true;
            if (headText.Length > 2 && headText[0] == '#' && headText[1] == '!') return true;
            // 无明显二进制特征且可打印比例高
            int printable = head.Count(b => b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127));
            return head.Length > 64 && printable * 100 / head.Length > 92 && (headText.Contains("function ") || headText.Contains("import ") || headText.Contains("#!/"));
        }

        private static string ScriptEvidence(string ext, string headText)
        {
            if (headText.StartsWith("#!")) return "shebang: " + headText.Split('\n')[0].Trim();
            if (ext == ".ps1") return "PowerShell 脚本扩展名";
            if (ext == ".py") return "Python 脚本扩展名";
            if (ext == ".js") return "JavaScript 扩展名";
            return "扩展名 " + ext;
        }

        private static string ZipListing(string path)
        {
            try
            {
                using var za = System.IO.Compression.ZipFile.OpenRead(path);
                var names = za.Entries.Take(4000).Select(e => e.FullName);
                return string.Join("\n", names);
            }
            catch { return ""; }
        }

        public static double Entropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;
            var counts = new int[256];
            foreach (var b in data) counts[b]++;
            double e = 0;
            foreach (var c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / data.Length;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }
    }
}
