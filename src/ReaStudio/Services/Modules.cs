using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ReaStudio.Services
{
    /// <summary>一个离线分析模块，对应一条 REA 内置静态分析命令（不需要 Ghidra/IDA 等外部引擎）。</summary>
    public sealed class AnalysisModule
    {
        public string Id { get; init; } = "";
        public string Command { get; init; } = "";
        public string Title { get; init; } = "";
        public string Group { get; init; } = "";
        public string Description { get; init; } = "";
        public bool DefaultOn { get; init; } = true;
        public int Weight { get; init; } = 1;

        public object ToDto() => new { id = Id, command = Command, title = Title, group = Group, description = Description, defaultOn = DefaultOn };
    }

    internal static class Modules
    {
        private static readonly AnalysisModule[] All =
        {
            new AnalysisModule { Id="artifact",  Command="inspect-artifact",        Title="目标总览",     Group="概览", Description="识别文件格式、架构与可继续探测的线索" },
            new AnalysisModule { Id="exposure",  Command="audit-release-exposure",  Title="发布暴露面",   Group="概览", Description="统计静态分析可从成品中还原出的信息量" },
            new AnalysisModule { Id="entropy",   Command="inspect-byte-entropy",    Title="字节熵分析",   Group="概览", Description="全文件与分块熵值，定位加壳/压缩/加密区段" },

            new AnalysisModule { Id="imports",   Command="inspect-pe-imports",      Title="导入表",       Group="PE 结构", Description="导入/延迟导入 DLL、序号、IAT RVA 与 import hash" },
            new AnalysisModule { Id="exports",   Command="inspect-native-exports",  Title="导出表",       Group="PE 结构", Description="PE/ELF 导出符号与地址" },
            new AnalysisModule { Id="resources", Command="inspect-pe-resources",    Title="资源目录",     Group="PE 结构", Description="资源类型、载荷区间、哈希与图标组关系" },
            new AnalysisModule { Id="loadcfg",   Command="inspect-pe-load-config",  Title="加载配置",     Group="PE 结构", Description="TLS 回调与 Load Config（CFG/安全 Cookie 等）", DefaultOn=false },
            new AnalysisModule { Id="hardening", Command="inspect-binary-hardening",Title="加固属性",     Group="PE 结构", Description="ASLR/DEP/CFG/SEH 等编译期缓解措施" },
            new AnalysisModule { Id="certs",     Command="inspect-pe-certificates", Title="签名证书",     Group="PE 结构", Description="Authenticode 签名者与证书链身份", DefaultOn=false },

            new AnalysisModule { Id="managed-artifact", Command="inspect-managed-artifact",         Title="CLR 程序集",   Group=".NET", Description="PE/CLI 身份、运行时版本与入口线索" },
            new AnalysisModule { Id="managed-members",  Command="inspect-managed-members",          Title="类型与成员",   Group=".NET", Description="类型/方法签名、CIL 锚点与 ldstr 字符串", DefaultOn=false },
            new AnalysisModule { Id="managed-native",   Command="inspect-managed-native-boundaries",Title="P/Invoke 边界", Group=".NET", Description="托管到原生的调用边界声明", DefaultOn=false },
            new AnalysisModule { Id="layout", Command="inspect-binary-layout", Title="文件布局", Group="PE 结构", Description="文件头、对齐与节区跨度等链接布局", DefaultOn=false },
            new AnalysisModule { Id="go", Command="inspect-go-binary", Title="Go 构建信息", Group="语言运行时", Description="Go 编译器版本、模块依赖与构建参数", DefaultOn=false },
            new AnalysisModule { Id="rust", Command="inspect-rust-binary", Title="Rust 依赖清单", Group="语言运行时", Description="cargo-auditable 内嵌的依赖与版本", DefaultOn=false },
            new AnalysisModule { Id="efuse", Command="inspect-electron-fuses", Title="Electron Fuse", Group="语言运行时", Description="打包开关状态（RunAsNode/NodeOptions 等）", DefaultOn=false },
            new AnalysisModule { Id="il2cpp", Command="inspect-il2cpp-metadata", Title="IL2CPP 元数据", Group="语言运行时", Description="global-metadata 类型、命名空间与字符串", DefaultOn=false }
        };

        public static IEnumerable<AnalysisModule> ForFile(string path)
        {
            var ext = (Path.GetExtension(path) ?? "").ToLowerInvariant();
            var list = new List<AnalysisModule>();
            var native = ext is ".exe" or ".dll" or ".sys" or ".ocx" or ".cpl" or ".scr" or ".node";
            if (native)
            {
                list.AddRange(All.Where(m => m.Group == "概览" || m.Group == "PE 结构"));
                list.AddRange(All.Where(m => m.Group == "语言运行时"));
            }
            if (ext is ".dll" or ".exe")
            {
                list.AddRange(All.Where(m => m.Group == ".NET"));
            }
            if (ext == ".lnk")
            {
                list.Add(new AnalysisModule { Id="lnk", Command="inspect-windows-shortcut", Title="快捷方式解析", Group="其他", Description="Shell Link 目标、参数、ExtraData 与 Tracker 数据" });
            }
            if (ext is ".gguf" or ".safetensors")
            {
                list.Add(new AnalysisModule { Id="model", Command="inspect-model-artifact", Title="模型文件结构", Group="其他", Description="GGUF/safetensors 头部、张量声明与统计" });
            }
            if (ext == ".pyc")
            {
                list.Add(new AnalysisModule { Id="pyc", Command="inspect-python-pyc", Title="Python 字节码", Group="其他", Description="CPython pyc 头与 marshal 代码对象" });
            }
            if (ext is ".db" or ".sqlite" or ".sqlite3")
            {
                list.Add(new AnalysisModule { Id="sqlite", Command="inspect-sqlite-database", Title="SQLite 结构", Group="其他", Description="表、列、索引、视图、触发器" });
            }
            if (ext is ".apk" or ".aab")
            {
                list.Add(new AnalysisModule { Id="apksig", Command="inspect-apk-signature", Title="APK 签名", Group="其他", Description="v1/v2/v3/v3.1 签名方案与证书指纹" });
                list.Add(new AnalysisModule { Id="apkpkg", Command="inspect-android-package", Title="APK 清单", Group="其他", Description="包名、SDK 级别、权限与组件声明" });
            }
            if (ext is ".wasm")
            {
                list.Add(new AnalysisModule { Id="wasm", Command="inspect-wasm-artifact", Title="WASM 构件", Group="其他", Description="节结构、导入/导出与 WAT 反汇编" });
            }
            return list;
        }

        public static AnalysisModule? Find(string id) => All.FirstOrDefault(m => m.Id == id);
    }
}
