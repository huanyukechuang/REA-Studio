using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ReaStudio.Services
{
    internal sealed class ReportInput
    {
        public string TargetPath { get; set; } = "";
        public string ItemsJson { get; set; } = "";
        public string TypesJson { get; set; } = "";
        public string NetworkJson { get; set; } = "";
        public string SiteJson { get; set; } = "";
        public string DynamicJson { get; set; } = "";
        public string AiText { get; set; } = "";
        /// <summary>病毒检测结果 JSON（VirusScanResult）。</summary>
        public string VirusJson { get; set; } = "";
        /// <summary>漏洞检测结果 JSON（VulnScanResult，CVE 库比对）。</summary>
        public string VulnJson { get; set; } = "";
        public string Format { get; set; } = "md";
        /// <summary>报告范围：static（软件逆向全量， network（仅网络分析， site（网站逆向， auto（旧行为，全量）</summary>
        public string Scope { get; set; } = "";
    }

    internal static class Reports
    {
        private static readonly JsonSerializerOptions JsonOpt = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        private static readonly JsonSerializerOptions VirusJsonOpt = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, IncludeFields = true };

        public static async Task<string?> ExportAsync(ReportInput input)
        {
            try
            {
                var dir = Path.Combine(Storage.AppRoot, "reports");
                Directory.CreateDirectory(dir);
                var scope = NormalizeScope(input.Scope);
                var target = input.TargetPath ?? "";
                string baseName;
                if (!string.IsNullOrEmpty(target) && !File.Exists(target))
                {
                    // 站点目标：用主机名做文件名
                    try
                    {
                        var u = new Uri(target.Contains("://") ? target : "https://" + target);
                        baseName = u.Host;
                    }
                    catch { baseName = target; }
                }
                else baseName = string.IsNullOrEmpty(target) ? "report" : Path.GetFileNameWithoutExtension(target);
                if (string.IsNullOrWhiteSpace(baseName)) baseName = "report";
                foreach (var c in Path.GetInvalidFileNameChars()) baseName = baseName.Replace(c, '_');
                var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                bool pdf = string.Equals(input.Format, "pdf", StringComparison.OrdinalIgnoreCase);

                var md = BuildMarkdown(input);
                if (!pdf)
                {
                    var mdFile = Path.Combine(dir, baseName + "_" + scope + "_" + stamp + ".md");
                    File.WriteAllText(mdFile, md, new UTF8Encoding(false));
                    return mdFile;
                }

                var html = BuildHtml(input);
                var pdfFile = Path.Combine(dir, baseName + "_" + scope + "_" + stamp + ".pdf");
                var (ok, err) = await PdfExporter.ExportAsync(html, pdfFile);
                if (ok) return pdfFile;
                // 回退：PDF 失败时仍落Markdown，保证有产出
                Log.Write("pdf failed: " + err);
                var fallback = Path.Combine(dir, baseName + "_" + scope + "_" + stamp + ".md");
                File.WriteAllText(fallback, md, new UTF8Encoding(false));
                return fallback;
            }
            catch (Exception ex)
            {
                Log.Write("report export: " + ex);
                return null;
            }
        }

        // ---------------- 数据准备 ----------------

        private sealed class Ctx
        {
            public string Target = "";
            public long Size;
            public string Sha256 = "";
            public DateTime Time = DateTime.Now;
            public List<JsonElement> Items = new List<JsonElement>();
            public List<SampleType> Types = new List<SampleType>();
            public NetworkReport? Net;
            public WebSiteReport? Site;
            public SiteStaticReport? SiteStatic;
            public SiteDynReport? SiteDynamic;
            public DynamicAnalyzer.DynResult? Dyn;
            public VirusScanResult? Virus;
            public VulnScanResult? Vuln;
            public string Ai = "";
            public string Scope = "auto";

            /// <summary>类型识别与模块明细属于软件逆向报告；网站网络报告不混入。/summary>
            public bool ShowStatic => Scope == "auto" || Scope == "static";
            /// <summary>网络章节：网络报告为主体；软件逆向与站点报告也保留（站点报告是站点自身的网络情报）。/summary>
            public bool ShowNet => Scope == "auto" || Scope == "network" || Scope == "static" || Scope == "site";
            public bool ShowSite => Scope == "auto" || Scope == "site";
            public bool ShowDynamic => Scope == "dynamic";
            /// <summary>病毒检测章节只对文件类报告有意义，站点报告不混入。</summary>
            public bool ShowVirus => (Scope == "auto" || Scope == "static" || Scope == "dynamic")
                && !string.IsNullOrEmpty(Target) && File.Exists(Target);
            /// <summary>漏洞检测章节与病毒检测一致：仅文件类报告，站点报告不混入。</summary>
            public bool ShowVuln => ShowVirus;
            public string Title => Scope == "network" ? "网络分析报告"
                : Scope == "site" ? "网站逆向报告"
                : Scope == "dynamic" ? "动态行为分析报告"
                : "静态分析报告";
        }

        private static string NormalizeScope(string? scope)
        {
            switch ((scope ?? "").Trim().ToLowerInvariant())
            {
                case "network": return "network";
                case "site": return "site";
                case "dynamic": return "dynamic";
                case "static": return "static";
                default: return "static";
            }
        }

        private static readonly string[] CnNum = { "零", "一", "二", "三", "四", "五", "六", "七", "八", "九", "十" };
        private static string Cn(int n) => n >= 0 && n < CnNum.Length ? CnNum[n] : n.ToString();

        private static Ctx Prepare(ReportInput input)
        {
            var c = new Ctx { Target = input.TargetPath ?? "", Ai = input.AiText ?? "" };
            try
            {
                if (!string.IsNullOrEmpty(c.Target) && File.Exists(c.Target)) c.Size = new FileInfo(c.Target).Length;
            }
            catch { }
            c.Sha256 = HashCache.Get(c.Target);
            try
            {
                if (!string.IsNullOrEmpty(input.ItemsJson))
                {
                    using var doc = JsonDocument.Parse(input.ItemsJson);
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        foreach (var it in doc.RootElement.EnumerateArray()) c.Items.Add(it.Clone());
                }
            }
            catch { }
            try
            {
                if (!string.IsNullOrEmpty(input.TypesJson))
                {
                    var list = JsonSerializer.Deserialize<List<SampleType>>(input.TypesJson, JsonOpt);
                    if (list != null) c.Types = list;
                }
            }
            catch { }
            if (c.Types.Count == 0)
            {
                try { c.Types = BinaryTypes.Detect(c.Target); } catch { }
            }
            try
            {
                if (!string.IsNullOrEmpty(input.NetworkJson))
                    c.Net = JsonSerializer.Deserialize<NetworkReport>(input.NetworkJson, JsonOpt);
            }
            catch { }
            try
            {
                if (!string.IsNullOrEmpty(input.SiteJson))
                {
                    c.Site = JsonSerializer.Deserialize<WebSiteReport>(input.SiteJson, JsonOpt);
                    // 站点目标可独立进行静态与动态分析，结果随site 对象一并传入
                    using var doc = JsonDocument.Parse(input.SiteJson);
                    if (doc.RootElement.TryGetProperty("siteStatic", out var ssEl) && ssEl.ValueKind == JsonValueKind.Object)
                        c.SiteStatic = JsonSerializer.Deserialize<SiteStaticReport>(ssEl.GetRawText(), JsonOpt);
                    if (doc.RootElement.TryGetProperty("siteDynamic", out var sdEl) && sdEl.ValueKind == JsonValueKind.Object)
                        c.SiteDynamic = JsonSerializer.Deserialize<SiteDynReport>(sdEl.GetRawText(), JsonOpt);
                }
            }
            catch { }
            c.Scope = NormalizeScope(input.Scope);
            try { if (!string.IsNullOrEmpty(input.DynamicJson)) c.Dyn = JsonSerializer.Deserialize<DynamicAnalyzer.DynResult>(input.DynamicJson, JsonOpt); } catch { }
            try
            {
                if (!string.IsNullOrEmpty(input.VirusJson))
                    c.Virus = JsonSerializer.Deserialize<VirusScanResult>(input.VirusJson, VirusJsonOpt);
            }
            catch { }
            // 前端未带上病毒检测结果时，导出前在沙箱内补跑一次（只读副本，不改动原文件）
            if (c.Virus == null && c.ShowVirus)
            {
                try { c.Virus = Task.Run(() => VirusDb.ScanAsync(c.Target)).GetAwaiter().GetResult(); } catch { }
            }
            // 漏洞检测（CVE 库比对）同上：前端未带则导出前补跑，保证 PDF/MD 两份报告都含漏洞章节
            try
            {
                if (!string.IsNullOrEmpty(input.VulnJson))
                    c.Vuln = JsonSerializer.Deserialize<VulnScanResult>(input.VulnJson, VirusJsonOpt);
            }
            catch { }
            if (c.Vuln == null && c.ShowVuln)
            {
                try { c.Vuln = Task.Run(() => VulnDb.ScanAsync(c.Target)).GetAwaiter().GetResult(); } catch { }
            }
            // 仅在需要网络章节、且目标确实是本机文件时才自动补跑（站点目标不跑文件情报）
            if (c.Net == null && c.ShowNet && !string.IsNullOrEmpty(c.Target) && File.Exists(c.Target))
            {
                try { c.Net = NetworkIntel.AnalyzeFile(c.Target); } catch { }
            }
            return c;
        }

        private static void AppendSiteEvidenceMd(StringBuilder sb, List<SiteEvidenceItem> ev)
        {
            if (ev == null || ev.Count == 0) return;
            sb.AppendLine();
            sb.AppendLine("**结构化证据（" + ev.Count + " 项）**");
            sb.AppendLine();
            foreach (var e in ev)
                sb.AppendLine("- " + (string.IsNullOrEmpty(e.Title) ? e.Module : e.Title)
                    + (string.IsNullOrEmpty(e.EvidenceFile) ? "" : "　`" + e.EvidenceFile + "`"));
        }

        private static void AppendSiteEvidenceHtml(StringBuilder sb, List<SiteEvidenceItem> ev)
        {
            if (ev == null || ev.Count == 0) return;
            sb.Append("<h4>结构化证据（" + ev.Count + " 项）</h4><ul>");
            foreach (var e in ev)
                sb.Append("<li>" + Esc(string.IsNullOrEmpty(e.Title) ? e.Module : e.Title)
                    + (string.IsNullOrEmpty(e.EvidenceFile) ? "" : "　<code>" + Esc(e.EvidenceFile) + "</code>") + "</li>");
            sb.Append("</ul>");
        }

        // ---------------- 病毒检测章节 ----------------

        private static void AppendVirusMd(StringBuilder sb, VirusScanResult v, int sec)
        {
            sb.AppendLine("## " + Cn(sec) + "、病毒检测（沙箱内比对）");
            sb.AppendLine();
            sb.AppendLine("- 检测结论：**" + v.Verdict + "**（评分 " + v.Score + "，高危 " + v.High + " / 中危 " + v.Medium + " / 低危 " + v.Low + "）");
            sb.AppendLine("- 检测方式：" + (v.InSandbox ? "样本只读副本在沙箱内比对，样本未被执行" : "在本机只读比对，样本未被执行"));
            if (!string.IsNullOrEmpty(v.Sha256)) sb.AppendLine("- SHA-256：`" + v.Sha256 + "`");
            if (!string.IsNullOrEmpty(v.Md5)) sb.AppendLine("- MD5：`" + v.Md5 + "`");
            if (!string.IsNullOrEmpty(v.PeInfo)) sb.AppendLine("- 结构特征：" + v.PeInfo);
            sb.AppendLine("- 病毒库：" + v.DbVersion + "（特征规则 " + v.RuleCount + " 条，样本哈希 " + v.HashCount + " 条）");
            sb.AppendLine("- 熵值：" + v.Entropy.ToString("F2") + "　耗时：" + v.ElapsedMs + " ms");
            if (!string.IsNullOrEmpty(v.ScanPath)) sb.AppendLine("- 沙箱副本：`" + v.ScanPath + "`");
            if (!string.IsNullOrEmpty(v.Summary))
            {
                sb.AppendLine();
                sb.AppendLine("**判定说明**：" + v.Summary);
            }
            if (v.Packed || v.Obfuscated || !string.IsNullOrEmpty(v.Installer) || v.InnerPayloads.Count > 0)
            {
                sb.AppendLine("**加壳 / 混淆识别**");
                sb.AppendLine();
                if (!string.IsNullOrEmpty(v.Packer)) sb.AppendLine("- 封装类型：" + v.Packer + (string.IsNullOrEmpty(v.PackerConfidence) ? "" : "（置信度 " + v.PackerConfidence + "）"));
                if (v.Obfuscated) sb.AppendLine("- 混淆特征：" + (string.IsNullOrEmpty(v.ObfuscationKind) ? "存在" : v.ObfuscationKind));
                if (!string.IsNullOrEmpty(v.Installer)) sb.AppendLine("- 安装器 / 自解压：是");
                sb.AppendLine("- 节区最高熵：" + v.PackMaxEntropy.ToString("F2") + (v.Overlay > 0 ? "　附加数据（overlay）：" + v.Overlay.ToString("N0") + " 字节" : ""));
                if (!string.IsNullOrEmpty(v.WeakSign)) sb.AppendLine("- 弱指纹：" + v.WeakSign);
                if (v.PackEvidence.Count > 0) sb.AppendLine("- 判定依据：" + string.Join("；", v.PackEvidence.Take(8)));
                sb.AppendLine("- 内层载荷：" + (v.InnerPayloads.Count == 0 ? "未解出（可能为强加密壳，建议结合动态分析）" : string.Join("；", v.InnerPayloads.Take(8))));
                if (v.InnerHits > 0) sb.AppendLine("- 内层复扫：命中 " + v.InnerHits + " 条特征，已计入评分（加壳补偿 +" + v.ScoreBonus + "）");
                sb.AppendLine();
            }
            sb.AppendLine();
            sb.AppendLine("| 等级 | 检测名称 | 家族 / 类型 | 来源 | 命中位置 | 说明 |");
            sb.AppendLine("| --- | --- | --- | --- | --- | --- |");
            if (v.Matches.Count == 0)
                sb.AppendLine("| - | 未命中 | - | 病毒库 | - | 与当前病毒库无任何匹配 |");
            else
                foreach (var m in v.Matches.Take(60))
                    sb.AppendLine("| " + m.Severity + " | " + Md(m.Name) + " | " + Md((m.Family + " / " + m.Type).Trim(' ', '/')) + " | " + Md(m.Source + (string.IsNullOrEmpty(m.RuleId) ? "" : " " + m.RuleId)) + " | " + Md(m.Match).Replace("|", "/") + " | " + Md(m.Desc).Replace("|", "/") + " |");
            sb.AppendLine();
            if (v.Notes.Count > 0)
            {
                sb.AppendLine("**检测备注**");
                sb.AppendLine();
                foreach (var n in v.Notes.Take(20)) sb.AppendLine("- " + n);
                sb.AppendLine();
            }
        }

        private static void AppendVirusHtml(StringBuilder sb, VirusScanResult v, ref int sec)
        {
            sb.Append("<h2>").Append(Cn(++sec)).Append("、病毒检测（沙箱内比对）</h2>");
            sb.Append("<p><b>检测结论：").Append(Esc(v.Verdict)).Append("</b>　评分 ").Append(v.Score)
              .Append("　高危 ").Append(v.High).Append(" / 中危 ").Append(v.Medium).Append(" / 低危 ").Append(v.Low).Append("</p>");
            sb.Append("<ul>");
            sb.Append("<li>检测方式：").Append(Esc(v.InSandbox ? "样本只读副本在沙箱内比对，样本未被执行" : "在本机只读比对，样本未被执行")).Append("</li>");
            if (!string.IsNullOrEmpty(v.Sha256)) sb.Append("<li>SHA-256：<code>").Append(Esc(v.Sha256)).Append("</code></li>");
            if (!string.IsNullOrEmpty(v.Md5)) sb.Append("<li>MD5：<code>").Append(Esc(v.Md5)).Append("</code></li>");
            if (!string.IsNullOrEmpty(v.PeInfo)) sb.Append("<li>结构特征：").Append(Esc(v.PeInfo)).Append("</li>");
            sb.Append("<li>病毒库：").Append(Esc(v.DbVersion)).Append("（特征规则 ").Append(v.RuleCount).Append(" 条，样本哈希 ").Append(v.HashCount).Append(" 条）</li>");
            sb.Append("<li>熵值：").Append(v.Entropy.ToString("F2")).Append("　耗时：").Append(v.ElapsedMs).Append(" ms</li>");
            if (!string.IsNullOrEmpty(v.ScanPath)) sb.Append("<li>沙箱副本：<code>").Append(Esc(v.ScanPath)).Append("</code></li>");
            sb.Append("</ul>");
            if (!string.IsNullOrEmpty(v.Summary)) sb.Append("<p><b>判定说明：</b>").Append(Esc(v.Summary)).Append("</p>");
            if (v.Packed || v.Obfuscated || !string.IsNullOrEmpty(v.Installer) || v.InnerPayloads.Count > 0)
            {
                sb.Append("<h4>加壳 / 混淆识别</h4><ul>");
                if (!string.IsNullOrEmpty(v.Packer)) sb.Append("<li>封装类型：").Append(Esc(v.Packer)).Append(string.IsNullOrEmpty(v.PackerConfidence) ? "" : "（置信度 " + Esc(v.PackerConfidence) + "）").Append("</li>");
                if (v.Obfuscated) sb.Append("<li>混淆特征：").Append(Esc(string.IsNullOrEmpty(v.ObfuscationKind) ? "存在" : v.ObfuscationKind)).Append("</li>");
                if (!string.IsNullOrEmpty(v.Installer)) sb.Append("<li>安装器 / 自解压：是</li>");
                sb.Append("<li>节区最高熵：").Append(v.PackMaxEntropy.ToString("F2")).Append(v.Overlay > 0 ? "　附加数据（overlay）：" + v.Overlay.ToString("N0") + " 字节" : "").Append("</li>");
                if (!string.IsNullOrEmpty(v.WeakSign)) sb.Append("<li>弱指纹：").Append(Esc(v.WeakSign)).Append("</li>");
                if (v.PackEvidence.Count > 0) sb.Append("<li>判定依据：").Append(Esc(string.Join("；", v.PackEvidence.Take(8)))).Append("</li>");
                sb.Append("<li>内层载荷：").Append(Esc(v.InnerPayloads.Count == 0 ? "未解出（可能为强加密壳，建议结合动态分析）" : string.Join("；", v.InnerPayloads.Take(8)))).Append("</li>");
                if (v.InnerHits > 0) sb.Append("<li>内层复扫：命中 ").Append(v.InnerHits).Append(" 条特征，已计入评分（加壳补偿 +").Append(v.ScoreBonus).Append("）</li>");
                sb.Append("</ul>");
            }
            sb.Append("<table><thead><tr><th>等级</th><th>检测名称</th><th>家族 / 类型</th><th>来源</th><th>命中位置</th><th>说明</th></tr></thead><tbody>");
            if (v.Matches.Count == 0)
                sb.Append("<tr><td>-</td><td>未命中</td><td>-</td><td>病毒库</td><td>-</td><td>与当前病毒库无任何匹配</td></tr>");
            else
                foreach (var m in v.Matches.Take(60))
                    sb.Append("<tr><td>").Append(Esc(m.Severity)).Append("</td><td>").Append(Esc(m.Name))
                      .Append("</td><td>").Append(Esc((m.Family + " / " + m.Type).Trim(' ', '/'))).Append("</td><td>")
                      .Append(Esc(m.Source + (string.IsNullOrEmpty(m.RuleId) ? "" : " " + m.RuleId))).Append("</td><td>")
                      .Append(Esc(m.Match)).Append("</td><td>").Append(Esc(m.Desc)).Append("</td></tr>");
            sb.Append("</tbody></table>");
            if (v.Notes.Count > 0)
            {
                sb.Append("<h4>检测备注</h4><ul>");
                foreach (var n in v.Notes.Take(20)) sb.Append("<li>").Append(Esc(n)).Append("</li>");
                sb.Append("</ul>");
            }
        }

        // ---------------- 漏洞检测（CVE）章节 ----------------

        private static void AppendVulnMd(StringBuilder sb, VulnScanResult v, int sec)
        {
            sb.AppendLine("## " + Cn(sec) + "、漏洞检测（CVE 库比对）");
            sb.AppendLine();
            sb.AppendLine("- 检测结论：**" + v.Verdict + "**（风险评分 " + v.Score + "，严重 " + v.Critical + " / 高危 " + v.High + " / 中危 " + v.Medium + " / 低危 " + v.Low + " / 待确认 " + v.Pending + "）");
            sb.AppendLine("- 检测方式：" + (v.InSandbox ? "样本只读副本在沙箱内比对，样本未被执行" : "在本机只读比对，样本未被执行") + "；基于版本资源、导入表与字符串 banner 识别第三方组件后与 CVE 库做版本区间/特征匹配");
            if (!string.IsNullOrEmpty(v.Sha256)) sb.AppendLine("- SHA-256：`" + v.Sha256 + "`");
            if (v.Size > 0) sb.AppendLine("- 样本大小：" + v.Size.ToString("N0") + " 字节");
            sb.AppendLine("- 漏洞库：" + v.DbVersion + "（当前可用 CVE " + v.CveCount + " 条）");
            sb.AppendLine("- 耗时：" + v.ElapsedMs + " ms");
            if (!string.IsNullOrEmpty(v.ScanPath)) sb.AppendLine("- 沙箱副本：`" + v.ScanPath + "`");
            if (!string.IsNullOrEmpty(v.Summary))
            {
                sb.AppendLine();
                sb.AppendLine("**判定说明**：" + v.Summary);
            }
            sb.AppendLine();
            if (!string.IsNullOrEmpty(v.PackSummary) || (v.InnerPayloads != null && v.InnerPayloads.Count > 0))
            {
                sb.AppendLine("**封装与内层复扫**");
                sb.AppendLine();
                if (!string.IsNullOrEmpty(v.PackSummary)) sb.AppendLine("- 封装识别：" + v.PackSummary);
                sb.AppendLine("- 内层载荷：" + (v.InnerPayloads == null || v.InnerPayloads.Count == 0 ? "未解出（可能为强加密壳，建议结合动态分析）" : string.Join("；", v.InnerPayloads.Take(8))));
                if (v.InnerHits > 0) sb.AppendLine("- 内层复扫：命中 " + v.InnerHits + " 条 CVE 关联，已并入命中明细与评分");
                sb.AppendLine();
            }
            sb.AppendLine("### 组件指纹");
            sb.AppendLine();
            sb.AppendLine("| 组件 | 版本 | 来源 | 证据 |");
            sb.AppendLine("| --- | --- | --- | --- |");
            if (v.Components == null || v.Components.Count == 0)
                sb.AppendLine("| - | 未识别 | - | 未从版本信息/导入表/字符串中识别到受 CVE 覆盖的第三方组件 |");
            else
                foreach (var c in v.Components.Take(40))
                    sb.AppendLine("| " + Md(c.Name) + " | " + Md(string.IsNullOrEmpty(c.Version) ? "未知" : c.Version) + " | " + Md(c.Source) + " | " + Md(c.Evidence).Replace("|", "/") + " |");
            sb.AppendLine();
            sb.AppendLine("### 命中明细");
            sb.AppendLine();
            sb.AppendLine("| CVE | 等级 | CVSS | 命中形态 | 组件 | 受影响版本 | 证据 | 说明 | 修复建议 |");
            sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            if (v.Matches == null || v.Matches.Count == 0)
            {
                sb.AppendLine("| - | - | - | - | - | - | - | 与当前 CVE 库无匹配 | - |");
            }
            else
            {
                foreach (var m in v.Matches.Take(80))
                {
                    sb.AppendLine("| " + Md(m.CveId) + " | " + Md(m.Severity) + " | " + m.Cvss.ToString("F1") + " | " + Md(m.Kind)
                        + " | " + Md(m.Component).Replace("|", "/")
                        + " | " + Md(m.Affected).Replace("|", "/")
                        + " | " + Md(m.Evidence).Replace("|", "/")
                        + " | " + Md(m.Desc).Replace("|", "/")
                        + " | " + Md(m.Fix).Replace("|", "/") + " |");
                }
            }
            sb.AppendLine();
            var refs = (v.Matches ?? new List<VulnHit>()).Where(m => !string.IsNullOrEmpty(m.Refs)).Select(m => m.CveId).Distinct().Take(20).ToList();
            if (refs.Count > 0)
            {
                sb.AppendLine("**NVD 参考**：" + string.Join("　", refs.Select(id => "[" + id + "](https://nvd.nist.gov/vuln/detail/" + id + ")")));
                sb.AppendLine();
            }
            if (v.Notes != null && v.Notes.Count > 0)
            {
                sb.AppendLine("**检测备注**");
                sb.AppendLine();
                foreach (var n in v.Notes.Take(20)) sb.AppendLine("- " + n);
                sb.AppendLine();
            }
        }

        private static void AppendVulnHtml(StringBuilder sb, VulnScanResult v, ref int sec)
        {
            sb.Append("<h2>").Append(Cn(++sec)).Append("、漏洞检测（CVE 库比对）</h2>");
            sb.Append("<p><b>检测结论：").Append(Esc(v.Verdict)).Append("</b>　风险评分 ").Append(v.Score)
              .Append("　严重 ").Append(v.Critical).Append(" / 高危 ").Append(v.High)
              .Append(" / 中危 ").Append(v.Medium).Append(" / 低危 ").Append(v.Low).Append(" / 待确认 ").Append(v.Pending).Append("</p>");
            sb.Append("<ul>");
            sb.Append("<li>检测方式：").Append(Esc(v.InSandbox ? "样本只读副本在沙箱内比对，样本未被执行" : "在本机只读比对，样本未被执行")).Append("；先识别第三方组件版本，再与 CVE 库做版本区间/特征匹配</li>");
            if (!string.IsNullOrEmpty(v.Sha256)) sb.Append("<li>SHA-256：<code>").Append(Esc(v.Sha256)).Append("</code></li>");
            if (v.Size > 0) sb.Append("<li>样本大小：").Append(v.Size.ToString("N0")).Append(" 字节</li>");
            sb.Append("<li>漏洞库：").Append(Esc(v.DbVersion)).Append("（当前可用 CVE ").Append(v.CveCount).Append(" 条）</li>");
            sb.Append("<li>耗时：").Append(v.ElapsedMs).Append(" ms</li>");
            if (!string.IsNullOrEmpty(v.ScanPath)) sb.Append("<li>沙箱副本：<code>").Append(Esc(v.ScanPath)).Append("</code></li>");
            sb.Append("</ul>");
            if (!string.IsNullOrEmpty(v.Summary)) sb.Append("<p><b>判定说明：</b>").Append(Esc(v.Summary)).Append("</p>");

            if (!string.IsNullOrEmpty(v.PackSummary) || (v.InnerPayloads != null && v.InnerPayloads.Count > 0))
            {
                sb.Append("<h4>封装与内层复扫</h4><ul>");
                if (!string.IsNullOrEmpty(v.PackSummary)) sb.Append("<li>封装识别：").Append(Esc(v.PackSummary)).Append("</li>");
                sb.Append("<li>内层载荷：").Append(Esc(v.InnerPayloads == null || v.InnerPayloads.Count == 0 ? "未解出（可能为强加密壳，建议结合动态分析）" : string.Join("；", v.InnerPayloads.Take(8)))).Append("</li>");
                if (v.InnerHits > 0) sb.Append("<li>内层复扫：命中 ").Append(v.InnerHits).Append(" 条 CVE 关联，已并入命中明细与评分</li>");
                sb.Append("</ul>");
            }

            sb.Append("<h4>组件指纹</h4>");
            sb.Append("<table><thead><tr><th>组件</th><th>版本</th><th>来源</th><th>证据</th></tr></thead><tbody>");
            if (v.Components == null || v.Components.Count == 0)
                sb.Append("<tr><td>-</td><td>未识别</td><td>-</td><td>未从版本信息/导入表/字符串中识别到受 CVE 覆盖的第三方组件</td></tr>");
            else
                foreach (var c in v.Components.Take(40))
                    sb.Append("<tr><td>").Append(Esc(c.Name)).Append("</td><td>").Append(Esc(string.IsNullOrEmpty(c.Version) ? "未知" : c.Version))
                      .Append("</td><td>").Append(Esc(c.Source)).Append("</td><td>").Append(Esc(c.Evidence)).Append("</td></tr>");
            sb.Append("</tbody></table>");

            sb.Append("<h4>命中明细</h4>");
            sb.Append("<table><thead><tr><th>CVE</th><th>等级</th><th>CVSS</th><th>命中形态</th><th>组件</th><th>受影响版本</th><th>说明</th><th>修复建议</th></tr></thead><tbody>");
            if (v.Matches == null || v.Matches.Count == 0)
            {
                sb.Append("<tr><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>与当前 CVE 库无匹配</td><td>-</td></tr>");
            }
            else
            {
                foreach (var m in v.Matches.Take(80))
                {
                    sb.Append("<tr><td>").Append(Esc(m.CveId)).Append("</td><td>").Append(Esc(m.Severity))
                      .Append("</td><td>").Append(m.Cvss.ToString("F1"))
                      .Append("</td><td>").Append(Esc(m.Kind))
                      .Append("</td><td>").Append(Esc(m.Component))
                      .Append("</td><td>").Append(Esc(m.Affected))
                      .Append("</td><td>").Append(Esc(m.Desc))
                      .Append("</td><td>").Append(Esc(m.Fix)).Append("</td></tr>");
                }
            }
            sb.Append("</tbody></table>");

            var refs = (v.Matches ?? new List<VulnHit>()).Where(m => !string.IsNullOrEmpty(m.Refs)).Select(m => m.CveId).Distinct().Take(20).ToList();
            if (refs.Count > 0)
            {
                sb.Append("<p class=\"note\">NVD 参考：");
                foreach (var id in refs)
                    sb.Append(Esc(id)).Append("　");
                sb.Append("</p>");
            }
            if (v.Notes != null && v.Notes.Count > 0)
            {
                sb.Append("<h4>检测备注</h4><ul>");
                foreach (var n in v.Notes.Take(20)) sb.Append("<li>").Append(Esc(n)).Append("</li>");
                sb.Append("</ul>");
            }
        }

        // ---------------- Markdown ----------------

        public static string BuildMarkdown(ReportInput input)
        {
            var c = Prepare(input);
            var sb = new StringBuilder();
            int sec = 0;
            sb.AppendLine("# REA Studio " + c.Title);
            sb.AppendLine();
            sb.AppendLine("- 目标：`" + c.Target + "`");
            if (c.Size > 0) sb.AppendLine("- 大小：" + c.Size.ToString("N0") + " 字节）" + (c.Size / 1048576.0).ToString("F2") + " MB）");
            if (!string.IsNullOrEmpty(c.Sha256)) sb.AppendLine("- SHA-256：`" + c.Sha256 + "`");
            sb.AppendLine("- 生成时间：" + c.Time.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("- 报告类型：" + c.Title);
            if (c.ShowStatic)
            {
                sb.AppendLine("- 分析模块：" + c.Items.Count + " 项");
                sb.AppendLine("- 样本类型：" + (c.Types.Count == 0 ? "未识别" : string.Join("、", c.Types.Select(t => t.Name))));
                if (c.Types.Count > 0)
                {
                    var main = c.Types.OrderByDescending(t => t.Confidence == "high" ? 3 : t.Confidence == "medium" ? 2 : 1).First();
                    sb.AppendLine("- 主判定：**" + main.Name + "**（置信度 " + Conf(main.Confidence) + "）");
                }
            }
            sb.AppendLine();
            sb.AppendLine(c.ShowDynamic
                ? "> 报告由REA Studio 本机离线生成；样本在受控作业内实际运行，观测结束即强制终止进程树。"
                : "> 报告由REA Studio 本机离线生成；全部结论来自静态分析证据，样本未被执行。");
            sb.AppendLine();

            // 结论摘要
            var risks = new List<string>();
            if (c.ShowStatic && c.Types.Count > 0) risks.Add("类型判定：" + string.Join(" / ", c.Types.Select(t => t.Name)));
            if (c.Net != null && c.Net.Ok && c.ShowNet)
            {
                if (!string.IsNullOrEmpty(c.Net.Verdict)) risks.Add("网络行为：" + c.Net.Verdict);
                risks.Add("外发端点共" + c.Net.TotalEndpoints + " 个（列示 " + c.Net.Endpoints.Count + " 个），危险发包" + c.Net.TotalDangerous + " 个（列示 " + c.Net.Dangerous.Count + " 个）");
                if (c.Net.Privacy.Count > 0) risks.Add("隐私字段 " + c.Net.Privacy.Count + " 类，高敏 " + c.Net.Privacy.Count(p => p.Risk == "高") + " 类");
            }
            if (c.Site != null && c.Site.Ok && c.ShowSite && !string.IsNullOrEmpty(c.Site.Verdict)) risks.Add("网站侧：" + c.Site.Verdict);
            if (risks.Count > 0)
            {
                sb.AppendLine("## 结论摘要");
                sb.AppendLine();
                foreach (var r in risks) sb.AppendLine("- " + r);
                sb.AppendLine();
            }

            // 九大类型
            if (c.ShowStatic)
            {
                sb.AppendLine("## " + Cn(++sec) + "、逆向类型识别（九类）");
                sb.AppendLine();
                sb.AppendLine("| 类型 | 置信度 | 判定依据 | 建议启用模块 |");
                sb.AppendLine("| --- | --- | --- | --- |");
                foreach (var t in c.Types) sb.AppendLine("| " + t.Name + " | " + Conf(t.Confidence) + " | " + Md(t.Evidence) + " | " + t.Modules + " |");
                var absent = BinaryTypes.Catalog.Select(x => x.Name).Where(n => !c.Types.Any(t => t.Name == n)).ToList();
                if (absent.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("未命中类型：" + string.Join("、", absent));
                }
                sb.AppendLine();
            }

            // 网络
            if (c.Net != null && c.Net.Ok && c.ShowNet)
            {
                sb.AppendLine("## " + Cn(++sec) + "、网络行为分析");
                sb.AppendLine();
                sb.AppendLine("扫描字符串" + c.Net.Strings + " 条，URL " + c.Net.UrlCount + " 个，裸IP " + c.Net.IpCount + " 处（已剔除内网环回/版本号），明文http 占比 " + c.Net.PlainHttpShare + "。命名空间类 URI 与非网络主机不计入端点。");
                sb.AppendLine();
                sb.AppendLine("### 流量指向");
                sb.AppendLine();
                sb.AppendLine("| 协议 | 主机 | 端口 | 次数 | 风险 | 路径/备注 |");
                sb.AppendLine("| --- | --- | --- | --- | --- | --- |");
                foreach (var e in c.Net.Endpoints.Take(30))
                    sb.AppendLine("| " + e.Scheme + " | " + Md(e.Host) + " | " + (e.Port == 0 ? "-" : e.Port.ToString()) + " | " + e.Hits + " | " + e.Level + "(" + e.Score + ") | " + Md(string.Join("，", e.Paths.Take(3))).Replace("|", "/") + " |");
                sb.AppendLine();

                sb.AppendLine("### 危险发包筛选（评分 ≥）");
                sb.AppendLine();
                if (c.Net.Dangerous.Count == 0) sb.AppendLine("未发现评分达到阈值的危险外发端点。");
                else
                {
                    sb.AppendLine("| 等级 | 评分 | 目标 | 判定理由 |");
                    sb.AppendLine("| --- | --- | --- | --- |");
                    foreach (var d in c.Net.Dangerous)
                        sb.AppendLine("| " + d.Level + " | " + d.Score + " | " + Md(d.Scheme + "://" + d.Host + (d.Port > 0 ? ":" + d.Port : "")) + " | " + Md(string.Join("；", d.Reasons)).Replace("|", "/") + " |");
                }
                sb.AppendLine();

                sb.AppendLine("### 隐私信息暴露");
                sb.AppendLine();
                if (c.Net.Privacy.Count == 0) sb.AppendLine("未命中个人数据字段。");
                else
                {
                    sb.AppendLine("| 类别 | 触发字段 | 含义 | 风险 | 命中次数 | 样例 |");
                    sb.AppendLine("| --- | --- | --- | --- | --- | --- |");
                    foreach (var p in c.Net.Privacy)
                        sb.AppendLine("| " + p.Category + " | " + Md(p.Key) + " | " + p.Meaning + " | " + p.Risk + " | " + p.Hits + " | " + Md(p.Samples.FirstOrDefault() ?? "").Replace("|", "/") + " |");
                }
                sb.AppendLine();

                sb.AppendLine("### 数据包内容特征");
                sb.AppendLine();
                if (c.Net.Packets.Count == 0) sb.AppendLine("未提取到结构化请求体。");
                else
                {
                    sb.AppendLine("| 类型 | 评分 | 字段 | 内容摘要 |");
                    sb.AppendLine("| --- | --- | --- | --- |");
                    foreach (var p in c.Net.Packets)
                        sb.AppendLine("| " + p.Kind + " | " + p.Score + " | " + Md(string.Join(",", p.Fields.Take(8))) + " | " + Md(p.Content).Replace("|", "/") + " |");
                }
                sb.AppendLine();
                if (c.Net.Services.Count > 0) { sb.AppendLine("**命中的第三方 SDK/服务**：" + string.Join("、", c.Net.Services)); sb.AppendLine(); }
                if (c.Net.UserAgents.Count > 0) { sb.AppendLine("**User-Agent**：`" + c.Net.UserAgents.First() + "`"); sb.AppendLine(); }
            }

            // 网站
            if (c.Site != null && c.Site.Ok && c.ShowSite)
            {
                sb.AppendLine("## " + Cn(++sec) + "、网站逆向：" + c.Site.Url + "）");
                sb.AppendLine();
                sb.AppendLine("- 最终地址：" + c.Site.FinalUrl + "（HTTP " + c.Site.Status + "）");
                sb.AppendLine("- 页面标题：" + (string.IsNullOrEmpty(c.Site.Title) ? "-" : c.Site.Title));
                if (!string.IsNullOrEmpty(c.Site.Description)) sb.AppendLine("- 站点描述：" + c.Site.Description);
                sb.AppendLine("- HTTPS：" + (c.Site.IsHttps ? "是" : "否"));
                sb.AppendLine("- 第三方外部域：" + c.Site.ExternalHosts.Count + " 个（" + string.Join("、", c.Site.ExternalHosts.Take(12)) + "）");
                if (c.Site.Signals.Count > 0) { sb.AppendLine(); sb.AppendLine("**合规与风险信号*"); sb.AppendLine(); foreach (var s in c.Site.Signals) sb.AppendLine("- " + s); }
                if (c.Site.Forms.Count > 0) { sb.AppendLine(); sb.AppendLine("**表单提交目标**：" + string.Join("、", c.Site.Forms)); }
                sb.AppendLine();
            }

            // 站点静态分析（独立证据流）
            if (c.SiteStatic != null && c.SiteStatic.Ok && c.ShowSite)
            {
                var sst = c.SiteStatic;
                var sm = sst.Summary;
                sb.AppendLine("## " + Cn(++sec) + "、站点静态分析（" + sst.Url + "）");
                sb.AppendLine();
                sb.AppendLine("- 最终地址：" + sm.FinalUrl + "（HTTP " + sm.Status + "）");
                sb.AppendLine("- 页面标题：" + (string.IsNullOrEmpty(sm.Title) ? "-" : sm.Title));
                sb.AppendLine("- 页面体积：" + sm.HtmlBytes.ToString("N0") + " 字节；同源脚本" + sm.JsFiles + " 个/ " + sm.JsBytes.ToString("N0") + " 字节；内联脚本" + sm.InlineScripts + " 段");
                sb.AppendLine("- 接口端点：" + sm.ApiEndpoints + " 个；敏感信息命中：" + sm.Secrets + " 处；外部域：" + sm.ExternalHosts + " 个；表单：" + sm.Forms + " 个");
                sb.AppendLine("- 安全头缺失：" + sm.MissingHeaders + " 项；属性不全Cookie：" + sm.UnsafeCookies + " 个");
                if (sm.Tech != null && sm.Tech.Count > 0) sb.AppendLine("- 技术指纹：" + string.Join("、", sm.Tech));
                if (sm.Signals != null && sm.Signals.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("**静态风险信号*");
                    sb.AppendLine();
                    foreach (var x in sm.Signals) sb.AppendLine("- " + x);
                }
                if (!string.IsNullOrEmpty(sm.Verdict)) { sb.AppendLine(); sb.AppendLine("**静态结论*：" + sm.Verdict); }
                AppendSiteEvidenceMd(sb, sst.Evidence);
                sb.AppendLine();
            }

            // 站点动态分析（独立证据流）
            if (c.SiteDynamic != null && c.SiteDynamic.Ok && c.ShowSite)
            {
                var sdy = c.SiteDynamic;
                var dm = sdy.Summary;
                sb.AppendLine("## " + Cn(++sec) + "、站点动态分析（" + sdy.Url + "）");
                sb.AppendLine();
                sb.AppendLine("- 加载地址：" + dm.FinalUrl + "（观测" + dm.DurationSec + " 秒，加载耗时 " + dm.LoadMs + " ms）");
                sb.AppendLine("- 页面标题：" + (string.IsNullOrEmpty(dm.Title) ? "-" : dm.Title));
                sb.AppendLine("- 网络请求：" + dm.Requests + " 次；第三方域：" + dm.ThirdPartyHosts + " 个；传输量：" + dm.TransferBytes.ToString("N0") + " 字节");
                sb.AppendLine("- 运行时接口调用：" + dm.ApiCalls + " 次；控制台异常：" + dm.ConsoleErrors + " 条；Cookie：" + dm.Cookies + " 个；存储键：" + dm.StorageKeys + " 个；可疑项：" + dm.DangerousCount + " 项");
                if (dm.Tech != null && dm.Tech.Count > 0) sb.AppendLine("- 技术指纹：" + string.Join("、", dm.Tech));
                if (dm.Signals != null && dm.Signals.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("**动态风险信号*");
                    sb.AppendLine();
                    foreach (var x in dm.Signals) sb.AppendLine("- " + x);
                }
                if (!string.IsNullOrEmpty(dm.Verdict)) { sb.AppendLine(); sb.AppendLine("**动态结论*：" + dm.Verdict); }
                var third = (sdy.Connections ?? new List<SiteDynConnection>()).Where(x => x.ThirdParty).Take(10).ToList();
                if (third.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("**第三方外联（前" + third.Count + "）*");
                    sb.AppendLine();
                    foreach (var x in third) sb.AppendLine("- " + x.Host + "　" + x.Count + " 次" + (x.PlainHttp ? "　（明文 HTTP）" : ""));
                }
                var calls = (sdy.ApiCalls ?? new List<SiteDynApiCall>()).Take(15).ToList();
                if (calls.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("**运行时接口调用（前" + calls.Count + "）*");
                    sb.AppendLine();
                    foreach (var x in calls) sb.AppendLine("- " + (string.IsNullOrEmpty(x.Method) ? "GET" : x.Method) + " " + x.Url + (x.HasCredential ? "　（含凭据）" : ""));
                }
                var errs = (sdy.Console ?? new List<SiteDynConsoleItem>()).Where(x => string.Equals(x.Level, "error", StringComparison.OrdinalIgnoreCase)).Take(10).ToList();
                if (errs.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("**控制台异常（前" + errs.Count + "）*");
                    sb.AppendLine();
                    foreach (var x in errs) sb.AppendLine("- " + x.Text);
                }
                AppendSiteEvidenceMd(sb, sdy.Evidence);
                sb.AppendLine();
            }

            // 病毒检测与漏洞检测（CVE）：置于详细报告内容之前
            if (c.Virus != null && c.Virus.Ok && c.ShowVirus) AppendVirusMd(sb, c.Virus, ++sec);

            if (c.Vuln != null && c.Vuln.Ok && c.ShowVuln) AppendVulnMd(sb, c.Vuln, ++sec);

            // 详细分析
            if (c.ShowStatic)
            {
                sb.AppendLine("## " + Cn(++sec) + "、详细分析结果");
            sb.AppendLine();
            string group = "";
            foreach (var it in c.Items)
            {
                var g = GetStr(it, "group") ?? "其他";
                if (g != group) { group = g; sb.AppendLine("### " + group); sb.AppendLine(); }
                var title = GetStr(it, "title") ?? GetStr(it, "module") ?? "未命名模块";
                bool ok = it.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
                long elapsed = it.TryGetProperty("elapsed", out var el) && el.ValueKind == JsonValueKind.Number ? el.GetInt64() : 0;
                sb.AppendLine("#### " + title);
                sb.AppendLine();
                if (!ok) { sb.AppendLine("- 状态：未产出证据（" + (GetStr(it, "code") ?? "unsupported") + "）"); sb.AppendLine(); continue; }
                sb.AppendLine("- 耗时：" + elapsed + " ms");
                var ev = GetStr(it, "evidenceFile");
                if (!string.IsNullOrEmpty(ev)) sb.AppendLine("- 证据文件：`" + ev + "`");
                sb.AppendLine();
                var body = GetStr(it, "json");
                if (!string.IsNullOrEmpty(body))
                {
                    var bullets = Summarize(body);
                    if (bullets.Count > 0)
                    {
                        sb.AppendLine("**关键指标**");
                        sb.AppendLine();
                        foreach (var b in bullets) sb.AppendLine("- " + Md(b));
                        sb.AppendLine();
                    }
                    sb.AppendLine("<details><summary>原始证据（截断展示）</summary>");
                    sb.AppendLine();
                    sb.AppendLine("```json");
                    sb.AppendLine(body.Length > 3000 ? body.Substring(0, 3000) + "\n… （已截断，完整内容见证据 JSON）" : body);
                    sb.AppendLine("```");
                    sb.AppendLine();
                    sb.AppendLine("</details>");
                    sb.AppendLine();
                }
            }
            }

            // 病毒与漏洞章节已前移至“详细分析结果”之前
            if (c.ShowDynamic && c.Dyn != null) BuildDynMd(sb, c.Dyn, ref sec);

            if (!string.IsNullOrWhiteSpace(c.Ai))
            {
                sb.AppendLine("## " + Cn(++sec) + "、AI 解读");
                sb.AppendLine();
                sb.AppendLine(c.Ai);
                sb.AppendLine();
            }
            return sb.ToString();
        }

        // ---------------- 动态分析章节----------------

        private static string KindCn(string kind)
        {
            switch (kind)
            {
                case "start": return "启动";
                case "stop": return "结束";
                case "proc": return "进程";
                case "net": return "网络";
                case "file": return "落盘";
                default: return "其他";
            }
        }

        private static string MdCell(string s)
        {
            var v = Md(s);
            if (string.IsNullOrEmpty(v)) return "-";
            return v.Replace("|", "\\|");
        }

        private static string Clip(string s, int n)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Length <= n ? s : s.Substring(0, n) + "…";
        }

        private static void BuildDynMd(StringBuilder sb, DynamicAnalyzer.DynResult d, ref int sec)
        {
            sb.AppendLine("## " + Cn(++sec) + "、动态行为概览");
            sb.AppendLine();
            sb.AppendLine("- 观测时长：" + (d.Unlimited ? "无限制（手动停止或样本退出）" : d.DurationSec + " 秒") + "（结束后强制终止样本及其子进程）");
            sb.AppendLine("- 启动时间：" + d.StartedAt);
            sb.AppendLine("- 判定结论：" + d.Verdict);
            sb.AppendLine("- 执行隔离：" + (string.IsNullOrEmpty(d.IsolationLevel) ? "未记录" : d.IsolationLevel)
                + (string.IsNullOrEmpty(d.Containment) ? "" : "（" + d.Containment + "）"));
            if (!string.IsNullOrEmpty(d.WorkDirectory)) sb.AppendLine("- 沙箱执行区：`" + d.WorkDirectory + "`");
            sb.AppendLine("- 网络隔离：" + (d.NetBlocked ? "已阻断（防火墙出站规则按可执行文件路径生效，会话结束自动清理）" : "未阻断（仅观测" + (string.IsNullOrEmpty(d.NetBlockNote) ? "" : "：" + d.NetBlockNote) + "）"));
            if (!string.IsNullOrEmpty(d.Desktop)) sb.AppendLine("- 私有桌面：" + d.Desktop);
            if (!string.IsNullOrEmpty(d.SandboxSession)) sb.AppendLine("- 沙箱会话：" + d.SandboxSession);
            sb.AppendLine("- 进程 / 子进程外联 / 新增文件 / 注册表变更：" + d.Processes.Count + " / " + d.Connections.Count + " / " + d.Files.Count + " / " + d.Registry.Count);
            sb.AppendLine("- 高危行为：" + d.DangerousCount + " 项");
            sb.AppendLine();

            sb.AppendLine("## " + Cn(++sec) + "、网络外联");
            sb.AppendLine();
            if (d.Connections.Count == 0) sb.AppendLine("运行窗口内未捕获到样本进程的网络连接。");
            else
            {
                sb.AppendLine("| 时刻 | 协议 | 远端 | 进程 | 研判 |");
                sb.AppendLine("| --- | --- | --- | --- | --- |");
                foreach (var x in d.Connections.Take(80))
                    sb.AppendLine("| " + x.Time + " | " + x.Proto + " | `" + MdCell(Clip(x.Remote, 44)) + "` | " + MdCell(Clip(x.Process, 22)) + " | " + (x.Dangerous ? "**" + MdCell(x.Note) + "**" : MdCell(x.Note)) + " |");
                if (d.Connections.Count > 80) sb.AppendLine("> 另有 " + (d.Connections.Count - 80) + " 条连接未列出。");
            }
            sb.AppendLine();

            sb.AppendLine("## " + Cn(++sec) + "、进程树");
            sb.AppendLine();
            if (d.Processes.Count == 0) sb.AppendLine("未捕获到子进程（系统权限不足或样本存活时间过短）。");
            else
            {
                sb.AppendLine("| PID | 父PID | 进程 | 首见 | 文件路径 |");
                sb.AppendLine("| --- | --- | --- | --- | --- |");
                foreach (var p in d.Processes.Take(60))
                    sb.AppendLine("| " + p.Pid + " | " + (p.ParentPid > 0 ? p.ParentPid.ToString() : "-") + " | " + MdCell(p.Name) + " | " + p.FirstSeen + " | " + MdCell(Clip(p.FilePath, 72)) + " |");
            }
            sb.AppendLine();

            sb.AppendLine("## " + Cn(++sec) + "、落盘行为");
            sb.AppendLine();
            if (d.Files.Count == 0) sb.AppendLine("未在监控目录发现新增文件。");
            else
            {
                sb.AppendLine("| 时刻 | 变更 | 类型 | 路径 |");
                sb.AppendLine("| --- | --- | --- | --- |");
                foreach (var f in d.Files.Take(80))
                    sb.AppendLine("| " + f.Time + " | " + (string.IsNullOrEmpty(f.Change) ? "新增" : MdCell(f.Change)) + " | " + MdCell(Clip(f.Kind, 20)) + " | " + MdCell(Clip(f.Path, 88)) + " |");
                if (d.Files.Count > 80) sb.AppendLine("> 另有 " + (d.Files.Count - 80) + " 个新增文件未列出。");
            }
            sb.AppendLine();

            sb.AppendLine("## " + Cn(++sec) + "、注册表持久化");
            sb.AppendLine();
            if (d.Registry.Count == 0) sb.AppendLine("运行窗口内未发现自启动、服务、映像劫持等持久化位置的变更。");
            else
            {
                sb.AppendLine("| 时刻 | 变更 | 位置 | 值名 | 数据 |");
                sb.AppendLine("| --- | --- | --- | --- | --- |");
                foreach (var g in d.Registry.Take(60))
                    sb.AppendLine("| " + g.Time + " | " + MdCell(g.Change) + " | `" + MdCell(Clip(g.Hive + "\\" + g.Key, 60)) + "` | " + MdCell(Clip(g.Name, 26)) + " | " + (g.Dangerous ? "**" + MdCell(Clip(g.Data, 46)) + "**" : MdCell(Clip(g.Data, 46))) + " |");
                if (d.Registry.Count > 60) sb.AppendLine("> 另有 " + (d.Registry.Count - 60) + " 条注册表变更未列出。");
            }
            sb.AppendLine();

            sb.AppendLine("## " + Cn(++sec) + "、行为时间线");
            sb.AppendLine();
            sb.AppendLine("| 时刻 | 类别 | 事件 | 详情 |");
            sb.AppendLine("| --- | --- | --- | --- |");
            foreach (var e in d.Events.Take(160))
                sb.AppendLine("| " + e.Time + " | " + KindCn(e.Kind) + " | " + (e.Dangerous ? "**" + MdCell(e.Title) + "**" : MdCell(e.Title)) + " | " + MdCell(Clip(e.Detail, 76)) + " |");
            if (d.Events.Count > 160) sb.AppendLine("> 另有 " + (d.Events.Count - 160) + " 条事件未列出。");
            sb.AppendLine();

            sb.AppendLine("## " + Cn(++sec) + "、行为链");
            sb.AppendLine();
            if (d.Chain.Count == 0) sb.AppendLine("未生成行为链。");
            else
            {
                sb.AppendLine("| # | 时刻 | 阶段 | 行为 | ATT&CK | 详情 |");
                sb.AppendLine("| --- | --- | --- | --- | --- | --- |");
                int i = 0;
                foreach (var c in d.Chain.Take(120))
                    sb.AppendLine("| " + (++i) + " | " + c.Time + " | " + MdCell(c.Stage) + " | " + (c.Danger >= 60 ? "**" + MdCell(Clip(c.Subject, 40)) + "**" : MdCell(Clip(c.Subject, 40))) + " | " + MdCell(c.Attck) + " | " + MdCell(Clip(c.Detail, 60)) + " |");
                if (d.Chain.Count > 120) sb.AppendLine("> 另有 " + (d.Chain.Count - 120)  + " 个环节未列出。");
            }
            sb.AppendLine();

            if (d.Rollback.Count > 0)
            {
                sb.AppendLine("## " + Cn(++sec) + "、宿主侧回滚清单");
                sb.AppendLine();
                sb.AppendLine("以下文件落在沙箱执行区之外，需人工确认后清理：");
                sb.AppendLine();
                foreach (var f in d.Rollback.Take(100)) sb.AppendLine("- `" + f + "`");
                if (d.Rollback.Count > 100) sb.AppendLine("- 另有 " + (d.Rollback.Count - 100) + " 个文件未列出。");
                sb.AppendLine();
            }

            if (d.Notes.Count > 0)
            {
                sb.AppendLine("## " + Cn(++sec) + "、采集说明");
                sb.AppendLine();
                foreach (var n in d.Notes) sb.AppendLine("- " + n);
                sb.AppendLine();
            }
        }

        private static void BuildDynHtml(StringBuilder sb, DynamicAnalyzer.DynResult d, ref int sec)
        {
            sb.Append("<h2>" + Cn(++sec) + "、动态行为概览</h2><div class=\"meta\">");
            sb.Append("<div><span class=\"k\">观测时长</span>" + (d.Unlimited ? "无限制（手动停止或样本退出）" : d.DurationSec + " 秒") + "（结束后强制终止样本及其子进程）</div>");
            sb.Append("<div><span class=\"k\">启动时间</span>" + Esc(d.StartedAt) + "</div>");
            sb.Append("<div><span class=\"k\">判定结论</span>" + Esc(d.Verdict) + "</div>");
            sb.Append("<div><span class=\"k\">执行隔离</span>" + Esc(string.IsNullOrEmpty(d.IsolationLevel) ? "未记录" : d.IsolationLevel) + (string.IsNullOrEmpty(d.Containment) ? "" : "（" + Esc(d.Containment) + "）") + "</div>");
            if (!string.IsNullOrEmpty(d.WorkDirectory)) sb.Append("<div><span class=\"k\">沙箱执行区</span>" + Esc(d.WorkDirectory) + "</div>");
            sb.Append("<div><span class=\"k\">网络隔离</span>" + (d.NetBlocked ? "已阻断（防火墙出站规则按可执行文件路径生效，会话结束自动清理）" : "未阻断（仅观测" + (string.IsNullOrEmpty(d.NetBlockNote) ? "" : "：" + Esc(d.NetBlockNote)) + "）") + "</div>");
            if (!string.IsNullOrEmpty(d.Desktop)) sb.Append("<div><span class=\"k\">私有桌面</span>" + Esc(d.Desktop) + "</div>");
            sb.Append("<div><span class=\"k\">数据规模</span>进程 " + d.Processes.Count + " 个· 外联 " + d.Connections.Count + " 条· 新增文件 " + d.Files.Count + " 个· 注册表变更 " + d.Registry.Count + " 项· 高危 " + d.DangerousCount + " 项</div>");
            sb.Append("</div>");

            sb.Append("<h2>" + Cn(++sec) + "、网络外联</h2>");
            if (d.Connections.Count == 0) sb.Append("<p class=\"note\">运行窗口内未捕获到样本进程的网络连接。</p>");
            else
            {
                sb.Append("<table><colgroup><col style=\"width:16%\"><col style=\"width:8%\"><col style=\"width:36%\"><col style=\"width:20%\"><col style=\"width:20%\"></colgroup>");
                sb.Append("<tr><th>时刻</th><th>协议</th><th>远端</th><th>进程</th><th>研判</th></tr>");
                foreach (var x in d.Connections.Take(80))
                    sb.Append("<tr><td>" + x.Time + "</td><td>" + x.Proto + "</td><td><code>" + Esc(Clip(x.Remote, 44)) + "</code></td><td>" + Esc(Clip(x.Process, 22)) + "</td><td>" + (x.Dangerous ? "<b>" + Esc(x.Note) + "</b>" : Esc(x.Note)) + "</td></tr>");
                sb.Append("</table>");
                if (d.Connections.Count > 80) sb.Append("<p class=\"note\">另有 " + (d.Connections.Count - 80) + " 条连接未列出。</p>");
            }

            sb.Append("<h2>" + Cn(++sec) + "、进程树</h2>");
            if (d.Processes.Count == 0) sb.Append("<p class=\"note\">未捕获到子进程（系统权限不足或样本存活时间过短）。</p>");
            else
            {
                sb.Append("<table><colgroup><col style=\"width:8%\"><col style=\"width:8%\"><col style=\"width:22%\"><col style=\"width:12%\"><col style=\"width:50%\"></colgroup>");
                sb.Append("<tr><th>PID</th><th>父PID</th><th>进程</th><th>首见</th><th>文件路径</th></tr>");
                foreach (var p in d.Processes.Take(60))
                    sb.Append("<tr><td>" + p.Pid + "</td><td>" + (p.ParentPid > 0 ? p.ParentPid.ToString() : "-") + "</td><td>" + Esc(p.Name) + "</td><td>" + p.FirstSeen + "</td><td>" + Esc(Clip(p.FilePath, 72)) + "</td></tr>");
                sb.Append("</table>");
            }

            sb.Append("<h2>" + Cn(++sec) + "、落盘行为</h2>");
            if (d.Files.Count == 0) sb.Append("<p class=\"note\">未在监控目录发现新增文件。</p>");
            else
            {
                sb.Append("<table><colgroup><col style=\"width:14%\"><col style=\"width:10%\"><col style=\"width:22%\"><col style=\"width:54%\"></colgroup>");
                sb.Append("<tr><th>时刻</th><th>变更</th><th>类型</th><th>路径</th></tr>");
                foreach (var f in d.Files.Take(80))
                    sb.Append("<tr><td>" + f.Time + "</td><td>" + Esc(string.IsNullOrEmpty(f.Change) ? "新增" : f.Change) + "</td><td>" + Esc(Clip(f.Kind, 20)) + "</td><td>" + Esc(Clip(f.Path, 88)) + "</td></tr>");
                sb.Append("</table>");
                if (d.Files.Count > 80) sb.Append("<p class=\"note\">另有 " + (d.Files.Count - 80) + " 个新增文件未列出。</p>");
            }

            sb.Append("<h2>" + Cn(++sec) + "、注册表持久化</h2>");
            if (d.Registry.Count == 0) sb.Append("<p class=\"note\">运行窗口内未发现自启动、服务、映像劫持等持久化位置的变更。</p>");
            else
            {
                sb.Append("<table><colgroup><col style=\"width:12%\"><col style=\"width:8%\"><col style=\"width:40%\"><col style=\"width:16%\"><col style=\"width:24%\"></colgroup>");
                sb.Append("<tr><th>时刻</th><th>变更</th><th>位置</th><th>值名</th><th>数据</th></tr>");
                foreach (var g in d.Registry.Take(60))
                    sb.Append("<tr><td>" + g.Time + "</td><td>" + Esc(g.Change) + "</td><td><code>" + Esc(Clip(g.Hive + "\\" + g.Key, 60)) + "</code></td><td>" + Esc(Clip(g.Name, 26)) + "</td><td>" + (g.Dangerous ? "<b>" + Esc(Clip(g.Data, 46)) + "</b>" : Esc(Clip(g.Data, 46))) + "</td></tr>");
                sb.Append("</table>");
                if (d.Registry.Count > 60) sb.Append("<p class=\"note\">另有 " + (d.Registry.Count - 60) + " 条注册表变更未列出。</p>");
            }

            sb.Append("<h2>" + Cn(++sec) + "、行为时间线</h2>");
            sb.Append("<table><colgroup><col style=\"width:16%\"><col style=\"width:10%\"><col style=\"width:40%\"><col style=\"width:34%\"></colgroup>");
            sb.Append("<tr><th>时刻</th><th>类别</th><th>事件</th><th>详情</th></tr>");
            foreach (var e in d.Events.Take(160))
                sb.Append("<tr><td>" + e.Time + "</td><td>" + KindCn(e.Kind) + "</td><td>" + (e.Dangerous ? "<b>" + Esc(e.Title) + "</b>" : Esc(e.Title)) + "</td><td>" + Esc(Clip(e.Detail, 76)) + "</td></tr>");
            sb.Append("</table>");
            if (d.Events.Count > 160) sb.Append("<p class=\"note\">另有 " + (d.Events.Count - 160) + " 条事件未列出。</p>");

            sb.Append("<h2>" + Cn(++sec) + "、行为链</h2>");
            if (d.Chain.Count == 0) sb.Append("<p class=\"note\">未生成行为链。</p>");
            else
            {
                sb.Append("<table><colgroup><col style=\"width:6%\"><col style=\"width:12%\"><col style=\"width:12%\"><col style=\"width:30%\"><col style=\"width:20%\"><col style=\"width:20%\"></colgroup>");
                sb.Append("<tr><th>#</th><th>时刻</th><th>阶段</th><th>行为</th><th>ATT&amp;CK</th><th>详情</th></tr>");
                int ci = 0;
                foreach (var c in d.Chain.Take(120))
                    sb.Append("<tr><td>" + (++ci) + "</td><td>" + c.Time + "</td><td>" + Esc(c.Stage) + "</td><td>" + (c.Danger >= 60 ? "<b>" + Esc(Clip(c.Subject, 40)) + "</b>" : Esc(Clip(c.Subject, 40))) + "</td><td>" + Esc(c.Attck) + "</td><td>" + Esc(Clip(c.Detail, 60)) + "</td></tr>");
                sb.Append("</table>");
                if (d.Chain.Count > 120) sb.Append("<p class=\"note\">另有 " + (d.Chain.Count - 120) + " 个环节未列出。</p>");
            }

            if (d.Rollback.Count > 0)
            {
                sb.Append("<h2>" + Cn(++sec) + "、宿主侧回滚清单</h2><p class=\"note\">以下文件落在沙箱执行区之外，需人工确认后清理：</p><ul>");
                foreach (var f in d.Rollback.Take(100)) sb.Append("<li><code>" + Esc(f) + "</code></li>");
                sb.Append("</ul>");
            }

            if (d.Notes.Count > 0)
            {
                sb.Append("<h2>" + Cn(++sec) + "、采集说明</h2><ul>");
                foreach (var n in d.Notes) sb.Append("<li>" + Esc(n) + "</li>");
                sb.Append("</ul>");
            }
        }

        // ---------------- HTML（用于PDF）----------------

        public static string BuildHtml(ReportInput input)
        {
            var c = Prepare(input);
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>REA Studio " + c.Title + "</title><style>");
            // ——打印版式：A4 固定页宽，所有元素不得超出页面（防横向溢出）——
            // 版心边距以CSS @page 为准（Chromium 打印时@page margin 优先于PrintSettings），
            // 与PdfExporter 的MarginTopMm/MarginBottomMm/MarginLeftMm/MarginRightMm 保持一致
            sb.Append("@page{size:A4;margin:16mm 14mm}");
            // ——屏幕预览版式：与PDF同一版心，避免预览时正文撑满导致左右留白不均——
            sb.Append("@media screen{html{background:#eceff3;overflow-y:scroll}");
            sb.Append("body{width:210mm;max-width:100%;margin:0 auto;padding:16mm 14mm;background:#fff;box-sizing:border-box;min-height:297mm;box-shadow:0 1px 4px rgba(0,0,0,.12)}}");
            sb.Append("@media screen and (max-width:720px){body{padding:16mm 10mm;min-height:0}}");
            // ——打印版式：显式给出A4版心宽度，避免 body 100% 参照整页导致右侧溢出、右白边丢失——
            sb.Append("@media print{html{width:auto;max-width:none;overflow:visible}");
            sb.Append("body{width:166mm;max-width:166mm;margin:0;padding:0;background:#fff;overflow:visible}}");
            // 分页细节：表头跨页重复、标题不落页尾、段落不留孤行
            sb.Append("thead{display:table-header-group}tfoot{display:table-footer-group}");
            sb.Append("p,li{orphans:2;widows:2}.sum,.meta{page-break-inside:avoid;break-inside:avoid}");
            sb.Append("*{box-sizing:border-box}html{width:100%;max-width:100%;overflow-x:hidden;background:#fff;color-scheme:light}");
            sb.Append("body{font-family:'Microsoft YaHei','Segoe UI',sans-serif;color:#1b1b1f;margin:0;padding:0;font-size:11px;line-height:1.55;background:#fff;width:100%;max-width:100%;overflow-wrap:anywhere;word-break:break-word}");
            sb.Append("h1{font-size:20px;margin:0 0 5px;color:#0b2e4f;letter-spacing:.4px;overflow-wrap:anywhere}");
            sb.Append("h2{font-size:14.5px;margin:18px 0 8px;padding-bottom:5px;border-bottom:2px solid #1f6feb;color:#0b2e4f;page-break-after:avoid;break-after:avoid}");
            sb.Append("h3{font-size:12.5px;margin:13px 0 6px;color:#11355c;page-break-after:avoid;break-after:avoid}h4{font-size:11.5px;margin:9px 0 5px;color:#24405f;page-break-after:avoid;break-after:avoid}");
            sb.Append(".meta{background:#f5f8fc;border:1px solid #dbe6f3;border-radius:8px;padding:9px 11px;margin:10px 0 6px;max-width:100%}");
            sb.Append(".meta div{margin:2px 0;overflow-wrap:anywhere}.k{color:#5a6b7d;display:inline-block;min-width:68px}");
            sb.Append("table{width:100%;max-width:100%;table-layout:fixed;border-collapse:collapse;margin:6px 0 10px;font-size:9.2px;page-break-inside:auto}");
            sb.Append("th{background:#eef4fb;text-align:left;padding:3px 5px;border:1px solid #cfdceb;font-weight:600;color:#11355c;overflow-wrap:anywhere;white-space:normal}");
            sb.Append("td{padding:3px 5px;border:1px solid #dbe6f3;vertical-align:top;white-space:normal;overflow-wrap:anywhere;word-break:break-word}");
            sb.Append("tr{page-break-inside:avoid}");
            sb.Append("code{font-family:Consolas,monospace;background:#f2f5f9;padding:1px 3px;border-radius:3px;font-size:9px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-all;max-width:100%}");
            sb.Append("pre{font-family:Consolas,monospace;background:#f7f9fc;border:1px solid #e2eaf4;border-radius:6px;padding:6px;font-size:8.6px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-all;max-height:190px;overflow:hidden;margin:4px 0;max-width:100%}");
            sb.Append(".badge{display:inline-block;padding:2px 8px;border-radius:11px;font-size:10.5px;margin-right:6px;background:#e8f0fe;color:#1f4f92;border:1px solid #cfe0f7}");
            sb.Append(".b-high{background:#fdecea;color:#b3261e;border-color:#f6c9c4}.b-mid{background:#fff4e5;color:#a15c00;border-color:#f7dcb4}.b-low{background:#e9f6ec;color:#1e7b34;border-color:#c9e8d2}");
            sb.Append(".sum{background:#fbfcfe;border-left:4px solid #1f6feb;padding:10px 14px;margin:10px 0}");
            sb.Append(".sum li{margin:3px 0}.note{color:#5a6b7d;font-size:10.5px;margin:6px 0 0}.mod{page-break-inside:avoid;border-bottom:1px dashed #e4ebf4;padding-bottom:8px}");
            sb.Append("ul{margin:6px 0 10px 18px}li{margin:2px 0}");
            // ——每页页脚：打印时以 fixed 元素在每页底部左侧重复绘制实验室 logo，右侧同排落款——
            sb.Append(".plogo{display:none}.pfoot{display:none}.pfoot-txt{display:none}.plogo-screen{display:block;height:34px;margin:0 0 8px}");
            sb.Append("@media print{.pfoot{display:flex;position:fixed;left:0;right:0;bottom:0;align-items:center;justify-content:space-between;background:#fff;border-top:1px solid #e4ebf4;padding:1.6mm 0 0;z-index:99}.plogo{display:block;height:7mm;width:auto;max-width:52mm}.pfoot-txt{display:block;font-size:8px;color:#5a6b7d;white-space:nowrap;letter-spacing:.2px}.plogo-screen{display:none}body{padding-bottom:13mm}}");
            sb.Append("</style></head><body>");
            sb.Append(LogoHtml());

            int sec = 0;
            sb.Append("<h1>REA Studio " + c.Title + "</h1>");
            sb.Append("<div class=\"meta\">");
            sb.Append("<div><span class=\"k\">目标</span><code>" + Esc(c.Target) + "</code></div>");
            if (c.Size > 0) sb.Append("<div><span class=\"k\">大小</span>" + c.Size.ToString("N0") + " 字节：" + (c.Size / 1048576.0).ToString("F2") + " MB）</div>");
            if (!string.IsNullOrEmpty(c.Sha256)) sb.Append("<div><span class=\"k\">SHA-256</span><code>" + Esc(c.Sha256) + "</code></div>");
            sb.Append("<div><span class=\"k\">报告类型</span>" + c.Title + "</div>");
            sb.Append("<div><span class=\"k\">生成时间</span>" + c.Time.ToString("yyyy-MM-dd HH:mm:ss") + "</div>");
            if (c.ShowStatic)
            {
                sb.Append("<div><span class=\"k\">分析模块</span>" + c.Items.Count + " 项</div>");
                sb.Append("<div><span class=\"k\">样本类型</span>");
                if (c.Types.Count == 0) sb.Append("未识别");
                else foreach (var t in c.Types) sb.Append("<span class=\"badge " + BadgeCls(t.Confidence) + "\">" + Esc(t.Name) + " · " + Conf(t.Confidence) + "</span>");
                sb.Append("</div>");
            }
            sb.Append("</div>");
            sb.Append(c.ShowDynamic
                ? "<p class=\"note\">报告由REA Studio 本机离线生成；样本在受控作业内实际运行，观测结束即强制终止进程树。</p>"
                : "<p class=\"note\">报告由REA Studio 本机离线生成；全部结论来自静态分析证据，样本未被执行。</p>");

            // 摘要
            var risks = new List<string>();
            if (c.ShowStatic && c.Types.Count > 0) risks.Add("类型判定：" + string.Join(" / ", c.Types.Select(t => t.Name)));
            if (c.Net != null && c.Net.Ok && c.ShowNet)
            {
                if (!string.IsNullOrEmpty(c.Net.Verdict)) risks.Add("网络行为：" + c.Net.Verdict);
                risks.Add("外发端点共" + c.Net.TotalEndpoints + " 个（列示 " + c.Net.Endpoints.Count + " 个），危险发包" + c.Net.TotalDangerous + " 个（列示 " + c.Net.Dangerous.Count + " 个）");
                if (c.Net.Privacy.Count > 0) risks.Add("隐私字段 " + c.Net.Privacy.Count + " 类（高敏 " + c.Net.Privacy.Count(p => p.Risk == "高") + " 类）");
            }
            if (c.Site != null && c.Site.Ok && c.ShowSite && !string.IsNullOrEmpty(c.Site.Verdict)) risks.Add("网站侧：" + c.Site.Verdict);
            if (risks.Count > 0)
            {
                sb.Append("<div class=\"sum\"><b>结论摘要</b><ul>");
                foreach (var r in risks) sb.Append("<li>" + Esc(r) + "</li>");
                sb.Append("</ul></div>");
            }

            // 一、九大类型
            if (c.ShowStatic)
            {
                sb.Append("<h2>" + Cn(++sec) + "、逆向类型识别（九类）</h2>");
                sb.Append("<table><tr><th style=\"width:18%\">类型</th><th style=\"width:9%\">置信度</th><th style=\"width:40%\">判定依据</th><th style=\"width:33%\">建议启用模块</th></tr>");
                foreach (var t in c.Types)
                    sb.Append("<tr><td><b>" + Esc(t.Name) + "</b></td><td>" + Conf(t.Confidence) + "</td><td>" + Esc(t.Evidence) + "</td><td><code>" + Esc(t.Modules) + "</code></td></tr>");
                sb.Append("</table>");
                var absent = BinaryTypes.Catalog.Select(x => x.Name).Where(n => !c.Types.Any(t => t.Name == n)).ToList();
                if (absent.Count > 0) sb.Append("<p class=\"note\">未命中类型：" + Esc(string.Join("、", absent)) + "</p>");
            }

            // 二、网络
            if (c.Net != null && c.Net.Ok && c.ShowNet)
            {
                sb.Append("<h2>" + Cn(++sec) + "、网络行为分析</h2>");
                sb.Append("<p class=\"note\">扫描字符串" + c.Net.Strings + " 条，URL " + c.Net.UrlCount + " 个，裸IP " + c.Net.IpCount + " 处（已剔除内网环回/版本号），明文http 占比 " + Esc(c.Net.PlainHttpShare) + "。命名空间类 URI 与非网络主机不计入端点。</p>");

                sb.Append("<h3>流量指向</h3><table><tr><th style=\"width:8%\">协议</th><th style=\"width:26%\">主机</th><th style=\"width:7%\">端口</th><th style=\"width:7%\">次数</th><th style=\"width:9%\">风险</th><th>路径/备注</th></tr>");
                foreach (var e in c.Net.Endpoints.Take(40))
                    sb.Append("<tr><td>" + Esc(e.Scheme) + "</td><td>" + Esc(e.Host) + "</td><td>" + (e.Port == 0 ? "-" : e.Port.ToString()) + "</td><td>" + e.Hits + "</td><td>" + LevelBadge(e.Level, e.Score) + "</td><td>" + Esc(string.Join("，", e.Paths.Take(3))) + "</td></tr>");
                sb.Append("</table>");

                sb.Append("<h3>危险发包筛选（评分 ≥）</h3>");
                if (c.Net.Dangerous.Count == 0) sb.Append("<p>未发现评分达到阈值的危险外发端点。</p>");
                else
                {
                    sb.Append("<table><tr><th style=\"width:9%\">等级</th><th style=\"width:6%\">评分</th><th style=\"width:30%\">目标</th><th>判定理由</th></tr>");
                    foreach (var d in c.Net.Dangerous)
                        sb.Append("<tr><td>" + LevelBadge(d.Level, d.Score) + "</td><td>" + d.Score + "</td><td><code>" + Esc(d.Scheme + "://" + d.Host + (d.Port > 0 ? ":" + d.Port : "")) + "</code></td><td>" + Esc(string.Join("；", d.Reasons)) + "</td></tr>");
                    sb.Append("</table>");
                }

                sb.Append("<h3>隐私信息暴露</h3>");
                if (c.Net.Privacy.Count == 0) sb.Append("<p>未命中个人数据字段。</p>");
                else
                {
                    sb.Append("<table><tr><th style=\"width:13%\">类别</th><th style=\"width:15%\">触发字段</th><th style=\"width:16%\">含义</th><th style=\"width:7%\">风险</th><th style=\"width:7%\">次数</th><th>样例</th></tr>");
                    foreach (var p in c.Net.Privacy)
                        sb.Append("<tr><td>" + Esc(p.Category) + "</td><td><code>" + Esc(p.Key) + "</code></td><td>" + Esc(p.Meaning) + "</td><td>" + RiskBadge(p.Risk) + "</td><td>" + p.Hits + "</td><td>" + Esc(p.Samples.FirstOrDefault() ?? "") + "</td></tr>");
                    sb.Append("</table>");
                }

                sb.Append("<h3>数据包内容特征</h3>");
                if (c.Net.Packets.Count == 0) sb.Append("<p>未提取到结构化请求体。</p>");
                else
                {
                    sb.Append("<table><tr><th style=\"width:8%\">类型</th><th style=\"width:6%\">评分</th><th style=\"width:28%\">字段</th><th>内容摘要</th></tr>");
                    foreach (var p in c.Net.Packets)
                        sb.Append("<tr><td>" + Esc(p.Kind) + "</td><td>" + p.Score + "</td><td><code>" + Esc(string.Join(",", p.Fields.Take(10))) + "</code></td><td>" + Esc(p.Content) + "</td></tr>");
                    sb.Append("</table>");
                }
                if (c.Net.Services.Count > 0) sb.Append("<p><b>命中的第三方 SDK/服务：</b>" + Esc(string.Join("、", c.Net.Services)) + "</p>");
                if (c.Net.UserAgents.Count > 0) sb.Append("<p><b>User-Agent：</b><code>" + Esc(c.Net.UserAgents.First()) + "</code></p>");
            }

            // 三、网站
            if (c.Site != null && c.Site.Ok && c.ShowSite)
            {
                sb.Append("<h2>" + Cn(++sec) + "、网站逆向：" + Esc(c.Site.Url) + "）</h2>");
                sb.Append("<div class=\"meta\">");
                sb.Append("<div><span class=\"k\">最终地址</span><code>" + Esc(c.Site.FinalUrl) + "</code>（HTTP " + c.Site.Status + "）</div>");
                sb.Append("<div><span class=\"k\">页面标题</span>" + (string.IsNullOrEmpty(c.Site.Title) ? "-" : Esc(c.Site.Title)) + "</div>");
                if (!string.IsNullOrEmpty(c.Site.Description)) sb.Append("<div><span class=\"k\">站点描述</span>" + Esc(c.Site.Description) + "</div>");
                sb.Append("<div><span class=\"k\">HTTPS</span>" + (c.Site.IsHttps ? "是" : "否") + "</div>");
                sb.Append("<div><span class=\"k\">外部域</span>" + c.Site.ExternalHosts.Count + " 个：" + Esc(string.Join("、", c.Site.ExternalHosts.Take(14))) + "</div>");
                if (c.Site.Forms.Count > 0) sb.Append("<div><span class=\"k\">表单目标</span>" + Esc(string.Join("、", c.Site.Forms)) + "</div>");
                sb.Append("</div>");
                if (c.Site.Signals.Count > 0)
                {
                    sb.Append("<h4>合规与风险信号</h4><ul>");
                    foreach (var s in c.Site.Signals) sb.Append("<li>" + Esc(s) + "</li>");
                    sb.Append("</ul>");
                }
            }

            if (c.SiteStatic != null && c.SiteStatic.Ok && c.ShowSite)
            {
                var sst = c.SiteStatic;
                var sm = sst.Summary;
                sb.Append("<h2>" + Cn(++sec) + "、站点静态分析（" + Esc(sst.Url) + "）</h2>");
                sb.Append("<div class=\"meta\">");
                sb.Append("<div><span class=\"k\">最终地址</span><code>" + Esc(sm.FinalUrl) + "</code>（HTTP " + sm.Status + "）</div>");
                sb.Append("<div><span class=\"k\">页面标题</span>" + Esc(string.IsNullOrEmpty(sm.Title) ? "-" : sm.Title) + "</div>");
                sb.Append("<div><span class=\"k\">页面体积</span>" + sm.HtmlBytes.ToString("N0") + " 字节</div>");
                sb.Append("<div><span class=\"k\">同源脚本</span>" + sm.JsFiles + " 个/ " + sm.JsBytes.ToString("N0") + " 字节；内联" + sm.InlineScripts + " 段</div>");
                sb.Append("<div><span class=\"k\">接口端点</span>" + sm.ApiEndpoints + " 个；敏感命中 " + sm.Secrets + " 处；外部域" + sm.ExternalHosts + " 个；表单 " + sm.Forms + " 个</div>");
                sb.Append("<div><span class=\"k\">安全头缺失</span>" + sm.MissingHeaders + " 项；属性不全Cookie " + sm.UnsafeCookies + " 个</div>");
                if (sm.Tech != null && sm.Tech.Count > 0) sb.Append("<div><span class=\"k\">技术指纹</span>" + Esc(string.Join("、", sm.Tech)) + "</div>");
                sb.Append("</div>");
                if (sm.Signals != null && sm.Signals.Count > 0)
                {
                    sb.Append("<h4>静态风险信号</h4><ul>");
                    foreach (var x in sm.Signals) sb.Append("<li>" + Esc(x) + "</li>");
                    sb.Append("</ul>");
                }
                if (!string.IsNullOrEmpty(sm.Verdict)) sb.Append("<p class=\"verdict\">" + Esc(sm.Verdict) + "</p>");
                AppendSiteEvidenceHtml(sb, sst.Evidence);
            }

            if (c.SiteDynamic != null && c.SiteDynamic.Ok && c.ShowSite)
            {
                var sdy = c.SiteDynamic;
                var dm = sdy.Summary;
                sb.Append("<h2>" + Cn(++sec) + "、站点动态分析（" + Esc(sdy.Url) + "）</h2>");
                sb.Append("<div class=\"meta\">");
                sb.Append("<div><span class=\"k\">加载地址</span><code>" + Esc(dm.FinalUrl) + "</code>（观测" + dm.DurationSec + " 秒，加载 " + dm.LoadMs + " ms）</div>");
                sb.Append("<div><span class=\"k\">页面标题</span>" + Esc(string.IsNullOrEmpty(dm.Title) ? "-" : dm.Title) + "</div>");
                sb.Append("<div><span class=\"k\">网络请求</span>" + dm.Requests + " 次；第三方域 " + dm.ThirdPartyHosts + " 个；传输 " + dm.TransferBytes.ToString("N0") + " 字节</div>");
                sb.Append("<div><span class=\"k\">运行时接口</span>" + dm.ApiCalls + " 次；控制台异常" + dm.ConsoleErrors + " 条；Cookie " + dm.Cookies + " 个；存储键" + dm.StorageKeys + " 个；可疑项" + dm.DangerousCount + " 项</div>");
                if (dm.Tech != null && dm.Tech.Count > 0) sb.Append("<div><span class=\"k\">技术指纹</span>" + Esc(string.Join("、", dm.Tech)) + "</div>");
                sb.Append("</div>");
                if (dm.Signals != null && dm.Signals.Count > 0)
                {
                    sb.Append("<h4>动态风险信号</h4><ul>");
                    foreach (var x in dm.Signals) sb.Append("<li>" + Esc(x) + "</li>");
                    sb.Append("</ul>");
                }
                if (!string.IsNullOrEmpty(dm.Verdict)) sb.Append("<p class=\"verdict\">" + Esc(dm.Verdict) + "</p>");
                var third = (sdy.Connections ?? new List<SiteDynConnection>()).Where(x => x.ThirdParty).Take(10).ToList();
                if (third.Count > 0)
                {
                    sb.Append("<h4>第三方外联（前" + third.Count + "）</h4><ul>");
                    foreach (var x in third) sb.Append("<li>" + Esc(x.Host) + "　" + x.Count + " 次" + (x.PlainHttp ? "　（明文 HTTP）" : "") + "</li>");
                    sb.Append("</ul>");
                }
                var calls = (sdy.ApiCalls ?? new List<SiteDynApiCall>()).Take(15).ToList();
                if (calls.Count > 0)
                {
                    sb.Append("<h4>运行时接口调用（前" + calls.Count + "）</h4><ul>");
                    foreach (var x in calls) sb.Append("<li><code>" + Esc(string.IsNullOrEmpty(x.Method) ? "GET" : x.Method) + " " + Esc(x.Url) + "</code>" + (x.HasCredential ? "　（含凭据）" : "") + "</li>");
                    sb.Append("</ul>");
                }
                var derrs = (sdy.Console ?? new List<SiteDynConsoleItem>()).Where(x => string.Equals(x.Level, "error", StringComparison.OrdinalIgnoreCase)).Take(10).ToList();
                if (derrs.Count > 0)
                {
                    sb.Append("<h4>控制台异常（前" + derrs.Count + "）</h4><ul>");
                    foreach (var x in derrs) sb.Append("<li>" + Esc(x.Text) + "</li>");
                    sb.Append("</ul>");
                }
                AppendSiteEvidenceHtml(sb, sdy.Evidence);
            }

            // 病毒检测与漏洞检测（CVE）：置于详细报告内容之前
            if (c.Virus != null && c.Virus.Ok && c.ShowVirus) AppendVirusHtml(sb, c.Virus, ref sec);

            if (c.Vuln != null && c.Vuln.Ok && c.ShowVuln) AppendVulnHtml(sb, c.Vuln, ref sec);

            // 详细
            if (c.ShowStatic)
            {
                sb.Append("<h2>" + Cn(++sec) + "、详细分析内容</h2>");
            string group = "";
            foreach (var it in c.Items)
            {
                var g = GetStr(it, "group") ?? "其他";
                if (g != group) { group = g; sb.Append("<h3>" + Esc(group) + "</h3>"); }
                var title = GetStr(it, "title") ?? GetStr(it, "module") ?? "未命名模块";
                bool ok = it.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
                long elapsed = it.TryGetProperty("elapsed", out var el) && el.ValueKind == JsonValueKind.Number ? el.GetInt64() : 0;
                sb.Append("<div class=\"mod\"><h4>" + Esc(title) + (ok ? "" : "（未产出证据）") + "</h4>");
                if (!ok) { sb.Append("<p class=\"note\">状态：" + Esc(GetStr(it, "code") ?? "unsupported") + "</p></div>"); continue; }
                sb.Append("<p class=\"note\">耗时 " + elapsed + " ms");
                var ev = GetStr(it, "evidenceFile");
                if (!string.IsNullOrEmpty(ev)) sb.Append("　证据文件 <code>" + Esc(ev) + "</code>");
                sb.Append("</p>");
                var body = GetStr(it, "json");
                if (!string.IsNullOrEmpty(body))
                {
                    var bullets = Summarize(body);
                    if (bullets.Count > 0)
                    {
                        sb.Append("<ul>");
                        foreach (var b in bullets) sb.Append("<li>" + Esc(b) + "</li>");
                        sb.Append("</ul>");
                    }
                    sb.Append("<pre>" + Esc(body.Length > 2200 ? body.Substring(0, 2200) + "\n… （已截断，完整内容见证据 JSON）" : body) + "</pre>");
                }
                sb.Append("</div>");
            }
            }

            // 病毒与漏洞章节已前移至“详细分析内容”之前
            if (c.ShowDynamic && c.Dyn != null) BuildDynHtml(sb, c.Dyn, ref sec);

            if (!string.IsNullOrWhiteSpace(c.Ai))
            {
                sb.Append("<h2>" + Cn(++sec) + "、AI 解读</h2><div class=\"sum\">");
                foreach (var line in c.Ai.Replace("\r", "").Split('\n'))
                    if (line.Trim().Length > 0) sb.Append("<p>" + Esc(line.Trim()) + "</p>");
                sb.Append("</div>");
            }

            sb.Append("<p class=\"note\" style=\"margin-top:16px;border-top:1px solid #e4ebf4;padding-top:6px\">©科创云玄武安全实验室　REA Studio 由本机离线生成</p>");
            sb.Append("</body></html>");
            return sb.ToString();
        }

        private static string Conf(string c) => c == "high" ? "高" : c == "medium" ? "中" : "低";
        private static string BadgeCls(string c) => c == "high" ? "b-high" : c == "medium" ? "b-mid" : "b-low";
        private static string LevelBadge(string level, int score)
            => "<span class=\"badge " + (level == "高" ? "b-high" : level == "中" ? "b-mid" : "b-low") + "\">" + Esc(level) + " " + score + "</span>";
        private static string RiskBadge(string risk)
            => "<span class=\"badge " + (risk == "高" ? "b-high" : risk == "中" ? "b-mid" : "b-low") + "\">" + Esc(risk) + "</span>";
        private static string Esc(string s) => string.IsNullOrEmpty(s) ? "" : s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

        // ——实验室 logo：内嵌资源 ui/assets/logo_pdf.png，转 data URI 供每页页眉与屏幕预览复用——
        private static string? _logoB64;
        private static string LogoB64
        {
            get
            {
                if (_logoB64 != null) return _logoB64;
                _logoB64 = "";
                try
                {
                    var asm = typeof(Reports).Assembly;
                    var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("logo_pdf.png", StringComparison.OrdinalIgnoreCase));
                    if (name != null)
                    {
                        using var st = asm.GetManifestResourceStream(name);
                        if (st != null)
                        {
                            using var ms = new MemoryStream();
                            st.CopyTo(ms);
                            _logoB64 = Convert.ToBase64String(ms.ToArray());
                        }
                    }
                }
                catch { }
                return _logoB64;
            }
        }

        private static string LogoHtml()
        {
            var b = LogoB64;
            if (string.IsNullOrEmpty(b)) return "";
            var src = "data:image/png;base64," + b;
            return "<div class=\"pfoot\"><img class=\"plogo\" src=\"" + src + "\" alt=\"科创云玄武安全实验室\"/>"
                 + "<span class=\"pfoot-txt\">©科创云玄武安全实验室</span></div>"
                 + "<img class=\"plogo-screen\" src=\"" + src + "\" alt=\"科创云玄武安全实验室\"/>";
        }
        private static string Md(string s) => string.IsNullOrEmpty(s) ? "" : s.Replace("\n", " ").Replace("\r", " ");

        /// <summary>把证据JSON 压成人类可读的关键指标列表。/summary>
        private static List<string> Summarize(string json)
        {
            var list = new List<string>();
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("normalized_result", out var nr) && nr.ValueKind == JsonValueKind.Object)
                    Flatten(nr, "", list, 0);
                else
                    Flatten(root, "", list, 0);
            }
            catch { }
            return list;
        }

        private static readonly string[] SkipKeys = { "sha256", "evidence_id", "local_path", "limitations", "raw_result" };

        private static void Flatten(JsonElement el, string prefix, List<string> outp, int depth)
        {
            if (outp.Count >= 36 || depth > 4) return;
            switch (el.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var p in el.EnumerateObject())
                    {
                        if (Array.IndexOf(SkipKeys, p.Name) >= 0) continue;
                        var name = prefix.Length == 0 ? p.Name : prefix + "." + p.Name;
                        Flatten(p.Value, name, outp, depth + 1);
                        if (outp.Count >= 36) return;
                    }
                    break;
                case JsonValueKind.Array:
                    var n = el.GetArrayLength();
                    if (n == 0) { outp.Add(prefix + "：空"); return; }
                    var first = el[0];
                    if (first.ValueKind == JsonValueKind.Object || first.ValueKind == JsonValueKind.Array)
                    {
                        var keys = first.ValueKind == JsonValueKind.Object
                            ? string.Join("/", first.EnumerateObject().Select(x => x.Name).Take(6))
                            : "嵌套数组";
                        outp.Add(prefix + "：共 " + n + " 项（字段 " + keys + "）");
                    }
                    else
                    {
                        var vals = new List<string>();
                        var k = 0;
                        foreach (var v in el.EnumerateArray())
                        {
                            if (k++ >= 8) break;
                            vals.Add(v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : v.GetRawText());
                        }
                        outp.Add(prefix + "：[" + string.Join(", ", vals) + (n > 8 ? " …共" + n + " 项" : "") + "]");
                    }
                    break;
                default:
                    var raw = el.ValueKind == JsonValueKind.String ? (el.GetString() ?? "") : el.GetRawText();
                    if (raw.Length > 140) raw = raw.Substring(0, 140) + "…";
                    outp.Add(prefix + "：" + raw);
                    break;
            }
        }

        private static string? GetStr(JsonElement el, string name)
            => el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }
}
