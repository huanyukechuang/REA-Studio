# REA Studio

> 本地逆向分析与恶意样本研判工作台 — 离线优先，样本不出机<p>
> 本项目已加入 <b>科创+开源计划</b><p>
> ©科创云玄武安全实验室

![platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%207--11-0078d4)
![runtime](https://img.shields.io/badge/runtime-%E5%86%85%E5%B5%8C%C2%B7%E6%97%A0%E9%9C%80%E5%AE%89%E8%A3%85-2ea44f)
![model](https://img.shields.io/badge/built--in%20model-Qwen3.5--0.8B%20(Q4__K__M)-8957e5)
![version](https://img.shields.io/badge/version-1.0.0-orange)

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [功能模块](#功能模块)
- [下载与版本](#下载与版本)
- [快速开始](#快速开始)
- [系统要求](#系统要求)
- [技术架构](#技术架构)
- [从源码构建](#从源码构建)
- [仓库结构](#仓库结构)
- [数据目录与日志](#数据目录与日志)
- [常见问题](#常见问题)
- [已知限制与路线图](#已知限制与路线图)
- [第三方组件与许可](#第三方组件与许可)
- [免责声明](#免责声明)
- [更新日志](#更新日志)

---

## 项目简介

REA Studio 是一款面向安全分析人员的**本地逆向分析一体化软件**。它在单台 Windows 电脑上完成从「样本载入」到「证据产出」再到「报告交付」的完整链路，把静态逆向、网络行为分析、病毒检测、漏洞检测与本地大模型研判收拢到同一个界面中。

软件的核心取向是**离线优先、数据不出机**：

- 分析不依赖云端算力，内置模型随包分发，断网可用；
- 样本只在沙箱只读副本上分析，**不执行样本**，不影响主系统；
- 病毒情报与漏洞情报提供在线源，但均为**可选增强**，关闭后所有本地检测能力照常运行；
- 交付形态为单文件自包含 EXE，无需安装 .NET 运行时、Node 运行时或浏览器内核。

> **English overview** — REA Studio is an offline-first reverse-engineering and malware triage workbench for Windows x64. It ships as a single self-contained executable bundling a WPF + WebView2 shell, a Node-based analysis engine (`rea-agents`), and a local GGUF inference server (`llama.cpp`). Samples are analysed from read-only sandbox copies and are never executed. Optional online threat/vulnerability feeds (ThreatBook, CNNVD/NVD) can be enabled by the user.

---

## 核心特性

| 特性 | 说明 |
| --- | --- |
| 完全离线可用 | 内置 Qwen3.5-0.8B（Q4_K_M，503 MB），无网络环境仍可完成 AI 研判 |
| 静态分析 24 模块 | PE / .NET / Go / Rust / Electron / IL2CPP / APK / WASM / SQLite / GGUF / Python 字节码全覆盖 |
| 双层病毒检测 | 内置 200 余条规则（覆盖 8 大攻击族谱）+ 哈希清单 + 外部 YARA 规则 + 可选在线情报 |
| 指纹驱动漏洞检测 | 内置 184 个 CVE 标识，先识别组件与版本再按区间匹配，降低误报 |
| 证据驱动 AI 研判 | AI 输入固定为本次分析的结构化证据集，输出结论可逐条回溯到证据 |
| 三格式报告 | Markdown / HTML / PDF 一键导出，章节顺序一致，PDF 页脚带实验室落款 |
| 模型可换 | 内置模型 / 用户自备本地 GGUF / 自定义云端模型（OpenAI 兼容）三路可选 |
| 免管理员安装 | 安装版写入当前用户态，HKCU 卸载项 + 快捷方式，无需提权 |
| 配置稳健 | 设置采用合并写入语义，改单项不会清空其他配置 |

---

## 功能模块

| 模块 | 能力概要 |
| --- | --- |
| **目标载入** | 拖拽文件/目录或载入站点地址；自动类型识别，给出类型、大小、熵值、签名状态总览 |
| **静态分析** | 24 个分析模块，按「概览 / PE 结构 / .NET / 语言运行时 / 其他」五组呈现；另产出接口端点汇总、敏感凭据线索、安全响应头检查、技术指纹 |
| **网络行为分析** | 站点静态抓取、站点动态分析（WebView2 隐身窗口，记录请求、运行时调用、存储与 Cookie 写入、控制台异常）、样本网络证据提取 |
| **动态分析** | 沙箱只读副本承载，支持开始、状态查询、目录打开、清理与开关切换；**不执行样本本体** |
| **病毒检测** | 内置规则库 + MD5/SHA1/SHA256 黑白名单导入（txt/csv/json）+ YARA 规则 + 微步情报在线核查 |
| **漏洞检测** | 184 个 CVE 内置库，覆盖 OpenSSL、zlib、libpng、libxml2、SQLite、curl、OpenSSH、Log4j、Struts、Spring、Tomcat、WebLogic、fastjson、jQuery 等组件 |
| **证据页** | 四类产出统一为证据视图，可按类型筛选、逐条下钻；是 AI 解读与报告生成的唯一输入源 |
| **AI 解读** | 基于证据生成研判结论（定性、行为、风险等级、可疑点排序、建议动作），支持本地/云端模型切换 |
| **报告导出** | MD / HTML / PDF 三格式，六章统一顺序：结论摘要 → 逆向类型识别 → 网络行为分析 → 病毒检测 → 漏洞检测 → 详细分析结果 |
| **设置** | 模型管理、规则与情报源、沙箱配置、运行时状态提示；在线模型库 36 个 GGUF 仓库 / 12 家厂商，支持断点续传下载 |

**AI 定位**：模型输出仅作**辅助研判**，关键结论须人工复核。软件是分析工具，不是免杀工具、不是破解工具，不对样本做任何修改或变形处理。

---

## 下载与版本

同一套代码产出「自带模型」与「无模型」两种网络条件：

| 产物 | 形态 | 内置模型 | 体积 |
| --- | --- | --- | --- |
| `REASetup.exe` | 安装版 | 含 Qwen3.5-0.8B | 约 734 MB |
| `REA Setup(no model).exe` | 安装版 | 无 | 约 231 MB |

**怎么选**

- 机器离线、希望开箱即用 → 选**含模型版**；
- 已有本地 GGUF 模型、或只打算用云端模型 → 选**无模型版**，体积小约 500 MB；

**无模型版怎么补 AI 能力**：进入「设置 → 模型管理」，本地已有 GGUF 可直接选择；或在在线模型库中下载任意模型（ModelScope 源，支持中断续传），下载完成后即刻可用。

> 请从本仓库 Releases 页面下载正式产物，不要使用来源不明的第三方转载包。

---

## 快速开始

### 安装版

1. 下载 `REASetup.exe` 并运行；
2. 三步向导：确认安装路径 → 部署 → 完成；
3. 安装过程在当前用户态完成，无需管理员权限；写入 HKCU 卸载项与开始菜单/桌面快捷方式。

### 首次使用流程

1. **载入目标**：拖入样本文件、选择目录，或输入站点地址；
2. **跑静态分析**：按需勾选模块（默认全量），等待证据表生成；
3. **补网络与动态视角**：站点目标做静态/动态分析；样本查看网络行为证据；
4. **病毒与漏洞检测**：导入哈希清单或 YARA 提升命中率，漏洞检测基于技术指纹自动匹配；
5. **看证据页**：按类型筛选、逐条核对，剔除误报；
6. **AI 研判**：选择本地或云端模型，基于证据生成结论；
7. **导出报告**：一次导出 MD / HTML / PDF。

---

## 系统要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 7 SP1 / 8.1 / 10 / 11，64 位（设计目标向下兼容至 Win7，实际验证环境 Windows 11） |
| 架构 | x64 |
| 运行时 | 无需额外安装，.NET 运行时、Node 运行时、推理引擎全部内嵌 |
| 浏览器内核 | WebView2（系统缺失时由安装包引导部署） |
| 磁盘 | 含模型版约需 1.5 GB 可用空间；无模型版约 400 MB |
| 内存 | 静态分析 4 GB 起；启用本地模型推理建议 8 GB 以上 |
| 显卡 | 非必需，CPU 推理可用 |

---

## 技术架构

```
┌──────────────────────────────────────────────────────────────┐
│  WPF 宿主进程（REAStudio.exe，单文件自包含）                  │
│                                                              │
│  ┌────────────────────────┐   ┌───────────────────────────┐  │
│  │ WebView2 渲染层         │   │ C# 服务层（Bridge）        │  │
│  │ HTML / CSS / JS         │◄─►│ 命令分发 · 编排 · 落盘     │  │
│  │ 目标 静态 证据 网络      │   │ 静态 · 病毒 · 漏洞 · 沙箱   │  │
│  │ 动态 AI 设置            │   │ 报告 · 情报同步            │  │
│  └────────────────────────┘   └───────┬───────────┬───────┘  │
│                                        │           │          │
│                          ┌─────────────▼──┐  ┌─────▼────────┐ │
│                          │ 内嵌 Node 运行时 │  │ llama-server │ │
│                          │ rea-agents 6.9.0│  │ (llama.cpp)  │ │
│                          │ 深度逆向后端引擎 │  │ 本地推理     │ │
│                          └─────────────────┘  └──────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

- **渲染层（WebView2）**：七个主页面 —— 目标、静态分析、证据、网络分析、动态分析、AI 解读、设置。视觉遵循 WinUI3 设计语言。
- **服务层（C# / WPF）**：统一命令总线，对外暴露 59 个命令域入口；所有落盘、规则库读写、情报同步由该层收口。
- **能力层**：`rea-agents`（Node 逆向引擎，提供 PE / .NET / 多语言运行时构件结构解析）、`llama-server`（llama.cpp 推理服务）、WebView2 内核（界面渲染 + 站点动态分析 + PDF 离屏渲染）。

依赖全部内置，用户无需另行安装运行时环境。

---

## 从源码构建

### 构建环境

| 依赖 | 说明 |
| --- | --- |
| Windows x64 | 构建机与目标平台一致（`win-x64`） |
| .NET 6 SDK | 主工程目标框架 `net6.0-windows` |
| Python 3.8+ | 执行 `build.py` / `build_setup.py`（仅用标准库） |
| Node.exe | 便携版 Node 运行时，放入载荷目录 |
| llama-server.exe | llama.cpp 的 Windows x64 可执行文件 |
| GGUF 模型 | 可选；不打含模型版时无需准备 |

### 构建步骤

```powershell
git clone <本仓库地址> F:\REA-Inverse
cd F:\REA-Inverse

# 1. 准备载荷：build\payload 下需存在
#    node\node.exe          便携 Node 运行时
#    llama\llama-server.exe llama.cpp 推理服务
#    model\model.gguf       内置模型（无模型版可跳过）
#    并将 rea-agents 解压到 build\rea-agents

# 2. 编译主工程
cd src\ReaStudio
dotnet build ReaStudio.csproj -c Release -v m

# 3. 打包便携版（输出到仓库 output\ 目录）
cd F:\REA-Inverse
python build.py            # 产出含模型版 + 无模型版
python build.py nomodel    # 只产出无模型版
python build.py skipzip    # 不重打载荷，仅重发布程序本体（UI 改动后使用）

# 4. 编译安装器并打包安装版
cd installer\ReaSetup
dotnet build ReaSetup.csproj -c Release -v m
cd F:\REA-Inverse
python build_setup.py
```

**打包机制要点**

- 便携版：`dotnet publish` 生成单文件骨架，再以 24 字节尾标（`REAPAY01` + 载荷偏移 + 载荷长度）把 `payload.zip` 追加到 EXE 尾部，运行时自尾部定位释放；
- 安装版：独立 WPF 安装器，同样以尾标（`REASET01` / `REASET02`）附加主程序载荷，运行时按 4 MB 缓冲复制释放；
- 载荷超过 700 MB 时自动分卷内嵌，旧分卷归档到 `build\temp\old-parts-<时间戳>\`；
- GGUF 在 zip 内使用 `ZIP_STORED`（不压缩），其余文件 `ZIP_DEFLATED`，避免大模型重复压缩耗时。

> 打包前请先结束正在运行的 `REAStudio*` / `REASetup*` 进程，否则输出文件被占用会报 `PermissionError`。

---

## 仓库结构

```
REA-Inverse/
├── src/ReaStudio/               主工程（WPF + WebView2）
│   ├── App.xaml(.cs)            应用入口
│   ├── MainWindow.xaml(.cs)     窗口宿主与载荷释放、调试钩子
│   ├── app.manifest             应用清单（DPI / 权限声明）
│   ├── resources/
│   │   └── app.ico              程序图标（多分辨率 16–256）
│   ├── Services/                C# 服务层（静态分析、病毒、漏洞、沙箱、报告、模型等）
│   └── ui/                      前端页面
│       ├── index.html           七页单文档结构
│       ├── styles.css           WinUI3 风格样式
│       ├── app.js               Bridge 调用与视图逻辑
│       └── assets/              页面 logo、PDF 页脚 logo
├── installer/ReaSetup/          安装器工程（WPF）
│   ├── MainWindow.xaml(.cs)     三步向导
│   ├── SetupCore.cs             载荷定位、释放、快捷方式与卸载项
│   └── resources/               安装器图标与向导页 logo
├── build.py                     便携版打包脚本
├── build_setup.py               安装版打包脚本
├── build/                       载荷组装工作区（node / rea-agents / llama / model）
└── output/                      构建产物输出目录
```

---

## 数据目录与日志

数据根目录按以下优先级解析，取第一个可用项：

1. 环境变量 `REASTUDIO_HOME` 指定的目录；
2. 程序同级目录 `REAStudio-Data`（可写探测通过则采用，即便携模式）；
3. `%LocalAppData%\REAStudio`（安装模式默认位置，无需管理员权限）。

| 路径 | 用途 |
| --- | --- |
| `settings.json` | 全部设置项（模型、规则、情报源、沙箱、界面偏好） |
| `models\` | 用户本地 GGUF 模型目录 |
| `logs\app-yyyyMMdd.log` | 按日切分运行日志（载荷解压、模型状态、推理耗时、错误堆栈） |
| 规则与清单 | 导入的 YARA 规则、哈希清单、自定义漏洞规则 |
| 沙箱工作区 | 样本只读副本与分析中间结果 |
| 报告输出 | 导出的 Markdown / HTML / PDF 报告 |

内置模型存放于程序内 `runtime\<版本>\model\` 目录，与用户模型目录分离，升级不覆盖用户数据。

**调试钩子**（面向开发与问题定位）：`REASTUDIO_PAGE` 直接导航到指定页面、`REASTUDIO_EVAL` 执行指定脚本并把结果写入日志、`REASTUDIO_AUTORUN` 启动即执行预设流程。

---

## 常见问题

**Q：双击后很久没有窗口？**
含模型便携版首次运行需要解压约 500 MB 载荷到 `REAStudio-Data\runtime\`，机械硬盘下可能需要数十秒到数分钟。查看 `REAStudio-Data\logs\app-yyyyMMdd.log` 可确认进度，请勿重复双击。

**Q：被安全软件拦截/查杀？**
主程序会把内嵌运行时（node、llama-server）释放到数据目录后执行，这一行为可能触发启发式拦截。请将程序目录与数据目录加入白名单后重试。

**Q：提示「所选模型文件未找到」？**
界面会同时回显配置值与已搜索路径。把 GGUF 放入 `models\` 目录，或在「设置 → 模型管理」重新选择；路径支持环境变量展开与多候选回退。

**Q：提示「未检测到本地模型」？**
无模型版的正常初始状态。可从在线模型库下载，或在设置中改用云端模型（OpenAI 兼容接口，需自行填写地址与密钥）。

**Q：界面白屏 / 报告 PDF 空白？**
多为 WebView2 运行时缺失或损坏。安装 Microsoft Edge WebView2 Runtime 后重试；安装版在系统缺失时会引导部署。

**Q：报告里的 AI 结论可以直接当判定结论吗？**
不可以。模型输出仅为辅助研判，关键结论须由具备资质的人员复核，报告中的每条结论都可回溯到证据页的具体条目。

**Q：软件会联网吗？**
默认不主动外联。仅在用户显式开启病毒检测在线情报（微步）、漏洞库在线同步（CNNVD/NVD）或在线模型库下载时才会访问对应服务。样本信息不会上传。

---

## 已知限制与路线图

**当前限制**

- 沙箱为**只读副本隔离**，不提供动态执行隔离；动态执行、进程树与行为链记录尚未实现；
- 病毒内置规则与内置 CVE 库为随包快照，新威胁需自行导入规则或依赖在线情报；
- 漏洞匹配依赖静态分析得到的技术指纹，无指纹的目标（加壳、混淆、自研格式）命中率有限；
- 本地推理为纯 CPU，性能取决于机型。

**路线图**

- [ ] 动态执行隔离与行为链采集
- [ ] 规则库与 CVE 库在线增量更新
- [ ] 报告模板自定义与批量样本批处理
- [ ] GPU 推理加速

---

## 第三方组件与许可

| 组件 | 版本 | 许可 | 用途 |
| --- | --- | --- | --- |
| `rea-agents` | 6.9.0 | MIT（MCP 标识 `io.github.morluto/rea`） | 深度逆向后端引擎 |
| `llama.cpp`（`llama-server`） | 随包 | MIT | 本地 GGUF 模型推理 |
| Node.js 运行时 | 随包 | MIT | 承载 rea-agents |
| Microsoft Edge WebView2 | 系统/随包 | Microsoft 许可 | 界面渲染、站点动态分析、PDF 渲染 |

第三方组件的完整许可与声明随包提供。引用上游代码或规则库时请遵循其原始许可。

**本软件本体**：版权归**环宇科创-科创云玄武安全实验室**所有，落款统一为「©科创云玄武安全实验室」。软件本体与源码的再分发、商用授权请以仓库 LICENSE 文件（如提供）或与作者联系确认为准。

---

## 免责声明

- 本软件仅供**授权的安全研究、应急响应、样本研判与教学培训**使用；
- 使用者须确保对分析目标具备合法授权，并自行承担使用过程中的全部法律责任；
- 软件不提供任何免杀、破解、绕过安全机制的能力，也不对样本做修改或变形；
- AI 输出为辅助研判建议，不构成确定性结论；
- 因违反法律法规或超出授权范围使用本软件造成的后果，由使用者自行承担。

---

## 更新日志

### v1.0.0

- 首个对外发布版本，双产物交付： `REASetup.exe` / `REA Setup(no model).exe`
- 静态分析 24 个模块，覆盖 PE、.NET、Go、Rust、Electron、IL2CPP、APK、WASM、SQLite、GGUF、Python 字节码
- 病毒检测内置 200 余条规则（8 大攻击族谱），支持哈希清单与 YARA 规则导入
- 漏洞检测内置 184 个 CVE 标识，指纹驱动区间匹配
- 内置 Qwen3.5-0.8B（Q4_K_M）离线研判；在线模型库 36 个仓库 / 12 家厂商，支持断点续传
- 报告导出 MD / HTML / PDF，六章统一顺序，PDF 页脚带实验室落款
- 新增无模型版产物与安装器尾标双版（`REASET01` / `REASET02`）
- 修复设置写入大小写敏感导致 `localModel` 字段被丢弃、出现「已选模型却提示未检测到」的问题，改为合并写入语义
- 更新程序图标与实验室标识

---

<p align="center">
  <img src="src/ReaStudio/ui/assets/logo.png" width="320" alt="科创云·玄武 网络安全实验室">
</p>

<p align="center">©环宇科创-科创云玄武安全实验室</p>
