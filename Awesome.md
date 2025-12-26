# Awesome 精选工具与资源

## 逆向工程与反编译 (Reverse Engineering & Decompilation)

### 二进制代码生成与混淆
- [amber](https://github.com/EgeBalci/amber) : 基于位置无关代码（PIC）的内存执行载体生成器，通过多层包装与混淆将任意EXE、DLL或ELF格式二进制文件转换为可直接注入运行的反射式Shellcode。

### .NET反编译与调试
- [dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy) : 基于.NET的反编译器、程序集编辑器与调试器，支持对C#、VB.NET二进制文件进行源码级逆向工程、IL指令实时修改及运行进程附加调试。

### AI辅助逆向
- [LLM4Decompile](https://github.com/albertan017/LLM4Decompile) : 专注于二进制代码逆向的预训练大语言模型，通过分析汇编代码重构对应的可读C语言源代码，提升复杂二进制逻辑的可解释性。

### 二进制分析工具
- [go_parser](https://github.com/0xjiayu/go_parser) : 针对IDA Pro定制的Go语言二进制文件解析脚本，通过恢复程序编译过程中的类型信息、函数符号及pclntab元数据，实现对Go静态链接二进制文件的符号还原与逆向结构分析。

### AI集成插件
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) : 为Ghidra逆向分析平台设计的模型上下文协议（MCP）扩展，通过标准化接口将反汇编器上下文暴露给下游大语言模型，实现自动化的汇编代码解释与逻辑分析。
- [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) : IDA Pro静态分析插件，通过MCP协议将IDB数据库中的函数逻辑、交叉引用及反汇编元数据导出至外部AI Agent，构建基于模型对话的闭环逆向辅助环境。

## 安全研究工具 (Security Research Tools)

### 可执行文件分析
- [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) : Python可执行文件解包脚本，支持提取PyInstaller封装包中的编译后字节码（pyc）及依赖资源，具备自动修复pyc文件头魔数的功能以适配各版本解释器。

### 网络流量分析
- [r0capture](https://github.com/r0ysue/r0capture) : 基于Frida的安卓全平台通用抓包工具，通过Hook系统底层TLS/SSL通信库实现无视证书校验的HTTPS明文数据截获及应用层Socket流量解析。
- [ecapture](https://github.com/gojue/ecapture) : 基于eBPF技术的无侵入式流量捕获工具，支持在不导入CA证书的情况下，通过Hook系统用户态共享库（如OpenSSL、GnuTLS）提取平文SSL/TLS密钥并解析HTTPS、gRPC等加密网络协议。

### 移动设备安全
- [objection](https://github.com/sensepost/objection) : 基于Frida构建的运行时移动设备探索工具包，支持在无需对应用进行重打包的情况下，对iOS和Android应用进行动态注入、内存操作、方法Hook、文件系统访问及绕过SSL Pinning。

### 漏洞研究与复现
- [LinuxFlaw](https://github.com/VulnReproduction/LinuxFlaw) : Linux内核漏洞复现与漏洞库集合，包含内核态提权、内存溢出等经典缺陷的POC脚本、复现文档及对应的受影响内核环境配置。

### CTF与安全竞赛
- [ctf-writeups-search](https://github.com/sarperavci/ctf-writeups-search) : 基于Web的CTF解题报告聚合搜索引擎，通过爬虫与结构化索引实现对全球各大赛事Writeups的精准检索，支持按题目类型、年份及特定关键词进行快速定位。

### 权限维持与提升
- [SearchAvailableExe](https://github.com/Neo-Maoku/SearchAvailableExe) : 权限维持与权限提升辅助脚本，通过自动化枚举系统路径下权限设置不当的可写可执行文件（EXE/DLL），识别用于劫持或替换的潜在二进制目标。

### 恶意代码加载
- [MaLoader](https://github.com/lv183037/MaLoader) : 针对macOS平台的反探测恶意代码加载器，通过私有API调用实现Mach-O文件的内存镜像映射与无落盘执行，绕过常规终端安全审计。

## 开发工具 (Development Tools)

### 文档处理
- [markitdown](https://github.com/microsoft/markitdown) : 异构文档转换工具，利用多模态处理能力将PDF、Word、Excel及图像等非结构化文件精准提取并转换为标准化Markdown格式。
- [ilovepdf](https://www.ilovepdf.com/) : 在线多功能PDF文档处理平台，集成PDF合并、拆分、压缩、Office格式双向转换、OCR文字识别、电子签名及文档加密解锁等核心编辑功能的Web自动化工具集。

### AI辅助开发
- [next-ai-draw-io](https://github.com/DayuanJiang/next-ai-draw-io) : 集成大语言模型的流程图绘制系统，支持通过自然语言描述自动生成、修改及优化基于Draw.io/Diagrams.net标准的矢量架构图与逻辑图。
- [aicodeguide](https://github.com/automata/aicodeguide) : AI辅助编程技术路线图与实践指南，旨在为开发者提供从基础工具选择到高级Agent协作的完整知识体系，涵盖自动化代码生成、Vibe Coding开发模式及安全性最佳实践等核心领域。
- [awesome-vibe-coding](https://github.com/filipecalegario/awesome-vibe-coding) : 专注于"Vibe Coding"开发范式的资源库，汇总了利用自然语言指令与生成式AI（如Claude 3.5 Sonnet）进行高频交互、快速原型迭代及无代码化工程实现的相关工具、案例与方法论。

### 图形化工具
- [asciiflow](https://asciiflow.com/) : 基于Web的ASCII流程图编辑工具，提供无限画布与网格引导，支持通过点击拖拽生成标准文本格式的架构图、时序图及示意图，兼容直接导出为纯文本文件。

## 调试与测试 (Debugging & Testing)

### 协议调试
- [modelcontextprotocol/inspector](https://github.com/modelcontextprotocol/inspector) : MCP（模型上下文协议）官方调试客户端，提供图形化界面用于交互式测试MCP服务器的资源接入、工具调用及提示词转换逻辑。