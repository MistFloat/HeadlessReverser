# HeadlessReverser
> 无需打开 Ghidra GUI，让 Codex 直接分析二进制文件

无GUI无头Ghidra逆向工具链，专为OpenAI Codex、AI编程助手设计。
全程命令行输出标准化JSON，无需启动图形界面即可完成二进制静态分析，内置缓存加速重复解析，原生支持接入MCP作为AI逆向技能集。

## 适用场景
- Codex/Copilot自然语言自动逆向PE/ELF/Mach-O/固件
- 轻量快速函数逻辑分析，省去打开Ghidra GUI耗时
- CI自动化恶意样本批量静态扫描流水线
- MCP协议对接AI，一句话完成跨流程二进制分析

## 文件结构
```
HeadlessReverser/
├── README.md                         # 项目说明文档
└── tool/                             # 核心工具根目录（所有操作以此为工作目录）
    ├── CODEX.md                      # AI专属说明书：逆向工作流 + 标准化分析报告模板
    ├── skills/scripts/               # Python上层工具链
    │   ├── ghidra_headless.py        # 核心封装：统一调用Ghidra analyzeHeadless
    │   ├── triage.py                 # 二进制初筛：文件格式、CPU架构、壳识别
    │   ├── strings_scan.py           # 字符串提取、分类、关联上下文
    │   ├── symexec_find.py           # angr符号执行，路径约束、漏洞搜索
    │   ├── capstone_disasm.py        # 裸固件原始二进制反汇编
    │   ├── hex2bin.py                # Intel HEX固件转Flat二进制
    │   └── ghidra_decompile.py       # 内部Jython后处理脚本（供Java脚本调用）
    └── ghidra/scripts/               # Ghidra Java后置分析脚本
        ├── summary.java              # 二进制全局概况
        ├── functions.java            # 全量函数列表（地址+符号名）
        ├── decompile.java            # 指定地址导出伪C代码
        ├── strings.java              # 模糊匹配搜索字符串
        ├── xrefs_to.java             # 查找所有引用目标地址的代码
        ├── xrefs_from.java           # 查找目标地址引用的所有对象
        └── finders.java              # 高级检索：调用指定函数/引用指定字符串
```

> **路径强制约束**
`ghidra_headless.py` 内置固定路径查找逻辑：
```python
SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent / "ghidra" / "scripts"
```
从核心脚本向上3级目录匹配`ghidra/scripts`，因此执行所有命令时**工作目录必须为`tool/`**，保证`skills/scripts/`与`ghidra/scripts`同级，否则直接报文件找不到。

---

# 一、人类用户：本地CLI直接使用
## 1. 前置依赖
### 必装（核心功能必需）
- Python 3.8+
- Ghidra 11.x
- JDK 17+（Ghidra强制配套版本）

### 可选（扩展功能）
- angr + claripy：符号执行分析
- capstone：裸固件离线反汇编
- intelhex：HEX固件格式转换

## 2. 安装与环境配置
### Linux / MacOS
```bash
# 拉取仓库
git clone https://github.com/MistFloat/HeadlessReverser.git
cd HeadlessReverser

# 全局环境变量
export GHIDRA_HOME=/path/to/ghidra_11.x       # 【必填】Ghidra根目录
export GHIDRA_PROJECTS=~/.ghidra-projects      # 【可选】缓存项目存放路径
export GHIDRA_TIMEOUT=300                      # 【可选】单文件分析超时秒数

# 安装可选扩展依赖
pip install angr claripy
pip install capstone
pip install intelhex
```

### Windows CMD 临时配置
```cmd
git clone https://github.com/MistFloat/HeadlessReverser.git
cd HeadlessReverser

:: 必填Ghidra路径
set GHIDRA_HOME=E:\ghidra_11.2_PUBLIC
set GHIDRA_PROJECTS=%USERPROFILE%\.ghidra-projects
set GHIDRA_TIMEOUT=300

pip install angr claripy capstone intelhex
```

### Windows PowerShell
```powershell
$env:GHIDRA_HOME = "E:\ghidra_11.2_PUBLIC"
$env:GHIDRA_PROJECTS = "$env:USERPROFILE\.ghidra-projects"
$env:GHIDRA_TIMEOUT = "300"
```

## 3. 基础使用示例
> 所有命令**必须先进入tool目录**执行
```bash
cd tool

# 1. 二进制快速初筛
python skills/scripts/triage.py sample.exe

# 2. 全局字符串扫描
python skills/scripts/strings_scan.py sample.exe

# 3. 获取二进制整体信息（架构、基址、函数总数）
python skills/scripts/ghidra_headless.py summary sample.exe

# 4. 反编译指定地址函数伪C代码
python skills/scripts/ghidra_headless.py decompile sample.exe 0x401000

# 5. 查询哪些代码会调用0x401000
python skills/scripts/ghidra_headless.py xrefs_to sample.exe 0x401000

# 6. 查找所有调用strcmp的函数
python skills/scripts/ghidra_headless.py functions_calling sample.exe "strcmp"

# 7. 缓存项目管理
python skills/scripts/ghidra_headless.py list_projects
python skills/scripts/ghidra_headless.py delete_project my_project_sha256
```

---

# 二、AI Agent（Codex/MCP）自动部署指南
> 本节专供Codex、GitHub Copilot等AI读取执行；普通人类可跳过。

> **前置要求**：AI Agent 自身应已具备一套逆向工程方法论 skill（如 `reverse-engineering/SKILL.md`、`ida-reverse/SKILL.md` 等），本项目提供的是操作 Ghidra headless 的**工具链层**而非方法论。两者配合使用：skill 告诉你"该分析什么"，本工具链提供"怎么拿到数据"。

## 1. 目录结构核心逻辑
`ghidra_headless.py` 向上三级目录定位Java分析脚本，因此AI部署后工作目录必须为`tool/`，固定目录结构如下：
```
<工作目录tool/>
├── CODEX.md
├── skills/scripts/
│   └── ghidra_headless.py ...其余Python脚本
└── ghidra/scripts/
    └── *.java 分析脚本
```

## 2. 两种部署方式（二选一）
### 方式A：仅拉取tool最小目录
仅下载仓库内`tool/`完整文件夹（包含CODEX.md、skills、ghidra），存放至本地任意路径，将该tool文件夹设置为MCP服务工作目录。
调用格式固定：
```
python skills/scripts/ghidra_headless.py <command> <binary_path> [args...]
```

### 方式B：完整克隆仓库后切换工作目录
```bash
git clone https://github.com/MistFloat/HeadlessReverser.git ~/HeadlessReverser
cd ~/HeadlessReverser/tool  # AI执行所有命令的基准目录
```

## 3. 部署校验命令
AI完成部署后先执行验证，确认环境正常：
```bash
python skills/scripts/ghidra_headless.py list_projects
```
正常输出示例：
```json
{"projects": [], "dir": "C:\\Users\\xxx\\.ghidra-projects"}
```
报错`FileNotFoundError: analyzeHeadless not found` → 未配置`GHIDRA_HOME`环境变量。

## 4. 注册为 Codex Skill（非 MCP）
> **本项目不是 MCP Server。** 脚本是普通 CLI 工具（接收命令行参数、输出 JSON、退出），不实现 MCP 协议。正确的使用方式是作为 Codex Skill 加载。

将工作目录下的 `CODEX.md` 注册为 Codex 的 skill 入口。AI 读取该文档后，会按其中定义的工作流直接通过 shell 调用脚本：

```
用户："分析这个 target.exe"
   ↓
AI 加载 CODEX.md skill → 读到分析工作流
   ↓
AI 执行 shell 命令：cd tool; python skills/scripts/ghidra_headless.py summary target.exe
   ↓
拿到 JSON → 继续反编译 → 输出 Logic Report
```

没有 MCP 协议参与，就是普通的"AI 读 skill 文档 → 调命令行工具"。

---

# 三、Ghidra分析命令速查表（带调用示例）
| 命令 | 功能 | 调用示例 |
|------|------|----------|
| `summary` | 获取二进制全局概况：架构、基址、函数总数、SHA缓存ID | `python skills/scripts/ghidra_headless.py summary test.exe` |
| `functions` | 导出全部函数列表（地址+符号名） | `python skills/scripts/ghidra_headless.py functions test.exe` |
| `decompile` | 反编译指定内存地址，输出完整伪C代码 | `python skills/scripts/ghidra_headless.py decompile test.exe 0x401200` |
| `strings` | 模糊匹配检索二进制内包含指定子串的字符串 | `python skills/scripts/ghidra_headless.py strings test.exe "password"` |
| `xrefs_to` | 查找所有跳转/调用引用目标地址的代码位置 | `python skills/scripts/ghidra_headless.py xrefs_to test.exe 0x401000` |
| `xrefs_from` | 列出目标地址内部所有引用的函数/全局变量/字符串 | `python skills/scripts/ghidra_headless.py xrefs_from test.exe 0x401000` |
| `functions_calling` | 查找所有调用目标符号的上层函数 | `python skills/scripts/ghidra_headless.py functions_calling test.exe "CreateFileA"` |
| `functions_referencing_string` | 查找所有使用目标字符串的函数 | `python skills/scripts/ghidra_headless.py functions_referencing_string test.exe "error log"` |
| `list_projects` | 列出本地全部缓存分析项目 | `python skills/scripts/ghidra_headless.py list_projects` |
| `delete_project` | 根据SHA缓存ID删除对应项目，释放磁盘空间 | `python skills/scripts/ghidra_headless.py delete_project 123abcdefsha256` |

# 四、自适应分析后端降级策略
针对不同分析目标自动切换最优工具，主工具异常时自动降级备选方案
| 分析目标 | 首选后端 | 降级备选 |
|---------|----------|----------|
| 代码反汇编 | Ghidra Headless | rizin → objdump → capstone |
| 伪C反编译 | Ghidra Headless | rizin `pdg` / `pdc` |
| 字符串提取 | strings_scan.py | 无降级 |
| 符号执行路径分析 | symexec_find.py (angr) | 无降级 |

# 五、核心设计特性
1. **零GUI全后台运行**
    完全基于`analyzeHeadless`，无图形界面，可后台、服务器、CI流水线静默执行；Codex单条自然语言指令即可串联完整分析链路。
2. **SHA256确定性项目缓存**
    每个二进制文件以SHA256哈希作为缓存项目名，首次完整解析，后续复用缓存秒级返回结果，大幅提升批量分析速度。
3. **纯静态分析无执行风险**
    仅解析二进制文件结构、控制流、伪代码，不会运行样本，规避恶意程序执行风险。
4. **全输出标准化JSON**
    所有工具统一输出JSON格式结构化数据，无杂乱日志，AI可直接解析、提取字段生成逆向报告。

# 六、标准输出示例（summary命令）
```json
{
  "binary_path": "D:\\samples\\test.exe",
  "arch": "x86_64-windows",
  "base_address": "0x400000",
  "total_functions": 246,
  "file_sha256": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "cache_project_path": "C:\\Users\\xxx\\.ghidra-projects\\xxxxxxxxxxxxxxxxxxxxxx"
}
```

# 七、常见报错与解决方案
1. `FileNotFoundError: xxx.java`
    - 当前工作目录不是`tool/`；必须cd进入tool再执行命令
    - 文件夹层级被修改，`skills`与`ghidra`目录不再同级
2. `analyzeHeadless not found`
    - 未正确配置`GHIDRA_HOME`环境变量，路径指向Ghidra根目录
3. Java version mismatch
    - Ghidra 11.x必须使用JDK17，更换配套Java环境
4. 分析卡死、长时间无输出
    - 调大环境变量`GHIDRA_TIMEOUT`数值，延长超时时间
5. ModuleNotFoundError: angr/capstone/intelhex
    - 执行对应pip命令安装可选扩展依赖

# 八、缓存机制说明
1. 每个二进制文件基于完整SHA256哈希生成独立Ghidra项目文件夹；
2. 首次运行：完整导入、解析、索引二进制，耗时较长；
3. 重复分析同一文件：直接读取缓存项目，跳过解析步骤，秒级响应；
4. 清理缓存：使用`delete_project`命令传入SHA哈希删除对应缓存。

# Roadmap
- [ ] 内置独立HTTP MCP服务，无需STDIO桥接脚本
- [ ] 批量二进制扫描批量导出分析报告
- [ ] 恶意代码特征库匹配插件集成
- [ ] 支持导出IDA .idc符号同步脚本
- [ ] Windows一键启动批处理脚本，自动配置环境变量

# License
MIT