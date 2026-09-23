# dsh-host-posture — 本机防御态势（语义文档）

## 1 · 元信息

| 项 | 值 |
|---|---|
| 能力名 | 本机防御态势（「我这台机器现在安全吗」） |
| 插件 | `self-plugins/dsh-host-posture` |
| 状态 | implemented（6 工具已落地并离线验收；挂载与技能改指待做） |
| 承接 | `dsh-blue-team` 的 `blue_baseline_check` + 三处本机卫生用法 + `blue_hash_lookup` |
| 依据 | `docs/plans/插件融合设计_安全交战_2026-09-23.md` §5.4 C 与 §10 步骤 2 |
| 最近复核 | 2026-09-23 |

## 2 · 定位与反定位

**定位**：读**本机**的防御态势——防火墙 / 共享 / RDP / 管理员组 / 自动登录 / 连接面 / 自启动面 / 日志 / 端口 / 文件哈希。

**反定位（不做）**：不改任何系统设置（不写注册表、不动防火墙规则、不改共享）· 不扫非本机目标（属交战域，走 `dsh-engagement`）· 不做持续监控/常驻（一次性查询）· 不装持久化 · 不替代 `dsh-engagement` 的检测侧校验（后者在**交战上下文内**回答「这次动作会留下什么信号」，本件回答「这台机器现在什么状态」）。

## 3 · 术语

| 术语 | 含义 |
|---|---|
| 本机（local host） | 回环与本机名：`127.0.0.1` / `localhost` / `::1` / `0.0.0.0`（归一化后判定，含尾点与大小写） |
| 基线（baseline） | 防火墙状态 + 共享 + RDP + 管理员组 + 自动登录这五项构成的加固态势快照 |
| 本机卫生用法 | 对**自己**这台机器做的盘点（与「对目标做侦察」相对）——这是本件存在的理由 |

## 4 · 概念模型与不变量

概念：`PostureAspect`（基线/连接/自启动/日志/端口/哈希）· `LocalHost`（本机判定）。

不变量：

- **H1 全只读**——本件不改任何系统状态；六个工具都只有读路径。
- **H2 本机限定**——端口探测只接受本机地址；非本机一律拒绝并指向 `dsh-engagement`（**拒绝时不发起任何连接**）。
- **H3 无状态**——不写盘、不建目录、不缓存（每次调用现读）。
- **H4 输出有界**——所有输出经 `maxChars` 截断，且截断处**显式标注**总长度（不静默丢内容）。

## 5 · 契约

### 5.1 工具面（6）

| # | 工具 | 意图 | 参数 |
|---|---|---|---|
| 1 | `posture_baseline` | 加固基线（防火墙/共享/RDP/管理员组/自动登录） | — |
| 2 | `posture_connections` | 连接与监听面 | `limit?` |
| 3 | `posture_autoruns` | 自启动面 | `limit?` |
| 4 | `posture_eventlog` | 安全日志 | `eventIds?` `days?` `logName?` `limit?` |
| 5 | `posture_local_ports` | 本机端口探测 | `host?` `ports?` `timeoutMs?` |
| 6 | `posture_hash` | 文件哈希 | `path` |

### 5.2 调用点清单

| 调用方 | 调用点（文件:符号） | 时机 |
|---|---|---|
| cordis 宿主 | `src/index.ts:name / inject / Config / apply` | 插件激活 |
| 宿主 agent | 6 处 `ctx.tools.register(...)` | 工具调用 |
| 本件 → PowerShell | `src/host.ts:runPs` | 基线/连接/自启动/日志/哈希（经 `psQuote` 拼参数） |
| 本件 → 网络 | `src/net.ts:scanPorts`（Node 并发 connect） | **仅本机**（H2） |
| 下游 · 技能 | `~/.agents/skills/windows-security-hardening/SKILL.md`（引用四个 `blue_*` 名） | **退役时必须同步改指本件** |

## 6 · 边界与信任

- **能力 ≠ 沙箱**：与宿主同进程同权限；「只读」是实现自律，不是权限隔离。
- **PowerShell 参数经 `psQuote`**：所有进脚本的字符串过单一引号出口（承 `blue-logic.ts`）。
- **端口探测的域边界**：本机 = 卫生；非本机 = 侦察（须授权）。这条边界由 `isLocalHost` 一处判定，**不散落**。
- **失败面**：PowerShell 不可用/超时 ⇒ 返回已有输出并如实标注；文件不存在 ⇒ 返回明确文案（不冒充成功）。

## 7 · 可证伪验收

| # | 可证伪命题 | 证据 | 状态 |
|---|---|---|---|
| H-1 | 工具面恰为 6，与设计表逐名一致 | `node --test tests/*.test.mjs`（加载冒烟组） | 已实测 |
| H-2 | 本机判定只认回环与本机名（含归一化） | 同上 `isLocalHost` 组（4 正 2 反） | 已实测 |
| H-3 | 非本机端口探测被拒且指向 `dsh-engagement` | 同上边界组 | 已实测 |
| H-4 | 本机端口探测可跑（回环 + 关闭端口快速返回） | 同上 | 已实测 |
| H-4b | 造脚本函数都被 `runPs()` 包住（返回脚本 = 语义错） | `tests/wiring.test.mjs`（源码级 + 真跑，7/7 全绿） | 已实测 |
| H-5 | 构建通过 | `tsc -p tsconfig.json` 退出码 0 | 已实测 |
| H-6 | 挂载后 6 工具可答 | `posture_baseline` 返回基线文本 | 待验收 |
| H-7 | 技能改指后不再悬空引用旧名 | `grep -n 'blue_baseline_check' ~/.agents/skills/windows-security-hardening/SKILL.md` 零命中 | 待验收 |

## 8 · 与实现的关系

**落点**：`src/index.ts`（6 工具）· `src/host.ts`（PowerShell 侧：基线/连接/自启动/日志/哈希，承 `blue-host.ts`）· `src/net.ts`（并发端口探测，承 `blue-net.ts`）· `src/logic.ts`（`psQuote` / `parseEventIds` 等纯层，承 `blue-logic.ts`）· `tests/posture.test.mjs`。

**生效判据**：构建 mtime 晚于进程启动 · `posture_baseline` 可答 · 非本机目标被拒。

**回退**：`plugin_unmount`；无状态不写盘 ⇒ 无损。

## 9 · 实践修订记录

| 日期 | 修订 |
|---|---|
| 2026-09-23 | 首版：从 `dsh-engagement` 的移植层复用三个模块（`blue-host` / `blue-net` / `blue-logic` → `host` / `net` / `logic`），加 6 工具与两条边界。**建立本件的原因**：融合设计 §10 步骤 2 规定「在 `dsh-host-posture` 就位前不 unmount `dsh-blue-team`」——技能 `windows-security-hardening` 正引用 `blue_baseline_check`，先退役会留下悬空引用。 |
| 2026-09-24 | **上线即抓出接线缺陷**：`posture_baseline` 返回的是 **PowerShell 脚本源码**而不是执行结果——`host.ts` 的 `baselineCheck()` / `auditConnections()` / `auditAutoruns()` / `queryEventLog()` / `hashFile()` **都是造脚本**，必须交给 `runPs()` 执行。加载冒烟、`tsc`、边界测试全绿都拦不住它：**返回值类型对（都是 string），语义错（一个是脚本、一个是结果）**。修复 5 处调用点 + 补 `tests/wiring.test.mjs`（源码级断言「每个造脚本函数都被 `runPs(` 包住」+ 真跑一次断言输出不含 `$ErrorActionPreference`）。 |

## 10 · 未决问题

1. **技能的改指时机**：设计稿把它排在「观察期后」；本次挂载后即改指（否则旧名悬空）。是否该先观察再改，待主人裁。
2. **是否要「改态势」能力**：当前全只读。若要能修（关共享/开防火墙），那是**写操作**，需单独的风险评估与回滚设计——本件不做。
3. **非 Windows 平台**：PowerShell 侧在非 Windows 上不可用；本件未做跨平台降级（如实标注，不假装）。
