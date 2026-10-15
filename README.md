<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: 本机防御态势：我这台机器现在安全吗——防火墙/共享/RDP/管理员组/自动登录 + 连接与自启动面 + 本机端口 + 文件哈希
  inject: 'tools'
  tools: posture_baseline,posture_connections,posture_autoruns,posture_eventlog,posture_local_ports,posture_hash
  runtime: host-only
  envDeps: Windows（事件日志与防火墙查询走 PowerShell 通道）
  boundary: **全只读**（不改系统设置/不写注册表/不动防火墙）；端口探测**限定本机**，非本机目标一律拒绝并指向 dsh-engagement
  compat: cordis ^4.0.1 / schemastery ^3.18.1-rc.1 / dsh-tools >=0.1.0-rc.6
-->
# dsh-host-posture — 本机防御态势

<p align="center">
  <a href="https://github.com/jonah791/dsh-host-posture"><img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version"></a>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/TypeScript-3178C6" alt="TypeScript">
  <img src="https://img.shields.io/badge/tests-16%20passed-brightgreen" alt="tests">
</p>

**一句话**：回答一个**独立的顶层目的**——「**我这台机器现在安全吗**」。

**为什么值得用**：本机加固态势与「一次安全交战」是两件事——前者不触达交战目标，硬塞进交战域会让「闸门只挡 active」的边界变模糊。本插件按**目的级**切开：六个工具全是**只读**的态势观察，回答的是「我自己的机器现在什么样」。

承接 `dsh-blue-team` 退役后留下的引用点（技能 `windows-security-hardening` 的 `blue_baseline_check` + `blue_process_audit` / `blue_autoruns_check` / `blue_port_scan` 的**本机卫生用法**）。

## 为什么单独一件

2026-09-23 融合设计 §5.4 C：旧 `blue_baseline_check` 的对象是**本机加固态势**，与「一次安全交战」无关——按目的级切开后它退出交战域。硬塞进 `dsh-engagement` 会让「闸门只挡 active」的边界变模糊（本机态势检查不触达交战目标）。

## 工具面（6，全只读）

| 工具 | 意图 | 承接自 |
|---|---|---|
| `posture_baseline` | 防火墙 / 共享 / RDP / 管理员组 / 自动登录 | `blue_baseline_check` |
| `posture_connections` | 本机连接与监听面（谁在跟谁说话） | `blue_process_audit` |
| `posture_autoruns` | 自启动面（重启后谁会自己起来） | `blue_autoruns_check` |
| `posture_eventlog` | 安全日志（4624/4625/4688 等） | `blue_event_log_query` |
| `posture_local_ports` | 本机端口探测（**仅限本机**） | `blue_port_scan` 的本机用法 |
| `posture_hash` | 文件哈希（核对下载件/被替换文件） | `blue_hash_lookup` |

## 两条边界

1. **全只读**：不改任何系统设置、不写注册表、不动防火墙规则。「看态势」与「改态势」是两件事。
2. **端口探测限定本机**：只接受 `127.0.0.1` / `localhost` / `::1` / `0.0.0.0`。非本机目标**一律拒绝**并指向 `dsh-engagement`（那里有授权闸门）——越出本机就是扫描，属交战域。

## 配置

| 字段 | 缺省 | 含义 |
|---|---|---|
| `maxChars` | 6000 | 输出截断上限 |
| `defaultPorts` | `22,80,135,139,443,445,3389,5985,5986` | 默认端口规格 |
| `defaultDays` | 7 | 日志查询默认天数 |

## 生效判据

1. 构建-进程先后：`lib/index.js` mtime 晚于 web 进程启动时间。
2. 工具可答：`posture_baseline` 返回基线文本。
3. 边界成立：`posture_local_ports(host='example.com')` 被拒且指向 `dsh-engagement`。

## 回退

`plugin_unmount dsh-host-posture`；无状态、不写盘 ⇒ 无损。

## 快速开始

**1) 装依赖**：

```jsonc
"dsh-host-posture": "link:E:/alice/self-plugins/dsh-host-posture"
```

**2) 挂组合**：

```yaml
- id: host-posture
  name: dsh-host-posture
```

**3) 30 秒验证**：`posture_baseline` → 应返回防火墙/共享/RDP/管理员组/自动登录五项基线；再 `posture_local_ports(host="example.com")` → **应被拒绝**并指向 `dsh-engagement`（边界成立的判据）。

## 落盘与自证

**本插件无持久产物**——六个工具全是**只读观察**，结果直接返回，不写文件、不落侧车。

**一条命令答五问**：`posture_baseline` / `posture_connections` / `posture_autoruns` 各一屏给出对应面的事实（谁在跟谁说话 / 重启后谁会自己起来 / 本机加固现状）。

## 测试

```bash
cd self-plugins/dsh-host-posture && npm test
```

**16 条用例**（跑一次得到）：覆盖端口规格解析（`80,443` / `1-1000`）· **本机限定**（非回环目标被拒且指向 `dsh-engagement`）· 事件日志失败按 **cause** 分辨（权限 / 通道不存在 / 未知，**未命中不假装知道**）。无需网络。

## 设计要点

- **全只读**：「看态势」与「改态势」是两件事——本插件只做前者（改设置需要独立的、显式的授权路径）。
- **端口探测限定本机**：只接受回环地址；越出本机就是**扫描**，属交战域（那里有授权闸门）。
- **失败按 cause 分辨**：探针失败时区分 `PERMISSION` / `NO_SUCH_CHANNEL` / `UNKNOWN`——旧版把三种都硬编码成「无权限」，与真实 reason 自相矛盾（2026-10-10 由庄园成员「哨」的独立复核指出）。
- **按目的级切开**：本机态势与安全交战是**两个目的**，合并会让闸门边界模糊。

## 相关文档

- [`docs/semantic.md`](docs/semantic.md) —— **权威契约**（定位/反定位 · 验收表）
- 中心仓：[alice-digital-life](https://github.com/jonah791/alice-digital-life)（本插件归 **安全层**）
- 相关技能：`windows-security-hardening`（本插件是它的引用点）

## License

MIT © jonah791

---

本插件属于**爱丽丝 DSH 自研插件生态**（[alice-digital-life](https://github.com/jonah791/alice-digital-life) · 73 个插件 · 8 个模块）：单一职责、独立仓库、独立可用。
