# dsh-host-posture — 本机防御态势

回答一个**独立的顶层目的**：「**我这台机器现在安全吗**」。

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
