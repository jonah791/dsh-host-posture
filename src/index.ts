/**
 * dsh-host-posture — 本机防御态势。
 *
 * 回答一个**独立的顶层目的**：「我这台机器现在安全吗」——防火墙 / 共享 / RDP / 管理员组 / 自动登录，
 * 外加连接与自启动面、本机端口、文件哈希。
 *
 * 为什么单独一件（2026-09-23 融合设计 §5.4 C）：旧 `dsh-blue-team` 的 `blue_baseline_check` 对象是
 * **本机加固态势**，与「一次安全交战」无关——按目的级切开后它退出交战域。技能
 * `windows-security-hardening` 正引用它（连同 `blue_process_audit` / `blue_autoruns_check` /
 * `blue_port_scan` 的**本机卫生用法**）⇒ 本件是那四处的承接者，也是 `dsh-blue-team` 退役的前置。
 *
 * 边界：
 * - **全只读**：不改任何系统设置、不写注册表、不动防火墙规则（「看态势」与「改态势」是两件事）。
 * - **端口扫描限定本机**：非本机目标属交战域（走 `dsh-engagement` 的授权闸门），本件一律拒绝。
 *
 * @module dsh-host-posture
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { auditAutoruns, auditConnections, baselineCheck, hashFile, queryEventLog, runPs } from './host.js'
import { parseEventIds } from './logic.js'
import { parsePorts, scanPorts } from './net.js'

export const name = 'host-posture'

export const inject = ['tools'] as const

export interface Config {
  enabled: boolean
  /** 输出截断上限（字符） */
  maxChars: number
  /** 默认端口规格 */
  defaultPorts: string
  /** 默认日志查询天数 */
  defaultDays: number
}

export const Config = z.object({
  enabled: z.boolean().default(true),
  maxChars: z.number().default(6000),
  defaultPorts: z.string().default('22,80,135,139,443,445,3389,5985,5986'),
  defaultDays: z.number().default(7),
})

const textOut = {
  schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
  render: (_a: unknown, v: { text: string }) => [{ type: 'text', text: v.text }],
} as const

const tool = (spec: unknown): never => defineTool(spec as never) as never

/** 本机判定：只接受回环与显式本机名（越出本机 = 扫描，属交战域） */
export function isLocalHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.+$/, '')
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '0.0.0.0'
}

export function apply(ctx: Context, config: Config): void {
  if (!config.enabled) return
  const logger = ctx.logger('dsh-host-posture')
  const cut = (s: string): string => (s.length > config.maxChars ? s.slice(0, config.maxChars) + `\n…（截断，共 ${s.length} 字符）` : s)

  // ── 1. posture_baseline ────────────────────────────────────────────────
  ctx.tools.register(tool({
    name: 'posture_baseline',
    description: '本机加固基线：防火墙状态 / 共享 / RDP / 管理员组成员 / 自动登录。**只读**，不改任何设置。'
      + '承接旧 `blue_baseline_check` 的职责（技能 windows-security-hardening 的引用点）。',
    parameters: {},
    output: textOut,
    async execute() {
      const out = await runPs(baselineCheck())
      return { text: cut(out.trim() === '' ? '（基线检查无输出）' : out) }
    },
  }))

  // ── 2. posture_connections ─────────────────────────────────────────────
  ctx.tools.register(tool({
    name: 'posture_connections',
    description: '本机连接与监听面（TCP 连接 + 监听端口 + 归属进程）。用于回答「这台机器现在在跟谁说话」。',
    parameters: {
      limit: { type: 'number', description: '条数上限（缺省 200）' },
    },
    output: textOut,
    async execute(args: { limit?: number }) {
      return { text: cut(await runPs(auditConnections(typeof args.limit === 'number' ? args.limit : 200))) }
    },
  }))

  // ── 3. posture_autoruns ────────────────────────────────────────────────
  ctx.tools.register(tool({
    name: 'posture_autoruns',
    description: '自启动面（注册表 Run 键 + 启动目录）。用于回答「重启后谁会自己起来」。',
    parameters: {
      limit: { type: 'number', description: '条数上限（缺省 100）' },
    },
    output: textOut,
    async execute(args: { limit?: number }) {
      return { text: cut(await runPs(auditAutoruns(typeof args.limit === 'number' ? args.limit : 100))) }
    },
  }))

  // ── 4. posture_eventlog ────────────────────────────────────────────────
  ctx.tools.register(tool({
    name: 'posture_eventlog',
    description: '安全日志查询（缺省 4624 登录成功 / 4625 登录失败 / 4688 进程创建）。eventIds 可传逗号分隔或数组。',
    parameters: {
      eventIds: { type: 'string', description: '事件 id（逗号分隔；缺省 4624,4625,4688）' },
      days: { type: 'number', description: '回溯天数（缺省用配置）' },
      logName: { type: 'string', description: '日志名（缺省 Security）' },
      limit: { type: 'number', description: '条数上限（缺省 100）' },
    },
    output: textOut,
    async execute(args: { eventIds?: string; days?: number; logName?: string; limit?: number }) {
      const ids = parseEventIds(args.eventIds ?? '4624,4625,4688')
      const days = typeof args.days === 'number' ? args.days : config.defaultDays
      const log = args.logName ?? 'Security'
      const limit = typeof args.limit === 'number' ? args.limit : 100
      return { text: cut(await runPs(queryEventLog(ids, days, log, limit))) }
    },
  }))

  // ── 5. posture_local_ports ─────────────────────────────────────────────
  ctx.tools.register(tool({
    name: 'posture_local_ports',
    description: '本机端口探测（Node 并发 TCP connect）。**仅限本机**（127.0.0.1 / localhost）——非本机目标属交战域，'
      + '须走 dsh-engagement 的授权闸门（本件一律拒绝）。',
    parameters: {
      host: { type: 'string', description: '本机地址（缺省 127.0.0.1；仅接受回环/本机名）' },
      ports: { type: 'string', description: '端口规格（缺省用配置；支持 80,443 与 1-1000）' },
      timeoutMs: { type: 'number', description: '单端口超时（缺省 1200ms）' },
    },
    output: textOut,
    async execute(args: { host?: string; ports?: string; timeoutMs?: number }) {
      const host = args.host ?? '127.0.0.1'
      if (!isLocalHost(host)) {
        return { text: `⛔ 拒绝：${host} 不是本机地址。非本机端口探测属交战域，请用 dsh-engagement（eng_recon_host）——它带授权闸门。` }
      }
      const spec = args.ports ?? config.defaultPorts
      const open = await scanPorts(host, parsePorts(spec), typeof args.timeoutMs === 'number' ? args.timeoutMs : 1200)
      return {
        text: `本机端口（${host}，开放 ${open.length} 个）：\n`
          + (open.length === 0 ? '  (无开放端口)' : open.map((p) => `  ${p.port}${p.service !== undefined ? ' ' + p.service : ''}`).join('\n'))
          + `\n口径：仅列出 connect 成功的端口；探测规格 ${spec}`,
      }
    },
  }))

  // ── 6. posture_hash ────────────────────────────────────────────────────
  ctx.tools.register(tool({
    name: 'posture_hash',
    description: '算一个文件的哈希（用于核对下载件/被替换文件）。承接旧 `blue_hash_lookup` 的通用能力。',
    parameters: {
      path: { type: 'string', required: true, description: '文件绝对路径' },
    },
    output: textOut,
    async execute(args: { path: string }) {
      const out = await runPs(hashFile(args.path))
      return { text: cut(out.trim() === '' ? `（无输出：${args.path}）` : out) }
    },
  }))

  logger.info(`ready（工具面 6，全只读；端口探测限本机）`)
}
