/**
 * posture.test.mjs — 加载冒烟 + 纯逻辑 + 边界。
 *
 * 边界那条是本件的**核心纪律**：端口探测只服务本机；非本机目标属交战域，必须走
 * `dsh-engagement` 的授权闸门——本件一律拒绝（且**拒绝时不发起任何连接**）。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { apply, Config, inject, isLocalHost, name } from '../lib/index.js'

const DESIGNED = [
  'posture_baseline', 'posture_connections', 'posture_autoruns',
  'posture_eventlog', 'posture_local_ports', 'posture_hash',
]

function registry() {
  const registered = []
  const ctx = {
    tools: { register: (spec) => { registered.push(spec); return () => {} } },
    on: () => () => {},
    effect: () => () => {},
    logger: () => ({ info: () => {}, warn: () => {}, debug: () => {}, error: () => {} }),
  }
  apply(ctx, { enabled: true, maxChars: 6000, defaultPorts: '22,80', defaultDays: 7 })
  return registered
}

test('加载冒烟：6 个工具全部注册成功（schema DSL 校验在此暴露）', () => {
  const registered = registry()
  assert.equal(registered.length, 6)
  assert.deepEqual(registered.map((t) => t.name).sort(), [...DESIGNED].sort())
  for (const t of registered) {
    assert.equal(typeof t.execute, 'function', `${t.name} 缺 execute`)
    assert.ok(t.output !== undefined && t.parameters !== undefined)
  }
})

test('isLocalHost：只认回环与本机名（含尾点/大小写归一）', () => {
  assert.equal(isLocalHost('127.0.0.1'), true)
  assert.equal(isLocalHost('LOCALHOST.'), true)
  assert.equal(isLocalHost('::1'), true)
  assert.equal(isLocalHost('192.168.1.1'), false)
  assert.equal(isLocalHost('example.com'), false)
  assert.equal(isLocalHost('127.0.0.2'), false)
})

test('边界：非本机端口探测被拒，且文案指向交战域（不发起连接）', async () => {
  const t = registry().find((x) => x.name === 'posture_local_ports')
  const out = await t.execute({ host: 'example.com', ports: '80' })
  assert.ok(out.text.includes('拒绝'), '未拒绝非本机目标：' + out.text)
  assert.ok(out.text.includes('dsh-engagement'), '未指向承接者：' + out.text)
})

test('本机端口探测可跑（回环 + 一个几乎必然关闭的端口，快速返回）', async () => {
  const t = registry().find((x) => x.name === 'posture_local_ports')
  const out = await t.execute({ host: '127.0.0.1', ports: '9', timeoutMs: 300 })
  assert.ok(out.text.includes('本机端口'), '未返回结果：' + out.text)
  assert.ok(!out.text.includes('拒绝'))
})

test('导出形状：name / inject / Config', () => {
  assert.equal(name, 'host-posture')
  assert.deepEqual([...inject], ['tools'])
  assert.equal(typeof Config, 'function')
})

/* ═══════════════════════════════════════════════════════════════════════════
   静默失败的两个尸体测试（2026-10-10 · 由庄园成员「哨」首次实跑抓出，主人批准修复）

   缺陷形态：`$ErrorActionPreference='SilentlyContinue'` + `if (-not $out) { '[]' }`
   ⇒ 「**没有读该日志的权限**」与「**7 天内确实没有事件**」吐出**一模一样的 `[]`**。
   她的反证：同进程读 Application/System/Defender 正常、`Get-WinEvent -LogName Security`
   抛 unauthorized ⇒ 空是**权限空白**，不是无事件。

   判据纪律：**对照组不失败 = 实验无结论**。所以这里两个用例必须**落在不同格子**——
   尸体（抛权限异常）⇒ DENIED；对照（可读但零命中）⇒ OK/count=0。
   只测前者会漏掉「改过头把真无事件也报成 DENIED」。
   ═══════════════════════════════════════════════════════════════════════════ */

import { execFileSync } from 'node:child_process'
import { queryEventLog, baselineCheck } from '../lib/host.js'

const PS = 'C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'

/** 在真实 PowerShell 里跑脚本，**与生产同构**：`-Command <整段脚本>` 单 argv。
 *
 *  ⚠ 不能用 `-Command -` + stdin 喂脚本（我第一版就是这么写的，四条测试全红）：
 *  PS 5.1 的 stdin 模式对多行结构（function / try-catch）行为不同 ——
 *  **装置与生产不同构，测的就不是同一个东西**（可能假绿，也可能像我这次假红）。
 *  生产的 `runPs` 就是把整段脚本当一个 argv 传给 `-Command`，这里照抄。 */
function runPs(script, stub = '') {
  const full = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; ${stub}\n${script}`
  const out = execFileSync(PS, ['-NoProfile', '-NonInteractive', '-Command', full], {
    encoding: 'utf8', timeout: 60_000, maxBuffer: 20 * 1024 * 1024,
  })
  return out.trim()
}

test('尸体：读日志无权限 ⇒ status=DENIED（不再是伪装成空结果的 []）', () => {
  const stub = `function Get-WinEvent { throw [System.UnauthorizedAccessException]::new('Attempted to perform an unauthorized operation.') }`
  const raw = runPs(queryEventLog([4624, 4625], 7, 'Security', 10), stub)
  const got = JSON.parse(raw)
  assert.equal(got.status, 'DENIED', '未把权限失败判成 DENIED：' + raw)
  assert.ok(got.reason && got.reason.length > 0, 'DENIED 必须带 reason')
  assert.ok(!Array.isArray(got), 'DENIED 时不得吐裸数组（那正是旧缺陷的形状）')
})

test('对照：通道可读但零命中 ⇒ status=OK 且 count=0（与尸体落在不同格子）', () => {
  // 探针（-MaxEvents 1）要成功，查询要成功但返回空
  const stub = `function Get-WinEvent { param([Parameter(ValueFromRemainingArguments=$true)]$rest) return @() }`
  const raw = runPs(queryEventLog([4624], 7, 'Security', 10), stub)
  const got = JSON.parse(raw)
  assert.equal(got.status, 'OK', '可读+零命中不该报 DENIED：' + raw)
  assert.equal(got.count, 0, 'OK 分支要带 count=0：' + raw)
})

test('共享判据：IPC$ 是 Windows 默认管理共享 ⇒ PASS（修误报，且不修过头）', () => {
  const stubIpc = `function Get-SmbShare { @([PSCustomObject]@{ Name='IPC$' }) }`
  const stubCustom = `function Get-SmbShare { @([PSCustomObject]@{ Name='IPC$' }, [PSCustomObject]@{ Name='MyShare' }) }`
  // 其它读源照旧（真机可读）；只在共享这一项上做单变量
  const run = (stub) => {
    const raw = runPs(baselineCheck(), stub)
    return JSON.parse(raw).find((c) => c.Check === 'SMB_NonDefaultShares')
  }
  assert.equal(run(stubIpc).Status, 'PASS', 'IPC$ 被误报成非默认共享：' + JSON.stringify(run(stubIpc)))
  assert.equal(run(stubCustom).Status, 'WARN', '真自定义共享必须仍报 WARN（防修过头）')
})

test('共享判据：读失败 ⇒ UNKNOWN（不是 PASS）', () => {
  const stub = `function Get-SmbShare { throw [System.UnauthorizedAccessException]::new('denied') }`
  const raw = runPs(baselineCheck(), stub)
  const c = JSON.parse(raw).find((x) => x.Check === 'SMB_NonDefaultShares')
  assert.equal(c.Status, 'UNKNOWN', '读失败退化成 PASS 正是被修的缺陷：' + JSON.stringify(c))
  assert.ok(c.Detail.includes('读取失败'), 'UNKNOWN 要写清读取失败：' + c.Detail)
})
