/**
 * wiring.test.mjs — **接线尸体测试**：造脚本的调用点必须在 `runPs()` 里。
 *
 * 事故（2026-09-24 上线即抓）：`posture_baseline` 返回的是 **PowerShell 脚本源码**而不是执行结果——
 * `blue-host.ts` 的 `baselineCheck()` / `auditConnections()` / `hashFile()` 等**都是造脚本**，
 * 必须交给 `runPs()` 执行。加载冒烟、`tsc`、边界测试全绿也拦不住这类错：**返回值类型对（都是 string），
 * 语义错（一个是脚本、一个是结果）**。
 *
 * ⇒ 判据：源码级断言「每个造脚本函数都被 `runPs(` 包住」，外加一次真跑（输出不得是脚本源码）。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { apply } from '../lib/index.js'

const SRC = readFileSync(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')

/** 造脚本的函数（返回 PowerShell 源码，不是结果） */
const SCRIPT_BUILDERS = ['baselineCheck', 'auditConnections', 'auditAutoruns', 'queryEventLog', 'hashFile']

test('尸体：每个造脚本函数都被 runPs( 包住（返回脚本 = 语义错，类型查不出）', () => {
  for (const fn of SCRIPT_BUILDERS) {
    const calls = [...SRC.matchAll(new RegExp('(\\S{0,12})' + fn + '\\(', 'g'))].map((m) => m[1])
    assert.ok(calls.length > 0, `没找到 ${fn} 的调用点`)
    for (const before of calls) {
      assert.ok(before.includes('runPs('), `${fn} 的调用点未被 runPs 包住（前文：${before}）`)
    }
  }
})

test('尸体：真跑一次 baseline，输出不得是脚本源码（判据：不含 $ErrorActionPreference）', async () => {
  const registered = []
  const ctx = {
    tools: { register: (spec) => { registered.push(spec); return () => {} } },
    on: () => () => {},
    effect: () => () => {},
    logger: () => ({ info: () => {}, warn: () => {}, debug: () => {}, error: () => {} }),
  }
  apply(ctx, { enabled: true, maxChars: 6000, defaultPorts: '22,80', defaultDays: 7 })
  const t = registered.find((x) => x.name === 'posture_baseline')
  const out = await t.execute({})
  assert.ok(!out.text.includes('$ErrorActionPreference'), '返回了脚本源码而不是执行结果：' + out.text.slice(0, 200))
  // 正向：基线脚本会输出 JSON（含 Check/Status），或至少非空
  assert.ok(out.text.trim().length > 0, '输出为空')
})
