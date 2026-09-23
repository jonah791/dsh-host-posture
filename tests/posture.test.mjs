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
