// 回归夹具：queryEventLog 的**三态分辨**（2026-10-10 · 由庄园成员「哨」的独立复核驱动）
//
// 病史（两代，同族）：
//   旧病：`SilentlyContinue` + `if (-not $out) { '[]' }` ⇒「无权限」与「真的没事件」**同形**。
//   第一版修法（我）：加①通道可读性探针 ⇒ 无权限单独成一格；②查询报错一律 ERROR。
//     **但 Get-WinEvent 零命中时会抛异常** ⇒ 「可读 + 零命中」落进 ERROR，
//     于是 `status='OK', count=0` 那条分支**结构上不可达** —— 病没走，换了格子。
//     哨的实测：`Application`/999999 ⇒ ERROR（我宣称 OK,count=0）；
//     本机 System 两天内无 7036（没重启过服务）会被读成「工具坏了」，而正确语义是「确实没有」。
//
// 关键判据（2026-10-10 实跑探测所得，非推断）：
//   零命中（带 FilterHashtable）        ⇒ System.Exception / "No events were found that match…"
//   无权限（带 FilterHashtable）        ⇒ **同一条消息**（与零命中同形）
//   无权限（不带 FilterHashtable，即①） ⇒ "unauthorized operation" ⇒ 被①拦下
//   通道不存在                          ⇒ "There is not an event log on the localhost computer…"
//   ⇒ 走到②说明①已通过（通道可读），故 "No events were found" 只可能来自零命中。
//
// ⚠ 装置纪律（第一版夹具就在这里翻车）：`queryEventLog()` 返回的是**PowerShell 脚本文本**，
//   执行要经 `runPs()` —— 忘了这层会把脚本当 JSON 解析，四格全红（错在装置，不在被测物）。
//
// 四格覆盖：OK(0) / DENIED(PERMISSION) / DENIED(NO_SUCH_CHANNEL) / OK(n)。
// 环境相关格（Security 权限、Application 有事件）**不假绿**：不适用时显式 return/skip。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { queryEventLog, runPs } from '../lib/host.js'

const call = async (ids, days, log) => JSON.parse((await runPs(queryEventLog(ids, days, log))).trim())

test('可读 + 零命中 ⇒ OK,count=0（不是 ERROR —— 旧版这条分支结构上不可达）', async () => {
  const r = await call([999999], 7, 'Application')
  assert.equal(r.status, 'OK', `实际: ${JSON.stringify(r)}`)
  assert.equal(r.count, 0)
  assert.deepEqual(r.events, [])
})

test('通道不存在 ⇒ DENIED + cause=NO_SUCH_CHANNEL（hint 不得再说「无权限」）', async () => {
  const r = await call([1], 7, 'NoSuchChannel-SHO-1')
  assert.equal(r.status, 'DENIED')
  assert.equal(r.cause, 'NO_SUCH_CHANNEL')
  // ⚠ 判据打在**结构化字段**（cause）与**正面陈述**上，别用「不含某词」这种整段文本断言 ——
  //   第一版写 `!r.hint.includes('无权限')`，而 hint 里正确地写着「**既不是无权限**，也不是没有事件」
  //   ⇒ 被自己的解释文案击穿（技能 `assertion-targets-value-not-text` 的同型错误）。
  assert.ok(r.hint.includes('不存在'), `hint 应正面说明通道不存在: ${r.hint}`)
})

test('无权限通道（非管理员读 Security）⇒ DENIED + cause=PERMISSION', async (t) => {
  const r = await call([4624], 7, 'Security')
  if (r.status !== 'DENIED') {
    t.skip('当前进程有 Security 读权限 —— 本格不适用（跳过，不假绿）')
    return
  }
  assert.equal(r.cause, 'PERMISSION', `实际: ${JSON.stringify(r)}`)
})

test('有事件的通道 ⇒ status=OK（不回归）', async () => {
  const r = await call([16394], 7, 'Application')
  if (r.count === 0) return // 该 Id 近期无事件 ⇒ 本格不适用
  assert.equal(r.status, 'OK')
  assert.ok(r.count > 0)
})
