/** 主机安全工具：进程/连接审计、自启动审计、事件日志、加固基线——本地 PowerShell 执行 */

import { execFile } from 'node:child_process'
import { psQuote } from './logic.js'

/** 执行 PowerShell 脚本并返回 stdout（UTF-8）。本机只有 PowerShell 5.1（无 pwsh 7），用 powershell.exe */
export function runPs(script: string, timeoutMs = 30000): Promise<string> {
  const full = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; ${script}`
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', full], {
      timeout: timeoutMs,
      maxBuffer: 20 * 1024 * 1024,
      windowsHide: true,
      encoding: 'utf8',
    }, (err, stdout) => {
      if (err) reject(new Error(`PowerShell 执行失败: ${err.message}`))
      else resolve(stdout.trim())
    })
  })
}

/** 进程 + 网络连接审计：监听端口 + 外部连接（进程映射） */
export function auditConnections(scriptLimit = 200): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$conns = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' }
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$out = foreach ($c in $conns) {
  $name = $procs[$c.OwningProcess]
  if (-not $name) { $name = "PID:$($c.OwningProcess)" }
  [PSCustomObject]@{
    State=$c.State.ToString(); Local=$c.LocalAddress+':'+$c.LocalPort
    Remote=$(if($c.RemoteAddress -and $c.RemoteAddress -ne '0.0.0.0' -and $c.RemoteAddress -ne '::'){"$($c.RemoteAddress):$($c.RemotePort)"}else{'-'})
    Proc=$name; PID=$c.OwningProcess
  }
}
$out | Select-Object -First ${scriptLimit} | Sort-Object Local | ConvertTo-Json -Compress
`
}

/** 自启动审计：Run 键 + 计划任务 + 自启动服务 */
export function auditAutoruns(scriptLimit = 100): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$result = @()
$runKeys = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
           'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
           'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
           'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
           'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
foreach ($k in $runKeys) {
  if (Test-Path $k) {
    (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $result += [PSCustomObject]@{ Type='RunKey'; Name=$_.Name; Command=[string]$_.Value; Source=$k }
    }
  }
}
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object -First 40 | ForEach-Object {
  $cmd = $_.Actions | Select-Object -First 1
  $result += [PSCustomObject]@{ Type='Task'; Name=$_.TaskName; Command=[string]$cmd.Execute; Source=$_.TaskPath }
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.PathName -notmatch 'System32|Windows\\\\' } | Select-Object -First 30 | ForEach-Object {
  $result += [PSCustomObject]@{ Type='Service'; Name=$_.Name; Command=[string]$_.PathName; Source='AutoStart' }
}
$result | Select-Object -First ${scriptLimit} | ConvertTo-Json -Depth 3 -Compress
`
}

/** 事件日志查询：按事件 ID 过滤（经典安全事件）
 *  `nowMs` 为时间注入点（缺省 `Date.now()`）——使脚本可离线确定性单测。
 *
 *  ⚠ **2026-10-10 修一个静默失败**（由庄园成员「哨」首次实跑抓出，主人批准修复）：
 *  旧实现 `$ErrorActionPreference='SilentlyContinue'` + `if (-not $out) { '[]' }`，
 *  使「**没有读该日志的权限**」与「**7 天内确实没有事件**」吐出一模一样的 `[]`。
 *  她用一个反证钉死了它：同进程读 Application/System/Defender 三个日志正常，
 *  但 `Get-WinEvent -LogName Security` 抛 unauthorized ⇒ 空是**权限空白**，不是无事件。
 *  ⇒ 现在**先探通道可读性**，不可读时返回 `status='DENIED'` 并带 reason；
 *    可读但零命中才返回 `status='OK', count=0`。两者在读数层面**必须长得不一样**。 */
export function queryEventLog(eventIds: number[], days: number, logName: string, limit = 100, nowMs: number = Date.now()): string {
  const since = new Date(nowMs - days * 86400_000).toISOString()
  const idList = eventIds.join(',')
  return `
$idArr = @(${idList})
$since = [datetime]'${since}'
$log = '${psQuote(logName)}'
# ── ① 通道可读性探针：读 1 条即可。失败 ⇒ DENIED（不是「无事件」）──────────────
$probeErr = $null
try { $null = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop } catch { $probeErr = $_.Exception.Message }
if ($probeErr) {
  # 2026-10-10 修（庄园成员「哨」的独立复核指出）：旧版把所有探针失败都硬编码成
  #   「无权限」那一条 hint，而实测通道不存在时 reason 是
  #   "There is not an event log on the localhost computer…" ⇒ hint 与 reason 自相矛盾。
  #   ⇒ 现在按 reason 分辨子情形（cause 字段），判据未命中时**不假装知道**，如实标 UNKNOWN。
  $cause = 'UNKNOWN'
  $pe = [string]$probeErr
  if ($pe -like '*unauthorized*' -or $pe -like '*Access is denied*' -or $pe -like '*拒绝访问*') { $cause = 'PERMISSION' }
  elseif ($pe -like '*There is not an event log*' -or $pe -like '*不存在*') { $cause = 'NO_SUCH_CHANNEL' }
  $hint = '通道探针失败，且判据未能分辨子情形（cause=UNKNOWN）——按 reason 原文判读，本工具不猜。'
  if ($cause -eq 'PERMISSION') { $hint = '当前进程无权限读该日志（常见：非管理员读 Security 通道）。这不是「没有事件」——空与看不见是两件事。' }
  if ($cause -eq 'NO_SUCH_CHANNEL') { $hint = '该日志通道在本机不存在（名字拼错，或该功能/角色未启用）。这是第三种情形：既不是无权限，也不是没有事件。' }
  [PSCustomObject]@{
    status='DENIED'
    logName=$log
    days=${days}
    eventIds=$idArr
    reason=$pe
    cause=$cause
    hint=$hint
  } | ConvertTo-Json -Compress -Depth 4
  exit 0
}
# ── ② 通道可读，再查命中 ────────────────────────────────────────────────
$queryErr = $null
$events = $null
try {
  $events = Get-WinEvent -FilterHashtable @{ LogName=$log; Id=$idArr; StartTime=$since } -MaxEvents ${limit} -ErrorAction Stop
} catch { $queryErr = $_.Exception.Message }
if ($queryErr) {
  # 2026-10-10 修（哨抓出的真缺陷 · 我的第一版修法「把病挪了格子」）：
  #   旧症状：无权限 与「真的没事件」同形（都吐 []）。
  #   我第一版：加①探针 ⇒ 无权限单独成一格；②查询报错一律 ERROR。
  #   **但这让「可读 + 零命中」落进了 ERROR** —— Get-WinEvent 零命中时**抛异常**，
  #   于是下面那条 status='OK', count=0 分支**结构上不可达**。
  #   哨的实测：Application/999999 ⇒ ERROR（我宣称 OK,count=0）；本机 System 两天内无 7036
  #   （没重启过服务）会被读成「工具坏了」，而正确语义是「确实没有」。
  #   ⇒ 新旧同族：都是「两种语义共用一个格子」，只是换了哪两种。
  #
  #   判据（2026-10-10 实跑探测，非推断）：
  #     零命中（带 FilterHashtable）        ⇒ System.Exception / "No events were found that match…"
  #     无权限（带 FilterHashtable）        ⇒ **同一条消息**（与零命中同形！）
  #     无权限（不带 FilterHashtable，即①） ⇒ "unauthorized operation" ⇒ 已被①拦下
  #     通道不存在                          ⇒ "There is not an event log on the localhost computer…"
  #   ⇒ 关键：**走到这里说明①已通过（通道可读）**，故 "No events were found" 只可能来自零命中。
  #   ⚠ 语言依赖如实说：该消息取自 .NET 资源，非英文系统措辞可能不同 ⇒ 做成显式常量表，
  #     匹配不上时**不假装**，退回 ERROR（保守：宁可说「我读不明白」也不谎报「没有」）。
  $noMatchMsgs = @('No events were found that match the specified selection criteria.')
  $isZero = $false
  foreach ($m in $noMatchMsgs) { if ([string]$queryErr -like ('*' + $m + '*')) { $isZero = $true } }
  if ($isZero) {
    [PSCustomObject]@{
      status='OK'
      logName=$log
      days=${days}
      eventIds=$idArr
      count=0
      events=@()
      note='通道可读、查询合法，但该时间窗/Id 组合下确实没有事件。「确实没有」与「读不到」是两件事。'
    } | ConvertTo-Json -Compress -Depth 4
    exit 0
  }
  [PSCustomObject]@{ status='ERROR'; logName=$log; days=${days}; eventIds=$idArr; reason=[string]$queryErr; note='查询失败，且异常消息与已知的「零命中」措辞不匹配 ⇒ 按错误上报（不渲染成空，也不谎报没有事件）。' } | ConvertTo-Json -Compress -Depth 4
  exit 0
}
$out = @(foreach ($e in $events) {
  $msg = ($e.Message -split "\\r?\\n" | Select-Object -First 2) -join ' '
  [PSCustomObject]@{ Time=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id=$e.Id; Level=$e.LevelDisplayName; Machine=$e.MachineName; Msg=[string]$msg }
})
[PSCustomObject]@{
  status='OK'
  logName=$log
  days=${days}
  eventIds=$idArr
  count=$out.Count
  events=$out
} | ConvertTo-Json -Compress -Depth 4
`
}

/** 安全基线快检：防火墙/共享/RDP/管理员/自动登录
 *
 *  ⚠ **2026-10-10 两处修正**（庄园成员「哨」首次实跑抓出，主人批准修复）：
 *  ① 共享判据的正则错了：旧写 `^\\\\$`（本意「排除 $ 结尾的管理共享」）——该正则实际要求
 *     「行首 + 字面反斜杠 + 行尾」，**永不匹配** ⇒ `IPC$` 被当成「非默认共享」报 WARN。误报。
 *     正确写法是 `\\$$`（排除 `$` 结尾）。IPC$/C$/ADMIN$ 都是 Windows 默认管理共享。
 *  ② 更根本的一条：每项检查的读数**都可能因权限不足读不到**，而旧实现一律 `SilentlyContinue`
 *     ⇒ 读失败会退化成 `$null` ⇒ 落进 `else { 'PASS' }` ⇒ **假 PASS**。
 *     ⇒ 现在每项先 try/catch，失败报 `UNKNOWN`（附 reason），**只有真的读到才允许判 PASS/WARN**。 */
export function baselineCheck(): string {
  return `
$checks = @()
# 统一出口：读不到源 ⇒ UNKNOWN；读到才允许 PASS/WARN/FAIL。
# ⚠ 用「返回对象」而不是「$script:checks +=」—— 后者在 powershell -Command -（stdin）模式下
#   作用域不成立，会让整段脚本**静默吐空**（2026-10-10 尸体测试当场抓到）。
function New-Check($name, $err, $statusIfOk, $detailIfOk, $detailIfErr) {
  if ($err) { return [PSCustomObject]@{ Check=$name; Status='UNKNOWN'; Detail="读取失败：$detailIfErr" } }
  return [PSCustomObject]@{ Check=$name; Status=$statusIfOk; Detail=$detailIfOk }
}
# 防火墙三档
$fwErr = $null; $fw = $null
try { $fw = Get-NetFirewallProfile -ErrorAction Stop } catch { $fwErr = $_.Exception.Message }
if ($fwErr) {
  $checks += New-Check 'Firewall' $fwErr '' '' $fwErr
} else {
  foreach ($p in $fw) {
    $checks += [PSCustomObject]@{ Check="Firewall_$($p.Name)"; Status=$(if($p.Enabled){'PASS'}else{'FAIL'}); Detail="Inbound=$($p.DefaultInboundAction)" }
  }
}
# 共享：**排除 $ 结尾的 Windows 默认管理共享**（IPC$/C$/ADMIN$/PRINT$…）
$shErr = $null; $shares = $null
try { $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '\\$$' }) } catch { $shErr = $_.Exception.Message }
$checks += New-Check 'SMB_NonDefaultShares' $shErr $(if($shares.Count -gt 0){'WARN'}else{'PASS'}) $(if($shares.Count -gt 0){$shares.Name -join ','}else{'（仅默认管理共享）'}) $shErr
# RDP
$rdpErr = $null; $rdp = $null
try { $rdp = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections } catch { $rdpErr = $_.Exception.Message }
$checks += New-Check 'RDP_Enabled' $rdpErr $(if($rdp -eq 0){'WARN'}else{'PASS'}) "fDenyTSConnections=$rdp" $rdpErr
# 管理员组
$admErr = $null; $admins = $null
try { $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object -ExpandProperty Name) } catch { $admErr = $_.Exception.Message }
$checks += New-Check 'AdminGroup' $admErr 'INFO' ($admins -join ',') $admErr
# 自动登录 —— ⚠ 读**键**而不是读**属性**：属性不存在 = 「没配自动登录」= PASS（正常形态），
#   若按「属性不存在 ⇒ 抛异常 ⇒ UNKNOWN」去判，就把一个正常的机器报成了读数缺口（修过头）。
#   只有**键本身读不到**才算 UNKNOWN。
$autoErr = $null; $auto = $null
try { $auto = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction Stop).DefaultUserName } catch { $autoErr = $_.Exception.Message }
$checks += New-Check 'AutoLogon' $autoErr $(if($auto){'WARN'}else{'PASS'}) "DefaultUserName=$auto" $autoErr
$checks | ConvertTo-Json -Compress
`
}

/** 文件哈希计算（多算法） */
export function hashFile(filePath: string): string {
  return `
$ErrorActionPreference='SilentlyContinue'
$p = '${psQuote(filePath)}'
if (-not (Test-Path -LiteralPath $p)) { Write-Output 'NOT_FOUND'; exit }
$md5 = (Get-FileHash -LiteralPath $p -Algorithm MD5).Hash
$sha1 = (Get-FileHash -LiteralPath $p -Algorithm SHA1).Hash
$sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
$size = (Get-Item -LiteralPath $p).Length
[PSCustomObject]@{ Path=$p; Size=$size; MD5=$md5; SHA1=$sha1; SHA256=$sha256 } | ConvertTo-Json -Compress
`
}
