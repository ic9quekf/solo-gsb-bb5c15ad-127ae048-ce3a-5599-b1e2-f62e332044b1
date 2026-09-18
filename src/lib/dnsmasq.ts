// dnsmasq 静态租约生成：把主机地址登记（含 MAC）转换为 dnsmasq 的 dhcp-host 行。
// 本模块只读取主机登记与其校验结果，绝不修改规划（plan）、基线、路由汇总与导出数据。
//
// 关键不变量：
//   1. MAC 录入接受冒号或连字符分隔的六组十六进制（大小写不限），统一规范为小写冒号格式；
//   2. 拒绝全零 MAC、组播 MAC（首字节最低位 I/G 为 1）以及与其他设备重复的 MAC；
//   3. 只有「当前规划中有效且具备合法 MAC」的登记才会生成 dhcp-host 行；
//      失效或缺失 MAC 的登记列入 skipped（附原因），绝不出现在输出中；
//   4. 输出按 IPv4 升序，每行形如 dhcp-host=<MAC>,<IPv4>。

import type { HostRow } from './hosts'
import { intToIp } from './ip'
import type { HostAssignment } from './types'

const MAC_RE =
  /^([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})$/

/**
 * 解析并规范化 MAC：接受 aa:bb:cc:dd:ee:ff 或 aa-bb-cc-dd-ee-ff（大小写不限），
 * 返回小写冒号格式；格式非法返回 null。
 */
export function normalizeMac(raw: string): string | null {
  const m = MAC_RE.exec(raw.trim())
  if (!m) return null
  return m.slice(1).join(':').toLowerCase()
}

/** 全零 MAC（00:00:00:00:00:00）为保留地址，不能分配给设备 */
export function isAllZeroMac(mac: string): boolean {
  return mac === '00:00:00:00:00:00'
}

/** 组播 MAC：首字节最低位（I/G 位）为 1，如 01:00:5e:*；ff:ff:ff:ff:ff:ff 也落在其中 */
export function isMulticastMac(mac: string): boolean {
  return (parseInt(mac.slice(0, 2), 16) & 1) === 1
}

/**
 * 校验一次 MAC 录入。返回 null 表示可接受；否则返回面向用户的拒绝原因。
 * 允许留空（表示暂不录入，生成区会将其列为缺失 MAC 而不输出）；
 * 重复检查覆盖全部设备登记（MAC 在 dnsmasq 中全局唯一，不限于同网段）。
 */
export function validateMac(
  raw: string,
  assignments: HostAssignment[],
  selfId?: string,
): string | null {
  const value = raw.trim()
  if (!value) return null
  const mac = normalizeMac(value)
  if (!mac) return `“${value}”不是合法的 MAC 地址（需为六组十六进制，用冒号或连字符分隔）`
  if (isAllZeroMac(mac)) return '全零 MAC（00:00:00:00:00:00）是保留地址，不能分配给设备'
  if (isMulticastMac(mac)) return `${mac} 是组播 MAC（首字节最低位为 1），不能分配给设备`
  const clash = assignments.find((a) => a.id !== selfId && a.mac !== '' && a.mac === mac)
  if (clash) return `${mac} 已被设备“${clash.name || '未命名'}”使用`
  return null
}

/** 一条被跳过（不输出）的登记及原因 */
export interface DnsmasqSkipped {
  id: string
  name: string
  address: number
  reason: string
}

export interface DnsmasqLeases {
  /** 按 IPv4 升序的 dhcp-host 行 */
  lines: string[]
  /** lines 以换行连接（复制 / 下载用） */
  text: string
  /** 失效或缺失 MAC 的登记（附原因，不输出） */
  skipped: DnsmasqSkipped[]
}

/**
 * 由重新校验后的登记生成 dnsmasq 静态租约。
 * 仅纳入 valid 且 MAC 合法的登记；输出按 IPv4 升序。
 * 防御：若有效登记间出现相同 MAC（经界面正常录入不可能出现），
 * 保留先出现的一条，其余列入 skipped。
 */
export function buildDnsmasqLeases(rows: HostRow[]): DnsmasqLeases {
  const eligible: { mac: string; address: number }[] = []
  const skipped: DnsmasqSkipped[] = []
  const seenMac = new Set<string>()

  for (const row of rows) {
    const a = row.assignment
    if (!row.valid) {
      skipped.push({
        id: a.id,
        name: a.name,
        address: a.address,
        reason: row.reasonText ?? '登记已失效',
      })
      continue
    }
    if (!a.mac) {
      skipped.push({ id: a.id, name: a.name, address: a.address, reason: '未录入 MAC 地址' })
      continue
    }
    // 存储的 MAC 在录入时已规范化并校验；这里再复核一次，保证输出一定合法
    const mac = normalizeMac(a.mac)
    if (!mac || isAllZeroMac(mac) || isMulticastMac(mac)) {
      skipped.push({
        id: a.id,
        name: a.name,
        address: a.address,
        reason: `MAC 地址“${a.mac}”不合法`,
      })
      continue
    }
    if (seenMac.has(mac)) {
      skipped.push({
        id: a.id,
        name: a.name,
        address: a.address,
        reason: `MAC 地址 ${mac} 与另一台设备重复`,
      })
      continue
    }
    seenMac.add(mac)
    eligible.push({ mac, address: a.address })
  }

  eligible.sort((x, y) => x.address - y.address)
  const lines = eligible.map((e) => `dhcp-host=${e.mac},${intToIp(e.address)}`)
  return { lines, text: lines.join('\n'), skipped }
}
