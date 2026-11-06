import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { Terminal as XTerminal } from '@xterm/xterm'
import type { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import './real-app.css'
import {
  Activity, AlertTriangle, ArrowUpRight, AudioLines, Bluetooth, Cable, Check,
  ChevronRight, CircleHelp, Clock3, Cpu, FileClock, Gauge, HardDrive,
  Headphones, LayoutDashboard, ListChecks, LoaderCircle, LockKeyhole, Menu,
  Mic, Moon, Network, Play, Power, RefreshCw, Search, Server,
  ShieldCheck, Signal, SquareTerminal, Sun, Terminal, Trash2, Wifi, X, Zap,
} from 'lucide-react'

type Page = 'overview' | 'network' | 'services' | 'bluetooth' | 'audio' | 'terminal' | 'logs'
type Target = { id: string; name: string; host: string; port: number; username: string }
type HostInterface = { name: string; kind: string; mac?: string; ipv4: string[]; carrier: boolean; state: string; mtu?: number }
type HostInfo = { hostname: string; os: string; interfaces: HostInterface[] }
type DiscoveredHost = { address: string; interface: string; port: number; portOpen: boolean; source: string }
type HostKeyStatus = { fingerprints: string[]; pinnedFingerprints: string[]; trusted: boolean; changed: boolean }
type RemoteOverview = { hostname: string; uptime: string; load: string; memoryTotalKb?: number; memoryAvailableKb?: number; temperatureC?: number }
type Service = { name: string; description: string; active: string; subState: string; enabled: string }
type WifiNetwork = { inUse: boolean; ssid: string; signal: number; security: string }
type NetworkDevice = { device: string; kind: string; state: string; connection: string }
type RemoteNetwork = { supported: boolean; wifiEnabled: boolean; devices: NetworkDevice[]; wifiNetworks: WifiNetwork[]; note?: string }
type BluetoothDevice = { address: string; name: string; paired: boolean; connected: boolean; trusted: boolean }
type BluetoothSnapshot = { available: boolean; powered: boolean; adapter: string; devices: BluetoothDevice[] }
type AudioDevice = { name: string; description: string; isDefault: boolean }
type AudioSnapshot = { available: boolean; sinks: AudioDevice[]; sources: AudioDevice[]; alsaPlayback: AudioDevice[]; alsaCapture: AudioDevice[]; defaultSinkVolume?: number; defaultSourceVolume?: number; note?: string }
type AppLog = { at: string; text: string; tone: 'ok' | 'warn' | 'info' }
type Confirm = { title: string; description: string; danger?: boolean; run: () => Promise<void> }
type TerminalEvent = { sessionId: string; data: string }

const nav: { id: Page; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', label: '设备总览', icon: LayoutDashboard },
  { id: 'network', label: '网络与 Wi-Fi', icon: Network },
  { id: 'services', label: '系统服务', icon: Server },
  { id: 'bluetooth', label: '蓝牙设备', icon: Bluetooth },
  { id: 'audio', label: '音频设备', icon: AudioLines },
  { id: 'terminal', label: '终端', icon: SquareTerminal },
  { id: 'logs', label: '诊断记录', icon: FileClock },
]
const pageInfo: Record<Page, { title: string; subtitle: string }> = {
  overview: { title: '设备总览', subtitle: '查看开发机直连状态、机器人健康和常用调试入口。' },
  network: { title: '网络与 Wi-Fi', subtitle: '有线点对点连接属于开发机 ↔ 机器人；机器人 Wi-Fi 单独管理。' },
  services: { title: '系统服务', subtitle: '读取机器人 systemd 服务状态；启停操作会再次确认。' },
  bluetooth: { title: '蓝牙设备', subtitle: '查看机器人 BlueZ 适配器并扫描、配对和连接设备。' },
  audio: { title: '音频设备', subtitle: '读取 PulseAudio/PipeWire 控件和 ALSA 硬件设备；ALSA 项仅用于识别。' },
  terminal: { title: '终端', subtitle: '交互式 SSH PTY；主机、用户和危险命令提示始终可见。' },
  logs: { title: '诊断记录', subtitle: '本地记录本次会话的应用操作；不会记录密码或终端输入。' },
}
const DANGEROUS = /(^|[^A-Za-z0-9_])(sudo|su|reboot|shutdown|poweroff|halt|rm|mkfs|dd|fdisk|parted|wipefs|systemctl\s+(stop|restart|disable|mask)|nmcli\s+(radio\s+wifi\s+off|connection\s+(down|delete))|ip\s+(addr|route|link)|iptables|nft|chmod\s+-R|chown\s+-R)(\s|$)/i
const now = () => new Date().toLocaleTimeString('zh-CN', { hour12: false })
const displayError = (e: unknown) => typeof e === 'string' ? e : e instanceof Error ? e.message : String(e)
const formatMemory = (kb?: number) => kb ? `${(kb / 1024 / 1024).toFixed(1)} GB` : '—'
const terminalWriterRef: { current: { sessionId: string; write: (data: string) => void; confirmDangerous: () => Promise<void>; cancelDangerous: () => Promise<void>; confirmPaste: () => Promise<void>; cancelPaste: () => Promise<void> } | null } = { current: null }
const activeTerminalRef = { current: '' }
const openingTerminalRef = { current: false }
const terminalOutputQueue = new Map<string, string[]>()
const terminalExitQueue = new Set<string>()
const terminalEventsReadyRef: { current: Promise<void> } = { current: Promise.resolve() }

export default function RealApp() {
  const [page, setPage] = useState<Page>('overview')
  const [visitedPages, setVisitedPages] = useState<Set<Page>>(() => new Set<Page>(['overview']))
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('robolink-theme')
    const value = saved === 'light' ? 'light' : 'dark'
    document.documentElement.dataset.theme = value
    return value
  })
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [selectedId, setSelectedId] = useState(localStorage.getItem('robolink-selected-target') ?? '')
  const selected = useMemo(() => targets.find(t => t.id === selectedId), [targets, selectedId])
  const [localInterface, setLocalInterface] = useState('')
  const [scanPort, setScanPort] = useState('22')
  const [discovered, setDiscovered] = useState<DiscoveredHost[]>([])
  const [remoteOverview, setRemoteOverview] = useState<RemoteOverview | null>(null)
  const [services, setServices] = useState<Service[]>([])
  const [remoteNetwork, setRemoteNetwork] = useState<RemoteNetwork | null>(null)
  const [wifiNetworks, setWifiNetworks] = useState<WifiNetwork[]>([])
  const [bluetooth, setBluetooth] = useState<BluetoothSnapshot | null>(null)
  const [audio, setAudio] = useState<AudioSnapshot | null>(null)
  const [keyStatus, setKeyStatus] = useState<HostKeyStatus | null>(null)
  const [sessionId, setSessionId] = useState('')
  const [terminalExited, setTerminalExited] = useState(false)
  const [sshReady, setSshReady] = useState(false)
  const [targetDialog, setTargetDialog] = useState(false)
  const [targetDraft, setTargetDraft] = useState({ id: '', name: '', host: '', port: '22', username: 'robot' })
  const [keyDialog, setKeyDialog] = useState(false)
  const [trustChecked, setTrustChecked] = useState(false)
  const [selectedFingerprint, setSelectedFingerprint] = useState('')
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const [dangerLine, setDangerLine] = useState('')
  const [pastePreview, setPastePreview] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [toast, setToast] = useState('')
  const [logs, setLogs] = useState<AppLog[]>([])
  const [mobileNav, setMobileNav] = useState(false)
  const [refreshCount, setRefreshCount] = useState(0)
  const [serviceQuery, setServiceQuery] = useState('')
  const [sourceVolume, setSourceVolume] = useState(100)
  const [sinkVolume, setSinkVolume] = useState(68)

  const log = (text: string, tone: AppLog['tone'] = 'info') => {
    setLogs(items => [{ at: now(), text, tone }, ...items].slice(0, 500))
  }
  const notify = (text: string) => {
    setToast(text)
    window.setTimeout(() => setToast(''), 3000)
  }
  const toggleTheme = () => setTheme(current => {
    const next = current === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    localStorage.setItem('robolink-theme', next)
    return next
  })
  const withBusy = async <T,>(action: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true); setError('')
    try { return await action() }
    catch (e) { setError(displayError(e)); return undefined }
    finally { setBusy(false) }
  }

  useEffect(() => {
    void (async () => {
      try {
        const [h, t] = await Promise.all([invoke<HostInfo>('get_host_info'), invoke<Target[]>('list_targets')])
        setHostInfo(h); setTargets(t)
        const remembered = localStorage.getItem('robolink-selected-target') ?? ''
        const chosen = t.some(x => x.id === remembered) ? remembered : t[0]?.id ?? ''
        setSelectedId(chosen); setLocalInterface(h.interfaces.find(i => i.kind === '有线以太网')?.name ?? '')
      } catch (e) { setError(displayError(e)) }
    })()
  }, [])

  useEffect(() => {
    if (!selectedId) { setKeyStatus(null); setRemoteOverview(null); setServices([]); return }
    let cancelled = false
    void invoke<HostKeyStatus>('get_host_key_status', { targetId: selectedId }).then(status => {
      if (!cancelled) setKeyStatus(status)
    }).catch(() => { if (!cancelled) setKeyStatus(null) })
    return () => { cancelled = true }
  }, [selectedId])

  useEffect(() => {
    if (!selectedId || !keyStatus?.trusted || !sshReady) return
    let cancelled = false
    const load = async () => {
      setBusy(true); setError('')
      try {
        if (page === 'overview') {
          const [o, s] = await Promise.all([invoke<RemoteOverview>('get_remote_overview', { targetId: selectedId }), invoke<Service[]>('list_services', { targetId: selectedId })])
          if (!cancelled) { setRemoteOverview(o); setServices(s) }
        } else if (page === 'services') {
          const data = await invoke<Service[]>('list_services', { targetId: selectedId }); if (!cancelled) setServices(data)
        } else if (page === 'network') {
          const data = await invoke<RemoteNetwork>('get_remote_network', { targetId: selectedId }); if (!cancelled) { setRemoteNetwork(data); setWifiNetworks(data.wifiNetworks) }
        } else if (page === 'bluetooth') {
          const data = await invoke<BluetoothSnapshot>('get_bluetooth_snapshot', { targetId: selectedId }); if (!cancelled) setBluetooth(data)
        } else if (page === 'audio') {
          const data = await invoke<AudioSnapshot>('get_audio_snapshot', { targetId: selectedId }); if (!cancelled) { setAudio(data); setSinkVolume(data.defaultSinkVolume ?? 100); setSourceVolume(data.defaultSourceVolume ?? 100) }
        }
      } catch (e) { if (!cancelled) setError(displayError(e)) }
      finally { if (!cancelled) setBusy(false) }
    }
    void load()
    return () => { cancelled = true }
  }, [page, selectedId, keyStatus?.trusted, sshReady, refreshCount])

  useEffect(() => {
    localStorage.setItem('robolink-selected-target', selectedId)
  }, [selectedId])

  useEffect(() => {
    let offOutput: UnlistenFn | undefined
    let offExit: UnlistenFn | undefined
    const outputReady = listen<TerminalEvent>('terminal-output', event => {
      const id = event.payload.sessionId
      if (id === activeTerminalRef.current && terminalWriterRef.current?.sessionId === id) terminalWriterRef.current.write(event.payload.data)
      else if (id === activeTerminalRef.current || openingTerminalRef.current) {
        const queued = terminalOutputQueue.get(id) ?? []
        queued.push(event.payload.data)
        terminalOutputQueue.set(id, queued.slice(-300))
      }
    }).then(fn => { offOutput = fn })
    const exitReady = listen<TerminalEvent>('terminal-exit', event => {
      const id = event.payload.sessionId
      if (id === activeTerminalRef.current) { setTerminalExited(true); setSshReady(false); terminalWriterRef.current?.write(event.payload.data) }
      else if (openingTerminalRef.current) terminalExitQueue.add(id)
    }).then(fn => { offExit = fn })
    terminalEventsReadyRef.current = Promise.all([outputReady, exitReady]).then(() => undefined)
    return () => { offOutput?.(); offExit?.() }
  }, [])

  useEffect(() => {
    if (!sessionId || !selectedId || terminalExited) { setSshReady(false); return }
    let cancelled = false
    let timer = 0
    const poll = async () => {
      try {
        const ready = await invoke<boolean>('ssh_connection_ready', { targetId: selectedId })
        if (ready && !cancelled) {
          setSshReady(true)
          setLogs(items => items.some(item => item.text === 'SSH 认证完成') ? items : [{ at: now(), text: 'SSH 认证完成', tone: 'ok' as const }, ...items].slice(0, 500))
          window.clearInterval(timer)
        }
      } catch { /* A missing ControlMaster means the user may still be entering SSH credentials. */ }
    }
    void poll()
    timer = window.setInterval(() => { void poll() }, 800)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [sessionId, selectedId, terminalExited])

  const selectTarget = async (id: string) => {
    if (sessionId) await invoke('close_ssh_terminal', { sessionId }).catch(() => {})
    terminalOutputQueue.delete(sessionId); terminalExitQueue.delete(sessionId); activeTerminalRef.current = ''; terminalWriterRef.current = null; setSessionId(''); setTerminalExited(false); setSshReady(false)
    setRemoteOverview(null); setServices([]); setRemoteNetwork(null); setBluetooth(null); setAudio(null)
    setSelectedId(id); setKeyStatus(null); setError(''); setPage('overview')
  }
  const refreshNow = () => { setRefreshCount(n => n + 1); void invoke<HostInfo>('get_host_info').then(setHostInfo).catch(e => setError(displayError(e))) }
  const openNewTarget = (prefill = '', port = 22) => {
    setTargetDraft({ id: '', name: prefill ? `机器人 ${prefill}` : '', host: prefill, port: String(port), username: 'robot' })
    setTargetDialog(true)
  }
  const saveTarget = async (e: FormEvent) => {
    e.preventDefault()
    const draft = { id: targetDraft.id || null, name: targetDraft.name, host: targetDraft.host, port: Number(targetDraft.port), username: targetDraft.username }
    const saved = await withBusy(() => invoke<Target>('save_target', { draft }))
    if (saved) {
      const latest = await invoke<Target[]>('list_targets')
      setTargets(latest); setSelectedId(saved.id); setTargetDialog(false); setKeyStatus(null)
      log(`已保存 SSH 目标 ${saved.name} · ${saved.username}@${saved.host}:${saved.port}`)
      notify('SSH 目标已保存；首次连接前需核对主机指纹')
    }
  }
  const deleteTarget = (target: Target) => setConfirm({ title: `移除 ${target.name}？`, description: '将从本机删除目标配置和本应用保存的主机指纹，不会改动机器人，也不会删除系统 SSH 配置。', danger: true, run: async () => {
    if (sessionId && selectedId === target.id) { await invoke('close_ssh_terminal', { sessionId }).catch(() => {}); activeTerminalRef.current = ''; setSessionId(''); setSshReady(false) }
    await invoke('delete_target', { id: target.id }); const latest = await invoke<Target[]>('list_targets'); setTargets(latest); setSelectedId(latest[0]?.id ?? ''); setKeyStatus(null); setConfirm(null); log(`移除目标 ${target.name}`, 'warn')
  } })

  const connectTarget = async () => {
    if (!selected) { openNewTarget(); return }
    const status = await withBusy(() => invoke<HostKeyStatus>('get_host_key_status', { targetId: selected.id }))
    if (!status) return
    if (status.trusted && !status.changed) { setKeyStatus(status); await openTerminal(); return }
    setKeyStatus(status); setTrustChecked(false); setSelectedFingerprint(status.fingerprints[0] ?? ''); setKeyDialog(true)
    if (status.changed) log(`检测到 ${selected.name} 的 SSH 主机密钥与已固定值不同`, 'warn')
  }
  const trustAndConnect = async () => {
    if (!selected || !keyStatus || !trustChecked || !selectedFingerprint) return
    if (keyStatus.changed) { notify('主机指纹变化需先显式清除旧 pin，再重新核对'); return }
    const result = await withBusy(() => invoke<boolean>('trust_host_key', { targetId: selected.id, fingerprint: selectedFingerprint }))
    if (!result) return
    setKeyStatus({ ...keyStatus, trusted: true, changed: false, pinnedFingerprints: [selectedFingerprint] })
    setKeyDialog(false); log(`已由用户确认并固定 ${selected.name} 的 SSH 主机密钥`, 'ok')
    await openTerminal()
  }
  const clearChangedPin = () => {
    if (!selected) return
    setConfirm({ title: '清除旧主机指纹？', description: `目标 ${selected.username}@${selected.host}:${selected.port} 的密钥发生变化。只有在已通过机器人本地控制台或可信渠道核验新指纹后，才继续。清除后仍需再次手动确认新指纹。`, danger: true, run: async () => {
      await invoke('forget_host_key', { targetId: selected.id }); const status = await invoke<HostKeyStatus>('get_host_key_status', { targetId: selected.id }); setKeyStatus(status); setTrustChecked(false); setSelectedFingerprint(status.fingerprints[0] ?? ''); setConfirm(null); log(`已清除 ${selected.name} 的旧 SSH 主机指纹，等待重新核验`, 'warn')
    } })
  }
  const openTerminal = async () => {
    if (!selected) return
    if (sessionId && !terminalExited && activeTerminalRef.current === sessionId) { setPage('terminal'); return }
    if (sessionId) await invoke('close_ssh_terminal', { sessionId }).catch(() => {})
    await terminalEventsReadyRef.current
    openingTerminalRef.current = true
    const result = await withBusy(() => invoke<string>('open_ssh_terminal', { targetId: selected.id }))
    openingTerminalRef.current = false
    if (result) { activeTerminalRef.current = result; terminalWriterRef.current = null; setSessionId(result); setTerminalExited(terminalExitQueue.delete(result)); setSshReady(false); setPage('terminal'); log(`已打开到 ${selected.name} 的 SSH PTY 会话`, 'ok') }
  }
  const disconnectTerminal = async () => {
    if (sessionId) await invoke('close_ssh_terminal', { sessionId }).catch(() => {})
    terminalWriterRef.current?.write('\r\n[已断开 SSH 会话]\r\n'); terminalOutputQueue.delete(sessionId); terminalExitQueue.delete(sessionId); activeTerminalRef.current = ''; terminalWriterRef.current = null; setSessionId(''); setTerminalExited(false); setSshReady(false); log('已断开 SSH 终端会话')
  }
  const scanInterface = async () => {
    if (!localInterface) { setError('请先选择本机物理有线网卡'); return }
    const port = Number(scanPort)
    if (!Number.isInteger(port) || port < 1 || port > 65535) { setError('TCP 探测端口必须是 1–65535 的整数'); return }
    setDiscovered([])
    const found = await withBusy(() => invoke<DiscoveredHost[]>('scan_direct_interface', { interface: localInterface, port }))
    if (found) {
      setDiscovered(found)
      const portCount = found.filter(host => host.portOpen).length
      log(`在 ${localInterface} 发现 ${found.length} 个邻居 IP 候选，其中 ${portCount} 个 TCP/${port} 可达`, found.length ? 'ok' : 'info')
      if (!found.length) notify('未发现邻居 IP；请确认两端 IPv4 同网段、网线和机器人电源')
      else if (!portCount) notify(`已发现邻居 IP，但 TCP/${port} 未确认；若 SSH 使用其他端口，请修改端口后重试`)
    }
  }
  const showConfirm = (title: string, description: string, run: () => Promise<void>, danger = false) => setConfirm({ title, description, run, danger })

  const doServiceAction = (service: Service, action: 'start' | 'stop' | 'restart') => {
    if (!selected) return
    const labels = { start: '启动', stop: '停止', restart: '重启' }
    showConfirm(`${labels[action]} ${service.name}？`, `将在机器人 ${selected.name} 上对 systemd 服务执行 ${labels[action]}。该操作可能影响机器人功能；应用不会自动提权。`, async () => {
      await invoke('service_action', { targetId: selected.id, service: service.name, action })
      setConfirm(null); log(`${labels[action]} ${service.name}`, action === 'stop' ? 'warn' : 'ok'); setRefreshCount(n => n + 1)
    }, action !== 'start')
  }
  const toggleWifiRadio = (enabled: boolean) => {
    if (!selected) return
    showConfirm(`${enabled ? '开启' : '关闭'}机器人 Wi-Fi？`, `将在 ${selected.name} 上执行 NetworkManager Wi-Fi ${enabled ? '开启' : '关闭'}。这可能会中断 SSH；有线直连是否仍然可达取决于机器人网线和地址配置。`, async () => {
      await invoke('set_remote_wifi_radio', { targetId: selected.id, enabled })
      setConfirm(null); log(`机器人 Wi-Fi 已请求${enabled ? '开启' : '关闭'}`, enabled ? 'info' : 'warn'); setRefreshCount(n => n + 1)
    }, !enabled)
  }
  const scanWifi = async () => {
    if (!selected) return
    const rows = await withBusy(() => invoke<WifiNetwork[]>('scan_remote_wifi', { targetId: selected.id }))
    if (rows) { setWifiNetworks(rows); setRemoteNetwork(v => v ? { ...v, wifiNetworks: rows } : v); log(`机器人 Wi-Fi 扫描完成：${rows.length} 个网络`) }
  }
  const connectWifi = (wifi: WifiNetwork) => {
    if (!selected) return
    showConfirm(`连接 ${wifi.ssid}？`, '应用会在机器人上启动 nmcli 交互连接，并切换到 SSH 终端。若需要密码，请在终端提示中输入；密码不会保存在 RoboLink。此操作可能导致当前 SSH 会话中断。', async () => {
      if (sessionId) await invoke('close_ssh_terminal', { sessionId }).catch(() => {})
      await terminalEventsReadyRef.current; openingTerminalRef.current = true
      let result: string
      try { result = await invoke<string>('start_wifi_connect', { targetId: selected.id, ssid: wifi.ssid }) } finally { openingTerminalRef.current = false }
      activeTerminalRef.current = result; terminalWriterRef.current = null; setSessionId(result); setTerminalExited(terminalExitQueue.delete(result)); setSshReady(false); setPage('terminal'); setConfirm(null); log(`在机器人终端启动 Wi-Fi 连接：${wifi.ssid}`, 'warn')
    }, true)
  }
  const scanBluetooth = async () => {
    if (!selected) return
    const snap = await withBusy(() => invoke<BluetoothSnapshot>('scan_bluetooth', { targetId: selected.id }))
    if (snap) { setBluetooth(snap); log(`蓝牙扫描完成：发现 ${snap.devices.length} 台设备`) }
  }
  const toggleBluetoothPower = (enabled: boolean) => {
    if (!selected) return
    showConfirm(`${enabled ? '开启' : '关闭'}机器人蓝牙？`, `将在 ${selected.name} 上切换 BlueZ 适配器电源。${enabled ? '开启后可扫描设备。' : '关闭会断开所有已连接的蓝牙设备。'}`, async () => {
      await invoke('set_bluetooth_power', { targetId: selected.id, enabled })
      const snap = await invoke<BluetoothSnapshot>('get_bluetooth_snapshot', { targetId: selected.id })
      setBluetooth(snap); setConfirm(null); log(`机器人蓝牙适配器已请求${enabled ? '开启' : '关闭'}`, enabled ? 'ok' : 'warn')
    }, !enabled)
  }
  const bluetoothAction = async (device: BluetoothDevice, action: string) => {
    if (!selected) return
    if (action === 'pair') {
      showConfirm(`配对 ${device.name}？`, `将在机器人 ${selected.name} 上请求与 ${device.address} 配对。若 BlueZ 要求 PIN 或确认，交互会显示在 SSH 终端。`, async () => {
        if (sessionId) await invoke('close_ssh_terminal', { sessionId }).catch(() => {})
        await terminalEventsReadyRef.current; openingTerminalRef.current = true
        let result: string | null
        try { result = await invoke<string | null>('bluetooth_action', { targetId: selected.id, address: device.address, action }) } finally { openingTerminalRef.current = false }
        setConfirm(null); if (result) { activeTerminalRef.current = result; terminalWriterRef.current = null; setSessionId(result); setTerminalExited(terminalExitQueue.delete(result)); setSshReady(false); setPage('terminal') } log(`请求蓝牙配对 ${device.name}`, 'warn')
      }, true); return
    }
    await withBusy(async () => {
      await invoke('bluetooth_action', { targetId: selected.id, address: device.address, action })
      log(`蓝牙设备 ${device.name}：${action}`); setRefreshCount(n => n + 1)
    })
  }
  const setDefaultAudio = async (kind: 'sink' | 'source', device: string) => {
    if (!selected) return
    await withBusy(async () => { await invoke('set_audio_default', { targetId: selected.id, kind, device }); log(`已设置机器人音频${kind === 'sink' ? '输出' : '输入'}：${device}`, 'ok'); setRefreshCount(n => n + 1) })
  }
  const commitAudioVolume = async (kind: 'sink' | 'source', device: string, volume: number) => {
    if (!selected) return
    await withBusy(async () => { await invoke('set_audio_volume', { targetId: selected.id, kind, device, volume }); log(`机器人音频${kind === 'sink' ? '输出' : '输入'}音量设为 ${volume}%`) })
  }
  const playTestAudio = async () => {
    if (!selected) return
    await withBusy(async () => { await invoke('play_test_audio', { targetId: selected.id }); log('已在机器人请求播放 440 Hz 测试音') })
  }
  const visibleServices = services.filter(s => `${s.name} ${s.description}`.toLowerCase().includes(serviceQuery.toLowerCase()))
  const wiredInterfaces = hostInfo?.interfaces.filter(i => i.kind === '有线以太网') ?? []
  const navPage = (id: Page) => { setVisitedPages(pages => pages.has(id) ? pages : new Set(pages).add(id)); setPage(id); setMobileNav(false); setError('') }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
      <div className="brand-row"><div className="brand-mark"><Cable size={19}/></div><div><div className="brand-name">RoboLink</div><div className="brand-caption">ROBOT DEBUG CONSOLE</div></div><button className="icon-button mobile-close" onClick={() => setMobileNav(false)} aria-label="关闭菜单"><X size={18}/></button></div>
      <div className="workspace-label">SSH 目标</div>
      <div className="target-selector">
        <select aria-label="选择机器人目标" value={selectedId} onChange={e => selectTarget(e.target.value)}><option value="">选择机器人…</option>{targets.map(t => <option value={t.id} key={t.id}>{t.name} · {t.host}</option>)}</select>
        <button className="icon-button target-add" onClick={() => openNewTarget()} title="添加 SSH 目标" aria-label="添加 SSH 目标">+</button>
      </div>
      {selected && <div className="target-summary"><span className={`target-status-dot ${keyStatus?.trusted ? 'online' : ''}`}/><span><strong>{selected.name}</strong><small>{selected.username}@{selected.host}:{selected.port}</small></span><button className="icon-button" title="删除目标" aria-label="删除目标" onClick={() => deleteTarget(selected)}><Trash2 size={14}/></button></div>}
      <div className="nav-label">设备管理</div>
      <nav className="nav-list" aria-label="主导航">{nav.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => navPage(id)}><Icon size={18}/><span>{label}</span>{id === 'services' && services.some(s => s.active !== 'active') && <span className="nav-badge">!</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="connection-mini"><div className="connection-mini-top"><span className={`pulse-dot ${sshReady && !terminalExited ? '' : 'offline'}`}/>{sshReady && !terminalExited ? 'SSH 已认证' : sessionId && !terminalExited ? '等待 SSH 认证' : '等待 SSH 连接'}</div><div className="connection-mini-bottom"><Cable size={13}/>{hostInfo?.hostname ?? 'Linux 开发机'} <ChevronRight size={12}/>{localInterface || '选择有线网卡'}<ChevronRight size={12}/>机器人</div></div>
        <div className="profile-row"><div className="profile-avatar">RL</div><div className="profile-copy"><strong>{hostInfo?.os ?? 'Linux 开发机'}</strong><small>本机操作 · 默认不提权</small></div><ShieldCheck size={17} className="muted"/></div></div>
    </aside>
    {mobileNav && <button className="mobile-scrim" onClick={() => setMobileNav(false)} aria-label="关闭菜单"/>}
    <button className="theme-toggle" onClick={toggleTheme} aria-label={theme === 'dark' ? '切换到浅色模式' : '切换到深色模式'} title={theme === 'dark' ? '浅色模式' : '深色模式'}>{theme === 'dark' ? <Sun size={16}/> : <Moon size={16}/>}<span>{theme === 'dark' ? '浅色' : '深色'}</span></button>
    <main className="main-area">
      <header className="topbar"><div className="topbar-left"><button className="icon-button menu-button" onClick={() => setMobileNav(true)} aria-label="打开菜单"><Menu size={19}/></button><div className="breadcrumb">RoboLink <ChevronRight size={14}/><strong>{selected?.name ?? '未选择设备'}</strong></div></div><div className="topbar-actions"><div className="secure-pill"><LockKeyhole size={13}/>{sshReady ? 'SSH 已认证' : keyStatus?.trusted ? sessionId && !terminalExited ? '指纹已固定 · 认证中' : 'SSH 指纹已固定' : '本地会话'}</div>{selected && <button className={`button ${sessionId && !terminalExited ? 'button-subtle' : 'button-primary'} connect-button`} onClick={sessionId && !terminalExited ? () => navPage('terminal') : connectTarget} disabled={busy}>{busy ? <LoaderCircle className="spin-icon" size={15}/> : sessionId && !terminalExited ? <Terminal size={15}/> : <Cable size={15}/>}<span>{sessionId && !terminalExited ? '打开终端' : '连接机器人'}</span></button>}<button className="icon-button" onClick={() => notify('安全说明：本机网卡只读；SSH 使用本应用的指纹 pin。')} aria-label="安全说明"><CircleHelp size={18}/></button><div className="top-avatar">RL</div></div></header>
      <div className="content-wrap">
        <div className="page-heading"><div><div className="eyebrow">LINUX HOST <span>·</span> DIRECT ETHERNET / SSH</div><h1>{pageInfo[page].title}</h1><p>{pageInfo[page].subtitle}</p></div><div className="heading-actions"><span className={`runtime-tag ${selected && keyStatus?.trusted ? 'live' : ''}`}><span/>{selected && keyStatus?.trusted ? '真实设备' : '尚未连接'}</span><button className="button button-subtle" onClick={refreshNow} disabled={busy}><RefreshCw size={15}/>刷新</button></div></div>
        {error && <div className="inline-error"><AlertTriangle size={16}/><span>{error}</span><button onClick={() => setError('')} aria-label="关闭错误"><X size={15}/></button></div>}
        <div className="page-view" hidden={page !== 'overview'}>{visitedPages.has('overview') && <OverviewPage hostInfo={hostInfo} target={selected} trusted={!!keyStatus?.trusted} connected={sshReady && !terminalExited} remote={remoteOverview} services={services} onAdd={() => openNewTarget()} onConnect={connectTarget} onPage={navPage}/>}</div>
        <div className="page-view" hidden={page !== 'network'}>{visitedPages.has('network') && <NetworkPage hostInfo={hostInfo} interfaces={wiredInterfaces} selectedInterface={localInterface} setSelectedInterface={name => { setLocalInterface(name); setDiscovered([]) }} scanPort={scanPort} setScanPort={setScanPort} discovered={discovered} onScan={scanInterface} network={remoteNetwork} wifi={wifiNetworks} onScanWifi={scanWifi} onToggleWifi={toggleWifiRadio} onConnectWifi={connectWifi} onAddHost={openNewTarget} busy={busy}/>}</div>
        <div className="page-view" hidden={page !== 'services'}>{visitedPages.has('services') && <ServicesPage services={visibleServices} query={serviceQuery} setQuery={setServiceQuery} onAction={doServiceAction} busy={busy}/>}</div>
        <div className="page-view" hidden={page !== 'bluetooth'}>{visitedPages.has('bluetooth') && <BluetoothPage snapshot={bluetooth} onScan={scanBluetooth} onTogglePower={toggleBluetoothPower} onAction={bluetoothAction} busy={busy}/>}</div>
        <div className="page-view" hidden={page !== 'audio'}>{visitedPages.has('audio') && <AudioPage snapshot={audio} sourceVolume={sourceVolume} sinkVolume={sinkVolume} setSourceVolume={setSourceVolume} setSinkVolume={setSinkVolume} onDefault={setDefaultAudio} onVolume={commitAudioVolume} onTest={playTestAudio} busy={busy}/>}</div>
        <div className="page-view" hidden={page !== 'terminal'}>{visitedPages.has('terminal') && <TerminalPage key={sessionId} sessionId={sessionId} exited={terminalExited} sshReady={sshReady} target={selected} theme={theme} onConnect={connectTarget} onDisconnect={disconnectTerminal} onRisk={setDangerLine} onPaste={setPastePreview} onError={setError}/>}</div>
        <div className="page-view" hidden={page !== 'logs'}>{visitedPages.has('logs') && <LogsPage logs={logs} onClear={() => setConfirm({ title: '清空本地诊断记录？', description: '只删除 RoboLink 本机界面中的操作记录，不会影响机器人。', run: async () => { setLogs([]); setConfirm(null) } })}/>}</div>
        <footer className="footer-note"><ShieldCheck size={14}/>默认只读本机网卡 · SSH 使用独立 known_hosts · RoboLink v0.2.2 <span>·</span><span>{hostInfo?.os ?? 'Linux'}</span></footer>
      </div>
    </main>
    {targetDialog && <TargetDialog value={targetDraft} setValue={setTargetDraft} onClose={() => setTargetDialog(false)} onSubmit={saveTarget} busy={busy}/>}
    {keyDialog && selected && keyStatus && <HostKeyDialog target={selected} status={keyStatus} fingerprint={selectedFingerprint} setFingerprint={setSelectedFingerprint} checked={trustChecked} setChecked={setTrustChecked} onTrust={trustAndConnect} onClear={clearChangedPin} onClose={() => setKeyDialog(false)} busy={busy}/>}
    {confirm && <ConfirmDialog confirm={confirm} onCancel={() => setConfirm(null)} onConfirm={async () => { setBusy(true); setError(''); try { await confirm.run() } catch (e) { setError(displayError(e)); setConfirm(null) } finally { setBusy(false) } }}/>}
    {dangerLine && <ConfirmDialog confirm={{ title: '高风险终端命令', description: `目标：${selected?.username}@${selected?.host}\n命令：${dangerLine}\n\n此命令可能改变网络、服务或磁盘。确认后才会将回车发送到远端 Shell。`, danger: true, run: async () => { await terminalWriterRef.current?.confirmDangerous(); setDangerLine('') } }} onCancel={async () => { await terminalWriterRef.current?.cancelDangerous(); setDangerLine('') }} onConfirm={async () => { await terminalWriterRef.current?.confirmDangerous(); setDangerLine('') }}/>}
    {pastePreview && <ConfirmDialog confirm={{ title: '确认粘贴多行命令？', description: `目标：${selected?.username}@${selected?.host}\n\n${pastePreview.slice(0, 1600)}${pastePreview.length > 1600 ? '\n…（预览已截断）' : ''}\n\n粘贴内容可能包含多个会执行的命令。请先检查目标和每一行。`, danger: true, run: async () => { await terminalWriterRef.current?.confirmPaste(); setPastePreview('') } }} onCancel={async () => { await terminalWriterRef.current?.cancelPaste(); setPastePreview('') }} onConfirm={async () => { await terminalWriterRef.current?.confirmPaste(); setPastePreview('') }}/>}
    {toast && <div className="toast"><Check size={16}/>{toast}</div>}
  </div>
}

function OverviewPage({ hostInfo, target, trusted, connected, remote, services, onAdd, onConnect, onPage }: { hostInfo: HostInfo | null; target?: Target; trusted: boolean; connected: boolean; remote: RemoteOverview | null; services: Service[]; onAdd: () => void; onConnect: () => void; onPage: (page: Page) => void }) {
  const failed = services.filter(s => s.active !== 'active')
  return <div className="dashboard-grid real-dashboard">
    <section className="main-column">
      <section className="panel connection-card real-connection"><div className="panel-heading"><div><div className="section-kicker">DIRECT ETHERNET · NO INTERMEDIARY</div><h2>{target ? `${target.name} · ${target.host}` : '添加机器人 SSH 目标'}</h2></div><span className={`connected-pill ${connected ? '' : 'not-connected'}`}><span/>{connected ? 'SSH 会话已连接' : trusted ? '指纹已固定' : '未连接'}</span></div>
        <div className="connection-map"><div className="endpoint"><div className="endpoint-icon host"><MonitorGlyph/></div><div><strong>本地 Linux 开发机</strong><small>{hostInfo?.hostname ?? '读取中…'}</small></div></div><div className="link-track"><div className="link-line"/><div className="link-chip"><Cable size={14}/>一根网线直接连接</div></div><div className="endpoint"><div className="endpoint-icon robot"><Cpu size={21}/></div><div><strong>{target?.name ?? 'Linux 机器人'}</strong><small>{target ? `${target.username}@${target.host}:${target.port}` : '未配置目标'}</small></div></div></div>
        <div className="connection-footer"><span><ShieldCheck size={14}/>{trusted ? '独立主机指纹已固定' : '连接前需要核验 SSH 指纹'}</span><button onClick={target ? onConnect : onAdd}>{target ? '核验并连接' : '添加 SSH 目标'} <ArrowUpRight size={14}/></button></div></section>
      {!target && <div className="first-run-card"><div className="first-run-icon"><Cable size={22}/></div><div><strong>开始调试你的无头机器人</strong><p>网线从开发机直接连接机器人。先选择目标 IP/主机名和 SSH 用户；应用不会替你更改开发机网络。</p></div><button className="button button-primary" onClick={onAdd}>添加设备</button></div>}
      {target && !trusted && <div className="network-warning"><div className="warning-icon"><LockKeyhole size={17}/></div><div><strong>尚未验证机器人的 SSH 身份</strong><p>首次连接前需核对 SSH 指纹；在机器人本地可信控制台运行 <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> 进行比对。</p></div><button className="button button-subtle" onClick={onConnect}>查看指纹</button></div>}
      <div className="metric-grid real-metrics"><Metric label="系统服务" value={trusted ? `${services.filter(s => s.active === 'active').length} / ${services.length}` : '未连接'} detail={trusted ? `${failed.length} 个非运行状态` : '连接并验证后读取'} tone="green" icon={Server} onClick={() => onPage('services')}/><Metric label="机器人 Wi-Fi" value="SSH 连接后读取" detail="只操作机器人，不改本机网络" tone="blue" icon={Wifi} onClick={() => onPage('network')}/><Metric label="机器人蓝牙" value="SSH 连接后读取" detail="BlueZ · 配对需确认" tone="violet" icon={Bluetooth} onClick={() => onPage('bluetooth')}/><Metric label="音频设备" value="SSH 连接后读取" detail="PipeWire / PulseAudio" tone="amber" icon={AudioLines} onClick={() => onPage('audio')}/></div>
      <section className="panel service-panel"><div className="panel-heading"><div><div className="section-kicker">SYSTEMD</div><h2>服务概况</h2></div><button className="text-button" onClick={() => onPage('services')}>查看服务 <ChevronRight size={15}/></button></div>{!trusted ? <EmptyState text="连接并验证 SSH 指纹后显示真实服务状态。"/> : services.length ? services.slice(0,5).map(s => <div className="service-row real-service-row" key={s.name}><div className="service-name-cell"><span className={`service-icon ${s.active === 'active' ? 'is-running' : 'is-stopped'}`}><Zap size={15}/></span><span><strong>{s.name}</strong><small>{s.description}</small></span></div><span className={`state-label ${s.active === 'active' ? 'state-ok' : 'state-down'}`}><i/>{s.active} · {s.subState}</span><span className="uptime-text">{s.enabled}</span></div>) : <EmptyState text="未读到 systemd 服务，或当前用户无权读取。"/>}</section>
    </section>
    <aside className="right-column"><section className="panel health-panel"><div className="panel-heading"><div><div className="section-kicker">ROBOT HEALTH</div><h2>机器人状态</h2></div><span className="small-muted">{remote ? '实时读取' : '连接后读取'}</span></div>{remote ? <div className="remote-health"><HealthRow icon={Cpu} label="主机名" value={remote.hostname} sub={remote.uptime} percent={100} color="green"/><HealthRow icon={Gauge} label="系统负载" value={remote.load} sub="1 / 5 / 15 分钟" percent={Math.min(100, parseFloat(remote.load) * 25 || 0)} color="blue"/><HealthRow icon={HardDrive} label="可用内存" value={`${formatMemory(remote.memoryAvailableKb)} / ${formatMemory(remote.memoryTotalKb)}`} sub="/proc/meminfo" percent={remote.memoryTotalKb && remote.memoryAvailableKb ? 100 - remote.memoryAvailableKb / remote.memoryTotalKb * 100 : 0} color="violet"/>{remote.temperatureC != null && <HealthRow icon={Zap} label="CPU 温度" value={`${remote.temperatureC.toFixed(1)}°C`} sub="thermal zone" percent={Math.min(100,remote.temperatureC)} color="amber"/>}</div> : <EmptyState text="尚无机器人遥测。连接并授权后读取主机名、负载和内存。"/>}<div className="health-time"><Clock3 size={13}/>{remote ? `运行时间 · ${remote.uptime}` : '未创建远端会话'}</div></section>
      <section className="panel quick-panel"><div className="panel-heading"><div><div className="section-kicker">QUICK ACCESS</div><h2>快速调试</h2></div></div><QuickAction icon={Terminal} title="打开 SSH 终端" detail={connected ? '持久交互式 PTY' : '先连接并核验主机'} onClick={() => onPage('terminal')}/><QuickAction icon={ListChecks} title="检查 systemd 服务" detail={trusted ? `${services.length} 项` : '连接后读取'} onClick={() => onPage('services')}/><QuickAction icon={FileClock} title="查看诊断记录" detail="本机操作历史" onClick={() => onPage('logs')}/></section>
      <section className="safety-note"><div className="safety-icon"><ShieldCheck size={17}/></div><div><strong>安全默认值</strong><p>本机网卡只读；host key 独立固定；不保存 SSH 或 Wi-Fi 密码。</p></div></section>
    </aside>
  </div>
}
function MonitorGlyph() { return <div className="monitor-glyph"><div/><span/></div> }
function Metric({ label, value, detail, tone, icon: Icon, onClick }: { label: string; value: string; detail: string; tone: string; icon: typeof Cpu; onClick: () => void }) { return <button className="panel metric-card" onClick={onClick}><div className={`metric-icon ${tone}`}><Icon size={18}/></div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-detail">{detail}<ArrowUpRight size={12}/></div></button> }
function HealthRow({ icon: Icon, label, value, sub, percent, color }: { icon: typeof Cpu; label: string; value: string; sub: string; percent: number; color: string }) { return <div className="health-row"><div className="health-row-top"><span className="health-label"><Icon size={15}/>{label}</span><span className="health-value">{value}</span></div><div className="health-meter"><span className={color} style={{ width: `${Math.max(2,Math.min(100,percent))}%` }}/></div><div className="health-sub">{sub}</div></div> }
function QuickAction({ icon: Icon, title, detail, onClick }: { icon: typeof Terminal; title: string; detail: string; onClick: () => void }) { return <button className="quick-action" onClick={onClick}><span className="quick-icon blue"><Icon size={17}/></span><span><strong>{title}</strong><small>{detail}</small></span><ChevronRight size={16}/></button> }
function EmptyState({ text }: { text: string }) { return <div className="empty-state"><Activity size={17}/><span>{text}</span></div> }

function NetworkPage({ hostInfo, interfaces, selectedInterface, setSelectedInterface, scanPort, setScanPort, discovered, onScan, network, wifi, onScanWifi, onToggleWifi, onConnectWifi, onAddHost, busy }: { hostInfo: HostInfo | null; interfaces: HostInterface[]; selectedInterface: string; setSelectedInterface: (v: string) => void; scanPort: string; setScanPort: (v: string) => void; discovered: DiscoveredHost[]; onScan: () => void; network: RemoteNetwork | null; wifi: WifiNetwork[]; onScanWifi: () => void; onToggleWifi: (v: boolean) => void; onConnectWifi: (n: WifiNetwork) => void; onAddHost: (host?: string, port?: number) => void; busy: boolean }) {
  const selectedLink = interfaces.find(i => i.name === selectedInterface)
  const linkLocalOnly = !!selectedLink?.ipv4.length && selectedLink.ipv4.every(address => address.startsWith('169.254.'))
  return <div className="page-stack"><div className="network-warning"><div className="warning-icon"><AlertTriangle size={18}/></div><div><strong>有线网络按点对点连接处理</strong><p>网线直接连接 Linux 开发机和机器人，不依赖交换机或路由器。这里不会自动改开发机地址、默认路由、DNS 或防火墙。</p></div></div>
    <section className="panel detail-panel"><div className="panel-heading"><div className="heading-icon cable-bg"><Cable size={18}/></div><div><div className="section-kicker">LOCAL LINUX HOST</div><h2>开发机有线网卡</h2></div><span className="small-muted push-right">{hostInfo?.hostname ?? '读取中'}</span></div>
      {!interfaces.length ? <EmptyState text="未检测到物理有线网卡。请插入网线或检查 iproute2。"/> : <div className="interface-cards">{interfaces.map(i => <button className={`interface-card ${selectedInterface === i.name ? 'selected' : ''}`} key={i.name} onClick={() => setSelectedInterface(i.name)}><span className="interface-card-top"><Cable size={15}/><strong>{i.name}</strong><i className={i.carrier ? 'carrier-up' : 'carrier-down'}/></span><span>{i.carrier ? '物理链路已连接' : '无物理链路'}</span><small>{i.ipv4.join(' · ') || '未配置 IPv4'}{i.mac ? ` · ${i.mac}` : ''}</small></button>)}</div>}
      <div className={`direct-link-state ${selectedLink?.carrier && selectedLink.ipv4.length ? 'ready' : 'needs-setup'}`}><Cable size={16}/><div><strong>{!selectedLink ? '先选择直连接口' : !selectedLink.carrier ? '尚未检测到网线链路' : !selectedLink.ipv4.length ? '网线已连通，但开发机接口尚无 IPv4 地址' : linkLocalOnly ? '检测到 IPv4 链路本地地址' : '直连接口已配置 IPv4'}</strong><p>{!selectedLink ? '插入直连网线后，选择连接机器人的本机物理以太网口。' : !selectedLink.carrier ? '检查机器人电源、网线两端和所选网卡。直连不需要 Internet，但必须先建立物理链路。' : !selectedLink.ipv4.length ? '本机接口没有 IPv4 时，单靠网线不能推导机器人任意静态 IP。请按机器人说明为两端设置同一网段地址，例如开发机 192.168.77.1/24、机器人 192.168.77.2/24；应用不会自动改本机网络。' : linkLocalOnly ? '169.254/16 可用于无路由器直连；扫描只检查此接口已知的链路本地邻居，不遍历整个 /16。若没有邻居，请按机器人说明配置同网段地址或使用已知 IP。' : `本机直连接口地址：${selectedLink.ipv4.join(' · ')}。无需预先知道机器人 IP；扫描会列出同网段邻居 IP 候选。`}</p>{selectedLink?.carrier && <button className="text-button" onClick={() => onAddHost()}>我已知道机器人 IP / 主机名，手动添加 <ChevronRight size={14}/></button>}</div></div>
      <div className="connection-steps"><strong>直连操作步骤</strong><ol><li>用网线把本机和已开机的机器人直接相连。</li><li>选择显示“物理链路已连接”、且本机 IPv4 与机器人同网段的有线网卡。</li><li>设置机器人 SSH 的 TCP 端口（默认 22；若使用其他端口，请在下方修改），再点击扫描。</li><li>将 IP 添加为机器人目标；端口可达仍不代表 SSH 身份已验证，首次连接要核对主机指纹。</li></ol></div>
      <div className="subtle-callout"><ShieldCheck size={16}/><span>扫描只使用所选物理网卡：普通地址仅限其 /24–/30 子网（最多 254 个候选）；169.254/16 只看已知邻居，不扫完整 /16。邻居缓存可能含过期地址；结果标注的是你选定 TCP 端口的可达性，不验证 SSH 握手。不会扫描 Wi‑Fi/其他接口，也不会改本机 IP、路由或防火墙。</span></div>
      <div className="scan-controls"><label className="scan-port-field"><span>SSH TCP 端口</span><input aria-label="SSH TCP 端口" type="number" min="1" max="65535" step="1" value={scanPort} onChange={event => setScanPort(event.target.value)} disabled={busy}/></label><button className="button button-primary" onClick={onScan} disabled={busy || !selectedInterface || !Number.isInteger(Number(scanPort)) || Number(scanPort) < 1 || Number(scanPort) > 65535}>{busy ? <LoaderCircle className="spin-icon" size={15}/> : <Search size={15}/>}扫描直连设备 IP</button></div>
      {discovered.length > 0 && <div className="discovery-list"><div className="section-kicker">发现结果 · {discovered.length}</div>{discovered.map(host => <div className="discovered-row" key={host.address}><span className="wifi-small-icon"><Signal size={16}/></span><span><strong>{host.address}</strong><small>{host.interface} · {host.source} · TCP/{host.port} {host.portOpen ? '可达' : '未确认'}</small></span><button className="button button-subtle" onClick={() => onAddHost(host.address, host.port)}>添加为机器人</button></div>)}</div>}
    </section>
    <section className="panel detail-panel"><div className="panel-heading"><div className="heading-icon wifi-bg"><Wifi size={18}/></div><div><div className="section-kicker">ROBOT ONLY · NETWORKMANAGER</div><h2>机器人 Wi-Fi</h2></div>{network?.supported && <span className={`connected-pill ${network.wifiEnabled ? '' : 'not-connected'} push-right`}><span/>{network.wifiEnabled ? '无线已开启' : '无线已关闭'}</span>}</div>
      {!network ? <EmptyState text="连接机器人并固定 SSH 指纹后读取 NetworkManager 状态。"/> : !network.supported ? <EmptyState text={network.note ?? '机器人没有可用的 NetworkManager/nmcli。'}/> : <><div className="remote-device-list">{network.devices.filter(d => d.kind.toLowerCase().includes('wifi') || d.kind.toLowerCase().includes('wireless')).map(d => <InfoRow key={d.device} label={`${d.device} · ${d.kind}`} value={`${d.state}${d.connection ? ` · ${d.connection}` : ''}`}/>)}</div><div className="wifi-actions"><div className="section-kicker">AVAILABLE NETWORKS</div><div className="inline-actions"><button className="button button-subtle" onClick={onScanWifi} disabled={busy}><RefreshCw size={14}/>扫描机器人 Wi-Fi</button><button className="button button-subtle" onClick={() => onToggleWifi(!network.wifiEnabled)} disabled={busy}><Power size={14}/>{network.wifiEnabled ? '关闭无线…' : '开启无线…'}</button></div></div><div className="wifi-list">{wifi.map((w, i) => <div className="wifi-row real-wifi-row" key={`${w.ssid}-${i}`}><span className="wifi-small-icon"><Wifi size={16}/></span><span className="wifi-row-copy"><strong>{w.ssid || '(隐藏网络)'} {w.inUse && <span className="current-badge">当前网络</span>}</strong><small>{w.security || '开放网络'} · 信号 {w.signal}%</small></span><button className="button button-subtle" onClick={() => onConnectWifi(w)} disabled={busy}>{w.inUse ? '重新连接…' : '连接…'}</button></div>)}</div></>}
      <div className="subtle-callout"><AlertTriangle size={15}/><span>Wi-Fi 操作只在机器人执行。连接/关闭无线可能中断 SSH；需要密码时通过远端 nmcli 交互提示输入，不由 RoboLink 保存。</span></div>
    </section>
  </div>
}
function InfoRow({ label, value }: { label: string; value: string }) { return <div className="info-row"><span>{label}</span><strong>{value}</strong></div> }

function ServicesPage({ services, query, setQuery, onAction, busy }: { services: Service[]; query: string; setQuery: (v: string) => void; onAction: (s: Service, a: 'start'|'stop'|'restart') => void; busy: boolean }) {
  return <div className="page-stack"><div className="summary-strip"><span className="summary-dot ok"/><strong>{services.filter(s => s.active === 'active').length} 个运行中</strong><span className="summary-separator"/><span className="summary-dot warn"/><strong>{services.filter(s => s.active !== 'active').length} 个非运行状态</strong><span className="summary-note">systemctl · 真实设备</span></div><section className="panel service-list-panel"><div className="list-toolbar"><div className="search-input"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="筛选服务…" aria-label="筛选服务"/></div><span className="small-muted">{services.length} 个服务</span></div>{!services.length ? <EmptyState text="没有服务数据。请先核验 SSH 主机指纹，并确认机器人运行 systemd。"/> : services.map(service => <div className="service-detail-row" key={service.name}><div className={`service-icon ${service.active === 'active' ? 'is-running' : 'is-stopped'}`}><Zap size={16}/></div><div className="service-detail-copy"><strong>{service.name}</strong><small>{service.description}</small></div><span className={`state-label ${service.active === 'active' ? 'state-ok' : 'state-down'}`}><i/>{service.active} · {service.subState}</span><span className={`autostart ${service.enabled === 'enabled' ? 'enabled' : ''}`}>{service.enabled}</span><div className="service-action-set">{service.active === 'active' ? <button className="button button-subtle" onClick={() => onAction(service,'stop')} disabled={busy}><Power size={14}/>停止</button> : <button className="button button-subtle" onClick={() => onAction(service,'start')} disabled={busy}><Play size={14}/>启动</button>}<button className="button button-subtle" onClick={() => onAction(service,'restart')} disabled={busy}><RefreshCw size={14}/>重启</button></div></div>)}</section><div className="subtle-callout"><AlertTriangle size={16}/><span>服务操作通过当前 SSH 用户执行，不自动使用 sudo。权限不足时请按你的策略在机器人端配置最小权限。</span></div></div>
}

function BluetoothPage({ snapshot, onScan, onTogglePower, onAction, busy }: { snapshot: BluetoothSnapshot | null; onScan: () => void; onTogglePower: (enabled: boolean) => void; onAction: (device: BluetoothDevice, action: string) => void; busy: boolean }) {
  if (!snapshot) return <div className="page-stack"><section className="panel detail-panel"><EmptyState text="连接机器人后读取 BlueZ 状态。"/></section></div>
  if (!snapshot.available) return <div className="page-stack"><section className="panel detail-panel"><EmptyState text="机器人未安装 bluetoothctl/BlueZ。"/></section></div>
  return <div className="page-stack">
    <section className="panel detail-panel">
      <div className="panel-heading">
        <div className="heading-icon bluetooth-bg"><Bluetooth size={18}/></div>
        <div><div className="section-kicker">ROBOT RADIO · BLUEZ</div><h2>蓝牙适配器</h2></div>
        <span className={`connected-pill ${snapshot.powered ? '' : 'not-connected'}`}><span/>{snapshot.powered ? '已开启' : '已关闭'}</span>
        <div className="bt-page-actions">
          <button className="button button-subtle" onClick={() => onTogglePower(!snapshot.powered)} disabled={busy}><Power size={14}/>{snapshot.powered ? '关闭蓝牙…' : '开启蓝牙…'}</button>
          <button className="button button-primary" onClick={onScan} disabled={busy || !snapshot.powered}><Search size={15}/>扫描设备</button>
        </div>
      </div>
      <div className="subtle-callout"><Bluetooth size={15}/><span>适配器 {snapshot.adapter || '未识别'} · 配对和连接由机器人蓝牙控制栈处理。</span></div>
    </section>
    <section className="panel detail-panel"><div className="panel-heading"><div><div className="section-kicker">NEARBY & PAIRED</div><h2>设备列表</h2></div><span className="count-pill">{snapshot.devices.length}</span></div>{snapshot.devices.length ? snapshot.devices.map(d => <div className="bluetooth-row" key={d.address}><div className={`device-avatar ${d.paired ? 'bt-device' : 'controller'}`}><Bluetooth size={18}/></div><div className="device-row-copy"><strong>{d.name}</strong><small>{d.address} · {d.paired ? '已配对' : '未配对'}{d.trusted ? ' · 已信任' : ''}</small></div><span className={`state-label ${d.connected ? 'state-ok' : 'small-muted'}`}><i/>{d.connected ? '已连接' : d.paired ? '已配对' : '附近'}</span>{!d.paired ? <button className="button button-subtle" onClick={() => onAction(d,'pair')} disabled={busy}>配对…</button> : d.connected ? <button className="button button-subtle" onClick={() => onAction(d,'disconnect')} disabled={busy}>断开</button> : <button className="button button-subtle" onClick={() => onAction(d,'connect')} disabled={busy}>连接</button>}<button className="icon-button" title="移除配对" aria-label="移除配对" onClick={() => onAction(d,'remove')} disabled={!d.paired || busy}><Trash2 size={15}/></button></div>) : <EmptyState text={snapshot.powered ? '尚未发现设备。点击扫描；扫描只发生在机器人蓝牙适配器上。' : '适配器已关闭，请先开启蓝牙后扫描设备。'}/>}</section>
    <div className="subtle-callout"><LockKeyhole size={16}/><span>配对操作需再次确认；蓝牙配对可能需要 PIN/确认，提示会出现在 SSH PTY 终端中。</span></div>
  </div>
}

function AudioPage({ snapshot, sourceVolume, sinkVolume, setSourceVolume, setSinkVolume, onDefault, onVolume, onTest, busy }: { snapshot: AudioSnapshot | null; sourceVolume: number; sinkVolume: number; setSourceVolume: (n: number) => void; setSinkVolume: (n: number) => void; onDefault: (kind: 'sink' | 'source', device: string) => void; onVolume: (kind: 'sink' | 'source', device: string, volume: number) => void; onTest: () => void; busy: boolean }) {
  if (!snapshot) return <div className="page-stack"><section className="panel detail-panel"><EmptyState text="连接机器人后读取音频服务器设备。"/></section></div>
  const currentSink = snapshot.sinks.find(d => d.isDefault)?.name ?? snapshot.sinks[0]?.name ?? ''
  const currentSource = snapshot.sources.find(d => d.isDefault)?.name ?? snapshot.sources[0]?.name ?? ''
  return <div className="page-stack">
    {snapshot.available ? <div className="audio-grid">
    <section className="panel audio-card">
      <div className="audio-title"><div className="heading-icon mic-bg"><Mic size={18}/></div><div><div className="section-kicker">INPUT · PULSEAUDIO / PIPEWIRE</div><h2>麦克风</h2></div></div>
      <div className="audio-device-display"><div className="audio-device-icon"><Mic size={23}/></div><div><strong>{currentSource || '无默认输入'}</strong><small>机器人默认输入设备</small></div></div>
      <label className="field-label">输入设备</label>
      <select value={currentSource} onChange={e => onDefault('source', e.target.value)} disabled={busy}><option value="">选择输入设备</option>{snapshot.sources.map(d => <option value={d.name} key={d.name}>{d.description}{d.isDefault ? ' · 当前默认' : ''}</option>)}</select>
      <div className="volume-label"><span>输入增益</span><strong>{sourceVolume}%</strong></div>
      <input className="volume-slider" type="range" min="0" max="150" value={sourceVolume} onChange={e => setSourceVolume(Number(e.target.value))} onPointerUp={() => currentSource && onVolume('source', currentSource, sourceVolume)} onKeyUp={() => currentSource && onVolume('source', currentSource, sourceVolume)} disabled={busy || !currentSource} aria-label="麦克风输入增益"/>
      <div className="audio-card-bottom"><span>通过 pactl 控制 · 不采集音频</span><button className="button button-subtle" onClick={() => notifyAudioNote()}><Activity size={14}/>输入说明</button></div>
    </section>
    <section className="panel audio-card">
      <div className="audio-title"><div className="heading-icon speaker-bg"><AudioLines size={18}/></div><div><div className="section-kicker">OUTPUT · PULSEAUDIO / PIPEWIRE</div><h2>扬声器</h2></div></div>
      <div className="audio-device-display"><div className="audio-device-icon speaker-icon"><Headphones size={23}/></div><div><strong>{currentSink || '无默认输出'}</strong><small>机器人默认输出设备</small></div></div>
      <label className="field-label">输出设备</label>
      <select value={currentSink} onChange={e => onDefault('sink', e.target.value)} disabled={busy}><option value="">选择输出设备</option>{snapshot.sinks.map(d => <option value={d.name} key={d.name}>{d.description}{d.isDefault ? ' · 当前默认' : ''}</option>)}</select>
      <div className="volume-label"><span>输出音量</span><strong>{sinkVolume}%</strong></div>
      <input className="volume-slider" type="range" min="0" max="150" value={sinkVolume} onChange={e => setSinkVolume(Number(e.target.value))} onPointerUp={() => currentSink && onVolume('sink', currentSink, sinkVolume)} onKeyUp={() => currentSink && onVolume('sink', currentSink, sinkVolume)} disabled={busy || !currentSink} aria-label="扬声器音量"/>
      <div className="audio-card-bottom"><span>测试音会在机器人扬声器播放</span><button className="button button-primary" onClick={onTest} disabled={busy || !currentSink}><Play size={14}/>播放测试音</button></div>
    </section>
    <div className="audio-footnote"><ShieldCheck size={15}/>PulseAudio/PipeWire 控件只负责切换默认设备与音量，不录音；音频服务器需在 SSH 用户可访问的会话中运行。</div>
    </div> : <section className="panel detail-panel"><EmptyState text={snapshot.note ?? '机器人没有可用的 PulseAudio/PipeWire 控制接口。'}/></section>}
    <section className="panel detail-panel alsa-panel">
      <div className="panel-heading"><div className="heading-icon speaker-bg"><AudioLines size={18}/></div><div><div className="section-kicker">ROBOT HARDWARE · ALSA</div><h2>ALSA 识别到的设备</h2></div><span className="count-pill">{snapshot.alsaPlayback.length + snapshot.alsaCapture.length}</span></div>
      <div className="subtle-callout"><Activity size={15}/><span>直接读取机器人内核提供的 /proc/asound/pcm，不依赖 PipeWire、PulseAudio 或本机音频服务。此处只枚举硬件端点；ALSA 项不能通过上方 pactl 控件切换或调节音量。</span></div>
      <div className="alsa-device-list">
        {snapshot.alsaPlayback.map(device => <div className="alsa-device-row" key={`playback-${device.name}`}><span className="audio-device-icon speaker-icon"><AudioLines size={17}/></span><div><strong>{device.name}</strong><small>{device.description}</small></div><span className="state-label">播放</span></div>)}
        {snapshot.alsaCapture.map(device => <div className="alsa-device-row" key={`capture-${device.name}`}><span className="audio-device-icon"><Mic size={17}/></span><div><strong>{device.name}</strong><small>{device.description}</small></div><span className="state-label">采集</span></div>)}
        {!snapshot.alsaPlayback.length && !snapshot.alsaCapture.length && <EmptyState text="未从 /proc/asound/pcm 识别到 ALSA 硬件端点；精简内核或未启用 ALSA 的机器人可能没有此文件。"/>}
      </div>
    </section>
  </div>
}
function notifyAudioNote() { window.alert('RoboLink 不读取或录制麦克风内容。输入设备切换通过机器人上的 pactl 完成；若服务不可访问，请检查机器人 PipeWire/PulseAudio 用户会话。') }

function TerminalPage({ sessionId, exited, sshReady, target, theme, onConnect, onDisconnect, onRisk, onPaste, onError }: { sessionId:string; exited:boolean; sshReady:boolean; target?:Target; theme:'dark'|'light'; onConnect:()=>void; onDisconnect:()=>void; onRisk:(v:string)=>void; onPaste:(v:string)=>void; onError:(v:string)=>void }) {
  const container = useRef<HTMLDivElement>(null)
  const term = useRef<XTerminal|null>(null)
  const fitAddon = useRef<FitAddon|null>(null)
  const themeRef = useRef(theme)
  const bufferRef = useRef('')
  const pendingDanger = useRef<(() => Promise<void>)|null>(null)
  const pendingPaste = useRef<(() => Promise<void>)|null>(null)
  useEffect(()=>{
    themeRef.current = theme
    if(term.current) term.current.options.theme=theme==='dark'?{background:'#080d13',foreground:'#d2dce6',cursor:'#69d7a2',selectionBackground:'#3f6454'}:{background:'#111923',foreground:'#e2e8ef',cursor:'#75d6a8',selectionBackground:'#456454'}
  },[theme])
  useEffect(()=>{
    if(!sessionId || !container.current) return
    let cancelled=false
    let cleanup=()=>{}
    const initialize=async()=>{
      const [{Terminal:TerminalClass},{FitAddon:FitAddonClass}]=await Promise.all([import('@xterm/xterm'),import('@xterm/addon-fit')])
      if(cancelled || !container.current) return
      const currentTheme=themeRef.current==='dark'?{background:'#080d13',foreground:'#d2dce6',cursor:'#69d7a2',selectionBackground:'#3f6454'}:{background:'#111923',foreground:'#e2e8ef',cursor:'#75d6a8',selectionBackground:'#456454'}
      const x=new TerminalClass({cursorBlink:true,convertEol:true,scrollback:4000,fontSize:13,fontFamily:'"Ubuntu Mono", "Liberation Mono", "DejaVu Sans Mono", monospace',letterSpacing:-0.15,lineHeight:1.05,allowProposedApi:false,theme:currentTheme})
      const fit=new FitAddonClass(); x.loadAddon(fit); x.open(container.current); fit.fit(); term.current=x; fitAddon.current=fit
      void invoke('resize_terminal',{sessionId,cols:x.cols,rows:x.rows}).catch(()=>{})
      const send=async(data:string):Promise<void>=>{try{await invoke('send_terminal_input',{sessionId,data})}catch(e){onError(displayError(e))}}
      const disposable=x.onData(data=>{
        if(data.includes('\r')||data.includes('\n')) {
          const normalized=data.replace(/\r\n/g,'\n').replace(/\r/g,'\n')
          if(normalized.includes('\n')&&normalized.replace(/\n/g,'').length>0) {
            const paste=normalized.replace(/\n/g,'\r'); onPaste(paste); pendingPaste.current=async()=>{await send(paste)}; return
          }
          const command=bufferRef.current.trim()
          if(command&&DANGEROUS.test(command)) { onRisk(command); pendingDanger.current=async()=>{await send('\r')}; bufferRef.current=''; return }
          void send(data); bufferRef.current=''; return
        }
        if(data==='\x7f'||data==='\b') bufferRef.current=bufferRef.current.slice(0,-1)
        else if(data.includes('\x03')||data.includes('\x15')) bufferRef.current=''
        else if(data.startsWith('\x1b')) bufferRef.current=''
        else bufferRef.current+=data
        void send(data)
      })
      let resizeFrame=0
      let lastCols=x.cols
      let lastRows=x.rows
      const resize=()=>{
        if(resizeFrame) cancelAnimationFrame(resizeFrame)
        resizeFrame=requestAnimationFrame(()=>{
          resizeFrame=0
          if(!container.current || !container.current.clientWidth || !container.current.clientHeight) return
          try {
            fit.fit()
            if(x.cols===lastCols && x.rows===lastRows) return
            lastCols=x.cols; lastRows=x.rows
            void invoke('resize_terminal',{sessionId,cols:x.cols,rows:x.rows}).catch(()=>{})
          } catch {}
        })
      }
      const observer=new ResizeObserver(resize); observer.observe(container.current)
      terminalWriterRef.current={sessionId,write:(data:string)=>x.write(data),confirmDangerous:async()=>{await pendingDanger.current?.();pendingDanger.current=null},cancelDangerous:async()=>{await send('\x15');x.write('\r\n[已取消高风险命令]\r\n');pendingDanger.current=null},confirmPaste:async()=>{await pendingPaste.current?.();pendingPaste.current=null},cancelPaste:async()=>{x.write('\r\n[已取消多行粘贴]\r\n');pendingPaste.current=null}}
      const queued=terminalOutputQueue.get(sessionId)??[]; queued.forEach(data=>x.write(data)); terminalOutputQueue.delete(sessionId)
      cleanup=()=>{observer.disconnect();if(resizeFrame) cancelAnimationFrame(resizeFrame);disposable.dispose();x.dispose();term.current=null;fitAddon.current=null;if(terminalWriterRef.current?.sessionId===sessionId)terminalWriterRef.current=null}
    }
    void initialize().catch(e=>{cleanup();if(!cancelled)onError(`加载 SSH 终端失败：${displayError(e)}`)})
    return ()=>{cancelled=true;cleanup()}
  },[sessionId])
  return <div className="terminal-page real-terminal"><div className="terminal-toolbar"><div className="terminal-target"><span className={`terminal-dot ${exited?'offline':''}`}/><span><strong>{target?.host ?? '未选择目标'}</strong><small>{target ? `${target.username} · SSH ${target.port}` : 'SSH PTY'}</small></span><LockKeyhole size={14}/></div><div className="terminal-tools"><span className="terminal-mode"><LockKeyhole size={13}/>{!sessionId ? '未连接' : exited ? '会话结束' : sshReady ? 'SSH 已认证' : '等待 SSH 认证'}</span>{sessionId && <button className="button button-subtle" onClick={onDisconnect}>断开 SSH</button>}{!sessionId && <button className="button button-primary" onClick={onConnect}>连接 SSH</button>}</div></div><div className="terminal-safety"><AlertTriangle size={15}/><span>这是机器人上的真实 Shell。输入命令会立即发往 <strong>{target?.username}@{target?.host}</strong>；高风险回车与多行粘贴需要确认。远端输出按不可信文本处理。</span></div>{sessionId ? <div className="xterm-shell" ref={container} aria-label="SSH 终端"/> : <div className="terminal-disconnected"><Terminal size={24}/><strong>尚未建立 SSH 会话</strong><p>先核验 SSH 主机指纹，再启动交互式终端。密码认证提示会在终端内交互，不会存入 RoboLink。</p><button className="button button-primary" onClick={onConnect}>连接并打开终端</button></div>}<div className="terminal-bottom"><div><span className={`terminal-bottom-dot ${sessionId&&!exited?'':'offline'}`}/>目标 <strong>{target?.host ?? '—'}</strong><span className="dot-divider">·</span>用户 <strong>{target?.username ?? '—'}</strong><span className="dot-divider">·</span>不自动提权</div><span className="terminal-status-note">SSH 使用应用独立指纹文件</span></div></div>
}

function LogsPage({ logs, onClear }: { logs: AppLog[]; onClear:()=>void }) { return <div className="page-stack"><div className="logs-toolbar list-toolbar"><span className="small-muted">{logs.length} 条本地事件 · 终端输入与密码不记录</span><button className="button button-subtle" onClick={onClear}><Trash2 size={14}/>清空</button></div><section className="panel logs-panel">{logs.length ? logs.map((l,i)=><div className="log-row" key={`${l.at}-${i}`}><span className={`log-tone ${l.tone}`}>{l.tone==='warn'?<AlertTriangle size={14}/>:l.tone==='ok'?<Check size={14}/>:<Activity size={14}/>}</span><span className="log-time">{l.at}</span><span className="log-message">{l.text}</span><span className={`log-category ${l.tone}`}>{l.tone==='warn'?'注意':l.tone==='ok'?'完成':'系统'}</span></div>) : <EmptyState text="尚无本地操作记录。"/>}</section><div className="subtle-callout"><LockKeyhole size={16}/><span>诊断日志仅记操作事件，不采集终端输入、SSH 密码、Wi-Fi 密码或麦克风内容。</span></div></div> }

function HostKeyDialog({ target, status, fingerprint, setFingerprint, checked, setChecked, onTrust, onClear, onClose, busy }: { target: Target; status: HostKeyStatus; fingerprint: string; setFingerprint: (v: string) => void; checked: boolean; setChecked: (v: boolean) => void; onTrust: () => void; onClear: () => void; onClose: () => void; busy: boolean }) {
  return <div className="modal-backdrop"><div className="modal-card hostkey-modal">
    <div className="modal-title"><div><div className="section-kicker">SSH HOST AUTHENTICITY</div><h2>{status.changed ? '主机指纹发生变化' : '核对机器人主机指纹'}</h2></div><button className="icon-button" onClick={onClose} aria-label="关闭"><X size={18}/></button></div>
    <p className="modal-intro">目标：<strong>{target.username}@{target.host}:{target.port}</strong> · 网络扫描本身无法证明身份。请通过机器人本地可信控制台或其他可信渠道核对一把密钥。</p>
    {status.changed && <div className="inline-error"><AlertTriangle size={15}/><span>已固定的密钥不匹配或来自旧版多密钥规则。连接已阻断；请先可信核验，再清除旧 pin 并重新固定。</span></div>}
    <div className="fingerprint-list"><div className="section-kicker">选择一把主机密钥并核对 SHA-256 指纹（推荐 ED25519）</div>
      {status.fingerprints.map(fp => <label className={`fingerprint-choice ${fingerprint === fp ? 'selected' : ''}`} key={fp}><input type="radio" name="host-fingerprint" value={fp} checked={fingerprint === fp} onChange={() => { setFingerprint(fp); setChecked(false) }}/><code>{fp}</code></label>)}
      {!status.fingerprints.length && <EmptyState text="未读取到主机指纹。"/>}
    </div>
    <div className="subtle-callout"><LockKeyhole size={15}/><span>可在机器人可信控制台运行 <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>，将输出的 SHA-256 值与所选项比较。RoboLink 仅固定所选这一把密钥。</span></div>
    {status.changed && <div className="fingerprint-list old"><div className="section-kicker">之前固定的指纹</div>{status.pinnedFingerprints.map(fp => <code key={fp}>{fp}</code>)}</div>}
    <label className="confirm-check"><input type="checkbox" checked={checked} onChange={e => setChecked(e.target.checked)}/><span>我已通过可信渠道核对所选指纹，并确认它属于这台机器人。</span></label>
    <div className="modal-actions">{status.changed && <button className="button button-danger" onClick={onClear}>清除旧指纹后重新核验</button>}<button className="button button-subtle" onClick={onClose}>取消</button><button className="button button-primary" onClick={onTrust} disabled={!checked || busy || status.changed || !fingerprint || !status.fingerprints.includes(fingerprint)}>{busy ? <LoaderCircle className="spin-icon" size={15}/> : null}确认并固定所选指纹</button></div>
  </div></div>
}
function ConfirmDialog({ confirm, onCancel, onConfirm }: { confirm:Confirm;onCancel:()=>void|Promise<void>;onConfirm:()=>void|Promise<void> }) { return <div className="modal-backdrop"><div className="modal-card confirm-modal"><div className="modal-title"><div className={`confirm-icon ${confirm.danger?'danger':''}`}>{confirm.danger?<AlertTriangle size={20}/>:<ShieldCheck size={20}/>}</div><div><div className="section-kicker">OPERATION CONFIRMATION</div><h2>{confirm.title}</h2></div></div><p className="modal-intro preserve-lines">{confirm.description}</p><div className="modal-actions"><button className="button button-subtle" onClick={onCancel}>返回</button><button className={`button ${confirm.danger?'button-danger':'button-primary'}`} onClick={onConfirm}>{confirm.danger?'确认执行':'继续'}</button></div></div></div> }


function TargetDialog({ value, setValue, onClose, onSubmit, busy }: { value: { id: string; name: string; host: string; port: string; username: string }; setValue: (v: { id: string; name: string; host: string; port: string; username: string }) => void; onClose: () => void; onSubmit: (e: FormEvent) => void; busy: boolean }) {
  return <div className="modal-backdrop" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}><form className="modal-card" onSubmit={onSubmit}>
    <div className="modal-title"><div><div className="section-kicker">SSH TARGET</div><h2>添加 Linux 机器人</h2></div><button type="button" className="icon-button" onClick={onClose} aria-label="关闭"><X size={18}/></button></div>
    <p className="modal-intro">目标可用机器人 IP 或主机名。密码不会保存；可使用 SSH Agent/密钥或在交互式终端输入密码。</p>
    <label>设备名称<input required maxLength={80} autoFocus value={value.name} onChange={e => setValue({ ...value, name: e.target.value })} placeholder="例如：R2 测试机器人"/></label>
    <label>机器人 IP / 主机名<input required maxLength={253} value={value.host} onChange={e => setValue({ ...value, host: e.target.value })} placeholder="192.168.7.2 或 robot-r2.local"/></label>
    <div className="form-split"><label>SSH 用户名<input required maxLength={64} value={value.username} onChange={e => setValue({ ...value, username: e.target.value })} placeholder="robot"/></label><label>SSH 端口<input required type="number" min="1" max="65535" value={value.port} onChange={e => setValue({ ...value, port: e.target.value })}/></label></div>
    <div className="subtle-callout"><Cable size={15}/><span>网线直接连接开发机与机器人；RoboLink 不会擅自改动本机网络配置。</span></div>
    <div className="modal-actions"><button type="button" className="button button-subtle" onClick={onClose}>取消</button><button className="button button-primary" disabled={busy}>{busy ? <LoaderCircle className="spin-icon" size={15}/> : null}保存目标</button></div>
  </form></div>
}
