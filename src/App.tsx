import { useState, type KeyboardEvent } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, AudioLines, Bluetooth, Cable, Check,
  ChevronDown, ChevronRight, CircleHelp, Clock3, Cpu, Download, FileClock,
  Gauge, HardDrive, Headphones, LayoutDashboard, ListChecks, LockKeyhole,
  Menu, Mic, MoreHorizontal, Network, Play, Power, RefreshCw,
  Search, Server, Settings2, ShieldCheck, Signal, SquareTerminal,
  Terminal, Volume2, Wifi, X, Zap,
} from 'lucide-react'

type Page = 'overview' | 'network' | 'services' | 'bluetooth' | 'audio' | 'terminal' | 'logs'
type Service = { name: string; description: string; state: '运行中' | '已停止'; uptime: string; enabled: boolean }
type LogItem = { time: string; message: string; tone: 'ok' | 'warn' | 'info' }
type TerminalLine = { kind: 'command' | 'output'; text: string }

const initialServices: Service[] = [
  { name: 'robot-bridge.service', description: '机器人通信桥接', state: '运行中', uptime: '运行 2 天 04:18', enabled: true },
  { name: 'ros2-daemon.service', description: 'ROS 2 后台守护进程', state: '运行中', uptime: '运行 2 天 04:18', enabled: true },
  { name: 'camera-stream.service', description: '前置相机视频流', state: '运行中', uptime: '运行 01:42', enabled: false },
  { name: 'motor-controller.service', description: '底盘电机控制器', state: '已停止', uptime: '已停止 18 分钟', enabled: true },
]
const navItems: { id: Page; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', label: '设备总览', icon: LayoutDashboard },
  { id: 'network', label: '网络与 Wi-Fi', icon: Network },
  { id: 'services', label: '系统服务', icon: Server },
  { id: 'bluetooth', label: '蓝牙设备', icon: Bluetooth },
  { id: 'audio', label: '音频设备', icon: AudioLines },
  { id: 'terminal', label: '终端', icon: SquareTerminal },
  { id: 'logs', label: '诊断记录', icon: FileClock },
]
const titles: Record<Page, { title: string; subtitle: string }> = {
  overview: { title: '设备总览', subtitle: '查看机器人连接、系统健康与常用调试入口。' },
  network: { title: '网络与 Wi-Fi', subtitle: '管理开发机到机器人的直连链路，并查看机器人无线网络。' },
  services: { title: '系统服务', subtitle: '查看服务状态、开机自启与最近运行情况。' },
  bluetooth: { title: '蓝牙设备', subtitle: '扫描、配对并管理机器人附近的蓝牙外设。' },
  audio: { title: '音频设备', subtitle: '选择机器人上的麦克风与扬声器，并快速验证设备。' },
  terminal: { title: '终端', subtitle: '运行远端 Shell 命令；连接与目标设备信息应始终清晰可见。' },
  logs: { title: '诊断记录', subtitle: '回看本次调试会话中的操作与连接事件。' },
}
const initialLogs: LogItem[] = [
  { time: '09:42:18', message: 'SSH 会话已建立 · 192.168.7.2', tone: 'ok' },
  { time: '09:41:52', message: '通过直连网卡 enp3s0 发现机器人 R2', tone: 'info' },
  { time: '09:38:06', message: 'motor-controller.service 检测到停止状态', tone: 'warn' },
  { time: '09:37:40', message: '开始新的调试会话', tone: 'info' },
]

function App() {
  const [page, setPage] = useState<Page>('overview')
  const [services, setServices] = useState(initialServices)
  const [logs, setLogs] = useState(initialLogs)
  const [wifiOn, setWifiOn] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [btScanning, setBtScanning] = useState(false)
  const [paired, setPaired] = useState(true)
  const [mic, setMic] = useState('ReSpeaker 2-Mics Pi HAT')
  const [speaker, setSpeaker] = useState('USB Audio DAC')
  const [toast, setToast] = useState('')
  const [lines, setLines] = useState<TerminalLine[]>([
    { kind: 'output', text: 'RoboLink 演示终端 · 命令仅在本地模拟，不会连接设备或执行系统操作。' },
    { kind: 'output', text: '输入 help 查看可用的演示命令。' },
  ])
  const [command, setCommand] = useState('')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  const notify = (message: string) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 2800)
  }
  const addLog = (message: string, tone: LogItem['tone'] = 'info') => {
    setLogs((items) => [{ time: new Date().toLocaleTimeString('zh-CN', { hour12: false }), message, tone }, ...items])
  }
  const toggleService = (name: string) => {
    setServices((items) => items.map((service) => service.name === name
      ? { ...service, state: service.state === '运行中' ? '已停止' : '运行中' }
      : service))
    const next = services.find((service) => service.name === name)?.state === '运行中' ? '停止' : '启动'
    addLog(`演示操作：${next} ${name}`, 'info')
    notify(`演示模式：已模拟${next}服务`)
  }
  const scanWifi = () => {
    setScanning(true)
    window.setTimeout(() => { setScanning(false); notify('扫描完成：发现 3 个网络（演示数据）') }, 950)
  }
  const scanBluetooth = () => {
    setBtScanning(true)
    window.setTimeout(() => { setBtScanning(false); notify('扫描完成：发现 2 台设备（演示数据）') }, 950)
  }

  const executeDemoCommand = () => {
    const cmd = command.trim()
    if (!cmd) return
    const outputs: Record<string, string> = {
      help: '可用命令：help · hostname · uptime · ip addr · systemctl --failed · sensors · clear',
      hostname: 'robot-r2',
      uptime: '09:45:12 up 2 days, 4 hours, 18 minutes,  load average: 0.28, 0.35, 0.31',
      'ip addr': 'enp3s0: 192.168.7.2/24  state UP  ·  wlan0: 10.0.0.24/24  state UP',
      'systemctl --failed': 'UNIT LOAD ACTIVE SUB DESCRIPTION\n0 loaded units listed.',
      sensors: 'CPU: 48.2°C  ·  SoC: 44.1°C  ·  Battery: 76%',
    }
    if (cmd === 'clear') { setLines([]); setCommand(''); return }
    setLines((items) => [...items, { kind: 'command', text: cmd }, { kind: 'output', text: outputs[cmd] ?? `bash: ${cmd}: 演示终端不支持此命令（不会执行）` }])
    setCommand('')
  }
  const onTerminalKey = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') executeDemoCommand()
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand-row"><div className="brand-mark"><Cable size={19} strokeWidth={2.5} /></div><div><div className="brand-name">RoboLink</div><div className="brand-caption">ROBOT DEBUG CONSOLE</div></div><button className="icon-button mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="关闭菜单"><X size={18} /></button></div>
        <div className="workspace-label">工作区</div>
        <button className="robot-switcher" onClick={() => notify('当前为演示设备 R2')}><span className="robot-avatar"><Cpu size={18} /></span><span className="robot-switcher-copy"><strong>机器人 R2</strong><small><i className="status-dot" /> 已连接 · 演示设备</small></span><ChevronDown size={16} className="muted" /></button>
        <div className="nav-label">设备管理</div>
        <nav className="nav-list" aria-label="主导航">
          {navItems.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => { setPage(id); setMobileNavOpen(false) }}><Icon size={18} /><span>{label}</span>{id === 'services' && <span className="nav-badge">1</span>}</button>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="connection-mini"><div className="connection-mini-top"><span className="pulse-dot" />直连链路正常</div><div className="connection-mini-bottom"><Cable size={13} />开发机 <ChevronRight size={12} /> enp3s0 <ChevronRight size={12} /> 机器人</div></div>
          <button className="nav-item settings-link" onClick={() => notify('更多设置将在后续版本提供')}><Settings2 size={18} /><span>设置与帮助</span><CircleHelp size={15} className="push-right" /></button>
          <div className="profile-row"><div className="profile-avatar">Z</div><div className="profile-copy"><strong>本地调试会话</strong><small>仅此电脑</small></div><MoreHorizontal size={18} className="muted" /></div>
        </div>
      </aside>

      {mobileNavOpen && <button className="mobile-scrim" onClick={() => setMobileNavOpen(false)} aria-label="关闭菜单" />}
      <main className="main-area">
        <header className="topbar"><div className="topbar-left"><button className="icon-button menu-button" onClick={() => setMobileNavOpen(true)} aria-label="打开菜单"><Menu size={19} /></button><div className="breadcrumb">设备 <ChevronRight size={14} /> <strong>机器人 R2</strong></div></div><div className="topbar-actions"><div className="secure-pill"><LockKeyhole size={13} />本地会话</div><button className="icon-button" onClick={() => notify('帮助文档尚未接入')} aria-label="帮助"><CircleHelp size={18} /></button><div className="top-avatar">Z</div></div></header>
        <div className="content-wrap">
          <div className="page-heading"><div><div className="eyebrow">ROBOT / R2 <span>·</span> DEBUG SESSION</div><h1>{titles[page].title}</h1><p>{titles[page].subtitle}</p></div><div className="heading-actions"><span className="demo-tag"><span />演示数据</span><button className="button button-subtle" onClick={() => notify('状态已刷新（演示数据）')}><RefreshCw size={15} />刷新状态</button></div></div>
          {page === 'overview' && <Overview services={services} logs={logs} setPage={setPage} notify={notify} />}
          {page === 'network' && <NetworkPage wifiOn={wifiOn} setWifiOn={setWifiOn} scanning={scanning} scanWifi={scanWifi} notify={notify} />}
          {page === 'services' && <ServicesPage services={services} toggleService={toggleService} />}
          {page === 'bluetooth' && <BluetoothPage scanning={btScanning} scan={scanBluetooth} paired={paired} setPaired={setPaired} notify={notify} />}
          {page === 'audio' && <AudioPage mic={mic} setMic={setMic} speaker={speaker} setSpeaker={setSpeaker} notify={notify} />}
          {page === 'terminal' && <TerminalPage lines={lines} command={command} setCommand={setCommand} onKey={onTerminalKey} run={executeDemoCommand} notify={notify} />}
          {page === 'logs' && <LogsPage logs={logs} notify={notify} />}
          <footer className="footer-note"><ShieldCheck size={14} />此原型不会连接或修改任何设备 · RoboLink v0.1 <span>·</span> <button onClick={() => notify('安全设计说明见仓库 docs/product-spec.md')}>安全说明</button></footer>
        </div>
      </main>
      {toast && <div className="toast"><Check size={16} />{toast}</div>}
    </div>
  )
}

function Overview({ services, logs, setPage, notify }: { services: Service[]; logs: LogItem[]; setPage: (page: Page) => void; notify: (message: string) => void }) {
  const running = services.filter((s) => s.state === '运行中').length
  return <div className="dashboard-grid">
    <section className="main-column">
      <div className="panel connection-card"><div className="panel-heading"><div><div className="section-kicker">DEVICE CONNECTION</div><h2>开发机与机器人已直连</h2></div><span className="connected-pill"><span />连接正常</span></div><div className="connection-map"><div className="endpoint"><div className="endpoint-icon host"><MonitorGlyph /></div><div><strong>本地开发机</strong><small>enp3s0 · 192.168.7.1</small></div></div><div className="link-track"><div className="link-line"/><div className="link-chip"><Cable size={14} />以太网直连</div><span className="link-speed">1 Gbps</span></div><div className="endpoint"><div className="endpoint-icon robot"><Cpu size={21} /></div><div><strong>机器人 R2</strong><small>robot-r2 · 192.168.7.2</small></div></div></div><div className="connection-footer"><span><Activity size={14} />延迟 <b>0.8 ms</b></span><span className="dot-divider">·</span><span>SSH 指纹已验证</span><button onClick={() => setPage('network')}>连接详情 <ArrowUpRight size={14} /></button></div></div>
      <div className="metric-grid"><Metric icon={Server} label="运行中服务" value={`${running} / ${services.length}`} detail="1 个服务已停止" tone="green" onClick={() => setPage('services')} /><Metric icon={Wifi} label="机器人 Wi-Fi" value="已连接" detail="Lab-Robot-5G · 82%" tone="blue" onClick={() => setPage('network')} /><Metric icon={Bluetooth} label="蓝牙" value="已开启" detail="1 台设备已配对" tone="violet" onClick={() => setPage('bluetooth')} /><Metric icon={AudioLines} label="音频设备" value="2 个可用" detail="麦克风与扬声器正常" tone="amber" onClick={() => setPage('audio')} /></div>
      <section className="panel service-panel"><div className="panel-heading"><div><div className="section-kicker">SYSTEMD</div><h2>关键服务</h2></div><button className="text-button" onClick={() => setPage('services')}>查看全部 <ChevronRight size={15} /></button></div><div className="service-table"><div className="service-table-head"><span>服务</span><span>状态</span><span>运行时间</span><span></span></div>{services.slice(0, 3).map((service) => <div className="service-row" key={service.name}><div className="service-name-cell"><span className={`service-icon ${service.state === '运行中' ? 'is-running' : 'is-stopped'}`}><Zap size={15} /></span><span><strong>{service.name}</strong><small>{service.description}</small></span></div><span className={`state-label ${service.state === '运行中' ? 'state-ok' : 'state-down'}`}><i />{service.state}</span><span className="uptime-text">{service.uptime}</span><button className="icon-button row-more" onClick={() => notify('服务操作可在系统服务页查看（演示模式）')} aria-label="服务操作"><MoreHorizontal size={17} /></button></div>)}</div></section>
    </section>
    <aside className="right-column"><section className="panel health-panel"><div className="panel-heading"><div><div className="section-kicker">ROBOT HEALTH</div><h2>系统状态</h2></div><button className="icon-button" onClick={() => notify('系统状态已刷新')} aria-label="刷新"><RefreshCw size={15} /></button></div><div className="health-list"><HealthRow icon={Cpu} label="CPU 温度" value="48°C" sub="正常" percent={38} color="green" /><HealthRow icon={Gauge} label="处理器负载" value="23%" sub="4 核" percent={23} color="blue" /><HealthRow icon={HardDrive} label="内存使用" value="3.2 / 8 GB" sub="40%" percent={40} color="violet" /><HealthRow icon={Zap} label="电池电量" value="76%" sub="约 2.4 h" percent={76} color="amber" /></div><div className="health-time"><Clock3 size={13} />最近更新 · 刚刚</div></section>
      <section className="panel quick-panel"><div className="panel-heading"><div><div className="section-kicker">QUICK ACCESS</div><h2>快速调试</h2></div></div><button className="quick-action" onClick={() => setPage('terminal')}><span className="quick-icon purple"><Terminal size={17} /></span><span><strong>打开终端</strong><small>运行远端命令</small></span><ChevronRight size={16} /></button><button className="quick-action" onClick={() => setPage('services')}><span className="quick-icon blue"><ListChecks size={17} /></span><span><strong>检查服务</strong><small>{services.filter((s) => s.state === '已停止').length} 个需关注</small></span><ChevronRight size={16} /></button><button className="quick-action" onClick={() => setPage('logs')}><span className="quick-icon amber"><FileClock size={17} /></span><span><strong>查看诊断记录</strong><small>最近 {logs.length} 条事件</small></span><ChevronRight size={16} /></button></section>
      <section className="safety-note"><div className="safety-icon"><ShieldCheck size={17} /></div><div><strong>安全连接</strong><p>SSH 主机指纹已验证。网络操作仅作用于所选直连接口。</p></div><button onClick={() => notify('详细安全设计见 docs/product-spec.md')} aria-label="安全详情"><ArrowUpRight size={15} /></button></section>
    </aside>
  </div>
}
function MonitorGlyph() { return <div className="monitor-glyph"><div/><span/></div> }
function Metric({ icon: Icon, label, value, detail, tone, onClick }: { icon: typeof Cpu; label: string; value: string; detail: string; tone: string; onClick: () => void }) { return <button className="panel metric-card" onClick={onClick}><div className={`metric-icon ${tone}`}><Icon size={18} /></div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-detail">{detail}<ArrowUpRight size={12} /></div></button> }
function HealthRow({ icon: Icon, label, value, sub, percent, color }: { icon: typeof Cpu; label: string; value: string; sub: string; percent: number; color: string }) { return <div className="health-row"><div className="health-row-top"><span className="health-label"><Icon size={15} />{label}</span><span className="health-value">{value}</span></div><div className="health-meter"><span className={color} style={{ width: `${percent}%` }}/></div><div className="health-sub">{sub}</div></div> }

function NetworkPage({ wifiOn, setWifiOn, scanning, scanWifi, notify }: { wifiOn: boolean; setWifiOn: (on: boolean) => void; scanning: boolean; scanWifi: () => void; notify: (message: string) => void }) {
  return <div className="page-stack"><div className="network-warning"><div className="warning-icon"><AlertTriangle size={18} /></div><div><strong>直连以太网与机器人 Wi-Fi 是独立链路</strong><p>下方有线卡片描述开发机到机器人之间的点对点连接。切换机器人 Wi-Fi 可能会影响 SSH 是否可达。</p></div></div>
    <section className="panel detail-panel"><div className="panel-heading"><div className="heading-icon cable-bg"><Cable size={18} /></div><div><div className="section-kicker">HOST ↔ ROBOT · DIRECT LINK</div><h2>有线直连</h2></div><span className="connected-pill push-right"><span />链路已连接</span></div><div className="interface-grid"><InfoItem label="开发机网卡" value="enp3s0" sub="仅本机与机器人直连"/><InfoItem label="开发机地址" value="192.168.7.1 / 24"/><InfoItem label="机器人地址" value="192.168.7.2 / 24"/><InfoItem label="链路速度" value="1 Gbps · 全双工"/></div><div className="subtle-callout"><ShieldCheck size={16}/><span>当前模式只读取网卡状态，不会自动更改开发机网络、默认路由或防火墙。</span></div><div className="panel-actions"><button className="button button-subtle" onClick={() => notify('已重新探测所选网卡（演示数据）')}><Search size={15}/>重新发现设备</button><button className="button button-primary" onClick={() => notify('网卡配置预览后才会允许应用更改；本原型不会修改网络')}><Settings2 size={15}/>配置此网卡…</button></div></section>
    <section className="panel detail-panel"><div className="panel-heading"><div className="heading-icon wifi-bg"><Wifi size={18}/></div><div><div className="section-kicker">ROBOT RADIO</div><h2>机器人 Wi-Fi</h2></div><button className={`toggle ${wifiOn ? 'on' : ''}`} onClick={() => { setWifiOn(!wifiOn); notify(wifiOn ? '已模拟关闭机器人 Wi-Fi' : '已模拟开启机器人 Wi-Fi') }} aria-label="切换机器人 Wi-Fi"><span/></button></div><div className="wifi-current"><div className="wifi-network-icon"><Wifi size={20}/></div><div className="wifi-copy"><strong>Lab-Robot-5G <span className="current-badge">当前网络</span></strong><small>已连接 · WPA2 · 10.0.0.24</small></div><div className="signal-bars"><i/><i/><i/><i/></div><button className="button button-subtle" onClick={() => notify('演示模式：已模拟断开 Wi-Fi')}>断开</button></div><div className="wifi-actions"><div className="search-input"><Search size={15}/><input placeholder="搜索网络名称" aria-label="搜索 Wi-Fi"/></div><button className="button button-subtle" onClick={scanWifi} disabled={scanning}>{scanning ? <span className="spinner"/> : <RefreshCw size={15}/>}扫描网络</button></div><div className="wifi-list"><WifiRow ssid="RoboLab-Guest" security="WPA2" signal="强" onClick={() => notify('连接 Wi-Fi 前会提示 SSH 中断风险（演示模式）')} /><WifiRow ssid="RoboLab-IoT" security="WPA2" signal="中" onClick={() => notify('连接 Wi-Fi 前会提示 SSH 中断风险（演示模式）')} /></div></section>
  </div>
}
function InfoItem({ label, value, sub }: { label: string; value: string; sub?: string }) { return <div className="info-item"><span>{label}</span><strong>{value}</strong>{sub && <small>{sub}</small>}</div> }
function WifiRow({ ssid, security, signal, onClick }: { ssid: string; security: string; signal: string; onClick: () => void }) { return <button className="wifi-row" onClick={onClick}><span className="wifi-small-icon"><Wifi size={16}/></span><span className="wifi-row-copy"><strong>{ssid}</strong><small>{security} · 可用</small></span><span className="wifi-strength"><Signal size={15}/>{signal}</span><ChevronRight size={16}/></button> }

function ServicesPage({ services, toggleService }: { services: Service[]; toggleService: (name: string) => void }) {
  return <div className="page-stack"><div className="summary-strip"><span className="summary-dot ok"/><strong>{services.filter(s => s.state === '运行中').length} 个运行中</strong><span className="summary-separator"/><span className="summary-dot warn"/><strong>{services.filter(s => s.state === '已停止').length} 个已停止</strong><span className="summary-note">状态来自演示数据</span></div><section className="panel service-list-panel"><div className="list-toolbar"><div className="search-input"><Search size={15}/><input placeholder="筛选服务…" aria-label="筛选服务"/></div><button className="button button-subtle"><ListChecks size={15}/>全部服务 <ChevronDown size={14}/></button></div>{services.map((service) => <div className="service-detail-row" key={service.name}><div className={`service-icon ${service.state === '运行中' ? 'is-running' : 'is-stopped'}`}><Zap size={16}/></div><div className="service-detail-copy"><strong>{service.name}</strong><small>{service.description} · {service.uptime}</small></div><span className={`state-label ${service.state === '运行中' ? 'state-ok' : 'state-down'}`}><i/>{service.state}</span><span className={`autostart ${service.enabled ? 'enabled' : ''}`}>{service.enabled ? '开机自启' : '手动启动'}</span><button className="button button-subtle service-action" onClick={() => toggleService(service.name)}>{service.state === '运行中' ? <><Power size={14}/>停止</> : <><Play size={14}/>启动</>}</button><button className="icon-button" aria-label="查看服务日志"><MoreHorizontal size={17}/></button></div>)}</section><div className="subtle-callout"><AlertTriangle size={16}/><span>实际执行 start / stop / restart 前应显示目标设备、当前状态与操作后果，并写入可脱敏的审计记录。</span></div></div>
}

function BluetoothPage({ scanning, scan, paired, setPaired, notify }: { scanning: boolean; scan: () => void; paired: boolean; setPaired: (paired: boolean) => void; notify: (message: string) => void }) {
  return <div className="page-stack"><section className="panel detail-panel"><div className="panel-heading"><div className="heading-icon bluetooth-bg"><Bluetooth size={18}/></div><div><div className="section-kicker">ROBOT RADIO</div><h2>蓝牙</h2></div><span className="connected-pill push-right"><span/>已开启</span><button className="toggle on" onClick={() => notify('已模拟切换蓝牙')} aria-label="切换蓝牙"><span/></button></div><div className="bluetooth-overview"><div className="bt-big-icon"><Bluetooth size={27}/></div><div><strong>Bluetooth 5.0</strong><p>控制机器人侧蓝牙适配器 · hci0</p></div><button className="button button-primary push-right" onClick={scan} disabled={scanning}>{scanning ? <span className="spinner"/> : <Search size={15}/>}扫描附近设备</button></div></section><section className="panel detail-panel"><div className="panel-heading"><div><div className="section-kicker">PAIRED DEVICE</div><h2>已配对设备</h2></div><span className="count-pill">1</span></div><div className="device-row"><div className="device-avatar bt-device"><Headphones size={20}/></div><div className="device-row-copy"><strong>Jabra Speak 510</strong><small>音频设备 · AA:BB:CC:12:34:56</small></div><span className="state-label state-ok"><i/>已连接</span><button className="button button-subtle" onClick={() => { setPaired(!paired); notify(paired ? '已模拟断开耳机' : '已模拟连接耳机') }}>{paired ? '断开' : '连接'}</button><button className="icon-button" onClick={() => notify('忘记设备前会要求二次确认')} aria-label="更多设备操作"><MoreHorizontal size={17}/></button></div></section><section className="panel detail-panel"><div className="panel-heading"><div><div className="section-kicker">NEARBY DEVICES</div><h2>附近设备</h2></div><span className="small-muted">上次扫描 · 2 分钟前</span></div><BluetoothRow name="Xbox Wireless Controller" meta="游戏控制器 · 可配对" type="controller" onClick={() => notify('配对前会显示设备身份与确认提示（演示模式）')} /><BluetoothRow name="Jabra Speak 750" meta="音频设备 · 可配对" type="headphones" onClick={() => notify('配对前会显示设备身份与确认提示（演示模式）')} /></section><div className="subtle-callout"><LockKeyhole size={16}/><span>蓝牙配对需要用户明确确认；连接状态与音频路由状态分开展示。</span></div></div>
}
function BluetoothRow({ name, meta, type, onClick }: { name: string; meta: string; type: string; onClick: () => void }) { return <div className="bluetooth-row"><div className={`device-avatar ${type}`}><Bluetooth size={18}/></div><div className="device-row-copy"><strong>{name}</strong><small>{meta}</small></div><span className="signal-bars"><i/><i/><i/><i/></span><button className="button button-subtle" onClick={onClick}>配对</button></div> }

function AudioPage({ mic, setMic, speaker, setSpeaker, notify }: { mic: string; setMic: (value: string) => void; speaker: string; setSpeaker: (value: string) => void; notify: (message: string) => void }) {
  return <div className="audio-grid"><section className="panel audio-card"><div className="audio-title"><div className="heading-icon mic-bg"><Mic size={18}/></div><div><div className="section-kicker">INPUT</div><h2>麦克风</h2></div><span className="connected-pill push-right"><span/>可用</span></div><div className="audio-device-display"><div className="audio-device-icon"><Mic size={23}/></div><div><strong>{mic}</strong><small>USB 音频输入 · 默认设备</small></div><button className="icon-button push-right" onClick={() => notify('刷新麦克风列表（演示模式）')} aria-label="刷新麦克风"><RefreshCw size={15}/></button></div><label className="field-label">输入设备</label><select value={mic} onChange={(e) => { setMic(e.target.value); notify('已模拟切换输入设备') }}><option>ReSpeaker 2-Mics Pi HAT</option><option>USB PnP Sound Device</option><option>内置模拟输入</option></select><div className="level-label"><span>输入电平</span><span className="level-value">-18 dB</span></div><div className="level-meter"><i style={{width:'58%'}}/><i style={{width:'42%'}}/><i style={{width:'67%'}}/><i style={{width:'35%'}}/><i style={{width:'54%'}}/><i style={{width:'74%'}}/><i style={{width:'46%'}}/><i style={{width:'61%'}}/><i style={{width:'39%'}}/><i style={{width:'57%'}}/></div><div className="audio-card-bottom"><span><span className="tiny-live-dot"/>实时电平 · 演示</span><button className="button button-subtle" onClick={() => notify('测试录音需接入设备权限与安全存储（尚未实现）')}><Play size={14}/>测试录音</button></div></section>
    <section className="panel audio-card"><div className="audio-title"><div className="heading-icon speaker-bg"><Volume2 size={18}/></div><div><div className="section-kicker">OUTPUT</div><h2>扬声器</h2></div><span className="connected-pill push-right"><span/>可用</span></div><div className="audio-device-display"><div className="audio-device-icon speaker-icon"><Headphones size={23}/></div><div><strong>{speaker}</strong><small>USB 音频输出 · 默认设备</small></div><button className="icon-button push-right" onClick={() => notify('刷新扬声器列表（演示模式）')} aria-label="刷新扬声器"><RefreshCw size={15}/></button></div><label className="field-label">输出设备</label><select value={speaker} onChange={(e) => { setSpeaker(e.target.value); notify('已模拟切换输出设备') }}><option>USB Audio DAC</option><option>HDMI / DisplayPort</option><option>内置模拟输出</option></select><div className="volume-label"><span>输出音量</span><strong>68%</strong></div><input className="volume-slider" type="range" min="0" max="100" defaultValue="68" aria-label="输出音量"/><div className="audio-card-bottom"><span>当前输出 · 默认设备</span><button className="button button-primary" onClick={() => notify('演示模式：正在播放测试音效')}><Play size={14}/>播放测试音</button></div></section><div className="audio-footnote"><ShieldCheck size={15}/>切换默认设备可能影响运行中的语音/ROS 节点；正式版将提供即时测试与恢复选项。</div></div>
}

function TerminalPage({ lines, command, setCommand, onKey, run, notify }: { lines: TerminalLine[]; command: string; setCommand: (text: string) => void; onKey: (event: KeyboardEvent<HTMLInputElement>) => void; run: () => void; notify: (message: string) => void }) {
  return <div className="terminal-page"><div className="terminal-toolbar"><div className="terminal-target"><span className="terminal-dot"/><span><strong>robot-r2</strong><small>SSH · 192.168.7.2</small></span><ChevronDown size={15}/></div><div className="terminal-tools"><span className="terminal-mode"><LockKeyhole size={13}/>演示终端</span><button className="icon-button" onClick={() => notify('已模拟复制终端输出')} aria-label="复制输出"><Download size={16}/></button><button className="icon-button" onClick={() => notify('演示终端已清屏')} aria-label="终端选项"><MoreHorizontal size={17}/></button></div></div><div className="terminal-safety"><AlertTriangle size={15}/><span><strong>演示模式：</strong>命令不会发送至机器人。正式版将显示 SSH 目标、权限级别，并对危险命令与多行粘贴进行确认。</span></div><div className="terminal-window" onClick={() => document.getElementById('terminal-input')?.focus()}><div className="terminal-window-bar"><span/><span/><span/><div>ssh robot-r2 · bash</div><button onClick={() => notify('演示终端已清屏')}>清屏</button></div><div className="terminal-output">{lines.map((line, index) => line.kind === 'command' ? <div className="terminal-line command-line" key={index}><span>robot@r2:~$</span> {line.text}</div> : <pre className="terminal-line output-line" key={index}>{line.text}</pre>)}<div className="terminal-input-line"><span>robot@r2:~$</span><input id="terminal-input" value={command} onChange={(e) => setCommand(e.target.value)} onKeyDown={onKey} placeholder="输入 help 查看命令…"/><button onClick={run} aria-label="运行命令"><Play size={14}/></button></div></div></div><div className="terminal-bottom"><div><span className="terminal-bottom-dot"/>连接目标 <strong>robot-r2</strong><span className="dot-divider">·</span>用户 <strong>robot</strong><span className="dot-divider">·</span>权限 <strong>普通用户</strong></div><button onClick={() => notify('SSH 主机指纹应在首次连接时核对并固定')}>主机指纹已验证 <ShieldCheck size={14}/></button></div></div>
}

function LogsPage({ logs, notify }: { logs: LogItem[]; notify: (message: string) => void }) {
  return <div className="page-stack"><div className="list-toolbar logs-toolbar"><div className="search-input"><Search size={15}/><input placeholder="搜索事件…" aria-label="搜索事件"/></div><button className="button button-subtle" onClick={() => notify('已导出脱敏诊断包（演示模式）')}><Download size={15}/>导出诊断包</button></div><section className="panel logs-panel">{logs.map((log, index) => <div className="log-row" key={`${log.time}-${index}`}><span className={`log-tone ${log.tone}`}>{log.tone === 'ok' ? <Check size={14}/> : log.tone === 'warn' ? <AlertTriangle size={14}/> : <Activity size={14}/>}</span><span className="log-time">今天 {log.time}</span><span className="log-message">{log.message}</span><span className={`log-category ${log.tone}`}>{log.tone === 'ok' ? '连接' : log.tone === 'warn' ? '服务' : '系统'}</span></div>)}</section><div className="subtle-callout"><LockKeyhole size={16}/><span>导出诊断信息前应自动脱敏 SSH 密钥、Wi-Fi 密码、命令参数及其他凭证。</span></div></div>
}

export default App
