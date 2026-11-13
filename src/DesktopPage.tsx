import { useEffect, useRef, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { getCurrentWindow } from '@tauri-apps/api/window'
import {
  AlertTriangle, Check, ClipboardPaste, Download, Eye, Keyboard, LoaderCircle, Maximize2,
  Minimize2, Monitor, MonitorOff, Power, RefreshCw, ScanLine, X,
} from 'lucide-react'
import type RFBType from '@novnc/novnc/core/rfb.js'

type Target = { id: string; name: string; host: string; port: number; username: string }
type CheckItem = { id: string; label: string; status: 'ok' | 'warn' | 'fail'; detail: string; fix?: string | null }
type DesktopCheck = { ready: boolean; display?: string | null; sessionType: string; desktopUser: string; sshUser: string; monitors: number; board: CheckItem[]; host: CheckItem[] }
type DesktopStart = { wsUrl: string; password: string; display: string }
type Phase = 'idle' | 'checking' | 'checked' | 'installing' | 'starting' | 'connected'

const readyKey = (id: string) => `robolink-desktop-ready:${id}`
const store = {
  get: (key: string) => { try { return localStorage.getItem(key) } catch { return null } },
  set: (key: string, value: string) => { try { localStorage.setItem(key, value) } catch { /* optional */ } },
  remove: (key: string) => { try { localStorage.removeItem(key) } catch { /* optional */ } },
}
const errorText = (e: unknown) => {
  const text = typeof e === 'string' ? e : e instanceof Error ? e.message : String(e)
  return text.startsWith('[需要sudo] ') ? text.slice('[需要sudo] '.length) : text
}

export function DesktopPage({ target, sshReady, active, runPrivileged, sudoPassword, onLog, onGoTerminal }: {
  target?: Target
  sshReady: boolean
  active: boolean
  runPrivileged: <T>(reason: string, call: (sudoPassword?: string) => Promise<T>) => Promise<T>
  sudoPassword: () => string
  onLog: (text: string, tone?: 'ok' | 'warn' | 'info') => void
  onGoTerminal: () => void
}) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [check, setCheck] = useState<DesktopCheck | null>(null)
  const [display, setDisplay] = useState(':0')
  const [error, setError] = useState('')
  const [scale, setScale] = useState(true)
  const [viewOnly, setViewOnly] = useState(false)
  const [fullscreen, setFullscreen] = useState(false)
  const fullscreenRef = useRef(false)
  useEffect(() => { fullscreenRef.current = fullscreen }, [fullscreen])
  const screenRef = useRef<HTMLDivElement>(null)
  const frameRef = useRef<HTMLDivElement>(null)
  const rfbRef = useRef<RFBType | null>(null)
  const startedRef = useRef(false)

  const runCheck = async () => {
    if (!target) return
    setPhase('checking'); setError('')
    try {
      const result = await invoke<DesktopCheck>('check_remote_desktop', { targetId: target.id })
      setCheck(result)
      if (result.display) setDisplay(result.display)
      if (result.ready) { store.set(readyKey(target.id), result.display ?? ':0'); onLog(`桌面环境检查通过：${target.name} ${result.display ?? ''}`, 'ok') }
      else { store.remove(readyKey(target.id)); onLog(`桌面环境检查未通过：${target.name}`, 'warn') }
      setPhase('checked')
    } catch (e) { setError(errorText(e)); setPhase('idle') }
  }

  // Only the first visit for a board runs the environment check; afterwards go straight to "connect".
  useEffect(() => {
    if (!active || !target || !sshReady || phase !== 'idle' || check) return
    const remembered = store.get(readyKey(target.id))
    if (remembered) setDisplay(remembered)
    else void runCheck()
  }, [active, target?.id, sshReady])

  useEffect(() => { setCheck(null); setError(''); setPhase('idle'); return () => { void disconnect() } }, [target?.id])
  useEffect(() => { if (!sshReady && rfbRef.current) void disconnect('SSH 已断开') }, [sshReady])
  useEffect(() => () => { if (fullscreenRef.current) void getCurrentWindow().setFullscreen(false).catch(() => {}); rfbRef.current?.disconnect(); if (startedRef.current) void invoke('stop_remote_desktop', { sudoPassword: sudoPassword() || null }).catch(() => {}) }, [])
  useEffect(() => { if (rfbRef.current) rfbRef.current.scaleViewport = scale }, [scale])
  useEffect(() => { if (rfbRef.current) rfbRef.current.viewOnly = viewOnly }, [viewOnly])
  // The DOM Fullscreen API hangs/crashes WebKitGTK inside Tauri; instead make the window fullscreen and
  // pin the desktop frame over the whole page with CSS. Ctrl+F11 or Ctrl+Alt+Enter toggles it (captured
  // before noVNC, so the key is not sent to the board). Plain F11 is reserved by the board's apps.
  const setWindowFullscreen = async (on: boolean) => {
    setFullscreen(on)
    try { await getCurrentWindow().setFullscreen(on) } catch (e) { if (on) setError(`窗口全屏失败，已改为铺满窗口：${errorText(e)}`) }
    window.setTimeout(() => rfbRef.current?.focus(), 150)
  }
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const toggle = (event.ctrlKey && event.key === 'F11') || (event.ctrlKey && event.altKey && event.key === 'Enter')
      if (!toggle || !rfbRef.current) return
      event.preventDefault(); event.stopPropagation()
      void setWindowFullscreen(!fullscreenRef.current)
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [])

  const install = async () => {
    if (!target) return
    setPhase('installing'); setError('')
    try {
      const output = await runPrivileged('在开发板上安装 x11vnc（apt-get 需要管理员权限）', sudo => invoke<string>('install_remote_desktop', { targetId: target.id, sudoPassword: sudo ?? null }))
      onLog(`已在 ${target.name} 安装 x11vnc${output ? `：${output.split('\n').pop()}` : ''}`, 'ok')
      await runCheck()
    } catch (e) { setError(errorText(e)); setPhase('checked') }
  }

  const connect = async () => {
    if (!target || !screenRef.current) return
    setPhase('starting'); setError('')
    try {
      const start = await runPrivileged('启动开发板桌面共享（读取桌面授权需要管理员权限）', sudo => invoke<DesktopStart>('start_remote_desktop', { targetId: target.id, display, sudoPassword: sudo ?? null }))
      startedRef.current = true
      const { default: RFB } = await import('@novnc/novnc/core/rfb.js')
      screenRef.current.innerHTML = ''
      const rfb = new RFB(screenRef.current, start.wsUrl, { credentials: { password: start.password }, wsProtocols: ['binary'] })
      rfb.scaleViewport = scale
      rfb.resizeSession = false
      rfb.viewOnly = viewOnly
      rfb.focusOnClick = true
      rfb.qualityLevel = 6
      rfb.compressionLevel = 2
      rfb.addEventListener('connect', () => { setPhase('connected'); rfb.focus(); onLog(`已连接 ${target.name} 的桌面 ${start.display}`, 'ok') })
      rfb.addEventListener('credentialsrequired', () => rfb.sendCredentials({ password: start.password }))
      rfb.addEventListener('securityfailure', (event: Event) => { const detail = (event as CustomEvent<{ reason?: string }>).detail; setError(`VNC 认证失败：${detail?.reason ?? '未知原因'}`) })
      rfb.addEventListener('disconnect', (event: Event) => {
        const clean = (event as CustomEvent<{ clean: boolean }>).detail?.clean
        if (rfbRef.current === rfb) {
          rfbRef.current = null
          setPhase(phase => phase === 'idle' ? phase : 'idle')
          if (!clean) setError('桌面连接意外断开。可以重新连接；若反复出现，请重新检查环境。')
        }
      })
      rfbRef.current = rfb
    } catch (e) {
      const text = errorText(e)
      if (text.includes('没有安装 x11vnc')) store.remove(readyKey(target.id))
      setError(text); setPhase('idle')
    }
  }

  const disconnect = async (reason?: string) => {
    const rfb = rfbRef.current
    rfbRef.current = null
    rfb?.disconnect()
    if (startedRef.current) {
      startedRef.current = false
      await invoke('stop_remote_desktop', { sudoPassword: sudoPassword() || null }).catch(() => {})
      onLog(reason ? `桌面已断开：${reason}` : '已断开开发板桌面', reason ? 'warn' : 'info')
    }
    if (screenRef.current) screenRef.current.innerHTML = ''
    if (fullscreenRef.current) void setWindowFullscreen(false)
    setPhase('idle')
  }

  const toggleFullscreen = () => { void setWindowFullscreen(!fullscreenRef.current) }

  const pasteClipboard = async () => {
    try { const text = await navigator.clipboard.readText(); if (text) { rfbRef.current?.clipboardPasteFrom(text); onLog('已把本机剪贴板发送到开发板') } }
    catch { setError('无法读取本机剪贴板') }
  }

  if (!target) return <div className="page-stack"><section className="panel detail-panel"><div className="empty-state"><Monitor size={17}/><span>请先选择或添加一个开发板。</span></div></section></div>

  const connected = phase === 'connected'
  const failing = check ? [...check.board, ...check.host].filter(i => i.status === 'fail') : []
  const showCheck = check && (phase === 'checked' || phase === 'installing' || !check.ready)

  return <div className="page-stack desktop-page">
    <div className="subtle-callout"><Monitor size={15}/><span>桌面显示只适用于<strong>接了屏幕并运行 X11 图形桌面</strong>的开发板：画面来自开发板正在显示的桌面，本机键盘和鼠标会直接操作它。画面和键鼠全部经已固定指纹的 SSH 加密传输，开发板只在 127.0.0.1 上开放 VNC。</span></div>

    {error && <div className="desktop-error"><AlertTriangle size={15}/><span>{error}</span><button className="icon-button" onClick={() => setError('')} aria-label="关闭"><X size={14}/></button></div>}

    {!sshReady && !connected && <section className="panel detail-panel"><div className="empty-state"><MonitorOff size={17}/><span>SSH 尚未登录或已断开。先到终端页连接开发板，再回来打开桌面。</span></div><div className="desktop-actions"><button className="button button-primary" onClick={onGoTerminal}>去终端连接</button></div></section>}

    {sshReady && (phase === 'checking' || showCheck) && <section className="panel detail-panel">
      <div className="panel-heading"><div><div className="section-kicker">FIRST RUN · ENVIRONMENT CHECK</div><h2>桌面环境检查</h2></div>{phase === 'checking' ? <span className="small-muted"><LoaderCircle className="spin-icon" size={14}/> 检查中…</span> : check && <span className={`connected-pill ${check.ready ? '' : 'not-connected'}`}><span/>{check.ready ? '可以使用' : `${failing.length} 项需要处理`}</span>}</div>
      {check && <div className="desktop-checks">
        <CheckGroup title={`开发板 · ${target.username}@${target.host}`} items={check.board} onFix={fix => fix === 'install-x11vnc' && void install()} busy={phase === 'installing'}/>
        <CheckGroup title="本机" items={check.host} onFix={() => {}} busy={false}/>
      </div>}
      <div className="desktop-actions">
        <button className="button button-subtle" onClick={() => void runCheck()} disabled={phase === 'checking' || phase === 'installing'}><RefreshCw size={14}/>重新检查</button>
        {check?.ready && <button className="button button-primary" onClick={() => void connect()}><Monitor size={15}/>连接桌面</button>}
      </div>
    </section>}

    {sshReady && !showCheck && phase !== 'checking' && !connected && <section className="panel detail-panel">
      <div className="panel-heading"><div><div className="section-kicker">REMOTE DESKTOP · X11</div><h2>{target.name} 的桌面</h2></div></div>
      <div className="desktop-start">
        <label className="scan-port-field"><span>显示编号</span><input value={display} onChange={e => setDisplay(e.target.value.trim())} aria-label="X 显示编号" disabled={phase === 'starting'}/></label>
        <button className="button button-primary" onClick={() => void connect()} disabled={phase === 'starting'}>{phase === 'starting' ? <LoaderCircle className="spin-icon" size={15}/> : <Monitor size={15}/>}{phase === 'starting' ? '正在启动…' : '连接桌面'}</button>
        <button className="button button-subtle" onClick={() => void runCheck()} disabled={phase === 'starting'}><ScanLine size={14}/>重新检查环境</button>
      </div>
    </section>}

    <div className={`desktop-frame ${connected || phase === 'starting' ? '' : 'is-hidden'} ${fullscreen ? 'is-fullscreen' : ''}`} ref={frameRef}>
      <div className="desktop-toolbar">
        <span className="desktop-title"><span className={`terminal-dot ${connected ? '' : 'offline'}`}/>{target.host} · {display}{viewOnly ? ' · 仅查看' : ''}</span>
        <div className="desktop-tools">
          <button className={`button button-subtle ${scale ? 'active' : ''}`} onClick={() => setScale(v => !v)} title="缩放到窗口 / 原始大小">{scale ? <Minimize2 size={14}/> : <Maximize2 size={14}/>}{scale ? '适应窗口' : '原始大小'}</button>
          <button className={`button button-subtle ${viewOnly ? 'active' : ''}`} onClick={() => setViewOnly(v => !v)} title="仅查看时不发送键鼠"><Eye size={14}/>仅查看</button>
          <button className="button button-subtle" onClick={() => void pasteClipboard()} disabled={!connected || viewOnly} title="把本机剪贴板文本发给开发板"><ClipboardPaste size={14}/>粘贴</button>
          <button className="button button-subtle" onClick={() => { rfbRef.current?.sendCtrlAltDel(); rfbRef.current?.focus() }} disabled={!connected || viewOnly}><Keyboard size={14}/>Ctrl+Alt+Del</button>
          <button className="button button-subtle" onClick={toggleFullscreen} disabled={!connected}>{fullscreen ? <Minimize2 size={14}/> : <Maximize2 size={14}/>}{fullscreen ? '退出全屏 (Ctrl+F11)' : '全屏'}</button>
          <button className="button button-danger" onClick={() => void disconnect()}><Power size={14}/>断开</button>
        </div>
      </div>
      <div className="desktop-screen" ref={screenRef} onMouseEnter={() => rfbRef.current?.focus()}/>
      {phase === 'starting' && <div className="desktop-overlay"><LoaderCircle className="spin-icon" size={20}/><span>正在开发板上启动 x11vnc 并建立 SSH 通道…</span></div>}
    </div>
    {connected && <p className="small-muted desktop-hint"><Check size={12}/> 鼠标移入画面后键盘输入会发送到开发板；系统级快捷键（如 Alt+Tab）可能仍被本机拦截，可在全屏下使用。</p>}
  </div>
}

function CheckGroup({ title, items, onFix, busy }: { title: string; items: CheckItem[]; onFix: (fix: string) => void; busy: boolean }) {
  return <div className="desktop-check-group"><div className="section-kicker">{title}</div>{items.map(item => <div className={`desktop-check ${item.status}`} key={item.id}>
    <span className="desktop-check-icon">{item.status === 'ok' ? <Check size={14}/> : <AlertTriangle size={14}/>}</span>
    <span className="desktop-check-copy"><strong>{item.label}</strong><small>{item.detail}</small></span>
    {item.fix === 'install-x11vnc' && <button className="button button-primary" onClick={() => onFix(item.fix!)} disabled={busy}>{busy ? <LoaderCircle className="spin-icon" size={14}/> : <Download size={14}/>}{busy ? '安装中…' : '一键安装'}</button>}
  </div>)}</div>
}
