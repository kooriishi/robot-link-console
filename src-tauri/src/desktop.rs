//! Remote desktop: shows the board's own X11 screen inside RoboLink with local keyboard and mouse.
//!
//! Board: `x11vnc` attaches to the running X display, listens on 127.0.0.1 only and requires a
//! one-time random password. Host: a WebSocket server on 127.0.0.1 with a random path token bridges
//! each noVNC connection to `ssh -W 127.0.0.1:<port>` through the pinned, multiplexed SSH session,
//! so no VNC port is reachable from the network and no traffic leaves the SSH channel.

use crate::ssh::{self, RemoteOptions};
use crate::state::AppState;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::Mutex;
use tauri::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CheckItem {
    pub id: String,
    pub label: String,
    /// "ok", "warn" (works but worth knowing) or "fail" (blocks the desktop).
    pub status: String,
    pub detail: String,
    /// An action the UI can offer, e.g. "install-x11vnc".
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopCheck {
    pub ready: bool,
    pub display: Option<String>,
    pub session_type: String,
    pub desktop_user: String,
    pub ssh_user: String,
    pub monitors: i32,
    pub board: Vec<CheckItem>,
    pub host: Vec<CheckItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStart {
    pub ws_url: String,
    pub password: String,
    pub display: String,
}

struct DesktopSession {
    target_id: String,
    pid: u32,
    stop: watch::Sender<bool>,
}

static SESSION: Mutex<Option<DesktopSession>> = Mutex::new(None);

const CHECK_SCRIPT: &str = r#"export LC_ALL=C
printf 'USER=%s\n' "$(id -un)"
printf 'X11VNC=%s\n' "$(command -v x11vnc 2>/dev/null)"
printf 'APT=%s\n' "$(command -v apt-get 2>/dev/null)"
printf 'XSOCKS=%s\n' "$(ls /tmp/.X11-unix 2>/dev/null | tr '\n' ' ')"
M=-1; for f in /sys/class/drm/*/status; do [ -r "$f" ] || continue; [ "$M" -lt 0 ] && M=0; [ "$(cat "$f" 2>/dev/null)" = connected ] && M=$((M+1)); done
printf 'MONITORS=%s\n' "$M"
if command -v loginctl >/dev/null 2>&1; then
  for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
    printf 'SESSION='; loginctl show-session "$s" -p Type -p Name -p Display -p State -p Remote -p Class 2>/dev/null | tr '\n' ' '; echo
  done
fi
printf 'XSERVER=%s\n' "$(ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^(Xorg|X|Xvfb|Xtigervnc)$/ {print $1" "$2; exit}')"
printf 'XWAYLAND=%s\n' "$(ps -eo comm= 2>/dev/null | grep -m1 -E '^Xwayland$')"
"#;

fn value<'a>(output: &'a str, key: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .unwrap_or("")
        .trim()
}

fn valid_display(display: &str) -> bool {
    let Some(rest) = display.strip_prefix(':') else {
        return false;
    };
    let (num, screen) = rest.split_once('.').unwrap_or((rest, "0"));
    !num.is_empty()
        && num.len() <= 3
        && num.chars().all(|c| c.is_ascii_digit())
        && screen.len() <= 2
        && screen.chars().all(|c| c.is_ascii_digit())
}

fn item(id: &str, label: &str, status: &str, detail: String, fix: Option<&str>) -> CheckItem {
    CheckItem {
        id: id.into(),
        label: label.into(),
        status: status.into(),
        detail,
        fix: fix.map(str::to_string),
    }
}

/// Turns the board probe output into check results. Pure, so it is unit-tested.
fn parse_board_check(
    output: &str,
) -> (Vec<CheckItem>, Option<String>, String, String, String, i32) {
    let ssh_user = value(output, "USER").to_string();
    let x11vnc = !value(output, "X11VNC").is_empty();
    let apt = !value(output, "APT").is_empty();
    let monitors = value(output, "MONITORS").parse::<i32>().unwrap_or(-1);
    let xserver = value(output, "XSERVER").to_string();
    let xwayland = !value(output, "XWAYLAND").is_empty();
    let sockets: Vec<String> = value(output, "XSOCKS")
        .split_whitespace()
        .filter_map(|s| s.strip_prefix('X'))
        .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
        .map(|n| format!(":{n}"))
        .collect();

    // Local graphical sessions (not SSH ones) tell us X11 vs Wayland and the desktop's owner.
    let mut session_type = String::new();
    let mut desktop_user = String::new();
    let mut display = None;
    for line in output.lines().filter_map(|l| l.strip_prefix("SESSION=")) {
        let field = |key: &str| {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
                .unwrap_or("")
                .to_string()
        };
        let kind = field("Type");
        if field("Remote") == "yes" || !(kind == "x11" || kind == "wayland") {
            continue;
        }
        if field("Class") == "greeter" && !session_type.is_empty() {
            continue;
        }
        session_type = kind;
        desktop_user = field("Name");
        let d = field("Display");
        if valid_display(&d) {
            display = Some(d);
        }
        if field("State") == "active" {
            break;
        }
    }
    if display.is_none() {
        display = sockets.first().cloned();
    }
    if session_type.is_empty() && !xserver.is_empty() {
        session_type = "x11".into();
    }
    if desktop_user.is_empty() {
        desktop_user = xserver.split_whitespace().next().unwrap_or("").to_string();
    }

    let mut items = Vec::new();
    let has_x = !xserver.is_empty() || (display.is_some() && session_type == "x11");
    if session_type == "wayland" && xserver.is_empty() {
        items.push(item(
            "session",
            "桌面会话",
            "fail",
            format!(
                "开发板桌面运行在 Wayland{}，x11vnc 只能抓取 X11 桌面。",
                if xwayland {
                    "（仅有 Xwayland）"
                } else {
                    ""
                }
            ),
            None,
        ));
        items.push(item("session-fix", "如何切换到 X11", "warn",
            "在开发板登录界面选择 “Xorg / X11” 会话；GNOME 可在 /etc/gdm3/custom.conf 设置 WaylandEnable=false 后重启。".into(), None));
    } else if !has_x || display.is_none() {
        items.push(item("session", "桌面会话", "fail",
            "没有找到正在运行的 X 桌面。桌面显示只支持接了屏幕、已启动图形桌面（并已登录或自动登录）的开发板。".into(), None));
    } else {
        let owner = if desktop_user.is_empty() {
            String::new()
        } else {
            format!("，用户 {desktop_user}")
        };
        items.push(item(
            "session",
            "桌面会话",
            "ok",
            format!("X11 {}{owner}", display.clone().unwrap_or_default()),
            None,
        ));
    }
    match monitors {
        n if n > 0 => items.push(item("monitor", "显示器", "ok", format!("检测到 {n} 个已连接的显示输出"), None)),
        0 => items.push(item("monitor", "显示器", "warn",
            "没有检测到已连接的显示器。此功能面向接了屏幕的开发板；没有屏幕时桌面可能是黑屏或分辨率很低。".into(), None)),
        _ => items.push(item("monitor", "显示器", "warn",
            "无法读取显示器连接状态（/sys/class/drm 不可用），请确认开发板接了屏幕。".into(), None)),
    }
    if x11vnc {
        items.push(item("x11vnc", "x11vnc", "ok", "已安装".into(), None));
    } else if apt {
        items.push(item(
            "x11vnc",
            "x11vnc",
            "fail",
            "开发板未安装 x11vnc。可一键安装（sudo apt-get install -y x11vnc，需要开发板能上网）。"
                .into(),
            Some("install-x11vnc"),
        ));
    } else {
        items.push(item(
            "x11vnc",
            "x11vnc",
            "fail",
            "开发板未安装 x11vnc，且没有 apt-get，请按开发板系统的方式手动安装 x11vnc。".into(),
            None,
        ));
    }
    if !desktop_user.is_empty() && desktop_user != ssh_user && desktop_user != "root" {
        items.push(item("user", "登录用户", "warn",
            format!("桌面属于用户 {desktop_user}，SSH 用户是 {ssh_user}；启动时可能需要 sudo 密码才能读取桌面授权。"), None));
    } else if desktop_user == "root" {
        items.push(item(
            "user",
            "登录用户",
            "warn",
            "X 服务以 root 运行（显示管理器）；启动时可能需要 sudo 密码。".into(),
            None,
        ));
    }
    (
        items,
        display,
        session_type,
        desktop_user,
        ssh_user,
        monitors,
    )
}

fn host_checks(state: &AppState, target: &crate::model::Target) -> Vec<CheckItem> {
    let mut items = Vec::new();
    match std::process::Command::new("ssh").arg("-V").output() {
        Ok(out) => {
            let version = String::from_utf8_lossy(&out.stderr).trim().to_string();
            items.push(item("ssh", "本机 OpenSSH", "ok", version, None));
        }
        Err(e) => items.push(item(
            "ssh",
            "本机 OpenSSH",
            "fail",
            format!("无法运行 ssh：{e}。请安装 openssh-client。"),
            None,
        )),
    }
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => items.push(item(
            "loopback",
            "本机回环转发",
            "ok",
            "可在 127.0.0.1 建立仅本机可见的转发端口".into(),
            None,
        )),
        Err(e) => items.push(item(
            "loopback",
            "本机回环转发",
            "fail",
            format!("无法监听 127.0.0.1：{e}"),
            None,
        )),
    }
    let ready = ssh::connection_ready(state, target).unwrap_or(false);
    items.push(if ready {
        item(
            "tunnel",
            "SSH 通道",
            "ok",
            "已登录，桌面画面经已固定指纹的 SSH 加密传输".into(),
            None,
        )
    } else {
        item(
            "tunnel",
            "SSH 通道",
            "fail",
            "SSH 尚未登录或已断开。请先到“终端”页连接并完成登录。".into(),
            None,
        )
    });
    items.push(item(
        "viewer",
        "桌面查看器",
        "ok",
        "noVNC 已内置在 RoboLink 中，无需安装".into(),
        None,
    ));
    items
}

#[tauri::command(async)]
pub fn check_remote_desktop(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<DesktopCheck, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let host = host_checks(&state, &target);
    let output = ssh::remote_command(&state, &target, CHECK_SCRIPT)?;
    let (board, display, session_type, desktop_user, ssh_user, monitors) =
        parse_board_check(&output);
    let ready = board.iter().chain(host.iter()).all(|i| i.status != "fail");
    Ok(DesktopCheck {
        ready,
        display,
        session_type,
        desktop_user,
        ssh_user,
        monitors,
        board,
        host,
    })
}

#[tauri::command(async)]
pub fn install_remote_desktop(
    state: State<'_, AppState>,
    target_id: String,
    sudo_password: Option<String>,
) -> Result<String, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let password = sudo_password.filter(|p| !p.is_empty());
    if password.is_none() {
        return Err(format!(
            "{}安装 x11vnc 需要开发板的 sudo 权限。",
            ssh::SUDO_MARK
        ));
    }
    let script = "export DEBIAN_FRONTEND=noninteractive LC_ALL=C; apt-get install -y x11vnc >/tmp/robolink-apt.log 2>&1 || { apt-get update >>/tmp/robolink-apt.log 2>&1 && apt-get install -y x11vnc >>/tmp/robolink-apt.log 2>&1; }; rc=$?; tail -n 4 /tmp/robolink-apt.log; exit $rc";
    let output = ssh::remote_command_with(&state, &target, script, RemoteOptions {
        sudo_password: password.as_deref(),
        timeout_secs: Some(420),
        ..Default::default()
    })
    .map_err(|e| {
        if e.contains("Temporary failure resolving") || e.contains("Could not resolve") || e.contains("Unable to fetch") {
            format!("开发板无法访问软件源（没有联网）。请先在“网络与 Wi‑Fi”页让开发板连上网络后重试。详情：{e}")
        } else {
            format!("安装 x11vnc 失败：{e}")
        }
    })?;
    Ok(output.trim().to_string())
}

// The pkill patterns use `pas[s]` and the mktemp template is split with `""` so that the script's own
// `sh -c '<script>'` command line never matches and kills itself.
fn start_script(display: &str) -> String {
    format!(
        r#"export LC_ALL=C
P=''; while IFS= read -r L; do case "$L" in SECRET:*) P=${{L#SECRET:}}; break;; esac; done
command -v x11vnc >/dev/null 2>&1 || {{ echo ERR=NO_X11VNC; exit 3; }}
DIR=${{XDG_RUNTIME_DIR:-/tmp}}; [ -d "$DIR" ] && [ -w "$DIR" ] || DIR=/tmp
pkill -f 'robolink-vnc-pas[s]' 2>/dev/null; sleep 0.3
# Listening TCP ports from /proc (works without ss/netstat): listening <port> [only-loopback]
listening() {{
  cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v p="$(printf '%04X' "$1")" -v lo="$2" '$4=="0A" {{ n=split($2,a,":"); if (a[n]==p && (lo=="" || a[1]=="0100007F")) f=1 }} END {{ exit !f }}'
}}
PORT=''
for p in $(seq 5931 5960); do
  if ! listening "$p"; then PORT=$p; break; fi
done
[ -n "$PORT" ] || {{ echo ERR=NO_PORT; exit 4; }}
umask 077
LOG="$DIR/robolink-x11vnc.log"
: > "$LOG"
# Try the display manager's authority first, then an X server without access control.
for AUTH in guess none; do
  PF=$(mktemp "$DIR/robolink-vnc-""pass.XXXXXX") || exit 5
  printf '%s\n' "$P" > "$PF"
  if [ "$AUTH" = guess ]; then set -- -auth guess; else set --; fi
  x11vnc -display {display} "$@" -localhost -noipv6 -rfbport "$PORT" -passwdfile "rm:$PF" -shared -forever -xkb -repeat -noxdamage -norc -bg -o "$LOG" </dev/null >/dev/null 2>&1
  for i in 1 2 3 4 5 6 7 8; do
    if listening "$PORT" lo; then
      PID=$(pgrep -f "rfbport $PORT" | head -1)
      echo "OK PORT=$PORT PID=$PID"; exit 0
    fi
    sleep 0.5
  done
  rm -f "$PF"
done
echo ERR=START
tail -n 6 "$LOG" 2>/dev/null
exit 6"#
    )
}

fn parse_start(output: &str) -> Result<(u16, u32), String> {
    let line = output
        .lines()
        .find(|l| l.starts_with("OK "))
        .ok_or_else(|| start_failure(output))?;
    let port = value(&line.replace(' ', "\n"), "PORT")
        .parse::<u16>()
        .map_err(|_| "x11vnc 端口无效".to_string())?;
    let pid = value(&line.replace(' ', "\n"), "PID")
        .parse::<u32>()
        .unwrap_or(0);
    if !(5931..=5960).contains(&port) {
        return Err("x11vnc 端口无效".into());
    }
    Ok((port, pid))
}

fn start_failure(output: &str) -> String {
    if output.contains("ERR=NO_X11VNC") {
        return "开发板没有安装 x11vnc，请重新做环境检查并安装。".into();
    }
    if output.contains("ERR=NO_PORT") {
        return "开发板 5931–5960 端口都被占用，无法启动 x11vnc。".into();
    }
    let log = output
        .lines()
        .filter(|l| !l.starts_with("ERR="))
        .collect::<Vec<_>>()
        .join(" ");
    let lower = log.to_ascii_lowercase();
    if lower.contains("xopendisplay") || lower.contains("authorization") || lower.contains("-auth")
    {
        return format!(
            "{}x11vnc 无法打开开发板桌面（没有读取桌面授权的权限）：{}",
            ssh::SUDO_MARK,
            log.trim()
        );
    }
    format!(
        "x11vnc 启动失败：{}",
        if log.trim().is_empty() {
            "没有日志输出"
        } else {
            log.trim()
        }
    )
}

fn stop_board(
    state: &AppState,
    target: &crate::model::Target,
    pid: u32,
    sudo_password: Option<&str>,
) {
    let script = if pid > 0 {
        format!("kill {pid} 2>/dev/null; pkill -f 'robolink-vnc-pas[s]' 2>/dev/null; true")
    } else {
        "pkill -f 'robolink-vnc-pas[s]' 2>/dev/null; true".to_string()
    };
    let _ = ssh::remote_command_with(
        state,
        target,
        &script,
        RemoteOptions {
            sudo_password,
            ..Default::default()
        },
    );
}

#[tauri::command(async)]
pub fn start_remote_desktop(
    state: State<'_, AppState>,
    target_id: String,
    display: String,
    sudo_password: Option<String>,
) -> Result<DesktopStart, String> {
    if !valid_display(&display) {
        return Err("桌面显示编号无效".into());
    }
    let target = ssh::lookup_target(&state, &target_id)?;
    if !ssh::connection_ready(&state, &target).unwrap_or(false) {
        return Err("SSH 尚未登录或已断开。请先到“终端”页连接并完成登录。".into());
    }
    stop_session();
    // VNC authentication only uses the first 8 characters.
    let password: String = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let sudo = sudo_password.as_deref().filter(|p| !p.is_empty());
    let output = ssh::remote_command_with(
        &state,
        &target,
        &start_script(&display),
        RemoteOptions {
            sudo_password: sudo,
            stdin_line: Some(&password),
            timeout_secs: Some(25),
        },
    )?;
    let (port, pid) = parse_start(&output)?;

    let token = uuid::Uuid::new_v4().simple().to_string();
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("无法建立本机转发：{e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let ws_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut tunnel = vec!["ssh".to_string()];
    tunnel.extend(ssh::ssh_args(&state, &target, false, true));
    tunnel.push("-W".into());
    tunnel.push(format!("127.0.0.1:{port}"));
    tunnel.push(ssh::ssh_destination(&target));

    let (stop_tx, stop_rx) = watch::channel(false);
    let path = format!("/{token}");
    tauri::async_runtime::spawn(async move {
        let Ok(listener) = TcpListener::from_std(listener) else {
            return;
        };
        serve(listener, path, tunnel, stop_rx).await;
    });
    if let Ok(mut slot) = SESSION.lock() {
        *slot = Some(DesktopSession {
            target_id,
            pid,
            stop: stop_tx,
        });
    }
    Ok(DesktopStart {
        ws_url: format!("ws://127.0.0.1:{ws_port}/{token}"),
        password,
        display,
    })
}

fn stop_session() -> Option<DesktopSession> {
    let session = SESSION.lock().ok().and_then(|mut s| s.take());
    if let Some(s) = &session {
        let _ = s.stop.send(true);
    }
    session
}

#[tauri::command(async)]
pub fn stop_remote_desktop(
    state: State<'_, AppState>,
    sudo_password: Option<String>,
) -> Result<(), String> {
    if let Some(session) = stop_session() {
        if let Ok(target) = ssh::lookup_target(&state, &session.target_id) {
            stop_board(
                &state,
                &target,
                session.pid,
                sudo_password.as_deref().filter(|p| !p.is_empty()),
            );
        }
    }
    Ok(())
}

async fn serve(
    listener: TcpListener,
    path: String,
    tunnel: Vec<String>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                if !peer.ip().is_loopback() { continue; }
                let path = path.clone();
                let tunnel = tunnel.clone();
                let stop = stop.clone();
                tokio::spawn(async move { let _ = bridge(stream, path, tunnel, stop).await; });
            }
        }
    }
}

async fn bridge(
    stream: tokio::net::TcpStream,
    path: String,
    tunnel: Vec<String>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let callback = |request: &Request, mut response: Response| {
        if request.uri().path() != path {
            let mut reject = tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(
                Some("forbidden".into()),
            );
            *reject.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN;
            return Err(reject);
        }
        // noVNC may offer the "binary" subprotocol; echo it so the browser accepts the handshake.
        let offers_binary = request
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|p| p.trim() == "binary"));
        if offers_binary {
            response
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
        }
        Ok(response)
    };
    let ws = tokio_tungstenite::accept_hdr_async(stream, callback)
        .await
        .map_err(|e| e.to_string())?;
    let mut child = tokio::process::Command::new(&tunnel[0])
        .args(&tunnel[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut to_vnc = child.stdin.take().ok_or("no stdin")?;
    let mut from_vnc = child.stdout.take().ok_or("no stdout")?;
    let (mut ws_tx, mut ws_rx) = ws.split();
    let upstream = async {
        while let Some(message) = ws_rx.next().await {
            match message {
                Ok(Message::Binary(data)) => {
                    if to_vnc.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    };
    let downstream = async {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match from_vnc.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buffer[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.close().await;
    };
    tokio::select! {
        _ = upstream => {},
        _ = downstream => {},
        _ = stop.changed() => {},
    }
    let _ = child.kill().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bridge forwards WebSocket binary frames to the tunnel command's stdio and back, and
    /// rejects paths without the token. A local TCP "VNC server" stands in for `ssh -W`.
    #[test]
    fn websocket_bridge_relays_bytes_and_checks_the_token() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let vnc = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let vnc_port = vnc.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut sock, _) = vnc.accept().await.unwrap();
                sock.write_all(b"RFB 003.008\n").await.unwrap();
                let mut buf = [0_u8; 12];
                sock.read_exact(&mut buf).await.unwrap();
                sock.write_all(&buf).await.unwrap();
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (stop_tx, stop_rx) = watch::channel(false);
            // `nc` plays the role of `ssh -W host:port`.
            let tunnel = vec!["nc".into(), "127.0.0.1".into(), vnc_port.to_string()];
            tokio::spawn(serve(listener, "/tok".into(), tunnel, stop_rx));

            let bad =
                tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/wrong")).await;
            assert!(bad.is_err());

            let (mut ws, _) =
                tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/tok"))
                    .await
                    .unwrap();
            let first = ws.next().await.unwrap().unwrap();
            assert_eq!(first.into_data().as_ref() as &[u8], b"RFB 003.008\n");
            ws.send(Message::Binary(b"RFB 003.008\n".to_vec()))
                .await
                .unwrap();
            let echoed = ws.next().await.unwrap().unwrap();
            assert_eq!(echoed.into_data().as_ref() as &[u8], b"RFB 003.008\n");
            let _ = stop_tx.send(true);
        });
    }

    /// Manual end-to-end helper: ROBOLINK_E2E_VNC_PORT=5931 cargo test e2e_bridge -- --ignored
    /// serves ws://127.0.0.1:5999/e2e for a browser running noVNC.
    #[test]
    #[ignore]
    fn e2e_bridge() {
        let vnc_port = std::env::var("ROBOLINK_E2E_VNC_PORT").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:5999").await.unwrap();
            let (_stop_tx, stop_rx) = watch::channel(false);
            let tunnel = vec!["nc".into(), "127.0.0.1".into(), vnc_port];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(90),
                serve(listener, "/e2e".into(), tunnel, stop_rx),
            )
            .await;
        });
    }

    #[test]
    fn displays_are_validated() {
        assert!(valid_display(":0") && valid_display(":10.0"));
        assert!(
            !valid_display("0")
                && !valid_display(":0;rm")
                && !valid_display(":")
                && !valid_display(":1234")
        );
    }

    #[test]
    fn x11_board_with_screen_is_ready_once_x11vnc_exists() {
        let out = "USER=sunrise\nX11VNC=\nAPT=/usr/bin/apt-get\nXSOCKS=X0 \nMONITORS=1\nSESSION=Type=x11 Name=sunrise Display=:0 State=active Remote=no Class=user \nXSERVER=root Xorg\nXWAYLAND=\n";
        let (items, display, kind, user, ssh_user, monitors) = parse_board_check(out);
        assert_eq!(display.as_deref(), Some(":0"));
        assert_eq!(
            (kind.as_str(), user.as_str(), ssh_user.as_str(), monitors),
            ("x11", "sunrise", "sunrise", 1)
        );
        let x = items.iter().find(|i| i.id == "x11vnc").unwrap();
        assert_eq!(
            (x.status.as_str(), x.fix.as_deref()),
            ("fail", Some("install-x11vnc"))
        );
        assert!(items
            .iter()
            .filter(|i| i.id != "x11vnc")
            .all(|i| i.status != "fail"));
    }

    #[test]
    fn wayland_and_headless_boards_are_explained() {
        let wayland = "USER=u\nX11VNC=/usr/bin/x11vnc\nXSOCKS=X0\nMONITORS=1\nSESSION=Type=wayland Name=u Display= State=active Remote=no Class=user\nXSERVER=\nXWAYLAND=Xwayland\n";
        let (items, ..) = parse_board_check(wayland);
        assert!(items
            .iter()
            .any(|i| i.id == "session" && i.status == "fail" && i.detail.contains("Wayland")));
        let headless = "USER=u\nX11VNC=/usr/bin/x11vnc\nXSOCKS=\nMONITORS=0\nXSERVER=\n";
        let (items, display, ..) = parse_board_check(headless);
        assert!(display.is_none());
        assert!(items
            .iter()
            .any(|i| i.id == "session" && i.status == "fail"));
        assert!(items
            .iter()
            .any(|i| i.id == "monitor" && i.status == "warn"));
    }

    #[test]
    fn start_output_is_parsed_and_auth_errors_ask_for_sudo() {
        assert_eq!(
            parse_start("OK PORT=5931 PID=1234\n").unwrap(),
            (5931, 1234)
        );
        assert!(parse_start("OK PORT=22 PID=1\n").is_err());
        let err = parse_start("ERR=START\n08/11 XOpenDisplay(\":0\") failed.\n").unwrap_err();
        assert!(err.starts_with(ssh::SUDO_MARK));
        assert!(parse_start("ERR=NO_X11VNC\n")
            .unwrap_err()
            .contains("没有安装 x11vnc"));
    }

    #[test]
    fn start_script_reads_the_vnc_password_from_the_marked_line() {
        let script = start_script(":0");
        assert!(script.contains("SECRET:*) P=${L#SECRET:}"));
        assert!(script.contains("-localhost") && script.contains("passwdfile \"rm:$PF\""));
    }
}
