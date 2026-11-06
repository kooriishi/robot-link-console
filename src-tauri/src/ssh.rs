use crate::model::{HostKeyStatus, Target};
use crate::state::{AppState, HostPin};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

pub struct TerminalSession {
    pub writer: Box<dyn Write + Send>,
    pub master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn Child + Send + Sync>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TerminalEvent {
    session_id: String,
    data: String,
}

fn target_identity(target: &Target) -> String {
    format!("{}:{}", target.host.to_ascii_lowercase(), target.port)
}

pub fn lookup_target(state: &AppState, id: &str) -> Result<Target, String> {
    state
        .load_targets()?
        .into_iter()
        .find(|t| t.id == id)
        .ok_or_else(|| "找不到所选机器人".into())
}

fn ssh_host(target: &Target) -> String {
    if target.host.contains(':') && !target.host.starts_with('[') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    }
}

fn ssh_destination(target: &Target) -> String {
    format!("{}@{}", target.username, ssh_host(target))
}

fn host_key_algorithms(key_type: &str) -> Option<&'static str> {
    match key_type {
        "ssh-ed25519" => Some("ssh-ed25519"),
        "ecdsa-sha2-nistp256" => Some("ecdsa-sha2-nistp256"),
        "ecdsa-sha2-nistp384" => Some("ecdsa-sha2-nistp384"),
        "ecdsa-sha2-nistp521" => Some("ecdsa-sha2-nistp521"),
        "ssh-rsa" => Some("rsa-sha2-512,rsa-sha2-256"),
        _ => None,
    }
}

#[derive(Clone)]
struct ScannedKey {
    fingerprint: String,
    algorithm: String,
    known_hosts_line: String,
}

fn scan_keys(target: &Target) -> Result<Vec<ScannedKey>, String> {
    let output = Command::new("ssh-keyscan")
        .args([
            "-T",
            "5",
            "-p",
            &target.port.to_string(),
            "-t",
            "ed25519,ecdsa,rsa",
            &target.host,
        ])
        .output()
        .map_err(|e| format!("无法运行 ssh-keyscan：{e}；请安装 OpenSSH 客户端"))?;
    if !output.status.success() && output.stdout.is_empty() {
        let detail = safe_stderr(&output.stderr);
        let hint = unreachable_hint(&target.host, target.port);
        return Err(if detail.is_empty() {
            format!("读取机器人 SSH 主机密钥失败：{hint}")
        } else {
            format!("读取机器人 SSH 主机密钥失败：{detail}。{hint}")
        });
    }
    let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with('#') && line.split_whitespace().count() >= 3
        })
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        return Err("未获取到 SSH 主机密钥。请检查网线、目标 IP、SSH 服务及端口。".into());
    }
    let mut keys = Vec::new();
    for line in lines {
        let algorithm = line
            .split_whitespace()
            .nth(1)
            .ok_or("SSH 主机密钥格式无效")?
            .to_string();
        if host_key_algorithms(&algorithm).is_none() {
            continue;
        }
        let mut child = Command::new("ssh-keygen")
            .args(["-E", "sha256", "-lf", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("无法运行 ssh-keygen：{e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(line.as_bytes())
                .map_err(|e| e.to_string())?;
            stdin.write_all(b"\n").map_err(|e| e.to_string())?;
        }
        let result = child.wait_with_output().map_err(|e| e.to_string())?;
        if !result.status.success() {
            return Err(format!(
                "计算 SSH 指纹失败：{}",
                safe_stderr(&result.stderr)
            ));
        }
        let row = String::from_utf8_lossy(&result.stdout);
        let fingerprint = row
            .split_whitespace()
            .find(|c| c.starts_with("SHA256:"))
            .ok_or("ssh-keygen 没有返回可验证的 SHA-256 指纹")?;
        keys.push(ScannedKey {
            fingerprint: format!("{algorithm} · {fingerprint}"),
            algorithm,
            known_hosts_line: line,
        });
    }
    keys.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    keys.dedup_by(|a, b| a.fingerprint == b.fingerprint);
    if keys.is_empty() {
        return Err("ssh-keygen 没有返回可验证的 SHA-256 指纹".into());
    }
    Ok(keys)
}

pub fn host_key_status(state: &AppState, target: &Target) -> Result<HostKeyStatus, String> {
    let scanned = scan_keys(target)?;
    let fingerprints = scanned
        .iter()
        .map(|key| key.fingerprint.clone())
        .collect::<Vec<_>>();
    let key = target_identity(target);
    let pins = state.load_pins()?;
    let pin = pins.iter().find(|p| p.target_key == key);
    let pinned = pin.map(|p| p.fingerprints.clone()).unwrap_or_default();
    let legacy = pin
        .map(|p| {
            p.key_algorithm.is_empty()
                || p.fingerprints.len() != 1
                || p.known_hosts_lines.len() != 1
        })
        .unwrap_or(false);
    let current: HashSet<&str> = fingerprints.iter().map(String::as_str).collect();
    let trusted =
        !legacy && !pinned.is_empty() && pinned.iter().all(|fp| current.contains(fp.as_str()));
    let changed = !pinned.is_empty() && !trusted;
    Ok(HostKeyStatus {
        fingerprints,
        pinned_fingerprints: pinned,
        trusted,
        changed,
    })
}

pub fn trust_host_key(state: &AppState, target: &Target, fingerprint: &str) -> Result<(), String> {
    let scanned = scan_keys(target)?;
    let selected = scanned
        .iter()
        .find(|key| key.fingerprint == fingerprint)
        .ok_or("主机密钥在确认过程中发生变化。未保存，请重新读取指纹并核对。")?;
    let target_key = target_identity(target);
    let mut pins = state.load_pins()?;
    if let Some(old) = pins.iter().find(|p| p.target_key == target_key) {
        if old.fingerprints.len() != 1
            || old.fingerprints[0] != fingerprint
            || old.key_algorithm != selected.algorithm
            || old.known_hosts_lines.len() != 1
            || old.known_hosts_lines[0] != selected.known_hosts_line
        {
            return Err("机器人主机指纹与已固定值不一致。为防止中间人攻击，未覆盖旧值；请先核验后显式清除旧指纹。".into());
        }
        return Ok(());
    }
    pins.push(HostPin {
        target_key,
        fingerprints: vec![fingerprint.to_string()],
        key_algorithm: selected.algorithm.clone(),
        known_hosts_lines: vec![selected.known_hosts_line.clone()],
    });
    state.save_pins(&pins)
}

pub fn forget_host_key(state: &AppState, target: &Target) -> Result<(), String> {
    let key = target_identity(target);
    let mut pins = state.load_pins()?;
    pins.retain(|p| p.target_key != key);
    state.save_pins(&pins)
}

pub fn ensure_pinned(state: &AppState, target: &Target) -> Result<(), String> {
    let key = target_identity(target);
    let pins = state.load_pins()?;
    let pin = pins
        .iter()
        .find(|p| p.target_key == key)
        .ok_or("请先核对并固定机器人的 SSH 主机指纹，再连接。")?;
    if pin.fingerprints.len() != 1
        || pin.known_hosts_lines.len() != 1
        || host_key_algorithms(&pin.key_algorithm).is_none()
    {
        return Err("此机器人保存的是旧版或不受支持的多密钥 pin。请先核验可信的主机指纹，再显式清除旧 pin 并重新固定一把密钥。".into());
    }
    Ok(())
}

pub fn connection_ready(state: &AppState, target: &Target) -> Result<bool, String> {
    ensure_pinned(state, target)?;
    let socket = state
        .config_dir
        .join(format!("cm-{}", safe_socket_key(target)));
    let output = Command::new("ssh")
        .arg("-F")
        .arg("/dev/null")
        .arg("-p")
        .arg(target.port.to_string())
        .arg("-S")
        .arg(socket)
        .arg("-O")
        .arg("check")
        .arg(ssh_destination(target))
        .output()
        .map_err(|e| format!("无法检查 OpenSSH 会话：{e}"))?;
    Ok(output.status.success())
}

fn ssh_args(state: &AppState, target: &Target, tty: bool, batch: bool) -> Vec<String> {
    let socket = state
        .config_dir
        .join(format!("cm-{}", safe_socket_key(target)));
    let mut args = vec![
        "-F".into(),
        "/dev/null".into(),
        "-p".into(),
        target.port.to_string(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", state.known_hosts_file.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "HashKnownHosts=no".into(),
        "-o".into(),
        "ConnectTimeout=6".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        format!("ControlPath={}", socket.display()),
        "-o".into(),
        "ControlMaster=auto".into(),
        "-o".into(),
        "ControlPersist=120".into(),
    ];
    if let Ok(pins) = state.load_pins() {
        if let Some(pin) = pins
            .iter()
            .find(|pin| pin.target_key == target_identity(target))
        {
            if let Some(algorithms) = host_key_algorithms(&pin.key_algorithm) {
                args.extend(["-o".into(), format!("HostKeyAlgorithms={algorithms}")]);
            }
        }
    }
    if batch {
        args.extend(["-o".into(), "BatchMode=yes".into()]);
    }
    if tty {
        args.push("-tt".into());
    } else {
        args.push("-T".into());
    }
    args
}

fn safe_socket_key(target: &Target) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    target_identity(target).hash(&mut h);
    format!("{:016x}", h.finish())
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn remote_command(state: &AppState, target: &Target, script: &str) -> Result<String, String> {
    run_remote_script(state, target, script, None)
}

pub fn validate_sudo_password(password: &str) -> Result<(), String> {
    if password.len() > 1024 || password.chars().any(|c| matches!(c, '\0' | '\n' | '\r')) {
        return Err("机器人 sudo 密码格式无效".into());
    }
    Ok(())
}

/// Runs an allowlisted remote operation as root. The password is sent only over SSH stdin.
pub fn remote_command_sudo(
    state: &AppState,
    target: &Target,
    script: &str,
    password: &str,
) -> Result<String, String> {
    validate_sudo_password(password)?;
    let elevated = format!("sudo -S -p '' -- sh -lc {}", shell_quote(script));
    run_remote_script(state, target, &elevated, Some(password))
}

/// Runs a Wi-Fi operation after pinning only the active SSH client's return route to Ethernet.
/// No default route or DNS setting is changed, so ordinary internet traffic may use Wi-Fi.
pub fn remote_wifi_command_sudo(
    state: &AppState,
    target: &Target,
    script: &str,
    password: &str,
) -> Result<String, String> {
    validate_sudo_password(password)?;
    let guarded = wifi_route_guarded_command(script, false);
    run_remote_script(state, target, &guarded, Some(password))
}

/// Builds an interactive remote command for Wi-Fi connect, where sudo and nmcli may both prompt.
pub fn wifi_route_guarded_command(script: &str, interactive: bool) -> String {
    let sudo = if interactive {
        "sudo -p '[sudo] password for %u: ' --"
    } else {
        "sudo -S -p '' --"
    };
    let privileged = "set -eu; client=$1; server=$2; dev=$3; via=$4; family=$5; prefix=$6; needs_route=$7; shift 7; if [ \"$needs_route\" = 1 ]; then if [ -n \"$via\" ]; then ip \"$family\" route add \"$client/$prefix\" via \"$via\" dev \"$dev\" src \"$server\"; else ip \"$family\" route add \"$client/$prefix\" dev \"$dev\" src \"$server\"; fi; fi; exec sh -lc \"$1\"";
    format!(
        r#"set -eu
if [ -z "${{SSH_CONNECTION:-}}" ]; then echo '无法读取当前 SSH 连接信息；为保护有线管理连接，已取消 Wi-Fi 操作。' >&2; exit 1; fi
set -f
set -- $SSH_CONNECTION
if [ "$#" -lt 4 ]; then echo 'SSH 连接信息无效；为保护有线管理连接，已取消 Wi-Fi 操作。' >&2; exit 1; fi
client=$1
server=$3
case "$client" in *:*) family=-6; prefix=128;; *) family=-4; prefix=32;; esac
route=$(ip "$family" route get "$client" from "$server" 2>/dev/null || true)
route_field() {{ printf '%s\n' "$route" | awk -v key="$1" '{{ for (i = 1; i < NF; i++) if ($i == key) {{ print $(i + 1); exit }} }}'; }}
dev=$(route_field dev)
via=$(route_field via)
src=$(route_field src)
type=$(cat "/sys/class/net/$dev/type" 2>/dev/null || true)
if [ -z "$dev" ] || [ "$src" != "$server" ] || [ "$type" != 1 ] || [ -e "/sys/class/net/$dev/wireless" ]; then echo '无法确认当前 SSH 回程经过有线网卡；为避免断开管理连接，已取消 Wi-Fi 操作。请先通过有线 SSH 连接机器人。' >&2; exit 1; fi
exact=$(ip "$family" route show exact "$client/$prefix" 2>/dev/null || true)
needs_route=1
if [ -n "$exact" ]; then
  exact_dev=$(printf '%s\n' "$exact" | awk '{{ for (i = 1; i < NF; i++) if ($i == "dev") {{ print $(i + 1); exit }} }}')
  exact_via=$(printf '%s\n' "$exact" | awk '{{ for (i = 1; i < NF; i++) if ($i == "via") {{ print $(i + 1); exit }} }}')
  if [ "$exact_dev" != "$dev" ] || [ "$exact_via" != "$via" ]; then echo '目标主机已有不同的静态路由；为避免覆盖用户网络设置，已取消 Wi-Fi 操作。' >&2; exit 1; fi
  needs_route=0
fi
{sudo} sh -c {privileged} sh "$client" "$server" "$dev" "$via" "$family" "$prefix" "$needs_route" {script}"#,
        sudo = sudo,
        privileged = shell_quote(privileged),
        script = shell_quote(script),
    )
}

fn run_remote_script(
    state: &AppState,
    target: &Target,
    script: &str,
    password: Option<&str>,
) -> Result<String, String> {
    ensure_pinned(state, target)?;
    if script.len() > 24_000 || script.contains('\0') {
        return Err("远端命令长度无效".into());
    }
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_args(state, target, false, true));
    cmd.arg(ssh_destination(target));
    cmd.arg(format!("timeout 18s sh -lc {}", shell_quote(script)));
    if password.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("无法运行 OpenSSH：{e}"))?;
    if let Some(password) = password {
        let mut bytes = password.as_bytes().to_vec();
        bytes.push(b'\n');
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| "无法安全传入机器人 sudo 认证".to_string())?
            .write_all(&bytes);
        bytes.fill(0);
        if write_result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("无法安全传入机器人 sudo 认证；操作未执行".into());
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("等待 OpenSSH 命令结束失败：{e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        let stderr = safe_stderr(&output.stderr);
        let detail = if stderr.is_empty() {
            stdout.trim().to_string()
        } else {
            stderr
        };
        if password.is_some() {
            let lower = detail.to_ascii_lowercase();
            if [
                "sorry, try again",
                "incorrect password",
                "a password is required",
                "not in the sudoers",
                "not allowed to execute",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                return Err(
                    "机器人 sudo 认证失败：密码不正确，或当前 SSH 用户没有 sudo 权限。操作未完成。"
                        .into(),
                );
            }
        }
        return Err(if detail.is_empty() {
            format!("SSH 命令失败，退出码 {:?}", output.status.code())
        } else {
            detail
        });
    }
    Ok(stdout)
}

pub fn start_terminal(
    app: &AppHandle,
    state: &AppState,
    target: &Target,
    initial_command: Option<&str>,
) -> Result<String, String> {
    ensure_pinned(state, target)?;
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 28,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("无法建立终端：{e}"))?;
    let mut command = CommandBuilder::new("ssh");
    command.args(ssh_args(state, target, true, false));
    command.arg(ssh_destination(target));
    if let Some(remote) = initial_command {
        command.arg(remote);
    }
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| format!("启动 SSH 失败：{e}；请确认已安装 openssh-client"))?;
    drop(pair.slave);
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("读取终端失败：{e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("打开终端输入失败：{e}"))?;
    let master = pair.master;
    let session_id = Uuid::new_v4().to_string();
    let session = TerminalSession {
        writer,
        master,
        child,
    };
    state
        .sessions
        .lock()
        .map_err(|_| "终端状态锁不可用".to_string())?
        .insert(session_id.clone(), session);
    let app_handle = app.clone();
    let id = session_id.clone();
    thread::spawn(move || read_terminal(app_handle, id, reader));
    Ok(session_id)
}

fn read_terminal(app: AppHandle, session_id: String, mut reader: Box<dyn Read + Send>) {
    let mut buffer = [0_u8; 4096];
    let mut carry = Vec::new();
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                carry.extend_from_slice(&buffer[..n]);
                match std::str::from_utf8(&carry) {
                    Ok(text) => {
                        if !text.is_empty() {
                            let _ = app.emit(
                                "terminal-output",
                                TerminalEvent {
                                    session_id: session_id.clone(),
                                    data: text.to_string(),
                                },
                            );
                        }
                        carry.clear();
                    }
                    Err(error) => {
                        let valid = error.valid_up_to();
                        if valid > 0 {
                            let text = String::from_utf8_lossy(&carry[..valid]).to_string();
                            let _ = app.emit(
                                "terminal-output",
                                TerminalEvent {
                                    session_id: session_id.clone(),
                                    data: text,
                                },
                            );
                            carry.drain(..valid);
                        }
                        if error.error_len().is_some() {
                            let text = String::from_utf8_lossy(&carry).to_string();
                            if !text.is_empty() {
                                let _ = app.emit(
                                    "terminal-output",
                                    TerminalEvent {
                                        session_id: session_id.clone(),
                                        data: text,
                                    },
                                );
                            }
                            carry.clear();
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
    if !carry.is_empty() {
        let _ = app.emit(
            "terminal-output",
            TerminalEvent {
                session_id: session_id.clone(),
                data: String::from_utf8_lossy(&carry).to_string(),
            },
        );
    }
    let _ = app.emit(
        "terminal-exit",
        TerminalEvent {
            session_id: session_id.clone(),
            data: "\r\n[SSH 会话已结束]\r\n".into(),
        },
    );
    let app_state = app.state::<AppState>();
    let session = app_state
        .sessions
        .lock()
        .ok()
        .and_then(|mut sessions| sessions.remove(&session_id));
    if let Some(mut session) = session {
        let _ = session.child.wait();
    }
}

pub fn send_terminal_input(state: &AppState, session_id: &str, data: &str) -> Result<(), String> {
    if data.len() > 16_384 {
        return Err("单次终端输入不能超过 16 KB".into());
    }
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "终端状态锁不可用".to_string())?;
    let session = sessions
        .get_mut(session_id)
        .ok_or("终端会话不存在或已结束")?;
    session
        .writer
        .write_all(data.as_bytes())
        .map_err(|e| format!("发送终端输入失败：{e}"))?;
    session
        .writer
        .flush()
        .map_err(|e| format!("刷新终端输入失败：{e}"))
}

pub fn resize_terminal(
    state: &AppState,
    session_id: &str,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    if !(40..=240).contains(&cols) || !(10..=100).contains(&rows) {
        return Err("终端尺寸超出允许范围".into());
    }
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| "终端状态锁不可用".to_string())?;
    let session = sessions.get(session_id).ok_or("终端会话不存在或已结束")?;
    session
        .master
        .resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("调整终端尺寸失败：{e}"))
}

pub fn close_terminal(state: &AppState, session_id: &str) -> Result<(), String> {
    let session = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "终端状态锁不可用".to_string())?;
        sessions.remove(session_id)
    };
    if let Some(mut session) = session {
        let _ = session.writer.write_all(b"\x04");
        let _ = session.child.kill();
        let _ = session.child.wait();
    }
    Ok(())
}

/// ssh-keyscan prints nothing on timeout; explain the most likely reason instead of an empty error.
fn unreachable_hint(host: &str, port: u16) -> String {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return format!("{host}:{port} 在 5 秒内没有响应。请检查网线、目标 IP、SSH 服务及端口。");
    };
    let route = Command::new("ip")
        .args(["-4", "route", "get", &ip.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    unreachable_hint_from_route(ip, port, &route, |dev| {
        std::path::Path::new("/sys/class/net")
            .join(dev)
            .join("wireless")
            .exists()
    })
}

fn unreachable_hint_from_route(
    ip: std::net::Ipv4Addr,
    port: u16,
    route: &str,
    is_wireless: impl Fn(&str) -> bool,
) -> String {
    let words = route.split_whitespace().collect::<Vec<_>>();
    let value = |key: &str| {
        words
            .windows(2)
            .find(|w| w[0] == key)
            .map(|w| w[1].to_string())
    };
    let dev = value("dev").unwrap_or_default();
    let fix = "请到“网络与 Wi-Fi”页重新扫描，在该候选上点“临时配置本机 IPv4”（例如 192.168.127.10 对应本机 192.168.127.1/24），再核验连接。";
    if words.is_empty() {
        return format!("本机没有去往 {ip} 的路由，开发机网口与开发板不在同一网段。{fix}");
    }
    if let Some(gateway) = value("via") {
        return format!("去往 {ip} 的流量会经网关 {gateway}（{dev}）发出，而不是走直连网线：开发机网口与开发板不在同一网段。{fix}");
    }
    if !dev.is_empty() && is_wireless(&dev) {
        return format!("去往 {ip} 的流量会走无线网卡 {dev}，而不是直连网线。{fix}");
    }
    format!("{ip}:{port} 经 {dev} 在 5 秒内没有响应。请确认开发板 SSH 服务已启动、端口 {port} 正确，且防火墙未拦截。")
}

fn safe_stderr(input: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(input).trim().to_string();
    s = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(1200)
        .collect();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shell_quotes_arbitrary_network_names() {
        assert_eq!(shell_quote("Lab's WiFi"), "'Lab'\\''s WiFi'");
        assert_eq!(shell_quote("$(touch /tmp/x)"), "'$(touch /tmp/x)'");
    }

    #[test]
    fn sudo_password_is_ephemeral_input_and_rejects_line_breaks() {
        assert!(validate_sudo_password("").is_ok());
        assert!(validate_sudo_password("safe password").is_ok());
        assert!(validate_sudo_password("first\nsecond").is_err());
        assert!(validate_sudo_password("first\rsecond").is_err());
        assert!(validate_sudo_password("nul\0byte").is_err());
        assert!(validate_sudo_password(&"x".repeat(1025)).is_err());
    }

    #[test]
    fn wifi_route_guard_adds_only_ssh_host_route_and_preserves_existing_routes() {
        let command = wifi_route_guarded_command("nmcli radio wifi on", false);
        assert!(command.contains("SSH_CONNECTION"));
        assert!(command.contains("ip \"$family\" route add \"$client/$prefix\""));
        assert!(command.contains("route show exact \"$client/$prefix\""));
        assert!(command.contains("已有不同的静态路由"));
        assert!(command.contains("sudo -S -p '' --"));
        assert!(command.contains("nmcli radio wifi on"));
        assert!(!command.contains("route add default"));
        assert!(!command.contains("route replace default"));
    }

    #[test]
    fn interactive_wifi_route_command_keeps_sudo_and_nmcli_prompts_on_pty() {
        let command =
            wifi_route_guarded_command("nmcli --ask device wifi connect 'Lab WiFi'", true);
        assert!(command.contains("sudo -p '[sudo] password for %u: ' --"));
        assert!(command.contains("nmcli --ask device wifi connect"));
        assert!(command.contains("Lab WiFi"));
    }

    #[test]
    fn wifi_route_guarded_commands_are_valid_posix_shell() {
        for interactive in [false, true] {
            let command = wifi_route_guarded_command("nmcli radio wifi on", interactive);
            let checked = std::process::Command::new("sh")
                .args(["-n", "-c", &command])
                .output()
                .expect("POSIX shell should be available for tests");
            assert!(
                checked.status.success(),
                "generated shell syntax is invalid: {}",
                String::from_utf8_lossy(&checked.stderr)
            );
        }
    }

    #[test]
    fn unreachable_hint_explains_missing_direct_route() {
        let ip = "192.168.127.10".parse().unwrap();
        let via = unreachable_hint_from_route(
            ip,
            22,
            "192.168.127.10 via 10.0.0.1 dev wlp2s0 src 10.0.0.5 uid 1000",
            |_| true,
        );
        assert!(via.contains("网关 10.0.0.1") && via.contains("临时配置本机 IPv4"));
        let wifi = unreachable_hint_from_route(
            ip,
            22,
            "192.168.127.10 dev wlp2s0 src 192.168.127.5",
            |d| d == "wlp2s0",
        );
        assert!(wifi.contains("无线网卡 wlp2s0"));
        let wired = unreachable_hint_from_route(
            ip,
            2222,
            "192.168.127.10 dev enp3s0 src 192.168.127.1",
            |_| false,
        );
        assert!(wired.contains("端口 2222") && wired.contains("enp3s0"));
        assert!(unreachable_hint_from_route(ip, 22, "", |_| false).contains("没有去往"));
    }

    #[test]
    fn host_key_algorithm_is_pinned_and_rsa_uses_sha2_only() {
        assert_eq!(host_key_algorithms("ssh-ed25519"), Some("ssh-ed25519"));
        assert_eq!(
            host_key_algorithms("ecdsa-sha2-nistp256"),
            Some("ecdsa-sha2-nistp256")
        );
        assert_eq!(
            host_key_algorithms("ssh-rsa"),
            Some("rsa-sha2-512,rsa-sha2-256")
        );
        assert_eq!(host_key_algorithms("ssh-dss"), None);
        assert_eq!(host_key_algorithms("unexpected-algorithm"), None);
    }
}
