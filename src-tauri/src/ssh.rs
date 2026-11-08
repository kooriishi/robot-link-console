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

/// Prefix on errors that look like a permission problem the user can solve by entering the robot's
/// sudo password; the UI strips it and opens the sudo dialog.
pub const SUDO_MARK: &str = "[需要sudo] ";

#[derive(Default)]
pub struct RemoteOptions<'a> {
    /// Run the script with `sudo -S`; the password is written to ssh's stdin, never to argv or disk.
    pub sudo_password: Option<&'a str>,
    /// One more line for the script's own stdin, sent as `SECRET:<value>`. Scripts must look for
    /// that prefix: with a NOPASSWD sudo rule the sudo password line is not consumed by sudo.
    pub stdin_line: Option<&'a str>,
    /// Remote time limit in seconds (default 18).
    pub timeout_secs: Option<u64>,
}

pub fn looks_like_permission_error(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "not authorized",
        "notauthorized",
        "access denied",
        "accessdenied",
        "interactive authentication required",
        "insufficient privileges",
        "permission denied",
        "operation not permitted",
        "must be root",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub fn remote_command(state: &AppState, target: &Target, script: &str) -> Result<String, String> {
    remote_command_with(state, target, script, RemoteOptions::default())
}

pub fn remote_command_with(
    state: &AppState,
    target: &Target,
    script: &str,
    options: RemoteOptions,
) -> Result<String, String> {
    ensure_pinned(state, target)?;
    if script.len() > 24_000 || script.contains('\0') {
        return Err("远端命令长度无效".into());
    }
    let secrets_ok =
        |v: Option<&str>| v.is_none_or(|v| v.len() <= 512 && !v.contains(['\n', '\r', '\0']));
    if !secrets_ok(options.sudo_password) || !secrets_ok(options.stdin_line) {
        return Err("密码不能包含换行，且长度不超过 512".into());
    }
    let seconds = options.timeout_secs.unwrap_or(18).clamp(5, 120);
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_args(state, target, false, true));
    cmd.arg(ssh_destination(target));
    let mut input = String::new();
    if let Some(password) = options.sudo_password {
        cmd.arg(format!(
            "timeout {seconds}s sudo -S -k -p '' sh -c {}",
            shell_quote(script)
        ));
        input.push_str(password);
        input.push('\n');
    } else {
        cmd.arg(format!("timeout {seconds}s sh -lc {}", shell_quote(script)));
    }
    if let Some(line) = options.stdin_line {
        input.push_str("SECRET:");
        input.push_str(line);
        input.push('\n');
    }
    let deadline = std::time::Duration::from_secs(seconds + 7);
    let output = output_with_timeout(cmd, deadline, input.as_bytes())?;
    if options.sudo_password.is_some() && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("incorrect password") || stderr.contains("Sorry, try again") {
            return Err(format!("{SUDO_MARK}sudo 密码不正确，请重新输入。"));
        }
        if stderr.contains("not in the sudoers") || stderr.contains("not allowed to run sudo") {
            return Err(format!(
                "机器人用户 {} 没有 sudo 权限，无法提权执行。",
                target.username
            ));
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        let stderr = safe_stderr(&output.stderr);
        if output.status.code() == Some(255) && stderr.contains("Permission denied") {
            return Err("SSH 登录会话已结束（后台命令不会再次询问密码）。请到“终端”页点击连接并完成登录后再试。".into());
        }
        let detail = if stderr.is_empty() {
            stdout.trim().to_string()
        } else {
            stderr
        };
        if options.sudo_password.is_none() && looks_like_permission_error(&detail) {
            return Err(format!("{SUDO_MARK}{detail}"));
        }
        return Err(if detail.is_empty() {
            format!("SSH 命令失败，退出码 {:?}", output.status.code())
        } else {
            detail
        });
    }
    Ok(stdout)
}

// The remote side is limited by `timeout`, but a half-dead link (cable pulled, address gone) can keep
// the local ssh client waiting for ServerAlive to give up (~45 s), so remote_command_with also bounds
// it locally (remote limit + 7 s).

fn output_with_timeout(
    mut cmd: Command,
    deadline: std::time::Duration,
    input: &[u8],
) -> Result<std::process::Output, String> {
    let mut child = cmd
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("无法运行 OpenSSH：{e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let data = input.to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let mut stdout = child.stdout.take().ok_or("无法读取 OpenSSH 输出")?;
    let mut stderr = child.stderr.take().ok_or("无法读取 OpenSSH 输出")?;
    let out_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "机器人在 {} 秒内没有响应，SSH 链路可能已经断开。请检查网线，或到“终端”页重新连接。",
                deadline.as_secs()
            ));
        }
        thread::sleep(std::time::Duration::from_millis(50));
    };
    Ok(std::process::Output {
        status,
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
    })
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
    let neighbor = Command::new("ip")
        .args(["-4", "neigh", "show", &ip.to_string()])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let hint = unreachable_hint_from_route(ip, port, &route, |dev| {
        std::path::Path::new("/sys/class/net")
            .join(dev)
            .join("wireless")
            .exists()
    });
    match neighbor_hint(ip, &route, &neighbor) {
        Some(extra) => extra,
        None => hint,
    }
}

/// When the route is fine but the board never answered ARP, the board is not at that address
/// any more (rebooted with another IP, DHCP lease gone) rather than SSH being blocked.
fn neighbor_hint(ip: std::net::Ipv4Addr, route: &str, neighbor: &str) -> Option<String> {
    let words = route.split_whitespace().collect::<Vec<_>>();
    if words.is_empty() || words.contains(&"via") {
        return None;
    }
    let state = neighbor.split_whitespace().last().unwrap_or("");
    if state != "FAILED" && state != "INCOMPLETE" {
        return None;
    }
    let dev = words
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1])
        .unwrap_or("直连网卡");
    Some(format!("{ip} 经 {dev} 没有任何 ARP 应答：网线另一端现在没有这个地址。开发板可能重启后换了 IP（例如 DHCP 租约到期、直连 DHCP 已停止），或网线 / USB 网卡链路断开。请到“网络与 Wi‑Fi”页重新扫描，用扫描到的新地址连接。"))
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
    fn missing_arp_reply_is_reported_as_address_gone() {
        let ip = "192.168.77.126".parse().unwrap();
        let route = "192.168.77.126 dev enx00e04c3071f5 src 192.168.77.1 uid 1000";
        let gone = neighbor_hint(ip, route, "192.168.77.126 dev enx00e04c3071f5 FAILED").unwrap();
        assert!(gone.contains("没有任何 ARP 应答") && gone.contains("enx00e04c3071f5"));
        assert!(neighbor_hint(
            ip,
            route,
            "192.168.77.126 dev enx00e04c3071f5 lladdr 00:11:22:33:44:55 REACHABLE"
        )
        .is_none());
        assert!(neighbor_hint(ip, "192.168.77.126 via 10.0.0.1 dev wlp2s0", "x FAILED").is_none());
    }

    #[test]
    fn sudo_errors_are_detected() {
        assert!(looks_like_permission_error(
            "Error: org.freedesktop.NetworkManager.wifi.scan request failed: not authorized."
        ));
        assert!(looks_like_permission_error(
            "Failed to start bluetooth.service: Interactive authentication required."
        ));
        assert!(!looks_like_permission_error(
            "Error: No network with SSID 'x' found."
        ));
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
