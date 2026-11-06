use crate::model::*;
use crate::ssh;
use crate::state::AppState;
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, State};
use uuid::Uuid;

#[tauri::command]
pub fn get_host_info() -> Result<HostInfo, String> {
    let hostname = command_text("hostname", &[]).unwrap_or_else(|_| "Linux 开发机".into());
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let os = os_release
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .unwrap_or("Linux")
        .trim_matches('"')
        .to_string();
    let output = Command::new("ip")
        .args(["-json", "-4", "address", "show"])
        .output()
        .map_err(|e| format!("无法读取本机网卡：{e}；请安装 iproute2"))?;
    if !output.status.success() {
        return Err("iproute2 返回错误，无法读取本机网卡".into());
    }
    let rows: Vec<Value> =
        serde_json::from_slice(&output.stdout).map_err(|e| format!("解析本机网卡失败：{e}"))?;
    let mut interfaces = Vec::new();
    for row in rows {
        let Some(name) = row.get("ifname").and_then(Value::as_str) else {
            continue;
        };
        if name == "lo" {
            continue;
        }
        let sys = std::path::Path::new("/sys/class/net").join(name);
        let is_ethernet = fs::read_to_string(sys.join("type"))
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            == Some(1);
        let is_physical = sys.join("device").exists();
        let is_wireless = sys.join("wireless").exists();
        let kind = if is_ethernet && is_physical && !is_wireless {
            "有线以太网"
        } else if is_wireless {
            "Wi-Fi"
        } else {
            "其他"
        };
        let ipv4 = row
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|a| a.get("family").and_then(Value::as_str) == Some("inet"))
            .filter_map(|a| {
                Some(format!(
                    "{}/{}",
                    a.get("local")?.as_str()?,
                    a.get("prefixlen")?.as_u64()?
                ))
            })
            .collect();
        let carrier = fs::read_to_string(sys.join("carrier"))
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        let state = row
            .get("operstate")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        interfaces.push(HostInterface {
            name: name.to_string(),
            kind: kind.to_string(),
            mac: row
                .get("address")
                .and_then(Value::as_str)
                .map(str::to_string),
            ipv4,
            carrier,
            state,
            mtu: row.get("mtu").and_then(Value::as_u64),
        });
    }
    Ok(HostInfo {
        hostname: hostname.trim().to_string(),
        os,
        interfaces,
    })
}

fn command_text(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[tauri::command]
pub fn list_targets(state: State<'_, AppState>) -> Result<Vec<Target>, String> {
    state.load_targets()
}

#[tauri::command]
pub fn save_target(state: State<'_, AppState>, draft: TargetDraft) -> Result<Target, String> {
    let name = draft.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err("设备名称不能为空、不能超过 80 字或包含控制字符".into());
    }
    if draft.port == 0 {
        return Err("SSH 端口必须在 1–65535 之间".into());
    }
    let host = validate_host(&draft.host)?;
    let username = validate_username(&draft.username)?;
    let id = draft
        .id
        .filter(|id| Uuid::parse_str(id).is_ok())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let target = Target {
        id,
        name: name.into(),
        host,
        port: draft.port,
        username,
    };
    let mut targets = state.load_targets()?;
    if let Some(existing) = targets.iter_mut().find(|t| t.id == target.id) {
        *existing = target.clone();
    } else {
        if targets.iter().any(|t| {
            t.host == target.host && t.port == target.port && t.username == target.username
        }) {
            return Err("该 SSH 目标已存在，请从设备列表中编辑或选择它".into());
        }
        targets.push(target.clone());
    }
    state.save_targets(&targets)?;
    Ok(target)
}

#[tauri::command]
pub fn delete_target(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut targets = state.load_targets()?;
    let target = targets
        .iter()
        .find(|t| t.id == id)
        .cloned()
        .ok_or("找不到所选机器人")?;
    targets.retain(|t| t.id != id);
    state.save_targets(&targets)?;
    let _ = ssh::forget_host_key(&state, &target);
    Ok(())
}

#[tauri::command]
pub fn get_host_key_status(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<HostKeyStatus, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::host_key_status(&state, &target)
}

#[tauri::command]
pub fn trust_host_key(
    state: State<'_, AppState>,
    target_id: String,
    fingerprint: String,
) -> Result<bool, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::trust_host_key(&state, &target, &fingerprint)?;
    Ok(true)
}

#[tauri::command]
pub fn forget_host_key(state: State<'_, AppState>, target_id: String) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::forget_host_key(&state, &target)
}

#[tauri::command]
pub fn ssh_connection_ready(state: State<'_, AppState>, target_id: String) -> Result<bool, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::connection_ready(&state, &target)
}

#[tauri::command]
pub fn scan_direct_interface(interface: String) -> Result<Vec<DiscoveredHost>, String> {
    validate_ifname(&interface)?;
    let host_info = get_host_info()?;
    let iface = host_info
        .interfaces
        .iter()
        .find(|i| i.name == interface && i.kind == "有线以太网")
        .ok_or("请选择一张本机物理有线网卡")?;
    if !iface.carrier {
        return Err(format!(
            "{} 当前没有检测到物理链路，请检查直连网线和机器人电源",
            iface.name
        ));
    }
    let mut found = HashSet::new();
    let mut subnet = None;
    let mut link_local = None;
    for cidr in &iface.ipv4 {
        let (ip_text, prefix_text) = cidr.split_once('/').ok_or("网卡地址格式异常")?;
        let ip: Ipv4Addr = ip_text.parse().map_err(|_| "直连网卡不是 IPv4 地址")?;
        let bits: u32 = prefix_text.parse().map_err(|_| "直连网卡前缀长度异常")?;
        if (24..=30).contains(&bits) {
            subnet = Some((ip, bits));
            break;
        }
        let octets = ip.octets();
        if bits == 16 && octets[0] == 169 && octets[1] == 254 {
            link_local = Some(ip);
        }
    }
    let (local, candidates, link_local_mode) = if let Some((local, bits)) = subnet {
        let mask = u32::MAX << (32 - bits);
        let network = u32::from(local) & mask;
        let broadcast = network | !mask;
        let peers = ((network + 1)..broadcast)
            .map(Ipv4Addr::from)
            .filter(|ip| *ip != local)
            .collect::<Vec<_>>();
        (local, peers, false)
    } else if let Some(local) = link_local {
        let output = Command::new("ip")
            .args(["-json", "neigh", "show", "dev", &interface])
            .output()
            .map_err(|e| format!("读取直连接口邻居缓存失败：{e}"))?;
        if !output.status.success() {
            return Err("读取 Linux 邻居缓存失败；请检查 iproute2 安装。".into());
        }
        let rows: Vec<Value> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("解析链路本地邻居缓存失败：{e}"))?;
        let peers = link_local_neighbors(&rows, &interface, local);
        if peers.is_empty() {
            return Err("开发机与网线已建立链路本地地址，但 Linux 邻居缓存中还没有机器人地址。若机器人支持 IPv4 link-local/mDNS，请输入已知的 169.254.x.x 或 robot.local；否则需先按机器人固件说明配置静态 IP 和 SSH 服务。".into());
        }
        (local, peers, true)
    } else {
        return Err("网线已连接，但开发机这张网卡没有可扫描的 IPv4 地址。无 Internet 仍可直连 SSH，但开发机与机器人必须有同网段 IP，且机器人已启用 SSH；请按机器人固件说明设置临时静态地址。本程序不会擅自修改网络。".into());
    };
    if candidates.len() > 1024 {
        return Err("直连候选地址超过 1024 个，已停止扫描".into());
    }
    if candidates.is_empty() {
        return Err("直连网段没有可扫描的机器人地址".into());
    }
    let probe = candidates.first().ok_or("直连网段没有可扫描的主机地址")?;
    let route = Command::new("ip")
        .args([
            "-4",
            "route",
            "get",
            &probe.to_string(),
            "from",
            &local.to_string(),
        ])
        .output()
        .map_err(|e| format!("无法验证扫描路由：{e}"))?;
    let route_text = String::from_utf8_lossy(&route.stdout);
    if !route.status.success()
        || !route_text
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w[0] == "dev" && w[1] == interface)
    {
        return Err(
            "内核路由没有通过你选定的网卡；为避免扫描其他网络，已停止。请检查重复子网或接口配置。"
                .into(),
        );
    }
    let queue = Arc::new(Mutex::new(VecDeque::from(candidates)));
    let (tx, rx) = mpsc::channel();
    let workers = 16.min(queue.lock().map_err(|_| "扫描状态不可用")?.len().max(1));
    for _ in 0..workers {
        let q = Arc::clone(&queue);
        let tx = tx.clone();
        thread::spawn(move || loop {
            let next = q.lock().ok().and_then(|mut q| q.pop_front());
            let Some(ip) = next else { break };
            let remote = SockAddr::from(SocketAddrV4::new(ip, 22));
            let source = SockAddr::from(SocketAddrV4::new(local, 0));
            let reachable = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
                .and_then(|socket| {
                    socket.bind(&source)?;
                    socket.connect_timeout(&remote, Duration::from_millis(160))
                })
                .is_ok();
            if reachable {
                let _ = tx.send(ip);
            }
        });
    }
    drop(tx);
    for ip in rx {
        found.insert(ip.to_string());
    }
    let source = if link_local_mode {
        "选定直连接口已知链路本地邻居的 TCP/22 探测"
    } else {
        "选定直连接口的 TCP/22 探测"
    };
    let mut result: Vec<_> = found
        .into_iter()
        .map(|address| DiscoveredHost {
            address,
            interface: interface.clone(),
            port: 22,
            source: source.into(),
        })
        .collect();
    result.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(result)
}

fn link_local_neighbors(rows: &[Value], interface: &str, local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let unusable_state = |state: &str| matches!(state, "FAILED" | "INCOMPLETE" | "NONE");
    let mut peers = rows
        .iter()
        .filter_map(|row| {
            if row.get("dev").and_then(Value::as_str) != Some(interface) {
                return None;
            }
            let unusable = match row.get("state") {
                Some(Value::String(state)) => unusable_state(state),
                Some(Value::Array(states)) => {
                    states.iter().filter_map(Value::as_str).any(unusable_state)
                }
                _ => false,
            };
            if unusable {
                return None;
            }
            let ip = row
                .get("dst")
                .and_then(Value::as_str)?
                .parse::<Ipv4Addr>()
                .ok()?;
            let octets = ip.octets();
            (ip != local && octets[0] == 169 && octets[1] == 254).then_some(ip)
        })
        .collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    peers
}

#[tauri::command]
pub fn get_remote_overview(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<RemoteOverview, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = r#"printf 'HOST='; hostname; printf '\nUPTIME='; uptime -p 2>/dev/null || uptime; printf '\nLOAD='; awk '{print $1","$2","$3}' /proc/loadavg; printf '\nMEM='; awk '/MemTotal|MemAvailable/ {if ($1=="MemTotal:") t=$2; if ($1=="MemAvailable:") a=$2} END {printf "%s,%s\n",t,a}' /proc/meminfo; printf 'TEMP='; for f in /sys/class/thermal/thermal_zone*/temp; do if [ -r "$f" ]; then awk '{printf "%.1f\n",$1/1000; exit}' "$f"; break; fi; done"#;
    let output = ssh::remote_command(&state, &target, script)?;
    let mut map = HashMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k, v.trim());
        }
    }
    let mem = map
        .get("MEM")
        .copied()
        .unwrap_or("")
        .split(',')
        .collect::<Vec<_>>();
    Ok(RemoteOverview {
        hostname: map.get("HOST").copied().unwrap_or(&target.name).to_string(),
        uptime: map.get("UPTIME").copied().unwrap_or("未知").to_string(),
        load: map.get("LOAD").copied().unwrap_or("未知").to_string(),
        memory_total_kb: mem.first().and_then(|s| s.parse().ok()),
        memory_available_kb: mem.get(1).and_then(|s| s.parse().ok()),
        temperature_c: map.get("TEMP").and_then(|s| s.parse().ok()),
    })
}

#[tauri::command]
pub fn list_services(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<Vec<ServiceInfo>, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = "systemctl list-units --type=service --all --no-legend --no-pager --plain --no-ask-password; printf '\\0'; systemctl list-unit-files --type=service --no-legend --no-pager --no-ask-password";
    let output = ssh::remote_command(&state, &target, script)?;
    let (units, files) = output.split_once('\0').unwrap_or((&output, ""));
    let mut enabled = HashMap::new();
    for line in files.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 2 {
            enabled.insert(fields[0].to_string(), fields[1].to_string());
        }
    }
    let mut services = Vec::new();
    for line in units.lines().filter(|l| !l.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let name = fields[0];
        if !name.ends_with(".service") {
            continue;
        }
        services.push(ServiceInfo {
            name: name.into(),
            description: if fields.len() > 4 {
                fields[4..].join(" ")
            } else {
                name.into()
            },
            active: fields[2].into(),
            sub_state: fields[3].into(),
            enabled: enabled.get(name).cloned().unwrap_or_else(|| "未知".into()),
        });
    }
    services.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(services)
}

#[tauri::command]
pub fn service_action(
    state: State<'_, AppState>,
    target_id: String,
    service: String,
    action: String,
) -> Result<String, String> {
    validate_service_name(&service)?;
    if !["start", "stop", "restart"].contains(&action.as_str()) {
        return Err("不支持的服务操作".into());
    }
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = format!("systemctl --no-ask-password {} {}", action, service);
    ssh::remote_command(&state, &target, &script)?;
    Ok(format!("{service} 已执行 {action}；请刷新状态确认结果"))
}

fn parse_nmcli(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                current.push(n);
            }
        } else if c == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    fields.push(current);
    fields
}

fn wifi_rows(lines: &str) -> Vec<WifiNetwork> {
    lines
        .lines()
        .filter_map(|line| {
            let f = parse_nmcli(line);
            if f.len() < 4 || f[1].is_empty() {
                return None;
            }
            Some(WifiNetwork {
                in_use: f[0] == "*",
                ssid: f[1].clone(),
                signal: f[2].parse().unwrap_or(0),
                security: f[3].clone(),
            })
        })
        .collect()
}

#[tauri::command]
pub fn get_remote_network(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<RemoteNetwork, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = "if ! command -v nmcli >/dev/null 2>&1; then printf 'UNSUPPORTED\\n'; exit 0; fi; printf 'RADIO='; nmcli -t radio wifi 2>/dev/null || true; printf '\\nDEVICES\\n'; nmcli --terse --escape yes --fields DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null || true; printf '\\nAPS\\n'; nmcli --terse --escape yes --fields IN-USE,SSID,SIGNAL,SECURITY device wifi list 2>/dev/null || true";
    let output = ssh::remote_command(&state, &target, script)?;
    if output.contains("UNSUPPORTED") {
        return Ok(RemoteNetwork {
            supported: false,
            wifi_enabled: false,
            devices: vec![],
            wifi_networks: vec![],
            note: Some("机器人未安装 NetworkManager/nmcli；没有自动改动网络。".into()),
        });
    }
    let radio = output
        .lines()
        .find_map(|l| l.strip_prefix("RADIO="))
        .unwrap_or("");
    let devices_part = output
        .split_once("DEVICES\n")
        .map(|(_, r)| r.split_once("\nAPS\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("");
    let aps_part = output.split_once("\nAPS\n").map(|(_, r)| r).unwrap_or("");
    let devices = devices_part
        .lines()
        .filter_map(|line| {
            let f = parse_nmcli(line);
            if f.len() < 4 {
                return None;
            }
            Some(NetworkDevice {
                device: f[0].clone(),
                kind: f[1].clone(),
                state: f[2].clone(),
                connection: f[3].clone(),
            })
        })
        .collect();
    Ok(RemoteNetwork {
        supported: true,
        wifi_enabled: radio == "enabled",
        devices,
        wifi_networks: wifi_rows(aps_part),
        note: None,
    })
}

#[tauri::command]
pub fn scan_remote_wifi(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<Vec<WifiNetwork>, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = "command -v nmcli >/dev/null 2>&1 || { echo '缺少 nmcli'; exit 127; }; nmcli --terse --escape yes --fields IN-USE,SSID,SIGNAL,SECURITY device wifi list --rescan yes";
    let output = ssh::remote_command(&state, &target, script)?;
    Ok(wifi_rows(&output))
}

#[tauri::command]
pub fn set_remote_wifi_radio(
    state: State<'_, AppState>,
    target_id: String,
    enabled: bool,
) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let on_off = if enabled { "on" } else { "off" };
    ssh::remote_command(&state, &target, &format!("nmcli radio wifi {on_off}"))?;
    Ok(())
}

#[tauri::command]
pub fn start_wifi_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    ssid: String,
) -> Result<String, String> {
    validate_wifi_ssid(&ssid)?;
    let target = ssh::lookup_target(&state, &target_id)?;
    let command = format!(
        "nmcli --ask device wifi connect {}",
        ssh::shell_quote(&ssid)
    );
    ssh::start_terminal(&app, &state, &target, Some(&command))
}

fn parse_bt_devices(
    all: &str,
    paired: &str,
    state: &AppState,
    target: &Target,
) -> Result<Vec<BluetoothDevice>, String> {
    let mut names = HashMap::new();
    for line in all.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[0] == "Device" && validate_mac(fields[1]).is_ok() {
            names.insert(fields[1].to_ascii_uppercase(), fields[2..].join(" "));
        }
    }
    let paired_set: HashSet<String> = paired
        .lines()
        .filter_map(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() >= 2 && f[0] == "Device" {
                Some(f[1].to_ascii_uppercase())
            } else {
                None
            }
        })
        .collect();
    let mut devices = Vec::new();
    for (mac, name) in names {
        let info = ssh::remote_command(
            state,
            target,
            &format!("bluetoothctl info {}", ssh::shell_quote(&mac)),
        )
        .unwrap_or_default();
        let connected = info.lines().any(|l| l.trim() == "Connected: yes");
        let trusted = info.lines().any(|l| l.trim() == "Trusted: yes");
        devices.push(BluetoothDevice {
            address: mac.clone(),
            name,
            paired: paired_set.contains(&mac),
            connected,
            trusted,
        });
    }
    devices.sort_by_key(|device| device.name.to_lowercase());
    Ok(devices)
}

fn bluetooth_parts(
    state: &AppState,
    target: &Target,
    scan: bool,
) -> Result<BluetoothSnapshot, String> {
    let script = if scan {
        "command -v bluetoothctl >/dev/null 2>&1 || { echo 'UNSUPPORTED'; exit 0; }; bluetoothctl --timeout 8 scan on >/dev/null 2>&1 || true; printf 'SHOW\\n'; bluetoothctl show 2>/dev/null || true; printf '\\nALL\\n'; bluetoothctl devices 2>/dev/null || true; printf '\\nPAIRED\\n'; bluetoothctl devices Paired 2>/dev/null || true"
    } else {
        "command -v bluetoothctl >/dev/null 2>&1 || { echo 'UNSUPPORTED'; exit 0; }; printf 'SHOW\\n'; bluetoothctl show 2>/dev/null || true; printf '\\nALL\\n'; bluetoothctl devices 2>/dev/null || true; printf '\\nPAIRED\\n'; bluetoothctl devices Paired 2>/dev/null || true"
    };
    let output = ssh::remote_command(state, target, script)?;
    if output.contains("UNSUPPORTED") {
        return Ok(BluetoothSnapshot {
            available: false,
            powered: false,
            adapter: String::new(),
            devices: vec![],
        });
    }
    let show = output
        .split_once("SHOW\n")
        .map(|(_, r)| r.split_once("\nALL\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("");
    let all = output
        .split_once("\nALL\n")
        .map(|(_, r)| r.split_once("\nPAIRED\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("");
    let paired = output
        .split_once("\nPAIRED\n")
        .map(|(_, r)| r)
        .unwrap_or("");
    let powered = show.lines().any(|l| l.trim() == "Powered: yes");
    let adapter = show
        .lines()
        .find_map(|l| l.trim().strip_prefix("Controller "))
        .and_then(|x| x.split_whitespace().next())
        .unwrap_or("")
        .to_string();
    Ok(BluetoothSnapshot {
        available: true,
        powered,
        adapter,
        devices: parse_bt_devices(all, paired, state, target)?,
    })
}

#[tauri::command]
pub fn get_bluetooth_snapshot(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<BluetoothSnapshot, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    bluetooth_parts(&state, &target, false)
}

#[tauri::command]
pub fn scan_bluetooth(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<BluetoothSnapshot, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    bluetooth_parts(&state, &target, true)
}

#[tauri::command]
pub fn set_bluetooth_power(
    state: State<'_, AppState>,
    target_id: String,
    enabled: bool,
) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let power = if enabled { "on" } else { "off" };
    ssh::remote_command(&state, &target, &format!("bluetoothctl power {power}"))?;
    Ok(())
}

#[tauri::command]
pub fn bluetooth_action(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    address: String,
    action: String,
) -> Result<Option<String>, String> {
    validate_mac(&address)?;
    let target = ssh::lookup_target(&state, &target_id)?;
    let mac = address.to_ascii_uppercase();
    match action.as_str() {
        "pair" => Ok(Some(ssh::start_terminal(
            &app,
            &state,
            &target,
            Some(&format!("bluetoothctl pair {}", ssh::shell_quote(&mac))),
        )?)),
        "connect" | "disconnect" | "remove" | "trust" => {
            ssh::remote_command(
                &state,
                &target,
                &format!("bluetoothctl {} {}", action, ssh::shell_quote(&mac)),
            )?;
            Ok(None)
        }
        _ => Err("不支持的蓝牙操作".into()),
    }
}

fn parse_pactl_devices(text: &str, default: &str) -> Vec<AudioDevice> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() < 2 {
                return None;
            }
            let name = fields[1].trim();
            if name.is_empty() {
                return None;
            }
            Some(AudioDevice {
                name: name.into(),
                description: name.replace('_', " "),
                is_default: name == default,
            })
        })
        .collect()
}

#[tauri::command]
pub fn get_audio_snapshot(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<AudioSnapshot, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = r#"command -v pactl >/dev/null 2>&1 || { echo 'UNSUPPORTED'; exit 0; }; printf 'SINK_DEFAULT='; pactl get-default-sink 2>/dev/null || true; printf '\nSOURCE_DEFAULT='; pactl get-default-source 2>/dev/null || true; printf '\nSINK_VOLUME='; pactl get-sink-volume @DEFAULT_SINK@ 2>/dev/null | grep -oE '[0-9]+%' | head -n 1 | tr -d '%' || true; printf '\nSOURCE_VOLUME='; pactl get-source-volume @DEFAULT_SOURCE@ 2>/dev/null | grep -oE '[0-9]+%' | head -n 1 | tr -d '%' || true; printf '\nSINKS\n'; pactl list short sinks 2>/dev/null || true; printf '\nSOURCES\n'; pactl list short sources 2>/dev/null || true"#;
    let output = ssh::remote_command(&state, &target, script)?;
    if output.contains("UNSUPPORTED") {
        return Ok(AudioSnapshot {
            available: false,
            sinks: vec![],
            sources: vec![],
            default_sink_volume: None,
            default_source_volume: None,
            note: Some("未安装 pactl，或音频服务器未提供 PulseAudio 兼容接口。".into()),
        });
    }
    let sink_default = output
        .lines()
        .find_map(|l| l.strip_prefix("SINK_DEFAULT="))
        .unwrap_or("");
    let source_default = output
        .lines()
        .find_map(|l| l.strip_prefix("SOURCE_DEFAULT="))
        .unwrap_or("");
    let sink_volume = output
        .lines()
        .find_map(|l| l.strip_prefix("SINK_VOLUME="))
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.min(150));
    let source_volume = output
        .lines()
        .find_map(|l| l.strip_prefix("SOURCE_VOLUME="))
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.min(150));
    let sinks_part = output
        .split_once("SINKS\n")
        .map(|(_, r)| r.split_once("\nSOURCES\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("");
    let sources_part = output
        .split_once("\nSOURCES\n")
        .map(|(_, r)| r)
        .unwrap_or("");
    Ok(AudioSnapshot {
        available: true,
        sinks: parse_pactl_devices(sinks_part, sink_default),
        sources: parse_pactl_devices(sources_part, source_default),
        default_sink_volume: sink_volume,
        default_source_volume: source_volume,
        note: None,
    })
}

#[tauri::command]
pub fn set_audio_default(
    state: State<'_, AppState>,
    target_id: String,
    kind: String,
    device: String,
) -> Result<(), String> {
    if !["sink", "source"].contains(&kind.as_str()) {
        return Err("音频类型无效".into());
    }
    if device.is_empty()
        || device.len() > 256
        || !device.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'_'
                || b == b'-'
                || b == b'.'
                || b == b':'
                || b == b'@'
        })
    {
        return Err("音频设备标识包含不支持的字符".into());
    }
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::remote_command(
        &state,
        &target,
        &format!("pactl set-default-{kind} {}", ssh::shell_quote(&device)),
    )?;
    Ok(())
}

#[tauri::command]
pub fn set_audio_volume(
    state: State<'_, AppState>,
    target_id: String,
    kind: String,
    device: String,
    volume: u8,
) -> Result<(), String> {
    if !["sink", "source"].contains(&kind.as_str()) {
        return Err("音频类型无效".into());
    }
    if volume > 150 {
        return Err("音量必须在 0–150% 之间".into());
    }
    if device.is_empty()
        || device.len() > 256
        || !device.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'_'
                || b == b'-'
                || b == b'.'
                || b == b':'
                || b == b'@'
        })
    {
        return Err("音频设备标识包含不支持的字符".into());
    }
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::remote_command(
        &state,
        &target,
        &format!(
            "pactl set-{kind}-volume {} {}%",
            ssh::shell_quote(&device),
            volume
        ),
    )?;
    Ok(())
}

#[tauri::command]
pub fn play_test_audio(state: State<'_, AppState>, target_id: String) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::remote_command(&state, &target, "command -v speaker-test >/dev/null 2>&1 || { echo '机器人未安装 alsa-utils/speaker-test'; exit 127; }; timeout 4s speaker-test -t sine -f 440 -l 1")?;
    Ok(())
}

#[tauri::command]
pub fn open_ssh_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
) -> Result<String, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::start_terminal(&app, &state, &target, None)
}

#[tauri::command]
pub fn send_terminal_input(
    state: State<'_, AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    ssh::send_terminal_input(&state, &session_id, &data)
}

#[tauri::command]
pub fn resize_terminal(
    state: State<'_, AppState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    ssh::resize_terminal(&state, &session_id, cols, rows)
}

#[tauri::command]
pub fn close_ssh_terminal(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    ssh::close_terminal(&state, &session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nmcli_escaped_fields_parse_without_splitting_ssid_colons() {
        let fields = parse_nmcli("*:Lab\\:Robot:80:WPA2");
        assert_eq!(fields, vec!["*", "Lab:Robot", "80", "WPA2"]);
    }

    #[test]
    fn link_local_discovery_uses_only_live_neighbors_on_selected_interface() {
        let rows: Vec<Value> = serde_json::from_str(
            r#"[
          {"dst":"169.254.12.2","dev":"enp3s0","state":["REACHABLE"]},
          {"dst":"169.254.12.2","dev":"enp3s0","state":["REACHABLE"]},
          {"dst":"169.254.12.3","dev":"wlan0","state":["REACHABLE"]},
          {"dst":"192.168.1.4","dev":"enp3s0","state":["REACHABLE"]},
          {"dst":"169.254.12.5","dev":"enp3s0","state":["INCOMPLETE"]},
          {"dst":"169.254.12.6","dev":"enp3s0","state":"FAILED"}
        ]"#,
        )
        .unwrap();
        let found = link_local_neighbors(&rows, "enp3s0", Ipv4Addr::new(169, 254, 12, 1));
        assert_eq!(found, vec![Ipv4Addr::new(169, 254, 12, 2)]);
    }
}
