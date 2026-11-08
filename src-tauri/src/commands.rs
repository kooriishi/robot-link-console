use crate::model::*;
use crate::ssh;
use crate::state::{AppState, OwnedNetworkAddress};
use serde::Deserialize;
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, State};
use uuid::Uuid;

#[tauri::command(async)]
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
        .args(["-json", "address", "show"])
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

#[tauri::command(async)]
pub fn list_targets(state: State<'_, AppState>) -> Result<Vec<Target>, String> {
    state.load_targets()
}

#[tauri::command(async)]
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

#[tauri::command(async)]
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

#[tauri::command(async)]
pub fn get_host_key_status(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<HostKeyStatus, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::host_key_status(&state, &target)
}

#[tauri::command(async)]
pub fn trust_host_key(
    state: State<'_, AppState>,
    target_id: String,
    fingerprint: String,
) -> Result<bool, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::trust_host_key(&state, &target, &fingerprint)?;
    Ok(true)
}

#[tauri::command(async)]
pub fn forget_host_key(state: State<'_, AppState>, target_id: String) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::forget_host_key(&state, &target)
}

#[tauri::command(async)]
pub fn ssh_connection_ready(state: State<'_, AppState>, target_id: String) -> Result<bool, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::connection_ready(&state, &target)
}

#[tauri::command(async)]
pub fn scan_direct_interface(interface: String, port: u16) -> Result<Vec<DiscoveredHost>, String> {
    validate_ifname(&interface)?;
    validate_scan_port(port)?;
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
            return Err("本机已使用 169.254/16 链路本地地址，但所选网卡的邻居缓存还没有对端 IP。为避免遍历整个 /16，RoboLink 不会做全段扫描。请确认机器人也启用了 IPv4 link-local，先从本机对机器人发起一次连接/探测后重试；或按固件说明给两端配置同网段地址，再扫描。机器人还需启用 SSH 才能连接。".into());
        }
        (local, peers, true)
    } else {
        let message = if iface.ipv4.is_empty() {
            "网线链路已连接，但开发机所选网卡没有 IPv4 地址。仅有网线不能推导任意静态 IP；请先按机器人固件说明，为开发机和机器人配置同一 IPv4 子网（例如开发机 192.168.77.1/24、机器人 192.168.77.2/24），然后重新扫描。RoboLink 不会擅自修改本机网络。"
                .to_string()
        } else {
            format!(
                "开发机网卡有 IPv4 地址（{}），但扫描目前只支持 /24–/30 或 169.254/16 链路本地前缀。请将两端配置到受支持的同一 IPv4 子网后重新扫描。RoboLink 不会擅自修改本机网络。",
                iface.ipv4.join("、")
            )
        };
        return Err(message);
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
    let candidate_set = candidates.iter().copied().collect::<HashSet<_>>();
    let queue = Arc::new(Mutex::new(VecDeque::from(candidates)));
    let (tx, rx) = mpsc::channel();
    let workers = 16.min(queue.lock().map_err(|_| "扫描状态不可用")?.len().max(1));
    for _ in 0..workers {
        let q = Arc::clone(&queue);
        let tx = tx.clone();
        thread::spawn(move || loop {
            let next = q.lock().ok().and_then(|mut q| q.pop_front());
            let Some(ip) = next else { break };
            let remote = SockAddr::from(SocketAddrV4::new(ip, port));
            let source = SockAddr::from(SocketAddrV4::new(local, 0));
            let probe =
                Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).and_then(|socket| {
                    socket.bind(&source)?;
                    socket.connect_timeout(&remote, Duration::from_millis(160))
                });
            let port_open = match probe {
                Ok(_) => Some(true),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Some(false),
                Err(_) => None,
            };
            if let Some(port_open) = port_open {
                let _ = tx.send((ip, port_open));
            }
        });
    }
    drop(tx);
    let mut found = HashSet::new();
    let mut open_ips = HashSet::new();
    for (ip, port_open) in rx {
        found.insert(ip);
        if port_open {
            open_ips.insert(ip);
        }
    }
    let neighbors = Command::new("ip")
        .args(["-json", "neigh", "show", "dev", &interface])
        .output()
        .map_err(|e| format!("读取所选网卡的邻居缓存失败：{e}"))?;
    if !neighbors.status.success() {
        return Err("读取 Linux 邻居缓存失败；请检查 iproute2 安装。".into());
    }
    let rows: Vec<Value> = serde_json::from_slice(&neighbors.stdout)
        .map_err(|e| format!("解析所选网卡的邻居缓存失败：{e}"))?;
    found.extend(
        interface_neighbors(&rows, &interface)
            .into_iter()
            .filter(|ip| candidate_set.contains(ip)),
    );
    let source = if link_local_mode {
        "所选接口的链路本地邻居"
    } else {
        "所选接口同网段邻居"
    };
    let mut result: Vec<_> = found
        .into_iter()
        .map(|ip| DiscoveredHost {
            address: ip.to_string(),
            interface: interface.clone(),
            mac: neighbor_mac(&rows, &interface, ip).unwrap_or_else(|| "未知".into()),
            port,
            port_open: open_ips.contains(&ip),
            route_ready: true,
            source: source.into(),
            confidence: "路由/邻居候选".into(),
            arp_reachable: None,
            icmp_reachable: None,
            port_checked: true,
        })
        .collect();
    result.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(result)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PassiveArpCandidate {
    interface: String,
    address: String,
    mac: String,
    source: String,
    confidence: String,
    #[serde(default)]
    arp_reachable: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HelperDiscoveryReport {
    #[serde(default)]
    candidates: Vec<PassiveArpCandidate>,
    #[serde(default)]
    skipped_interfaces: Vec<String>,
    #[serde(default)]
    warnings: Vec<String>,
}

fn trusted_network_helper() -> Result<std::path::PathBuf, String> {
    let executable = std::env::current_exe().map_err(|e| format!("无法定位 RoboLink 程序：{e}"))?;
    let helper = executable
        .parent()
        .ok_or("无法定位 RoboLink 安装目录")?
        .join("robolink-net-helper");
    let metadata = fs::symlink_metadata(&helper)
        .map_err(|_| "没有找到系统安装的网络助手。请使用 RoboLink .deb 安装包；源码开发模式不会启用本机网络修改。".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(
            "网络助手安装路径不安全，已拒绝运行。请重新安装正式的 RoboLink .deb 候选包。".into(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("网络助手必须由系统包管理器安装为 root 所有且不可被普通用户改写。请重新安装 RoboLink .deb 候选包。".into());
        }
        let directory = helper.parent().ok_or("无法定位网络助手安装目录")?;
        let directory_metadata = fs::symlink_metadata(directory)
            .map_err(|e| format!("读取网络助手安装目录失败：{e}"))?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.uid() != 0
            || directory_metadata.mode() & 0o022 != 0
        {
            return Err("网络助手所在目录不是 root 所有的受保护系统目录，已拒绝提权。".into());
        }
    }
    Ok(helper)
}

fn run_network_helper(arguments: &[String]) -> Result<String, String> {
    let helper = trusted_network_helper()?;
    let output = Command::new("/usr/bin/pkexec")
        .arg(helper)
        .args(arguments)
        .output()
        .map_err(|e| format!("无法打开系统授权弹窗：{e}。请确认桌面环境安装并运行了 polkit。"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(network_helper_failure(output.status.code(), &detail));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn network_helper_failure(exit_code: Option<i32>, detail: &str) -> String {
    if let Some(operation) = detail.strip_prefix("ROBOLINK_NETWORK_OPERATION: ") {
        return format!("网络操作失败（系统授权已通过）：{operation}");
    }
    let lower = detail.to_ascii_lowercase();
    let authorization_denied = [
        "not authorized",
        "authentication failed",
        "authorization failed",
        "no authentication agent",
        "authentication was dismissed",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    if exit_code == Some(126) || authorization_denied {
        return "系统授权未完成、未通过或已取消；网络操作没有执行。请在系统授权窗口完成认证后重试。".into();
    }
    if exit_code == Some(127) {
        return if detail.is_empty() {
            "系统授权代理或网络助手无法启动；网络操作没有执行。请检查桌面 PolicyKit 服务和 RoboLink 安装。".into()
        } else {
            format!("系统授权代理或网络助手无法启动；网络操作没有执行：{detail}")
        };
    }
    if !detail.is_empty() {
        return format!("网络操作失败（系统授权已通过）：{detail}");
    }
    format!(
        "网络操作失败（助手退出码 {:?}，未提供错误详情）。",
        exit_code
    )
}

#[derive(Clone)]
struct DiscoveryCandidate {
    address: String,
    interface: String,
    mac: String,
    source: String,
    confidence: String,
    arp_reachable: Option<bool>,
}

fn route_details(address: &str, interface: &str) -> Option<String> {
    let ip = address
        .split('%')
        .next()
        .unwrap_or(address)
        .parse::<IpAddr>()
        .ok()?;
    let link_local_v6 = matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
    let destination = ip.to_string();
    let mut command = Command::new("ip");
    command.args([
        if ip.is_ipv4() { "-4" } else { "-6" },
        "route",
        "get",
        &destination,
    ]);
    if link_local_v6 {
        command.args(["oif", interface]);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let words = text.split_whitespace().collect::<Vec<_>>();
    if !words.windows(2).any(|w| w[0] == "dev" && w[1] == interface) {
        return None;
    }
    let source = words
        .windows(2)
        .find(|w| w[0] == "src" || w[0] == "prefsrc")
        .map(|w| w[1].to_string());
    Some(source.unwrap_or_default())
}

fn addresses_for_interface(interface: &str) -> Vec<IpAddr> {
    let Ok(output) = Command::new("ip")
        .args(["-json", "address", "show", "dev", interface])
        .output()
    else {
        return vec![];
    };
    let Ok(rows) = serde_json::from_slice::<Vec<Value>>(&output.stdout) else {
        return vec![];
    };
    rows.iter()
        .flat_map(|r| {
            r.get("addr_info")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|a| {
            a.get("scope").and_then(Value::as_str) != Some("host")
                && a.get("tentative").and_then(Value::as_bool) != Some(true)
                && a.get("dadfailed").and_then(Value::as_bool) != Some(true)
        })
        .filter_map(|a| a.get("local")?.as_str()?.parse::<IpAddr>().ok())
        .collect()
}
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.octets()[0] == 169 && v.octets()[1] == 254,
        IpAddr::V6(v) => v.is_unicast_link_local(),
    }
}
fn discover_neighbor_rows(interface: &str, family: &str) -> Vec<Value> {
    let Ok(out) = Command::new("ip")
        .args(["-json", family, "neigh", "show", "dev", interface])
        .output()
    else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }
    serde_json::from_slice(&out.stdout).unwrap_or_default()
}
fn probe_discovered(
    candidate: &DiscoveryCandidate,
    port: u16,
    options: &DiscoveryOptions,
) -> (bool, bool, Option<bool>, Option<bool>) {
    let Ok(ip) = candidate
        .address
        .split('%')
        .next()
        .unwrap_or(&candidate.address)
        .parse::<IpAddr>()
    else {
        return (false, false, None, None);
    };
    let Some(route_source) = route_details(&candidate.address, &candidate.interface) else {
        return (false, false, None, None);
    };
    let addresses = addresses_for_interface(&candidate.interface);
    let route_source_ip = route_source.parse::<IpAddr>().ok();
    let source_is_local = route_source_ip
        .map(|src| addresses.contains(&src))
        .unwrap_or(false);
    let source_for_family = route_source_ip.filter(|src| {
        src.is_ipv4() == ip.is_ipv4() && is_link_local(*src) == is_link_local(ip) && source_is_local
    });
    let tcp_result = if options.tcp {
        if let Some(local) = source_for_family {
            let scope = if matches!(local, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
                fs::read_to_string(format!("/sys/class/net/{}/ifindex", candidate.interface))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0)
            } else {
                0
            };
            let local_socket = match local {
                IpAddr::V4(v) => SocketAddr::V4(SocketAddrV4::new(v, 0)),
                IpAddr::V6(v) => SocketAddr::V6(SocketAddrV6::new(v, 0, 0, scope)),
            };
            let remote = match ip {
                IpAddr::V4(v) => SocketAddr::V4(SocketAddrV4::new(v, port)),
                IpAddr::V6(v) => SocketAddr::V6(SocketAddrV6::new(v, port, 0, scope)),
            };
            match Socket::new(
                if ip.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                },
                Type::STREAM,
                Some(Protocol::TCP),
            ) {
                Ok(socket) if socket.bind(&SockAddr::from(local_socket)).is_ok() => {
                    let result = match socket
                        .connect_timeout(&SockAddr::from(remote), Duration::from_millis(350))
                    {
                        Ok(()) => Some(true),
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(false),
                        Err(_) => None,
                    };
                    (true, result)
                }
                _ => (false, None),
            }
        } else {
            (false, None)
        }
    } else {
        (false, None)
    };
    let icmp_result = if options.icmp {
        let destination = if ip.is_ipv6() && is_link_local(ip) {
            format!("{}%{}", ip, candidate.interface)
        } else {
            ip.to_string()
        };
        match Command::new("ping")
            .args([
                if ip.is_ipv4() { "-4" } else { "-6" },
                "-I",
                &candidate.interface,
                "-c",
                "1",
                "-W",
                "1",
                &destination,
            ])
            .output()
        {
            Ok(out) => Some(out.status.success()),
            Err(_) => None,
        }
    } else {
        None
    };
    (true, tcp_result.0, tcp_result.1, icmp_result)
}

#[tauri::command(async)]
pub fn discover_direct_devices(
    port: u16,
    interfaces: Vec<String>,
    options: DiscoveryOptions,
) -> Result<DiscoveryReport, String> {
    validate_scan_port(port)?;
    options.validate()?;
    let host = get_host_info()?;
    let physical = host
        .interfaces
        .iter()
        .filter(|i| i.kind == "有线以太网")
        .collect::<Vec<_>>();
    let selected = if interfaces.is_empty() {
        physical.iter().map(|i| i.name.clone()).collect::<Vec<_>>()
    } else {
        let mut seen = HashSet::new();
        for name in &interfaces {
            validate_ifname(name)?;
            if !seen.insert(name) {
                return Err(format!("网卡 {name} 被重复选择"));
            }
            if !physical.iter().any(|i| i.name == *name) {
                return Err(format!("{name} 不是本机物理有线网卡"));
            }
        }
        interfaces
    };
    let mut report = DiscoveryReport {
        hosts: vec![],
        skipped_interfaces: vec![],
        warnings: vec![],
    };
    let active = selected
        .into_iter()
        .filter(|name| {
            let up = physical.iter().any(|i| i.name == *name && i.carrier);
            if !up {
                report.skipped_interfaces.push(name.clone());
            }
            up
        })
        .collect::<Vec<_>>();
    if active.is_empty() {
        if !report.skipped_interfaces.is_empty() {
            report
                .warnings
                .push("所选有线接口当前均无 carrier；未启动扫描。".into());
        }
        return Ok(report);
    }
    let options_json =
        serde_json::to_string(&options).map_err(|e| format!("序列化发现选项失败：{e}"))?;
    let mut args = vec!["discover".into(), "8".into(), options_json];
    args.extend(active.iter().cloned());
    let helper_output = run_network_helper(&args)?;
    let helper: HelperDiscoveryReport =
        serde_json::from_str(&helper_output).map_err(|e| format!("解析设备发现结果失败：{e}"))?;
    report.skipped_interfaces.extend(helper.skipped_interfaces);
    report.warnings.extend(helper.warnings);
    let allowed = active.iter().cloned().collect::<HashSet<_>>();
    let mut candidates: HashMap<(String, String, String), DiscoveryCandidate> = HashMap::new();
    for c in helper.candidates.into_iter().take(4096) {
        if !allowed.contains(&c.interface) {
            continue;
        }
        let Ok(ip) = c
            .address
            .split('%')
            .next()
            .unwrap_or(&c.address)
            .parse::<IpAddr>()
        else {
            report
                .warnings
                .push(format!("忽略无效候选地址 {}", c.address));
            continue;
        };
        if addresses_for_interface(&c.interface).contains(&ip) {
            continue;
        }
        let address = match ip {
            IpAddr::V6(v) if v.is_unicast_link_local() => format!("{v}%{}", c.interface),
            _ => ip.to_string(),
        };
        let mac_key = c.mac.clone();
        let candidate = DiscoveryCandidate {
            address: address.clone(),
            interface: c.interface.clone(),
            mac: c.mac,
            source: c.source,
            confidence: c.confidence,
            arp_reachable: c.arp_reachable,
        };
        candidates
            .entry((c.interface, address, mac_key))
            .and_modify(|old| {
                if old.arp_reachable.is_none() {
                    old.arp_reachable = candidate.arp_reachable;
                }
                if !old.source.contains(&candidate.source) {
                    old.source.push('、');
                    old.source.push_str(&candidate.source);
                }
            })
            .or_insert(candidate);
    }
    for interface in &active {
        if options.ipv6_link_local {
            let group = format!("ff02::1%{interface}");
            let _ = Command::new("ping")
                .args(["-6", "-I", interface, "-c", "1", "-W", "1", &group])
                .output();
        }
        let locals = addresses_for_interface(interface);
        for family in ["-4", "-6"] {
            if (family == "-4" && !options.passive_arp && !options.ipv4_link_local)
                || (family == "-6" && !options.passive_ipv6 && !options.ipv6_link_local)
            {
                continue;
            }
            for row in discover_neighbor_rows(interface, family) {
                if row.get("dev").and_then(Value::as_str) != Some(interface.as_str()) {
                    continue;
                }
                let bad = |s: &str| matches!(s, "FAILED" | "INCOMPLETE" | "NONE");
                let state_bad = match row.get("state") {
                    Some(Value::String(s)) => bad(s),
                    Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).any(bad),
                    _ => false,
                };
                if state_bad {
                    continue;
                }
                let Some(text) = row.get("dst").and_then(Value::as_str) else {
                    continue;
                };
                let Ok(ip) = text.split('%').next().unwrap_or(text).parse::<IpAddr>() else {
                    continue;
                };
                if locals.contains(&ip) {
                    continue;
                }
                if is_link_local(ip)
                    && match ip {
                        IpAddr::V4(_) => !options.ipv4_link_local,
                        IpAddr::V6(_) => !options.ipv6_link_local,
                    }
                {
                    continue;
                }
                let address = match ip {
                    IpAddr::V6(v) if v.is_unicast_link_local() => format!("{v}%{interface}"),
                    _ => ip.to_string(),
                };
                let mac = row
                    .get("lladdr")
                    .and_then(Value::as_str)
                    .unwrap_or("未知")
                    .to_string();
                let candidate = DiscoveryCandidate {
                    address: address.clone(),
                    interface: interface.clone(),
                    mac: mac.clone(),
                    source: "Linux 邻居缓存（缓存证据，未确认）".into(),
                    confidence: "缓存候选，未确认".into(),
                    arp_reachable: None,
                };
                candidates
                    .entry((interface.clone(), address, mac.clone()))
                    .or_insert(candidate);
            }
        }
    }
    let mut list = candidates.into_values().collect::<Vec<_>>();
    let mut evidence_keys = HashSet::new();
    let mut conflicts = HashSet::new();
    for candidate in &list {
        let key = (candidate.interface.clone(), candidate.address.clone());
        if !evidence_keys.insert(key.clone()) {
            conflicts.insert(key);
        }
    }
    for (interface, address) in conflicts {
        report.warnings.push(format!("{interface} 上的候选 {address} 对应多个不同 MAC；结果仅保留为发现证据，不能据此判定设备身份。"));
    }
    list.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then(a.address.cmp(&b.address))
    });
    if list.len() > 256 {
        report.warnings.push(format!(
            "共 {} 个候选；仅验证前 256 个，其余未验证。",
            list.len()
        ));
    }
    if options.ipv6_link_local {
        report.warnings.push("IPv6 链路本地设备可能不响应多播探测；不响应不代表不可达，且不保证可发现。未修改网卡 IPv6 配置。".into());
    }
    let count = list.len().min(256);
    let q = Arc::new(Mutex::new(VecDeque::from(
        list.iter().take(count).cloned().collect::<Vec<_>>(),
    )));
    let (tx, rx) = mpsc::channel();
    for _ in 0..16.min(count.max(1)) {
        let q = Arc::clone(&q);
        let tx = tx.clone();
        let options = options.clone();
        thread::spawn(move || {
            while let Some(c) = q.lock().ok().and_then(|mut q| q.pop_front()) {
                let v = probe_discovered(&c, port, &options);
                let _ = tx.send(((c.interface, c.address), v));
            }
        });
    }
    drop(tx);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut checked = HashMap::new();
    while checked.len() < count {
        let wait = deadline.saturating_duration_since(std::time::Instant::now());
        if wait.is_zero() {
            break;
        }
        match rx.recv_timeout(wait) {
            Ok((k, v)) => {
                checked.insert(k, v);
            }
            Err(_) => break,
        }
    }
    if checked.len() < count {
        report
            .warnings
            .push("部分验证在 20 秒总时限内未完成，相关字段保持未验证。".into());
    }
    report.hosts = list
        .into_iter()
        .map(|c| {
            let (route, port_checked, open, icmp) = checked
                .get(&(c.interface.clone(), c.address.clone()))
                .copied()
                .unwrap_or((false, false, None, None));
            DiscoveredHost {
                address: c.address,
                interface: c.interface,
                mac: c.mac,
                port,
                port_open: open.unwrap_or(false),
                route_ready: route,
                source: c.source,
                confidence: c.confidence,
                arp_reachable: c.arp_reachable,
                icmp_reachable: icmp,
                port_checked,
            }
        })
        .collect();
    report.skipped_interfaces.sort();
    report.skipped_interfaces.dedup();
    Ok(report)
}

#[tauri::command(async)]
pub fn get_dhcp_status() -> Result<Vec<DhcpStatus>, String> {
    let s = run_network_helper(&["dhcp-status".into()])?;
    serde_json::from_str(&s).map_err(|e| format!("解析 DHCP 状态失败：{e}"))
}
fn validate_dhcp_cidr(cidr: &str) -> Result<(), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or("DHCP 地址请使用 IPv4/CIDR 格式")?;
    let ip = addr
        .parse::<Ipv4Addr>()
        .map_err(|_| "DHCP 地址必须是 IPv4 地址")?;
    let bits = prefix.parse::<u8>().map_err(|_| "IPv4 前缀长度无效")?;
    if !(1..=30).contains(&bits)
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip == Ipv4Addr::BROADCAST
    {
        return Err("DHCP 服务仅支持普通 IPv4 地址和 /1–/30 前缀".into());
    }
    Ok(())
}
#[tauri::command(async)]
pub fn start_direct_dhcp(interface: String, cidr: String) -> Result<Vec<DhcpStatus>, String> {
    validate_ifname(&interface)?;
    validate_dhcp_cidr(&cidr)?;
    let host = get_host_info()?;
    if !host
        .interfaces
        .iter()
        .any(|i| i.name == interface && i.kind == "有线以太网" && i.carrier)
    {
        return Err("请选择当前已连接的本机物理有线网卡；DHCP 服务未启动。".into());
    }
    let s = run_network_helper(&["dhcp-start".into(), interface, cidr])?;
    serde_json::from_str(&s).map_err(|e| format!("解析 DHCP 启动结果失败：{e}"))
}
#[tauri::command(async)]
pub fn stop_direct_dhcp(interface: String) -> Result<Vec<DhcpStatus>, String> {
    validate_ifname(&interface)?;
    let s = run_network_helper(&["dhcp-stop".into(), interface])?;
    serde_json::from_str(&s).map_err(|e| format!("解析 DHCP 停止结果失败：{e}"))
}

#[tauri::command(async)]
pub fn scan_direct_interfaces(port: u16) -> Result<Vec<DiscoveredHost>, String> {
    discover_direct_devices(port, vec![], DiscoveryOptions::default()).map(|r| r.hosts)
}

#[tauri::command(async)]
pub fn list_owned_network_addresses(
    state: State<'_, AppState>,
) -> Result<Vec<OwnedNetworkAddress>, String> {
    state.load_network_addresses()
}

#[tauri::command(async)]
pub fn add_temporary_network_address(
    state: State<'_, AppState>,
    interface: String,
    peer: String,
    cidr: String,
    persistent: bool,
) -> Result<Vec<OwnedNetworkAddress>, String> {
    validate_ifname(&interface)?;
    let peer_ip = peer
        .parse::<Ipv4Addr>()
        .map_err(|_| "候选设备必须是 IPv4 地址".to_string())?;
    validate_temporary_cidr(&cidr, peer_ip)?;
    let host = get_host_info()?;
    if !host
        .interfaces
        .iter()
        .any(|item| item.name == interface && item.kind == "有线以太网" && item.carrier)
    {
        return Err("所选接口已断开或不再是物理有线网卡。请重新扫描。".into());
    }
    let mut owned = state.load_network_addresses()?;
    if let Some(existing) = owned
        .iter_mut()
        .find(|item| item.interface == interface && item.cidr == cidr)
    {
        existing.peer = peer_ip.to_string();
        existing.persistent = persistent;
        state.save_network_addresses(&owned)?;
        return Ok(owned);
    }
    let arguments = vec![
        "add-address".to_string(),
        interface.clone(),
        cidr.clone(),
        peer_ip.to_string(),
    ];
    run_network_helper(&arguments)?;
    owned.push(OwnedNetworkAddress {
        interface,
        cidr,
        peer: peer_ip.to_string(),
        persistent,
    });
    if let Err(error) = state.save_network_addresses(&owned) {
        let _ = run_network_helper(&[
            "remove-address".into(),
            owned
                .last()
                .map(|v| v.interface.clone())
                .unwrap_or_default(),
            owned.last().map(|v| v.cidr.clone()).unwrap_or_default(),
        ]);
        return Err(format!(
            "网络地址已添加，但无法记录归属；已尝试立即撤销：{error}"
        ));
    }
    Ok(owned)
}

#[tauri::command(async)]
pub fn remove_owned_network_address(
    state: State<'_, AppState>,
    interface: String,
    cidr: String,
) -> Result<Vec<OwnedNetworkAddress>, String> {
    let mut owned = state.load_network_addresses()?;
    if !owned
        .iter()
        .any(|item| item.interface == interface && item.cidr == cidr)
    {
        return Err("RoboLink 没有记录这条网络地址的所有权，因此拒绝删除。".into());
    }
    run_network_helper(&["remove-address".into(), interface.clone(), cidr.clone()])?;
    owned.retain(|item| item.interface != interface || item.cidr != cidr);
    state.save_network_addresses(&owned)?;
    Ok(owned)
}

#[tauri::command(async)]
pub fn cleanup_session_network_addresses(
    state: State<'_, AppState>,
) -> Result<Vec<OwnedNetworkAddress>, String> {
    cleanup_temporary_addresses(&state)
}

/// Removes the non-persistent RoboLink addresses. Called when the app exits, not when an SSH session
/// ends: a dropped session must keep the direct-link address so the user can reconnect straight away.
pub fn cleanup_temporary_addresses(state: &AppState) -> Result<Vec<OwnedNetworkAddress>, String> {
    let mut owned = state.load_network_addresses()?;
    let session_items = owned
        .iter()
        .filter(|item| !item.persistent)
        .cloned()
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for item in session_items {
        match run_network_helper(&[
            "remove-address".into(),
            item.interface.clone(),
            item.cidr.clone(),
        ]) {
            Ok(_) => owned
                .retain(|current| current.interface != item.interface || current.cidr != item.cidr),
            Err(error) => failures.push(format!("{} {}：{error}", item.interface, item.cidr)),
        }
    }
    state.save_network_addresses(&owned)?;
    if failures.is_empty() {
        Ok(owned)
    } else {
        Err(format!(
            "部分会话地址未能清理；可在“网络与 Wi‑Fi”页查看并重试：{}",
            failures.join("；")
        ))
    }
}

#[tauri::command(async)]
pub fn cleanup_owned_network_addresses(
    state: State<'_, AppState>,
) -> Result<Vec<OwnedNetworkAddress>, String> {
    let mut owned = state.load_network_addresses()?;
    let initial = owned.clone();
    let mut failures = Vec::new();
    for item in initial {
        match run_network_helper(&[
            "remove-address".into(),
            item.interface.clone(),
            item.cidr.clone(),
        ]) {
            Ok(_) => owned
                .retain(|current| current.interface != item.interface || current.cidr != item.cidr),
            Err(error) => failures.push(format!("{} {}：{error}", item.interface, item.cidr)),
        }
    }
    state.save_network_addresses(&owned)?;
    if failures.is_empty() {
        Ok(owned)
    } else {
        Err(format!(
            "部分 RoboLink 地址未能清理；仍保留在列表中：{}",
            failures.join("；")
        ))
    }
}

fn neighbor_mac(rows: &[Value], interface: &str, ip: Ipv4Addr) -> Option<String> {
    let ip_text = ip.to_string();
    rows.iter().find_map(|row| {
        (row.get("dev").and_then(Value::as_str) == Some(interface)
            && row.get("dst").and_then(Value::as_str) == Some(ip_text.as_str()))
        .then(|| {
            row.get("lladdr")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .flatten()
    })
}

fn validate_temporary_cidr(cidr: &str, peer: Ipv4Addr) -> Result<(), String> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or("本机地址请使用 IPv4/CIDR 格式，例如 192.168.127.1/24")?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| "本机 IPv4 地址格式无效".to_string())?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "IPv4 前缀长度无效".to_string())?;
    if !(1..=30).contains(&prefix)
        || address.is_unspecified()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return Err("仅支持普通 IPv4 地址和 /1–/30 前缀".into());
    }
    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(address) & mask;
    let host_mask = !mask;
    let local_host = u32::from(address) & host_mask;
    let peer_host = u32::from(peer) & host_mask;
    if local_host == 0 || local_host == host_mask || peer_host == 0 || peer_host == host_mask {
        return Err("本机地址和设备地址不能是所选子网的网络地址或广播地址".into());
    }
    if network != (u32::from(peer) & mask) {
        return Err(format!(
            "本机地址 {cidr} 与设备 {peer} 不在同一网段；请调整地址或前缀。"
        ));
    }
    Ok(())
}

fn validate_scan_port(port: u16) -> Result<(), String> {
    if port == 0 {
        Err("扫描端口必须在 1–65535 之间".into())
    } else {
        Ok(())
    }
}

fn interface_neighbors(rows: &[Value], interface: &str) -> Vec<Ipv4Addr> {
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
            row.get("dst")?.as_str()?.parse::<Ipv4Addr>().ok()
        })
        .collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    peers
}

fn link_local_neighbors(rows: &[Value], interface: &str, local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut peers = interface_neighbors(rows, interface)
        .into_iter()
        .filter(|ip| {
            let octets = ip.octets();
            *ip != local && octets[0] == 169 && octets[1] == 254
        })
        .collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    peers
}

#[tauri::command(async)]
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

#[tauri::command(async)]
pub fn list_services(
    state: State<'_, AppState>,
    target_id: String,
    scope: Option<String>,
) -> Result<Vec<ServiceInfo>, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let user = scope.as_deref() == Some("user");
    let script = if user {
        // An SSH login normally has the user's systemd manager; set the runtime dir explicitly for
        // boards whose sshd does not export XDG_RUNTIME_DIR.
        "export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}; systemctl --user list-units --type=service --all --no-legend --no-pager --plain; printf '\\0'; systemctl --user list-unit-files --type=service --no-legend --no-pager"
    } else {
        "systemctl list-units --type=service --all --no-legend --no-pager --plain --no-ask-password; printf '\\0'; systemctl list-unit-files --type=service --no-legend --no-pager --no-ask-password"
    };
    let output = ssh::remote_command(&state, &target, script).map_err(|e| {
        if user {
            format!(
                "读取用户服务失败（systemctl --user 需要该用户的 systemd 会话）：{}",
                e.trim_start_matches(ssh::SUDO_MARK)
            )
        } else {
            e
        }
    })?;
    let scope_name = if user { "user" } else { "system" };
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
            scope: scope_name.into(),
        });
    }
    services.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(services)
}

#[tauri::command(async)]
pub fn service_action(
    state: State<'_, AppState>,
    target_id: String,
    service: String,
    action: String,
    scope: Option<String>,
    sudo_password: Option<String>,
) -> Result<String, String> {
    validate_service_name(&service)?;
    if !["start", "stop", "restart"].contains(&action.as_str()) {
        return Err("不支持的服务操作".into());
    }
    let target = ssh::lookup_target(&state, &target_id)?;
    if scope.as_deref() == Some("user") {
        let script = format!(
            "export XDG_RUNTIME_DIR=${{XDG_RUNTIME_DIR:-/run/user/$(id -u)}}; systemctl --user {action} {service}"
        );
        ssh::remote_command(&state, &target, &script)?;
    } else {
        let script = format!("systemctl --no-ask-password {} {}", action, service);
        ssh::remote_command_with(&state, &target, &script, sudo_options(&sudo_password))?;
    }
    Ok(format!("{service} 已执行 {action}；请刷新状态确认结果"))
}

fn sudo_options(sudo_password: &Option<String>) -> ssh::RemoteOptions<'_> {
    ssh::RemoteOptions {
        sudo_password: sudo_password.as_deref().filter(|p| !p.is_empty()),
        ..Default::default()
    }
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

#[tauri::command(async)]
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

#[tauri::command(async)]
pub fn scan_remote_wifi(
    state: State<'_, AppState>,
    target_id: String,
    sudo_password: Option<String>,
) -> Result<WifiScanResult, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    // `list --rescan yes` fails as a whole when polkit refuses the scan (common for a non-root SSH
    // user), so request the rescan separately and still return NetworkManager's cached list.
    let script = "command -v nmcli >/dev/null 2>&1 || { echo '缺少 nmcli'; exit 127; }; R=$(LC_ALL=C nmcli device wifi rescan 2>&1); if [ $? -ne 0 ]; then printf 'RESCAN_ERR %s\n' \"$(printf '%s' \"$R\" | tr '\\n' ' ' | cut -c1-300)\"; else sleep 4; fi; printf 'APS\n'; nmcli --terse --escape yes --fields IN-USE,SSID,SIGNAL,SECURITY device wifi list --rescan no";
    let output = ssh::remote_command_with(&state, &target, script, sudo_options(&sudo_password))?;
    Ok(parse_wifi_scan(&output))
}

fn parse_wifi_scan(output: &str) -> WifiScanResult {
    let (head, aps) = output.split_once("APS\n").unwrap_or(("", output));
    let error = head
        .lines()
        .find_map(|line| line.strip_prefix("RESCAN_ERR "))
        .map(str::trim)
        .filter(|e| !e.is_empty());
    let needs_sudo = error.is_some_and(ssh::looks_like_permission_error);
    let warning = error.map(|e| {
        let lower = e.to_ascii_lowercase();
        let hint = if needs_sudo {
            "机器人上的 SSH 用户没有让 NetworkManager 主动扫描的权限，输入 sudo 密码即可重新扫描。"
        } else if lower.contains("immediately") || lower.contains("not allowed") {
            "NetworkManager 刚扫描过或 Wi‑Fi 不可用，稍等几秒再试。"
        } else {
            "可到终端执行 nmcli device wifi rescan 查看详情。"
        };
        format!("重新扫描未执行（{e}），下面是缓存的结果。{hint}")
    });
    WifiScanResult {
        networks: wifi_rows(aps),
        warning,
        needs_sudo,
    }
}

#[tauri::command(async)]
pub fn set_remote_wifi_radio(
    state: State<'_, AppState>,
    target_id: String,
    enabled: bool,
    sudo_password: Option<String>,
) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let on_off = if enabled { "on" } else { "off" };
    ssh::remote_command_with(
        &state,
        &target,
        &format!("nmcli radio wifi {on_off}"),
        sudo_options(&sudo_password),
    )?;
    Ok(())
}

/// Connects the robot to Wi-Fi without a terminal: the Wi-Fi password goes over ssh's stdin (read by
/// the remote shell), never into the local ssh argv or RoboLink's storage.
#[tauri::command(async)]
pub fn connect_remote_wifi(
    state: State<'_, AppState>,
    target_id: String,
    ssid: String,
    password: Option<String>,
    sudo_password: Option<String>,
) -> Result<String, String> {
    validate_wifi_ssid(&ssid)?;
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = format!(
        "WP=''; while IFS= read -r L; do case \"$L\" in SECRET:*) WP=${{L#SECRET:}}; break;; esac; done; if [ -n \"$WP\" ]; then nmcli --wait 40 device wifi connect {ssid} password \"$WP\"; else nmcli --wait 40 device wifi connect {ssid}; fi",
        ssid = ssh::shell_quote(&ssid)
    );
    let mut options = sudo_options(&sudo_password);
    options.stdin_line = Some(password.as_deref().unwrap_or(""));
    options.timeout_secs = Some(50);
    let output = ssh::remote_command_with(&state, &target, &script, options)?;
    Ok(output.trim().to_string())
}

#[tauri::command(async)]
pub fn start_wifi_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    ssid: String,
) -> Result<String, String> {
    validate_wifi_ssid(&ssid)?;
    let target = ssh::lookup_target(&state, &target_id)?;
    let command = with_sudo_retry(&format!(
        "nmcli --ask device wifi connect {}",
        ssh::shell_quote(&ssid)
    ));
    ssh::start_terminal(&app, &state, &target, Some(&command))
}

/// Runs an interactive command in the robot terminal; if it fails, offers (does not force) a retry
/// with sudo, since NetworkManager/BlueZ often refuse a non-root SSH user. The sudo password is typed
/// in the terminal and never passes through RoboLink.
fn with_sudo_retry(command: &str) -> String {
    format!(
        "{command}; rc=$?; if [ $rc -ne 0 ] && command -v sudo >/dev/null 2>&1; then printf '\\n命令失败（退出码 %s）。如果上面提示权限不足（Not authorized / Insufficient privileges / Access denied），按回车用 sudo 重试；按 Ctrl+C 结束。\\n' \"$rc\"; read _ && sudo {command}; fi"
    )
}

const BT_SCRIPT_HEAD: &str =
    "command -v bluetoothctl >/dev/null 2>&1 || { echo 'UNSUPPORTED'; exit 0; }; export LC_ALL=C; ";
// One SSH round trip: errors are kept (not sent to /dev/null) so permission problems are visible, and
// `info` is read for every device in the same call instead of one SSH command per device.
const BT_SCRIPT_TAIL: &str = "printf 'SHOW\\n'; bluetoothctl show 2>&1; printf '\\nINFO\\n'; bluetoothctl devices 2>/dev/null | awk '$1==\"Device\"{print $2}' | head -30 | while read -r m; do printf '@@DEV %s\\n' \"$m\"; bluetoothctl info \"$m\" 2>/dev/null; done";
const BT_SCAN: &str = "S=$(bluetoothctl --timeout 6 scan on 2>&1); printf 'SCAN\\n%s\\n' \"$S\" | grep -i -E 'fail|error|denied|not available|not ready' | head -3; ";

fn parse_bt_info(info: &str) -> Vec<BluetoothDevice> {
    let mut devices = Vec::new();
    for block in info.split("@@DEV ").skip(1) {
        let mut lines = block.lines();
        let mac = lines.next().unwrap_or("").trim().to_ascii_uppercase();
        if validate_mac(&mac).is_err() {
            continue;
        }
        let mut name = String::new();
        let (mut paired, mut connected, mut trusted) = (false, false, false);
        for line in lines {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Name: ") {
                name = v.trim().to_string();
            } else if name.is_empty() {
                if let Some(v) = line.strip_prefix("Alias: ") {
                    name = v.trim().to_string();
                }
            }
            match line {
                "Paired: yes" => paired = true,
                "Connected: yes" => connected = true,
                "Trusted: yes" => trusted = true,
                _ => {}
            }
        }
        if name.is_empty() {
            name = mac.clone();
        }
        devices.push(BluetoothDevice {
            address: mac,
            name,
            paired,
            connected,
            trusted,
        });
    }
    devices.sort_by_key(|device| {
        (
            !device.connected,
            !device.paired,
            device.name.to_lowercase(),
        )
    });
    devices.dedup_by(|a, b| a.address == b.address);
    devices
}

/// bluetoothctl often exits 0 even when the D-Bus call failed; look at what it printed.
fn bluetoothctl_result(output: &str) -> Result<(), String> {
    let failure = output.lines().map(str::trim).find(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("failed")
            || lower.contains("org.bluez.error")
            || lower.contains("access denied")
            || lower.contains("no default controller")
            || lower.contains("not available")
    });
    match failure {
        None => Ok(()),
        Some(line) if ssh::looks_like_permission_error(line) => {
            Err(format!("{}{line}", ssh::SUDO_MARK))
        }
        Some(line) => Err(format!("蓝牙操作失败：{line}。{}", bt_problem_hint(line))),
    }
}

fn bt_problem_hint(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("denied") || lower.contains("not authorized") {
        "机器人上的 SSH 用户没有访问 BlueZ 的权限：可输入 sudo 密码执行，或把该用户加入 bluetooth 组（sudo usermod -aG bluetooth $USER 后重新登录）。".into()
    } else if lower.contains("no default controller") {
        "机器人没有可用的蓝牙适配器：确认板子有蓝牙模块，并执行 sudo systemctl start bluetooth、rfkill unblock bluetooth。".into()
    } else if lower.contains("waiting to connect to bluetoothd") || lower.contains("not available")
    {
        "bluetoothd 没有运行：在终端执行 sudo systemctl start bluetooth。".into()
    } else {
        "可在终端执行 bluetoothctl show 查看详情。".into()
    }
}

fn parse_bluetooth_output(output: &str) -> BluetoothSnapshot {
    if output.lines().any(|l| l.trim() == "UNSUPPORTED") {
        return BluetoothSnapshot {
            available: false,
            powered: false,
            adapter: String::new(),
            devices: vec![],
            note: Some("机器人未安装 bluetoothctl（BlueZ）。".into()),
            needs_sudo: false,
        };
    }
    let scan_errors = output
        .split_once("SCAN\n")
        .map(|(_, r)| r.split_once("SHOW\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("")
        .trim()
        .to_string();
    let show = output
        .split_once("SHOW\n")
        .map(|(_, r)| r.split_once("\nINFO\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("");
    let info = output.split_once("\nINFO\n").map(|(_, r)| r).unwrap_or("");
    let adapter = show
        .lines()
        .find_map(|l| l.trim().strip_prefix("Controller "))
        .and_then(|x| x.split_whitespace().next())
        .unwrap_or("")
        .to_string();
    let powered = show.lines().any(|l| l.trim() == "Powered: yes");
    let needs_sudo =
        ssh::looks_like_permission_error(show) || ssh::looks_like_permission_error(&scan_errors);
    let note = if adapter.is_empty() {
        let detail = show
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let detail = if detail.is_empty() {
            "bluetoothctl show 没有输出".to_string()
        } else {
            detail
        };
        Some(format!(
            "无法读取蓝牙适配器（{detail}）。{}",
            bt_problem_hint(&detail)
        ))
    } else if !scan_errors.is_empty() {
        Some(format!(
            "扫描未完成（{}）。{}",
            scan_errors.replace('\n', " "),
            bt_problem_hint(&scan_errors)
        ))
    } else {
        None
    };
    BluetoothSnapshot {
        available: !adapter.is_empty(),
        powered,
        adapter,
        devices: parse_bt_info(info),
        note,
        needs_sudo,
    }
}

fn bluetooth_parts(
    state: &AppState,
    target: &Target,
    scan: bool,
    sudo_password: &Option<String>,
) -> Result<BluetoothSnapshot, String> {
    let script = format!(
        "{BT_SCRIPT_HEAD}{}{BT_SCRIPT_TAIL}",
        if scan { BT_SCAN } else { "" }
    );
    let mut options = sudo_options(sudo_password);
    options.timeout_secs = Some(25);
    let output = ssh::remote_command_with(state, target, &script, options)?;
    Ok(parse_bluetooth_output(&output))
}

#[tauri::command(async)]
pub fn get_bluetooth_snapshot(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<BluetoothSnapshot, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    bluetooth_parts(&state, &target, false, &None)
}

#[tauri::command(async)]
pub fn scan_bluetooth(
    state: State<'_, AppState>,
    target_id: String,
    sudo_password: Option<String>,
) -> Result<BluetoothSnapshot, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    bluetooth_parts(&state, &target, true, &sudo_password)
}

#[tauri::command(async)]
pub fn set_bluetooth_power(
    state: State<'_, AppState>,
    target_id: String,
    enabled: bool,
    sudo_password: Option<String>,
) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let power = if enabled { "on" } else { "off" };
    let output = ssh::remote_command_with(
        &state,
        &target,
        &format!("bluetoothctl power {power} 2>&1"),
        sudo_options(&sudo_password),
    )?;
    bluetoothctl_result(&output)?;
    Ok(())
}

#[tauri::command(async)]
pub fn bluetooth_action(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    address: String,
    action: String,
    sudo_password: Option<String>,
) -> Result<Option<String>, String> {
    validate_mac(&address)?;
    let target = ssh::lookup_target(&state, &target_id)?;
    let mac = address.to_ascii_uppercase();
    match action.as_str() {
        "pair" => Ok(Some(ssh::start_terminal(
            &app,
            &state,
            &target,
            Some(&with_sudo_retry(&format!(
                "bluetoothctl pair {}",
                ssh::shell_quote(&mac)
            ))),
        )?)),
        "connect" | "disconnect" | "remove" | "trust" => {
            let output = ssh::remote_command_with(
                &state,
                &target,
                &format!("bluetoothctl {} {} 2>&1", action, ssh::shell_quote(&mac)),
                sudo_options(&sudo_password),
            )?;
            bluetoothctl_result(&output)?;
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

fn parse_alsa_devices(text: &str, direction: &str) -> Vec<AudioDevice> {
    let mut seen = HashSet::new();
    text.lines()
        .filter_map(|line| {
            let (index, details) = line.split_once(": ")?;
            let (card, device) = index.split_once('-')?;
            let card = card.parse::<u32>().ok()?;
            let device = device.parse::<u32>().ok()?;
            let mut fields = details.split(" : ");
            let description = fields.next()?.trim();
            let has_direction = fields.any(|field| {
                field
                    .strip_prefix(direction)
                    .and_then(|count| count.split_whitespace().next())
                    .and_then(|count| count.parse::<u32>().ok())
                    .is_some_and(|count| count > 0)
            });
            if description.is_empty() || !has_direction {
                return None;
            }
            let name = format!("hw:{card},{device}");
            if !seen.insert(name.clone()) {
                return None;
            }
            Some(AudioDevice {
                name,
                description: description.to_string(),
                is_default: false,
            })
        })
        .collect()
}

#[tauri::command(async)]
pub fn get_audio_snapshot(
    state: State<'_, AppState>,
    target_id: String,
) -> Result<AudioSnapshot, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let script = r#"
if command -v pactl >/dev/null 2>&1; then
  printf 'PULSE_AVAILABLE=1\n'
  printf 'SINK_DEFAULT='; pactl get-default-sink 2>/dev/null || true
  printf '\nSOURCE_DEFAULT='; pactl get-default-source 2>/dev/null || true
  printf '\nSINK_VOLUME='; pactl get-sink-volume @DEFAULT_SINK@ 2>/dev/null | grep -oE '[0-9]+%' | head -n 1 | tr -d '%' || true
  printf '\nSOURCE_VOLUME='; pactl get-source-volume @DEFAULT_SOURCE@ 2>/dev/null | grep -oE '[0-9]+%' | head -n 1 | tr -d '%' || true
  printf '\nSINKS\n'; pactl list short sinks 2>/dev/null || true
  printf '\nSOURCES\n'; pactl list short sources 2>/dev/null || true
else
  printf 'PULSE_AVAILABLE=0\n'
fi
printf '\nALSA_PCM\n'
if [ -r /proc/asound/pcm ]; then cat /proc/asound/pcm; else printf 'UNAVAILABLE\n'; fi
"#;
    let output = ssh::remote_command(&state, &target, script)?;
    let (pulse_output, alsa_output) = output
        .split_once("\nALSA_PCM\n")
        .unwrap_or((output.as_str(), ""));
    let pulse_available = pulse_output
        .lines()
        .any(|line| line.trim() == "PULSE_AVAILABLE=1");
    let alsa_playback = parse_alsa_devices(alsa_output, "playback");
    let alsa_capture = parse_alsa_devices(alsa_output, "capture");
    let sink_default = pulse_output
        .lines()
        .find_map(|l| l.strip_prefix("SINK_DEFAULT="))
        .unwrap_or("");
    let source_default = pulse_output
        .lines()
        .find_map(|l| l.strip_prefix("SOURCE_DEFAULT="))
        .unwrap_or("");
    let sink_volume = pulse_output
        .lines()
        .find_map(|l| l.strip_prefix("SINK_VOLUME="))
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.min(150));
    let source_volume = pulse_output
        .lines()
        .find_map(|l| l.strip_prefix("SOURCE_VOLUME="))
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.min(150));
    let sinks_part = pulse_output
        .split_once("SINKS\n")
        .map(|(_, r)| r.split_once("\nSOURCES\n").map(|(a, _)| a).unwrap_or(r))
        .unwrap_or("");
    let sources_part = pulse_output
        .split_once("\nSOURCES\n")
        .map(|(_, r)| r)
        .unwrap_or("");
    Ok(AudioSnapshot {
        available: pulse_available,
        sinks: if pulse_available {
            parse_pactl_devices(sinks_part, sink_default)
        } else {
            vec![]
        },
        sources: if pulse_available {
            parse_pactl_devices(sources_part, source_default)
        } else {
            vec![]
        },
        alsa_playback,
        alsa_capture,
        default_sink_volume: sink_volume,
        default_source_volume: source_volume,
        note: if pulse_available {
            None
        } else {
            Some("未发现可用的 PulseAudio/PipeWire pactl 接口；以下 ALSA 硬件仅供识别，不能通过此页切换默认设备或调节音量。".into())
        },
    })
}

#[tauri::command(async)]
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

#[tauri::command(async)]
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

#[tauri::command(async)]
pub fn play_test_audio(state: State<'_, AppState>, target_id: String) -> Result<(), String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::remote_command(&state, &target, "command -v speaker-test >/dev/null 2>&1 || { echo '机器人未安装 alsa-utils/speaker-test'; exit 127; }; timeout 4s speaker-test -t sine -f 440 -l 1")?;
    Ok(())
}

#[tauri::command(async)]
pub fn open_ssh_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
) -> Result<String, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    ssh::start_terminal(&app, &state, &target, None)
}

#[tauri::command(async)]
pub fn send_terminal_input(
    state: State<'_, AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    ssh::send_terminal_input(&state, &session_id, &data)
}

#[tauri::command(async)]
pub fn resize_terminal(
    state: State<'_, AppState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    ssh::resize_terminal(&state, &session_id, cols, rows)
}

#[tauri::command(async)]
pub fn close_ssh_terminal(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    ssh::close_terminal(&state, &session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wifi_scan_keeps_cached_rows_when_rescan_is_refused() {
        let ok = parse_wifi_scan("APS\n*:Lab\\:Robot:80:WPA2\n:Guest:40:\n");
        assert_eq!(ok.networks.len(), 2);
        assert!(ok.warning.is_none());
        let denied = parse_wifi_scan(
            "RESCAN_ERR Error: Scanning not allowed: Not authorized to request a Wi-Fi scan.\nAPS\n:Guest:40:\n",
        );
        assert_eq!(denied.networks.len(), 1);
        assert!(denied.needs_sudo);
        let w = denied.warning.unwrap();
        assert!(w.contains("缓存") && w.contains("sudo 密码"));
        assert!(!parse_wifi_scan("RESCAN_ERR Error: Scanning not allowed immediately following previous scan.\nAPS\n").needs_sudo);
    }

    #[test]
    fn bluetooth_output_reports_permission_problems_instead_of_powered_off() {
        let denied = parse_bluetooth_output(
            "SHOW\nAccess denied: org.freedesktop.DBus.Error.AccessDenied\n\nINFO\n",
        );
        assert!(!denied.available);
        assert!(denied.note.unwrap().contains("bluetooth 组"));
        let none = parse_bluetooth_output("SHOW\nNo default controller available\n\nINFO\n");
        assert!(none.note.unwrap().contains("没有可用的蓝牙适配器"));
        let ok = parse_bluetooth_output(
            "SCAN\n\nSHOW\nController AA:BB:CC:DD:EE:FF (public)\n\tPowered: yes\n\nINFO\n@@DEV 11:22:33:44:55:66\nDevice 11:22:33:44:55:66 (public)\n\tName: Speaker\n\tPaired: yes\n\tConnected: yes\n@@DEV 77:88:99:AA:BB:CC\nDevice 77:88:99:AA:BB:CC\n\tAlias: 77-88\n\tPaired: no\n",
        );
        assert!(ok.available && ok.powered && ok.note.is_none());
        assert_eq!(ok.adapter, "AA:BB:CC:DD:EE:FF");
        assert_eq!(ok.devices.len(), 2);
        assert_eq!(ok.devices[0].name, "Speaker");
        assert!(ok.devices[0].paired && ok.devices[0].connected);
        assert!(!ok.devices[1].paired);
        let scan_failed = parse_bluetooth_output(
            "SCAN\nFailed to start discovery: org.bluez.Error.NotReady\nSHOW\nController AA:BB:CC:DD:EE:FF (public)\n\tPowered: yes\n\nINFO\n",
        );
        assert!(scan_failed.note.unwrap().contains("扫描未完成"));
    }

    #[test]
    fn wifi_password_is_only_taken_from_the_marked_line() {
        // Simulate the stdin RoboLink sends when sudo does not read its password line (NOPASSWD).
        let script = "WP=''; while IFS= read -r L; do case \"$L\" in SECRET:*) WP=${L#SECRET:}; break;; esac; done; printf '%s' \"$WP\"";
        let out = std::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(b"sudo-pass\nSECRET:wifi pass\n")?;
                child.wait_with_output()
            })
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "wifi pass");
    }

    #[test]
    fn sudo_retry_wraps_interactive_command_once() {
        let s = with_sudo_retry("nmcli --ask device wifi connect 'Lab'");
        assert!(s.starts_with("nmcli --ask device wifi connect 'Lab'; rc=$?"));
        assert!(s.contains("read _ && sudo nmcli --ask device wifi connect 'Lab'; fi"));
    }

    #[test]
    fn nmcli_escaped_fields_parse_without_splitting_ssid_colons() {
        let fields = parse_nmcli("*:Lab\\:Robot:80:WPA2");
        assert_eq!(fields, vec!["*", "Lab:Robot", "80", "WPA2"]);
    }

    #[test]
    fn scan_port_accepts_default_custom_and_maximum_ports() {
        assert!(validate_scan_port(0).is_err());
        assert!(validate_scan_port(22).is_ok());
        assert!(validate_scan_port(2222).is_ok());
        assert!(validate_scan_port(u16::MAX).is_ok());
    }

    #[test]
    fn system_authorization_and_network_operation_failures_are_distinguished() {
        assert!(network_helper_failure(Some(126), "").contains("系统授权未完成"));
        assert!(
            network_helper_failure(Some(1), "enx00e04c3071f5 当前没有物理链路")
                .contains("网络操作失败（系统授权已通过）")
        );
        assert!(
            network_helper_failure(Some(1), "enx00e04c3071f5 当前没有物理链路")
                .contains("当前没有物理链路")
        );
        assert!(network_helper_failure(Some(1), "Not authorized").contains("系统授权未完成"));
        assert!(network_helper_failure(
            Some(1),
            "ROBOLINK_NETWORK_OPERATION: Not authorized in network setup"
        )
        .contains("系统授权已通过"));
        assert!(network_helper_failure(Some(126), "").contains("系统授权未完成"));
        assert!(network_helper_failure(Some(127), "").contains("网络助手无法启动"));
    }

    #[test]
    fn temporary_address_requires_same_subnet_and_host_addresses() {
        assert!(
            validate_temporary_cidr("192.168.127.1/24", Ipv4Addr::new(192, 168, 127, 2)).is_ok()
        );
        assert!(
            validate_temporary_cidr("192.168.127.1/24", Ipv4Addr::new(192, 168, 128, 2)).is_err()
        );
        assert!(
            validate_temporary_cidr("192.168.127.1/24", Ipv4Addr::new(192, 168, 127, 255)).is_err()
        );
        assert!(
            validate_temporary_cidr("192.168.127.0/24", Ipv4Addr::new(192, 168, 127, 2)).is_err()
        );
    }

    #[test]
    fn subnet_discovery_includes_neighbor_ips_without_requiring_port_open() {
        let rows: Vec<Value> = serde_json::from_str(
            r#"[
          {"dst":"192.168.77.2","dev":"enp3s0","state":["REACHABLE"]},
          {"dst":"192.168.77.2","dev":"enp3s0","state":["STALE"]},
          {"dst":"192.168.77.3","dev":"wlan0","state":["REACHABLE"]},
          {"dst":"192.168.77.4","dev":"enp3s0","state":["INCOMPLETE"]},
          {"dst":"192.168.77.5","dev":"enp3s0","state":"FAILED"}
        ]"#,
        )
        .unwrap();
        let found = interface_neighbors(&rows, "enp3s0");
        assert_eq!(found, vec![Ipv4Addr::new(192, 168, 77, 2)]);
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

    #[test]
    fn alsa_pcm_listing_is_split_by_playback_and_capture_direction() {
        let pcm = "00-00: HDMI Audio : playback 1 : capture 0\n\
                   00-01: USB Audio : playback 0 : capture 1\n\
                   01-00: Built-in Codec : playback 1 : capture 1\n\
                   02-00: Disabled Device : playback 0 : capture 0\n\
                   malformed pcm entry";
        let playback = parse_alsa_devices(pcm, "playback");
        let capture = parse_alsa_devices(pcm, "capture");
        assert_eq!(playback.len(), 2);
        assert_eq!(playback[0].name, "hw:0,0");
        assert_eq!(playback[1].name, "hw:1,0");
        assert!(playback.iter().all(|device| !device.is_default));
        assert_eq!(capture.len(), 2);
        assert_eq!(capture[0].name, "hw:0,1");
        assert_eq!(capture[1].name, "hw:1,0");
    }
}
