use crate::model::*;
use crate::ssh;
use crate::state::{AppState, OwnedNetworkAddress};
use serde::Deserialize;
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
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
        let lower_up = row
            .get("flags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|flag| flag == "LOWER_UP");
        let carrier = fs::read_to_string(sys.join("carrier"))
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
            && lower_up;
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
        return Err(if detail.is_empty() {
            "系统授权未完成，网络操作没有执行。".into()
        } else {
            format!("系统授权未完成或网络操作失败：{detail}")
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn route_uses_interface(address: Ipv4Addr, interface: &str) -> bool {
    let output = Command::new("ip")
        .args(["-4", "route", "get", &address.to_string()])
        .output();
    let Ok(output) = output else { return false };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] == "dev" && pair[1] == interface)
}

#[tauri::command]
pub fn scan_direct_interfaces(port: u16) -> Result<Vec<DiscoveredHost>, String> {
    validate_scan_port(port)?;
    let host_info = get_host_info()?;
    let interfaces = host_info
        .interfaces
        .iter()
        .filter(|iface| iface.kind == "有线以太网" && iface.carrier)
        .map(|iface| iface.name.clone())
        .collect::<Vec<_>>();
    if interfaces.is_empty() {
        return Err(
            "没有检测到 LOWER_UP 的物理有线网口。请插好网线、检查机器人电源，再刷新网卡列表。"
                .into(),
        );
    }
    let mut arguments = vec!["discover".to_string(), "8".to_string()];
    arguments.extend(interfaces.iter().cloned());
    let output = run_network_helper(&arguments)?;
    let candidates: Vec<PassiveArpCandidate> =
        serde_json::from_str(&output).map_err(|e| format!("解析 ARP 发现结果失败：{e}"))?;
    let mut result = candidates
        .into_iter()
        .take(2048)
        .map(|candidate| {
            let address = candidate.address.parse::<Ipv4Addr>().ok();
            let route_ready = address
                .map(|ip| route_uses_interface(ip, &candidate.interface))
                .unwrap_or(false);
            let port_open = if route_ready {
                let Some(ip) = address else {
                    return DiscoveredHost {
                        address: candidate.address,
                        interface: candidate.interface,
                        mac: candidate.mac,
                        port,
                        port_open: false,
                        route_ready: false,
                        source: candidate.source,
                        confidence: candidate.confidence,
                    };
                };
                TcpStream::connect_timeout(
                    &SocketAddrV4::new(ip, port).into(),
                    Duration::from_millis(400),
                )
                .is_ok()
            } else {
                false
            };
            DiscoveredHost {
                address: candidate.address,
                interface: candidate.interface,
                mac: candidate.mac,
                port,
                port_open,
                route_ready,
                source: candidate.source,
                confidence: candidate.confidence,
            }
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then_with(|| a.address.cmp(&b.address))
            .then_with(|| a.mac.cmp(&b.mac))
    });
    Ok(result)
}

#[tauri::command]
pub fn list_owned_network_addresses(
    state: State<'_, AppState>,
) -> Result<Vec<OwnedNetworkAddress>, String> {
    state.load_network_addresses()
}

#[tauri::command]
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

#[tauri::command]
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

#[tauri::command]
pub fn cleanup_session_network_addresses(
    state: State<'_, AppState>,
) -> Result<Vec<OwnedNetworkAddress>, String> {
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

#[tauri::command]
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

#[tauri::command]
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
    fn scan_port_accepts_default_custom_and_maximum_ports() {
        assert!(validate_scan_port(0).is_err());
        assert!(validate_scan_port(22).is_ok());
        assert!(validate_scan_port(2222).is_ok());
        assert!(validate_scan_port(u16::MAX).is_ok());
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
