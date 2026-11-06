use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArpCandidate {
    interface: String,
    address: String,
    mac: String,
    source: String,
    confidence: String,
}

#[derive(Debug, Clone, Copy)]
struct ArpPacket {
    operation: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("网络助手必须由系统授权弹窗运行。".into());
    }
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("discover") => {
            let seconds = args
                .next()
                .ok_or("缺少监听时长")?
                .parse::<u64>()
                .map_err(|_| "监听时长无效")?;
            if !(3..=30).contains(&seconds) {
                return Err("监听时长必须为 3–30 秒".into());
            }
            let interfaces = args.collect::<Vec<_>>();
            if interfaces.is_empty() || interfaces.len() > 16 {
                return Err("需要 1–16 个已连接的有线网口".into());
            }
            let rows = discover(seconds, &interfaces)?;
            println!(
                "{}",
                serde_json::to_string(&rows).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Some("add-address") => {
            let interface = args.next().ok_or("缺少网卡名")?;
            let cidr = args.next().ok_or("缺少本机 IPv4/CIDR")?;
            let peer = args.next().ok_or("缺少已发现的对端 IPv4")?;
            if args.next().is_some() {
                return Err("参数过多".into());
            }
            add_address(&interface, &cidr, &peer)
        }
        Some("remove-address") => {
            let interface = args.next().ok_or("缺少网卡名")?;
            let cidr = args.next().ok_or("缺少本机 IPv4/CIDR")?;
            if args.next().is_some() {
                return Err("参数过多".into());
            }
            remove_address(&interface, &cidr)
        }
        _ => Err("不支持的网络助手操作".into()),
    }
}

fn validate_ifname(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 15
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        return Err("网卡名称格式无效".into());
    }
    Ok(())
}

fn physical_ethernet(name: &str, require_link: bool) -> Result<(), String> {
    validate_ifname(name)?;
    let root = std::path::Path::new("/sys/class/net").join(name);
    let kind = fs::read_to_string(root.join("type")).map_err(|_| format!("网卡 {name} 不存在"))?;
    if kind.trim() != "1" || !root.join("device").exists() || root.join("wireless").exists() {
        return Err(format!("{name} 不是物理有线网卡"));
    }
    if require_link {
        let flags = fs::read_to_string(root.join("flags")).unwrap_or_default();
        let flags = flags.trim().trim_start_matches("0x");
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        let carrier = fs::read_to_string(root.join("carrier"))
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        if flags & 0x1_0000 == 0 || !carrier {
            return Err(format!("{name} 已没有物理链路，请刷新网卡列表后重试"));
        }
    }
    Ok(())
}

fn interface_mac(name: &str) -> Result<[u8; 6], String> {
    let text = fs::read_to_string(
        std::path::Path::new("/sys/class/net")
            .join(name)
            .join("address"),
    )
    .map_err(|e| format!("读取 {name} 的 MAC 地址失败：{e}"))?;
    parse_mac(text.trim()).ok_or_else(|| format!("{name} 的 MAC 地址格式无效"))
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut bytes = [0_u8; 6];
    let parts = text.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return None;
    }
    for (slot, part) in bytes.iter_mut().zip(parts) {
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|part| format!("{part:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn arp_socket(interface: &str) -> Result<OwnedFd, String> {
    physical_ethernet(interface, true)?;
    let name = CString::new(interface).map_err(|_| "网卡名称无效")?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(format!("无法读取 {interface} 的内核接口编号"));
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::htons(0x0806) as i32,
        )
    };
    if raw < 0 {
        return Err(format!("无法监听 ARP：{}", std::io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = libc::htons(0x0806);
    address.sll_ifindex = index as i32;
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(format!(
            "绑定 ARP 监听网卡失败：{}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

fn discover(seconds: u64, interfaces: &[String]) -> Result<Vec<ArpCandidate>, String> {
    let mut sockets = Vec::new();
    let mut own_macs = HashMap::new();
    for interface in interfaces {
        physical_ethernet(interface, true)?;
        let socket = arp_socket(interface)?;
        own_macs.insert(interface.clone(), interface_mac(interface)?);
        sockets.push((interface.clone(), socket));
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut candidates: HashMap<(String, String, String), ArpCandidate> = HashMap::new();
    let mut buffer = [0_u8; 2048];
    while Instant::now() < deadline {
        let mut pollfds = sockets
            .iter()
            .map(|(_, socket)| libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = remaining.as_millis().min(250) as i32;
        let ready = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("ARP 监听失败：{error}"));
        }
        for (index, pollfd) in pollfds.iter().enumerate() {
            if pollfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let count = unsafe {
                libc::recv(
                    sockets[index].1.as_raw_fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if count <= 0 {
                continue;
            }
            let Some(packet) = parse_arp(&buffer[..count as usize]) else {
                continue;
            };
            if packet.sender_mac == own_macs[&sockets[index].0] {
                continue;
            }
            let (address, source, confidence) = if packet.sender_ip != Ipv4Addr::UNSPECIFIED
                && !packet.sender_ip.is_multicast()
                && packet.sender_ip != Ipv4Addr::BROADCAST
            {
                let label = match packet.operation {
                    2 => "ARP 应答中的源地址",
                    1 if packet.sender_ip == packet.target_ip => "免费 ARP",
                    _ => "ARP 请求中的源地址",
                };
                (packet.sender_ip, label, "较高")
            } else if packet.operation == 1
                && packet.sender_ip == Ipv4Addr::UNSPECIFIED
                && packet.target_ip != Ipv4Addr::UNSPECIFIED
                && !packet.target_ip.is_multicast()
                && packet.target_ip != Ipv4Addr::BROADCAST
            {
                (packet.target_ip, "ARP 地址探测目标", "候选")
            } else {
                continue;
            };
            let mac = format_mac(packet.sender_mac);
            let row = ArpCandidate {
                interface: sockets[index].0.clone(),
                address: address.to_string(),
                mac: mac.clone(),
                source: source.into(),
                confidence: confidence.into(),
            };
            let key = (row.interface.clone(), row.address.clone(), row.mac.clone());
            if candidates.len() < 2048 || candidates.contains_key(&key) {
                candidates
                    .entry(key)
                    .and_modify(|previous| {
                        if confidence == "较高" {
                            *previous = row.clone();
                        }
                    })
                    .or_insert(row);
            }
        }
    }
    let mut result = candidates.into_values().collect::<Vec<_>>();
    result.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then_with(|| a.address.cmp(&b.address))
            .then_with(|| a.mac.cmp(&b.mac))
    });
    Ok(result)
}

fn parse_arp(frame: &[u8]) -> Option<ArpPacket> {
    if frame.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type == 0x8100 || ether_type == 0x88a8 {
        if frame.len() < 18 {
            return None;
        }
        ether_type = u16::from_be_bytes([frame[16], frame[17]]);
        offset = 18;
    }
    if ether_type != 0x0806 || frame.len() < offset + 28 {
        return None;
    }
    let arp = &frame[offset..offset + 28];
    if u16::from_be_bytes([arp[0], arp[1]]) != 1
        || u16::from_be_bytes([arp[2], arp[3]]) != 0x0800
        || arp[4] != 6
        || arp[5] != 4
    {
        return None;
    }
    let operation = u16::from_be_bytes([arp[6], arp[7]]);
    if operation != 1 && operation != 2 {
        return None;
    }
    Some(ArpPacket {
        operation,
        sender_mac: arp[8..14].try_into().ok()?,
        sender_ip: Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]),
        target_ip: Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]),
    })
}

fn ip_command(args: &[&str]) -> Result<std::process::Output, String> {
    let executable = if std::path::Path::new("/usr/sbin/ip").exists() {
        "/usr/sbin/ip"
    } else {
        "/sbin/ip"
    };
    Command::new(executable)
        .args(args)
        .output()
        .map_err(|e| format!("无法运行 iproute2：{e}"))
}

fn parse_cidr(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or("IPv4 地址必须带前缀长度，例如 192.168.127.1/24")?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| "本机 IPv4 地址格式无效")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "IPv4 前缀长度无效")?;
    if !(1..=30).contains(&prefix)
        || address.is_unspecified()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return Err("仅支持非特殊 IPv4 地址和 /1–/30 前缀".into());
    }
    let host_mask = !(u32::MAX << (32 - prefix));
    if u32::from(address) & host_mask == 0 || u32::from(address) & host_mask == host_mask {
        return Err("本机地址不能是所选子网的网络地址或广播地址".into());
    }
    Ok((address, prefix))
}

fn network(ip: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask, mask)
}

fn networks_overlap(a: Ipv4Addr, a_prefix: u8, b: Ipv4Addr, b_prefix: u8) -> bool {
    let (a_network, a_mask) = network(a, a_prefix);
    let (b_network, b_mask) = network(b, b_prefix);
    a_network & b_mask == b_network || b_network & a_mask == a_network
}

fn check_route_conflicts(interface: &str, local: Ipv4Addr, prefix: u8) -> Result<(), String> {
    let routes = ip_command(&["-json", "-4", "route", "show", "table", "main"])?;
    if !routes.status.success() {
        return Err("无法读取本机路由表；为避免影响其他网络，未添加地址".into());
    }
    let rows: serde_json::Value =
        serde_json::from_slice(&routes.stdout).map_err(|e| format!("解析本机路由表失败：{e}"))?;
    for row in rows.as_array().into_iter().flatten() {
        let dev = row
            .get("dev")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let destination = row
            .get("dst")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("default");
        if dev == interface || destination == "default" {
            continue;
        }
        let (route_ip, route_prefix) = if let Some((ip, prefix)) = destination.split_once('/') {
            match (ip.parse::<Ipv4Addr>(), prefix.parse::<u8>()) {
                (Ok(ip), Ok(prefix)) if prefix <= 32 => (ip, prefix),
                _ => continue,
            }
        } else if let Ok(ip) = destination.parse::<Ipv4Addr>() {
            (ip, 32)
        } else {
            continue;
        };
        if networks_overlap(local, prefix, route_ip, route_prefix) {
            return Err(format!("新地址所在网段与现有 {dev} 路由 {destination} 重叠。为避免走错网卡，RoboLink 没有改动网络。"));
        }
    }
    Ok(())
}

fn duplicate_address_probe(interface: &str, address: Ipv4Addr) -> Result<bool, String> {
    let socket = arp_socket(interface)?;
    let name = CString::new(interface).map_err(|_| "网卡名称无效")?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    let mac = interface_mac(interface)?;
    let mut frame = [0_u8; 42];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
    frame[38..42].copy_from_slice(&address.octets());
    let mut destination: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    destination.sll_family = libc::AF_PACKET as u16;
    destination.sll_protocol = libc::htons(0x0806);
    destination.sll_ifindex = index as i32;
    destination.sll_halen = 6;
    destination.sll_addr[..6].fill(0xff);
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &destination as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent != frame.len() as isize {
        return Err(format!(
            "无法检查本机地址是否冲突：{}",
            std::io::Error::last_os_error()
        ));
    }
    let deadline = Instant::now() + Duration::from_millis(1100);
    let mut buffer = [0_u8; 2048];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut pollfd = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, remaining.as_millis().min(200) as i32) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("本机地址冲突检查失败：{error}"));
        }
        if pollfd.revents & libc::POLLIN == 0 {
            continue;
        }
        let count = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count <= 0 {
            continue;
        }
        if let Some(packet) = parse_arp(&buffer[..count as usize]) {
            if packet.sender_mac != mac
                && (packet.sender_ip == address
                    || (packet.sender_ip == Ipv4Addr::UNSPECIFIED && packet.target_ip == address))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn all_ipv4_addresses() -> Result<Vec<(String, Ipv4Addr, u8)>, String> {
    let output = ip_command(&["-json", "-4", "address", "show"])?;
    if !output.status.success() {
        return Err("无法读取当前 IPv4 地址列表".into());
    }
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("解析 IPv4 地址列表失败：{e}"))?;
    let mut result = Vec::new();
    for row in rows.as_array().into_iter().flatten() {
        let name = row
            .get("ifname")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        for address in row
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if address.get("family").and_then(serde_json::Value::as_str) != Some("inet") {
                continue;
            }
            if let (Some(local), Some(prefix)) = (
                address.get("local").and_then(serde_json::Value::as_str),
                address.get("prefixlen").and_then(serde_json::Value::as_u64),
            ) {
                if let (Ok(ip), Ok(prefix)) = (local.parse::<Ipv4Addr>(), u8::try_from(prefix)) {
                    result.push((name.to_string(), ip, prefix));
                }
            }
        }
    }
    Ok(result)
}

fn add_address(interface: &str, cidr: &str, peer_text: &str) -> Result<(), String> {
    physical_ethernet(interface, true)?;
    let (local, prefix) = parse_cidr(cidr)?;
    let peer = peer_text
        .parse::<Ipv4Addr>()
        .map_err(|_| "开发板候选 IPv4 格式无效")?;
    if peer == local || peer.is_unspecified() || peer.is_multicast() || peer == Ipv4Addr::BROADCAST
    {
        return Err("本机地址与开发板候选地址不匹配".into());
    }
    let host_mask = !(u32::MAX << (32 - prefix));
    if u32::from(peer) & host_mask == 0 || u32::from(peer) & host_mask == host_mask {
        return Err("开发板候选地址不能是所选子网的网络地址或广播地址".into());
    }
    if network(local, prefix).0 != network(peer, prefix).0 {
        return Err(format!("本机地址 {cidr} 与候选设备 {peer} 不在同一网段。前缀长度是用户选择的假设，请调整后再试。"));
    }
    let current = all_ipv4_addresses()?;
    if let Some((dev, _, _)) = current.iter().find(|(_, ip, _)| *ip == local) {
        return Err(format!(
            "本机 IPv4 {local} 已由网卡 {dev} 使用；RoboLink 不会接管或覆盖现有地址。"
        ));
    }
    check_route_conflicts(interface, local, prefix)?;
    if duplicate_address_probe(interface, local)? {
        return Err(format!("检测到其他设备正在使用本机候选地址 {local}。没有添加该地址；请在窗口里选择另一个地址。"));
    }
    let cidr_arg = format!("{local}/{prefix}");
    let output = ip_command(&["address", "add", &cidr_arg, "dev", interface])?;
    if !output.status.success() {
        return Err(format!(
            "添加临时 IPv4 地址失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let route = ip_command(&["-4", "route", "get", &peer.to_string()])?;
    let route_text = String::from_utf8_lossy(&route.stdout);
    if !route.status.success()
        || !route_text
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] == "dev" && pair[1] == interface)
    {
        let _ = ip_command(&["address", "del", &cidr_arg, "dev", interface]);
        return Err(
            "添加后路由检查没有指向选定网卡；已撤销刚添加的地址，其他网络未作更改。".into(),
        );
    }
    println!("已在 {interface} 添加临时地址 {cidr_arg}；默认路由、DNS、Wi‑Fi 和机器人端配置未修改。目标前缀 /{prefix} 为用户选择的假设。{peer}");
    Ok(())
}

fn remove_address(interface: &str, cidr: &str) -> Result<(), String> {
    validate_ifname(interface)?;
    let (address, prefix) = parse_cidr(cidr)?;
    let current = all_ipv4_addresses()?;
    let exact = current
        .iter()
        .any(|(dev, ip, bits)| dev == interface && *ip == address && *bits == prefix);
    if !exact {
        println!("{interface} 上已不存在 {cidr}，无需清理。\n");
        return Ok(());
    }
    physical_ethernet(interface, false)?;
    let cidr_arg = format!("{address}/{prefix}");
    let output = ip_command(&["address", "del", &cidr_arg, "dev", interface])?;
    if !output.status.success() {
        return Err(format!(
            "移除应用记录的临时地址失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    println!("已从 {interface} 移除应用记录的临时地址 {cidr_arg}；其他地址和默认路由未修改。\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_frame(operation: u16, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0_u8; 42];
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&operation.to_be_bytes());
        frame[22..28].copy_from_slice(&[0x64, 0xb4, 0xe8, 0x10, 0x15, 0x46]);
        frame[28..32].copy_from_slice(&sender_ip.octets());
        frame[38..42].copy_from_slice(&target_ip.octets());
        frame
    }

    #[test]
    fn parses_arp_sender_and_probe_target_without_conflating_them() {
        let sender = parse_arp(&arp_frame(
            1,
            Ipv4Addr::new(192, 168, 127, 10),
            Ipv4Addr::new(192, 168, 127, 10),
        ))
        .unwrap();
        assert_eq!(sender.sender_ip, Ipv4Addr::new(192, 168, 127, 10));
        let probe = parse_arp(&arp_frame(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 168, 127, 10),
        ))
        .unwrap();
        assert_eq!(probe.sender_ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(probe.target_ip, Ipv4Addr::new(192, 168, 127, 10));
    }

    #[test]
    fn route_overlap_checker_respects_prefixes() {
        assert!(networks_overlap(
            "192.168.127.1".parse().unwrap(),
            24,
            "192.168.127.0".parse().unwrap(),
            24
        ));
        assert!(!networks_overlap(
            "192.168.127.1".parse().unwrap(),
            24,
            "192.168.128.0".parse().unwrap(),
            24
        ));
        assert!(networks_overlap(
            "192.168.127.1".parse().unwrap(),
            24,
            "192.168.0.0".parse().unwrap(),
            16
        ));
    }
}
