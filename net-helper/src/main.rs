mod dhcp;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    arp_reachable: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
struct ArpPacket {
    operation: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ROBOLINK_NETWORK_OPERATION: {error}");
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
            let next = args.next().ok_or("缺少发现选项或网卡名")?;
            let (options, first_interface) = if next.trim_start().starts_with('{') {
                (
                    serde_json::from_str::<DiscoverOptions>(&next)
                        .map_err(|e| format!("发现选项无效：{e}"))?,
                    None,
                )
            } else {
                (DiscoverOptions::legacy(), Some(next))
            };
            let mut interfaces = first_interface.into_iter().collect::<Vec<_>>();
            interfaces.extend(args);
            if interfaces.is_empty() || interfaces.len() > 16 {
                return Err("需要 1–16 个有线网口".into());
            }
            let result = discover(seconds, &interfaces, &options)?;
            println!(
                "{}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Some(action @ ("dhcp-start" | "dhcp-stop" | "dhcp-status")) => {
            dhcp::run(action, args.collect())
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
    if require_link && !interface_has_carrier(name)? {
        return Err(format!(
            "{name} 当前没有物理链路，请检查网线和设备电源后重试"
        ));
    }
    Ok(())
}

fn interface_has_carrier(name: &str) -> Result<bool, String> {
    let path = std::path::Path::new("/sys/class/net")
        .join(name)
        .join("carrier");
    let value =
        fs::read_to_string(&path).map_err(|e| format!("无法读取 {name} 的物理链路状态：{e}"))?;
    parse_carrier_state(&value).map_err(|_| format!("{name} 的物理链路状态值无效"))
}

fn parse_carrier_state(value: &str) -> Result<bool, ()> {
    match value.trim() {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(()),
    }
}

#[cfg(test)]
fn interfaces_with_carrier<F>(
    interfaces: &[String],
    mut has_carrier: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&str) -> Result<bool, String>,
{
    let mut linked = Vec::new();
    for interface in interfaces {
        if has_carrier(interface)? {
            linked.push(interface.clone());
        }
    }
    Ok(linked)
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

#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DiscoverOptions {
    passive_arp: bool,
    passive_dhcp: bool,
    passive_ipv6: bool,
    mdns: bool,
    active_arp: bool,
    icmp: bool,
    tcp: bool,
    ipv4_link_local: bool,
    ipv6_link_local: bool,
    /// Actively sweep the subnets of the interface plus common development-board defaults.
    arp_sweep: bool,
    /// Additionally sweep all of 192.168.0.0/16 (and 169.254/16 with IPv4 link-local) on interfaces
    /// that do not carry a default route, i.e. look like a point-to-point cable.
    arp_sweep_deep: bool,
}
impl DiscoverOptions {
    fn legacy() -> Self {
        Self {
            passive_arp: true,
            ..Self::default()
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryResult {
    candidates: Vec<ArpCandidate>,
    skipped_interfaces: Vec<String>,
    warnings: Vec<String>,
}
#[derive(Debug, Clone, Copy)]
struct Ipv6Packet {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload_offset: usize,
    payload_end: usize,
}
#[derive(Debug, Clone, Copy)]
struct DhcpCandidate {
    address: Ipv4Addr,
}

fn arp_socket(interface: &str) -> Result<OwnedFd, String> {
    physical_ethernet(interface, false)?;
    let name = CString::new(interface).map_err(|_| "网卡名称无效")?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(format!("无法读取 {interface} 的内核接口编号"));
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::htons(0x0003) as i32,
        )
    };
    if raw < 0 {
        return Err(format!(
            "无法监听以太网：{}",
            std::io::Error::last_os_error()
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = libc::htons(0x0003);
    address.sll_ifindex = index as i32;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(format!(
            "绑定 {interface} 监听失败：{}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}
fn add_candidate(
    map: &mut HashMap<(String, String, String), ArpCandidate>,
    interface: &str,
    address: String,
    mac: [u8; 6],
    source: &str,
    confidence: &str,
) {
    let mac_text = format_mac(mac);
    let row = ArpCandidate {
        interface: interface.into(),
        address,
        mac: mac_text.clone(),
        source: source.into(),
        confidence: confidence.into(),
        arp_reachable: None,
    };
    let key = (row.interface.clone(), row.address.clone(), row.mac.clone());
    if map.len() < 2048 || map.contains_key(&key) {
        map.entry(key)
            .and_modify(|old| {
                if confidence == "较高" {
                    *old = row.clone();
                }
            })
            .or_insert(row);
    }
}
fn ipv4_allowed(ip: Ipv4Addr, options: &DiscoverOptions) -> bool {
    ipv4_usable_candidate(ip) && (options.ipv4_link_local || !ip.is_link_local())
}

fn ipv4_usable_candidate(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
        && !ip.is_loopback()
        && octets[0] != 0
        && octets[0] < 240
}

fn ipv4_arp_allowed(ip: Ipv4Addr, options: &DiscoverOptions) -> bool {
    ipv4_usable_candidate(ip)
        && if ip.is_link_local() {
            options.ipv4_link_local
        } else {
            options.passive_arp
        }
}

fn ipv6_observation_allowed(ip: Ipv6Addr, options: &DiscoverOptions) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && if ip.is_unicast_link_local() {
            options.ipv6_link_local
        } else {
            options.passive_ipv6
        }
}

fn format_ipv6_address(address: Ipv6Addr, interface: &str) -> String {
    if address.is_unicast_link_local() {
        format!("{address}%{interface}")
    } else {
        address.to_string()
    }
}
fn discover(
    seconds: u64,
    interfaces: &[String],
    options: &DiscoverOptions,
) -> Result<DiscoveryResult, String> {
    let mut sockets: Vec<(String, OwnedFd, [u8; 6])> = Vec::new();
    let mut skipped = Vec::new();
    let mut warnings = Vec::new();
    for interface in interfaces {
        if let Err(e) = physical_ethernet(interface, false) {
            skipped.push(interface.clone());
            warnings.push(format!("{e}；已跳过该网卡。"));
            continue;
        }
        match interface_has_carrier(interface) {
            Ok(true) => {}
            Ok(false) => {
                skipped.push(interface.clone());
                warnings.push(format!("{interface} 已断开（carrier=0），已跳过。"));
                continue;
            }
            Err(e) => {
                skipped.push(interface.clone());
                warnings.push(format!("{e}；已跳过该网卡。"));
                continue;
            }
        }
        match (arp_socket(interface), interface_mac(interface)) {
            (Ok(socket), Ok(mac)) => sockets.push((interface.clone(), socket, mac)),
            (Err(e), _) | (_, Err(e)) => {
                skipped.push(interface.clone());
                warnings.push(format!("{e}；已跳过该网卡。"));
            }
        }
    }
    if sockets.is_empty() {
        return Ok(DiscoveryResult {
            candidates: vec![],
            skipped_interfaces: skipped,
            warnings,
        });
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    for (_, socket, _) in &sockets {
        tune_capture_socket(socket);
    }
    let mut sweeps = if options.arp_sweep {
        build_sweep_plans(&sockets, options, &mut warnings)
    } else {
        Vec::new()
    };
    let sweep_total = sweeps.iter().map(|p| p.targets.len()).sum::<usize>();
    // Spread the sweep over ~60% of the listening window, 2k–40k frames per second overall.
    let sweep_rate_per_ms = (sweep_total as f64 / (seconds as f64 * 600.0)).clamp(2.0, 40.0);
    let mut sweep_sent = 0_usize;
    let mut candidates = HashMap::<(String, String, String), ArpCandidate>::new();
    let mut dhcp_without_address = std::collections::HashSet::new();
    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline {
        let mut pollfds = sockets
            .iter()
            .map(|(_, s, _)| libc::pollfd {
                fd: s.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        let sweeping = sweeps.iter().any(|p| p.next < p.targets.len());
        if sweeping {
            let budget = (started.elapsed().as_secs_f64() * 1000.0 * sweep_rate_per_ms) as usize;
            let allowed = budget.saturating_sub(sweep_sent).min(4096);
            sweep_sent += send_sweep_batch(&mut sweeps, &sockets, allowed, &mut warnings);
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(if sweeping { 5 } else { 200 }) as i32;
        let ready =
            unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("被动发现监听失败：{e}"));
        }
        for (i, pfd) in pollfds.iter().enumerate() {
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let n = unsafe {
                libc::recv(
                    sockets[i].1.as_raw_fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                continue;
            }
            let frame = &buffer[..n as usize];
            let (Some((ethertype, offset, src_mac)), Some(iface)) =
                (ethernet_payload(frame), Some(sockets[i].0.as_str()))
            else {
                continue;
            };
            if src_mac == sockets[i].2 {
                continue;
            }
            if ethertype == 0x0806
                && (options.passive_arp || options.ipv4_link_local || options.arp_sweep)
            {
                if let Some(packet) = parse_arp(frame) {
                    if packet.sender_mac == sockets[i].2 {
                        continue;
                    }
                    if options.arp_sweep
                        && is_sweep_reply(&packet, sockets[i].2)
                        && ipv4_allowed(packet.sender_ip, options)
                    {
                        add_candidate(
                            &mut candidates,
                            iface,
                            packet.sender_ip.to_string(),
                            packet.sender_mac,
                            "主动 ARP 扫描应答",
                            "较高",
                        );
                        let key = (
                            iface.to_string(),
                            packet.sender_ip.to_string(),
                            format_mac(packet.sender_mac),
                        );
                        if let Some(row) = candidates.get_mut(&key) {
                            row.arp_reachable = Some(true);
                        }
                        continue;
                    }
                    if !(options.passive_arp || options.ipv4_link_local) {
                        continue;
                    }
                    // ARP targets are evidence only for a strict address probe (SPA=0); ordinary targets are not hosts.
                    if ipv4_arp_allowed(packet.sender_ip, options) {
                        let label = if packet.sender_ip == packet.target_ip {
                            "免费 ARP"
                        } else if packet.operation == 2 {
                            "ARP 应答中的源地址"
                        } else {
                            "ARP 请求中的源地址"
                        };
                        add_candidate(
                            &mut candidates,
                            iface,
                            packet.sender_ip.to_string(),
                            packet.sender_mac,
                            label,
                            "较高",
                        );
                    } else if packet.operation == 1
                        && packet.sender_ip == Ipv4Addr::UNSPECIFIED
                        && ipv4_arp_allowed(packet.target_ip, options)
                    {
                        add_candidate(
                            &mut candidates,
                            iface,
                            packet.target_ip.to_string(),
                            packet.sender_mac,
                            "ARP 地址探测目标",
                            "候选",
                        );
                    }
                }
            } else if ethertype == 0x0800 {
                if let Some((src, dst, proto, payload)) = parse_ipv4(frame, offset) {
                    if proto == 17 {
                        if options.passive_dhcp {
                            if let Some(d) = parse_dhcp(payload) {
                                if d.address != Ipv4Addr::UNSPECIFIED
                                    && ipv4_allowed(d.address, options)
                                {
                                    add_candidate(
                                        &mut candidates,
                                        iface,
                                        d.address.to_string(),
                                        src_mac,
                                        "DHCP Discover/Request",
                                        "较低",
                                    );
                                } else {
                                    dhcp_without_address.insert(iface.to_string());
                                }
                            }
                        }
                        if options.mdns
                            && is_mdns_v4(src, dst, payload)
                            && ipv4_allowed(src, options)
                        {
                            add_candidate(
                                &mut candidates,
                                iface,
                                src.to_string(),
                                src_mac,
                                "mDNS 报文源地址",
                                "较高",
                            );
                        }
                    }
                }
            } else if ethertype == 0x86dd {
                if let Some(ip6) = parse_ipv6(frame, offset) {
                    let payload = &frame[ip6.payload_offset..ip6.payload_end];
                    if ip6.next_header == 58 {
                        if options.passive_ipv6 || options.ipv6_link_local {
                            if let Some((kind, target)) = parse_valid_nd(ip6, payload) {
                                if kind == 135 && ip6.source.is_unspecified() {
                                    if ipv6_observation_allowed(target, options) {
                                        add_candidate(
                                            &mut candidates,
                                            iface,
                                            format_ipv6_address(target, iface),
                                            src_mac,
                                            "IPv6 ND DAD 目标",
                                            "候选",
                                        );
                                    }
                                } else if ipv6_observation_allowed(ip6.source, options) {
                                    add_candidate(
                                        &mut candidates,
                                        iface,
                                        format_ipv6_address(ip6.source, iface),
                                        src_mac,
                                        "IPv6 ND 源地址",
                                        "较高",
                                    );
                                }
                            }
                        }
                    } else if ipv6_observation_allowed(ip6.source, options) {
                        // Non-ND IPv6 sources require passive IPv6; the link-local toggle only adds LL identities.
                        add_candidate(
                            &mut candidates,
                            iface,
                            format_ipv6_address(ip6.source, iface),
                            src_mac,
                            "IPv6 报文源地址",
                            "较高",
                        );
                    }
                    if options.mdns
                        && ip6.next_header == 17
                        && is_mdns_v6(ip6.destination, payload)
                        && ipv6_observation_allowed(ip6.source, options)
                    {
                        add_candidate(
                            &mut candidates,
                            iface,
                            format_ipv6_address(ip6.source, iface),
                            src_mac,
                            "mDNS 报文源地址",
                            "较高",
                        );
                    }
                }
            }
        }
    }
    if options.passive_dhcp {
        let linked_interfaces = sockets
            .iter()
            .map(|(interface, _, _)| interface.clone())
            .collect::<Vec<_>>();
        match dhcp::lease_candidates(&linked_interfaces) {
            Ok(rows) => {
                for row in rows {
                    if !linked_interfaces.contains(&row.interface) {
                        continue;
                    }
                    let Ok(address) = row.address.parse::<Ipv4Addr>() else {
                        continue;
                    };
                    let Some(mac) = parse_mac(&row.mac) else {
                        continue;
                    };
                    if ipv4_allowed(address, options) {
                        add_candidate(
                            &mut candidates,
                            &row.interface,
                            address.to_string(),
                            mac,
                            "DHCP 租约日志缓存（非实时）",
                            "较低",
                        );
                    }
                }
            }
            Err(error) => warnings.push(format!(
                "读取 DHCP 租约缓存失败：{error}；继续使用其他发现来源。"
            )),
        }
    }
    for iface in dhcp_without_address {
        warnings.push(format!("{iface} 上观察到无可用 IPv4 地址的 DHCP Discover/Request；可在 GUI 中选择启用 DHCP Server 后重新发现。"));
    }
    if options.active_arp {
        active_arp_verify(&mut candidates, &sockets, &mut skipped, &mut warnings)?;
    }
    let mut rows = candidates.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then(a.address.cmp(&b.address))
            .then(a.mac.cmp(&b.mac))
    });
    Ok(DiscoveryResult {
        candidates: rows,
        skipped_interfaces: skipped,
        warnings,
    })
}
fn ethernet_payload(frame: &[u8]) -> Option<(u16, usize, [u8; 6])> {
    if frame.len() < 14 {
        return None;
    }
    let mac = frame[6..12].try_into().ok()?;
    let mut ty = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = 14;
    let mut tags = 0;
    while ty == 0x8100 || ty == 0x88a8 || ty == 0x9100 {
        if tags >= 2 || frame.len() < off + 4 {
            return None;
        }
        ty = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
        off += 4;
        tags += 1;
    }
    Some((ty, off, mac))
}
fn parse_arp(frame: &[u8]) -> Option<ArpPacket> {
    let (ty, off, _) = ethernet_payload(frame)?;
    if ty != 0x0806 || frame.len() < off + 28 {
        return None;
    }
    let a = &frame[off..off + 28];
    if u16::from_be_bytes([a[0], a[1]]) != 1
        || u16::from_be_bytes([a[2], a[3]]) != 0x0800
        || a[4] != 6
        || a[5] != 4
    {
        return None;
    }
    let op = u16::from_be_bytes([a[6], a[7]]);
    if op != 1 && op != 2 {
        return None;
    }
    Some(ArpPacket {
        operation: op,
        sender_mac: a[8..14].try_into().ok()?,
        sender_ip: Ipv4Addr::new(a[14], a[15], a[16], a[17]),
        target_mac: a[18..24].try_into().ok()?,
        target_ip: Ipv4Addr::new(a[24], a[25], a[26], a[27]),
    })
}
fn parse_ipv4(frame: &[u8], off: usize) -> Option<(Ipv4Addr, Ipv4Addr, u8, &[u8])> {
    if frame.len() < off + 20 {
        return None;
    }
    let h = &frame[off..];
    if h[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((h[0] & 15) as usize) * 4;
    if ihl < 20 || h.len() < ihl {
        return None;
    }
    let total = u16::from_be_bytes([h[2], h[3]]) as usize;
    if total < ihl || h.len() < total {
        return None;
    }
    let frag = u16::from_be_bytes([h[6], h[7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    Some((
        Ipv4Addr::new(h[12], h[13], h[14], h[15]),
        Ipv4Addr::new(h[16], h[17], h[18], h[19]),
        h[9],
        &h[ihl..total],
    ))
}
fn parse_dhcp(udp: &[u8]) -> Option<DhcpCandidate> {
    if udp.len() < 8 {
        return None;
    }
    let sp = u16::from_be_bytes([udp[0], udp[1]]);
    let dp = u16::from_be_bytes([udp[2], udp[3]]);
    if !((sp == 68 && dp == 67) || (sp == 67 && dp == 68)) {
        return None;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if len < 8 + 240 || udp.len() < len {
        return None;
    }
    let b = &udp[8..len];
    if b[0] != 1 || b[1] != 1 || b[2] != 6 || b[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let ciaddr = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let mut requested = None;
    let mut msg = None;
    let mut i = 240;
    while i < b.len() {
        let code = b[i];
        i += 1;
        if code == 255 {
            break;
        }
        if code == 0 {
            continue;
        }
        if i >= b.len() {
            return None;
        }
        let n = b[i] as usize;
        i += 1;
        if i + n > b.len() {
            return None;
        }
        if code == 53 && n == 1 {
            msg = Some(b[i]);
        }
        if code == 50 && n == 4 {
            requested = Some(Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3]));
        }
        i += n;
    }
    let message_type = msg?;
    if message_type != 1 && message_type != 3 {
        return None;
    }
    let address = if !ciaddr.is_unspecified() {
        ciaddr
    } else {
        requested.unwrap_or(Ipv4Addr::UNSPECIFIED)
    };
    Some(DhcpCandidate { address })
}
fn udp_datagram(udp: &[u8]) -> Option<(u16, u16, &[u8])> {
    if udp.len() < 8 {
        return None;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if len < 8 || len > udp.len() {
        return None;
    }
    Some((
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
        &udp[8..len],
    ))
}
fn is_mdns_v4(_src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> bool {
    matches!(udp_datagram(udp), Some((sp, dp, payload)) if (sp == 5353 || dp == 5353) && payload.len() >= 12)
        && dst == Ipv4Addr::new(224, 0, 0, 251)
}
fn parse_ipv6(frame: &[u8], off: usize) -> Option<Ipv6Packet> {
    if frame.len() < off + 40 {
        return None;
    }
    let h = &frame[off..];
    if h[0] >> 4 != 6 {
        return None;
    }
    let plen = u16::from_be_bytes([h[4], h[5]]) as usize;
    let end = off + 40 + plen;
    if frame.len() < end {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&h[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&h[24..40]).ok()?);
    let mut next = h[6];
    let mut pos = off + 40;
    let mut count = 0;
    while matches!(next, 0 | 43 | 60 | 51 | 44) {
        if count >= 8 {
            return None;
        }
        count += 1;
        if next == 44 {
            return None;
        }
        if pos + 2 > end || pos >= end {
            return None;
        }
        let n = next;
        next = frame[pos];
        let len = if n == 51 {
            (frame[pos + 1] as usize + 2) * 4
        } else {
            (frame[pos + 1] as usize + 1) * 8
        };
        if len < 8 || pos + len > end {
            return None;
        }
        pos += len;
    }
    Some(Ipv6Packet {
        source,
        destination,
        next_header: next,
        hop_limit: h[7],
        payload_offset: pos,
        payload_end: end,
    })
}
fn parse_nd(icmp: &[u8]) -> Option<(u8, Ipv6Addr)> {
    if icmp.len() < 24 || icmp[1] != 0 {
        return None;
    }
    let kind = icmp[0];
    if kind != 135 && kind != 136 {
        return None;
    }
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&icmp[8..24]).ok()?);
    if target.is_unspecified() || target.is_multicast() {
        return None;
    }
    Some((kind, target))
}
fn parse_valid_nd(packet: Ipv6Packet, payload: &[u8]) -> Option<(u8, Ipv6Addr)> {
    if packet.next_header != 58 || packet.hop_limit != 255 {
        return None;
    }
    parse_nd(payload)
}
fn is_mdns_v6(dst: Ipv6Addr, udp: &[u8]) -> bool {
    matches!(udp_datagram(udp), Some((sp, dp, payload)) if (sp == 5353 || dp == 5353) && payload.len() >= 12)
        && dst == "ff02::fb".parse::<Ipv6Addr>().unwrap()
}
fn send_arp_request(
    fd: i32,
    index: i32,
    mac: [u8; 6],
    target: Ipv4Addr,
    sender: Ipv4Addr,
) -> Result<(), String> {
    send_arp_frame(fd, index, mac, target, sender, 0)
        .map_err(|e| format!("定向 ARP 验证发送失败：{e}"))
}
fn send_arp_frame(
    fd: i32,
    index: i32,
    mac: [u8; 6],
    target: Ipv4Addr,
    sender: Ipv4Addr,
    flags: i32,
) -> std::io::Result<()> {
    let mut frame = [0u8; 42];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1u16.to_be_bytes());
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[38..42].copy_from_slice(&target.octets());
    let mut dst: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    dst.sll_family = libc::AF_PACKET as u16;
    dst.sll_protocol = libc::htons(0x0806);
    dst.sll_ifindex = index;
    dst.sll_halen = 6;
    dst.sll_addr[..6].fill(0xff);
    let n = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            flags,
            &dst as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n != frame.len() as isize {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A reply addressed to our own MAC: the answer to one of our sweep or verification requests.
fn is_sweep_reply(packet: &ArpPacket, own_mac: [u8; 6]) -> bool {
    packet.operation == 2 && packet.target_mac == own_mac && packet.sender_mac != own_mac
}

/// Ignore our own transmitted frames and enlarge the receive buffer so that thousands of
/// outgoing sweep requests cannot crowd out the single reply we are waiting for.
fn tune_capture_socket(socket: &OwnedFd) {
    const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
    let one: libc::c_int = 1;
    let size: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_PACKET,
            PACKET_IGNORE_OUTGOING,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// Default /24 networks used by common Linux development boards, phone/PC sharing and
/// vendor images. Swept on every direct interface in addition to its own subnets.
const COMMON_BOARD_SUBNETS: &[[u8; 3]] = &[
    [192, 168, 1],
    [192, 168, 0],
    [192, 168, 127],
    [192, 168, 137],
    [192, 168, 2],
    [192, 168, 3],
    [192, 168, 5],
    [192, 168, 6],
    [192, 168, 7],
    [192, 168, 8],
    [192, 168, 10],
    [192, 168, 11],
    [192, 168, 31],
    [192, 168, 42],
    [192, 168, 43],
    [192, 168, 50],
    [192, 168, 55],
    [192, 168, 77],
    [192, 168, 88],
    [192, 168, 100],
    [192, 168, 123],
    [192, 168, 199],
    [10, 0, 0],
    [10, 1, 1],
    [10, 10, 10],
    [10, 42, 0],
    [172, 16, 0],
    [172, 17, 0],
];

struct SweepPlan {
    socket: usize,
    index: i32,
    targets: Vec<(Ipv4Addr, Ipv4Addr)>,
    next: usize,
}

/// Pure target generation: returns (target, sender) pairs. The sender is the local address when
/// the target lies in one of the interface's own subnets, otherwise 0.0.0.0 (an RFC 5227 probe,
/// which Linux answers for any address configured on the receiving interface).
fn sweep_targets(
    locals: &[(Ipv4Addr, u8)],
    direct_link: bool,
    deep: bool,
    link_local: bool,
) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    fn range(base: u32, prefix: u8) -> impl Iterator<Item = Ipv4Addr> {
        let size = 1_u32 << (32 - prefix);
        (1..size.saturating_sub(1)).map(move |host| Ipv4Addr::from(base + host))
    }
    let mut ordered: Vec<Ipv4Addr> = Vec::new();
    // 1. The interface's own subnets (capped at /22, otherwise the /24 around the address).
    for (ip, prefix) in locals {
        if ip.is_link_local() && !(deep && direct_link && link_local) {
            continue;
        }
        let prefix = if *prefix >= 22 { *prefix } else { 24 };
        if prefix <= 30 {
            ordered.extend(range(network(*ip, prefix).0, prefix));
        }
    }
    // Interfaces carrying a default route are shared LANs: only probe our own subnet there.
    if direct_link {
        // 2. Well-known board defaults.
        for net in COMMON_BOARD_SUBNETS {
            ordered.extend(range(
                u32::from(Ipv4Addr::new(net[0], net[1], net[2], 0)),
                24,
            ));
        }
        if deep {
            // 3. Every 192.168.x.y.
            ordered.extend(range(u32::from(Ipv4Addr::new(192, 168, 0, 0)), 16));
            // 4. IPv4 link-local hosts 169.254.1.0–169.254.254.255 (RFC 3927).
            if link_local {
                for third in 1..=254_u8 {
                    ordered
                        .extend((0..=255_u8).map(|fourth| Ipv4Addr::new(169, 254, third, fourth)));
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    ordered
        .into_iter()
        .filter(|target| {
            ipv4_usable_candidate(*target)
                && !locals.iter().any(|(ip, _)| ip == target)
                && seen.insert(*target)
        })
        .map(|target| {
            let sender = locals
                .iter()
                .find(|(ip, prefix)| network(*ip, *prefix).0 == network(target, *prefix).0)
                .map(|(ip, _)| *ip)
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            (target, sender)
        })
        .collect()
}

fn default_route_interfaces() -> std::collections::HashSet<String> {
    fs::read_to_string("/proc/net/route")
        .map(|text| parse_default_route_interfaces(&text))
        .unwrap_or_default()
}

fn parse_default_route_interfaces(text: &str) -> std::collections::HashSet<String> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 8 && fields[1] == "00000000" && fields[7] == "00000000")
                .then(|| fields[0].to_string())
        })
        .collect()
}

fn build_sweep_plans(
    sockets: &[(String, OwnedFd, [u8; 6])],
    options: &DiscoverOptions,
    warnings: &mut Vec<String>,
) -> Vec<SweepPlan> {
    let locals = all_ipv4_addresses().unwrap_or_default();
    let uplinks = default_route_interfaces();
    let mut plans = Vec::new();
    for (socket, (name, _, _)) in sockets.iter().enumerate() {
        let Ok(c) = CString::new(name.as_str()) else {
            continue;
        };
        let index = unsafe { libc::if_nametoindex(c.as_ptr()) } as i32;
        if index == 0 {
            continue;
        }
        let own = locals
            .iter()
            .filter(|(dev, _, _)| dev == name)
            .map(|(_, ip, prefix)| (*ip, *prefix))
            .collect::<Vec<_>>();
        let direct_link = !uplinks.contains(name);
        if !direct_link {
            warnings.push(format!(
                "{name} 承载默认路由（像是接入了路由器/局域网），主动 ARP 扫描只覆盖其本机网段，未扫描常见开发板网段。"
            ));
        }
        let targets = sweep_targets(
            &own,
            direct_link,
            options.arp_sweep_deep,
            options.ipv4_link_local,
        );
        if !targets.is_empty() {
            plans.push(SweepPlan {
                socket,
                index,
                targets,
                next: 0,
            });
        }
    }
    plans
}

/// Sends up to `allowed` sweep requests round-robin across interfaces; returns how many were sent.
fn send_sweep_batch(
    plans: &mut [SweepPlan],
    sockets: &[(String, OwnedFd, [u8; 6])],
    allowed: usize,
    warnings: &mut Vec<String>,
) -> usize {
    let mut sent = 0;
    let mut progressed = true;
    while sent < allowed && progressed {
        progressed = false;
        for plan in plans.iter_mut() {
            if sent >= allowed || plan.next >= plan.targets.len() {
                continue;
            }
            let (name, socket, mac) = &sockets[plan.socket];
            let (target, sender) = plan.targets[plan.next];
            match send_arp_frame(
                socket.as_raw_fd(),
                plan.index,
                *mac,
                target,
                sender,
                libc::MSG_DONTWAIT,
            ) {
                Ok(()) => {
                    plan.next += 1;
                    sent += 1;
                    progressed = true;
                }
                Err(e) if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::ENOBUFS)) => {
                    // Transmit queue full: retry this target on the next loop iteration.
                }
                Err(e) => {
                    warnings.push(format!(
                        "{name} 主动 ARP 扫描中止（已发送 {} / {}）：{e}",
                        plan.next,
                        plan.targets.len()
                    ));
                    plan.next = plan.targets.len();
                }
            }
        }
    }
    sent
}
fn active_arp_verify(
    candidates: &mut HashMap<(String, String, String), ArpCandidate>,
    sockets: &[(String, OwnedFd, [u8; 6])],
    skipped: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for row in candidates.values_mut() {
        if row.arp_reachable == Some(true) {
            continue;
        }
        if let Ok(ip) = row.address.parse::<Ipv4Addr>() {
            let key = (row.interface.clone(), ip);
            if targets.len() < 256 && (seen.contains(&key) || seen.insert(key.clone())) {
                row.arp_reachable = Some(false);
                if !targets
                    .iter()
                    .any(|(name, target)| name == &row.interface && *target == ip)
                {
                    targets.push(key);
                }
            }
        }
    }
    for row in candidates.values_mut() {
        if row.arp_reachable == Some(true) {
            continue;
        }
        if let Ok(ip) = row.address.parse::<Ipv4Addr>() {
            if targets
                .iter()
                .any(|(name, target)| name == &row.interface && *target == ip)
            {
                row.arp_reachable = Some(false);
            }
        }
    }
    if targets.is_empty() {
        return Ok(());
    }
    let local = all_ipv4_addresses().unwrap_or_default();
    let mut sent = Vec::new();
    for (iface, target) in targets {
        let Some((_, sock, mac)) = sockets.iter().find(|(n, _, _)| n == &iface) else {
            continue;
        };
        let source = local
            .iter()
            .find(|(n, ip, _)| n == &iface && !ip.is_link_local())
            .map(|(_, ip, _)| *ip)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let c = CString::new(iface.as_str()).map_err(|_| "网卡名称无效")?;
        let index = unsafe { libc::if_nametoindex(c.as_ptr()) } as i32;
        if let Err(error) = send_arp_request(sock.as_raw_fd(), index, *mac, target, source) {
            if !skipped.contains(&iface) {
                skipped.push(iface.clone());
            }
            warnings.push(format!(
                "{iface} 在主动 ARP 验证期间失去可用链路（{error}）；已跳过该接口的主动验证。"
            ));
            continue;
        }
        sent.push((iface, target));
    }
    let deadline = Instant::now() + Duration::from_millis(1400);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        let mut pf = sockets
            .iter()
            .map(|(_, s, _)| libc::pollfd {
                fd: s.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        let ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(100) as i32;
        let n = unsafe { libc::poll(pf.as_mut_ptr(), pf.len() as libc::nfds_t, ms) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("定向 ARP 接收失败：{e}"));
        }
        for (i, p) in pf.iter().enumerate() {
            if p.revents & libc::POLLIN == 0 {
                continue;
            }
            let n = unsafe {
                libc::recv(
                    sockets[i].1.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                continue;
            }
            if let Some(a) = parse_arp(&buf[..n as usize]) {
                if a.sender_mac == sockets[i].2 || a.operation != 2 {
                    continue;
                }
                let iface = &sockets[i].0;
                if !sent
                    .iter()
                    .any(|(name, ip)| name == iface && *ip == a.sender_ip)
                {
                    continue;
                }
                for row in candidates.values_mut() {
                    if row.interface == *iface && row.address == a.sender_ip.to_string() {
                        row.mac = format_mac(a.sender_mac);
                        row.arp_reachable = Some(true);
                    }
                }
            }
        }
    }
    Ok(())
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
    physical_ethernet(interface, true)?;
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
    let via_nm = nm_manages(interface);
    if via_nm {
        nm_add_address(interface, &cidr_arg)?;
    } else {
        let output = ip_command(&["address", "add", &cidr_arg, "dev", interface])?;
        if !output.status.success() {
            return Err(format!(
                "添加临时 IPv4 地址失败：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
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
        let _ = remove_address(interface, &cidr_arg);
        return Err(
            "添加后路由检查没有指向选定网卡；已撤销刚添加的地址，其他网络未作更改。".into(),
        );
    }
    if via_nm {
        println!("已通过 NetworkManager 临时连接“{}”在 {interface} 配置 {cidr_arg}（不设默认路由、不改 DNS），切换 Wi‑Fi 或网络重连时不会被清掉；清理后恢复该网口原来的连接。目标前缀 /{prefix} 为用户选择的假设。{peer}", nm_profile_name(interface));
    } else {
        println!("已在 {interface} 添加临时地址 {cidr_arg}；默认路由、DNS、Wi‑Fi 和机器人端配置未修改。目标前缀 /{prefix} 为用户选择的假设。{peer}");
    }
    Ok(())
}

// NetworkManager integration. A bare `ip address add` on an interface that NetworkManager manages is
// flushed whenever NM (re)activates that interface – e.g. its DHCP profile times out and retries, or
// the network is reconfigured after switching Wi-Fi – and traffic to the board then leaves via Wi-Fi.
// When NM manages the interface we instead activate an in-memory (not saved to disk) manual profile
// that never becomes the default route; deleting it lets NM bring back the user's original profile.

fn nmcli_path() -> Option<&'static str> {
    ["/usr/bin/nmcli", "/bin/nmcli"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
}

fn nmcli(args: &[&str]) -> Result<std::process::Output, String> {
    let path = nmcli_path().ok_or("找不到 nmcli")?;
    Command::new(path)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("无法运行 nmcli：{e}"))
}

fn nm_profile_name(interface: &str) -> String {
    format!("robolink-{interface}")
}

fn nm_manages(interface: &str) -> bool {
    if nmcli_path().is_none() || !std::path::Path::new("/run/NetworkManager").exists() {
        return false;
    }
    match nmcli(&["-g", "GENERAL.STATE", "device", "show", interface]) {
        Ok(out) if out.status.success() => {
            nm_state_is_managed(&String::from_utf8_lossy(&out.stdout))
        }
        _ => false,
    }
}

fn nm_state_is_managed(state: &str) -> bool {
    let state = state.trim();
    !state.is_empty() && !state.contains("unmanaged") && !state.starts_with("10 ")
}

/// Addresses of our profile for this interface, or None when the profile does not exist.
fn nm_profile_addresses(interface: &str) -> Option<Vec<String>> {
    nmcli_path()?;
    let out = nmcli(&[
        "-g",
        "ipv4.addresses",
        "connection",
        "show",
        &nm_profile_name(interface),
    ])
    .ok()?;
    out.status
        .success()
        .then(|| parse_nm_addresses(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_nm_addresses(text: &str) -> Vec<String> {
    text.trim()
        .split(',')
        .map(|item| item.trim().replace("\\", ""))
        .filter(|item| parse_cidr(item).is_ok())
        .collect()
}

fn nm_profile_args(interface: &str, addresses: &[String], create: bool) -> Vec<String> {
    let name = nm_profile_name(interface);
    let mut args: Vec<String> = if create {
        [
            "connection",
            "add",
            "save",
            "no",
            "type",
            "ethernet",
            "con-name",
            &name,
            "ifname",
            interface,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    } else {
        vec!["connection".into(), "modify".into(), name]
    };
    for (key, value) in [
        ("connection.autoconnect", "yes"),
        ("connection.autoconnect-priority", "100"),
        ("ipv4.method", "manual"),
        ("ipv4.addresses", &addresses.join(",")),
        ("ipv4.gateway", ""),
        ("ipv4.never-default", "yes"),
        ("ipv4.ignore-auto-dns", "yes"),
        ("ipv4.may-fail", "no"),
        ("ipv6.method", "link-local"),
        ("ipv6.never-default", "yes"),
    ] {
        args.push(key.into());
        args.push(value.into());
    }
    args
}

fn nm_apply_profile(interface: &str, addresses: &[String]) -> Result<(), String> {
    let exists = nm_profile_addresses(interface).is_some();
    let args = nm_profile_args(interface, addresses, !exists);
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let out = nmcli(&refs)?;
    if !out.status.success() {
        return Err(format!(
            "创建 NetworkManager 临时连接失败：{}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let name = nm_profile_name(interface);
    let up = nmcli(&[
        "--wait",
        "20",
        "connection",
        "up",
        &name,
        "ifname",
        interface,
    ])?;
    if !up.status.success() {
        let detail = String::from_utf8_lossy(&up.stderr).trim().to_string();
        if !exists {
            let _ = nmcli(&["connection", "delete", &name]);
        }
        return Err(format!("启用 NetworkManager 临时连接失败：{detail}"));
    }
    Ok(())
}

/// Adds an address to RoboLink's in-memory NetworkManager profile for this interface (creating and
/// activating it if needed). Prints nothing, so DHCP commands can keep stdout for JSON.
fn nm_add_address(interface: &str, cidr: &str) -> Result<(), String> {
    let mut addresses = nm_profile_addresses(interface).unwrap_or_default();
    if !addresses.iter().any(|item| item == cidr) {
        addresses.push(cidr.to_string());
    }
    nm_apply_profile(interface, &addresses)
}

/// Removes an address from RoboLink's NM profile; Ok(false) when the profile does not hold it.
fn nm_remove_address(interface: &str, cidr: &str) -> Result<bool, String> {
    let Some(addresses) = nm_profile_addresses(interface) else {
        return Ok(false);
    };
    if !addresses.iter().any(|item| item == cidr) {
        return Ok(false);
    }
    let remaining = addresses
        .into_iter()
        .filter(|item| item != cidr)
        .collect::<Vec<_>>();
    if remaining.is_empty() {
        let out = nmcli(&["connection", "delete", &nm_profile_name(interface)])?;
        if !out.status.success() {
            return Err(format!(
                "删除 NetworkManager 临时连接失败：{}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    } else {
        nm_apply_profile(interface, &remaining)?;
    }
    Ok(true)
}

fn remove_address(interface: &str, cidr: &str) -> Result<(), String> {
    validate_ifname(interface)?;
    let (address, prefix) = parse_cidr(cidr)?;
    let cidr_text = format!("{address}/{prefix}");
    if nm_remove_address(interface, &cidr_text)? {
        println!(
            "已从 NetworkManager 临时连接“{}”移除 {cidr_text}；其他网络未修改。\n",
            nm_profile_name(interface)
        );
        return Ok(());
    }
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
    fn carrier_state_is_independent_of_sysfs_flags_and_offline_interfaces_are_skipped() {
        assert_eq!(parse_carrier_state("1\n"), Ok(true));
        assert_eq!(parse_carrier_state("0\n"), Ok(false));
        assert!(parse_carrier_state("unknown").is_err());

        let interfaces = vec!["enx00e04c3071f5".to_string(), "enp2s0".to_string()];
        let linked =
            interfaces_with_carrier(&interfaces, |name| Ok(name == "enx00e04c3071f5")).unwrap();
        assert_eq!(linked, vec!["enx00e04c3071f5"]);
    }

    fn ethernet(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[..6].fill(0xff);
        f[6..12].copy_from_slice(&[0x64, 0xb4, 0xe8, 0x10, 0x15, 0x46]);
        f[12..14].copy_from_slice(&ty.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }
    #[test]
    fn ordinary_arp_target_is_not_a_candidate() {
        let p = parse_arp(&arp_frame(
            1,
            "192.168.1.4".parse().unwrap(),
            "192.168.1.99".parse().unwrap(),
        ))
        .unwrap();
        assert_ne!(p.sender_ip, p.target_ip);
        assert!(!p.sender_ip.is_unspecified());
    }
    #[test]
    fn arp_gratuitous_probe_vlan_and_truncation() {
        let mut f = arp_frame(
            1,
            "0.0.0.0".parse().unwrap(),
            "169.254.1.8".parse().unwrap(),
        );
        let p = parse_arp(&f).unwrap();
        assert_eq!(p.target_ip, "169.254.1.8".parse::<Ipv4Addr>().unwrap());
        assert!(parse_arp(&f[..30]).is_none());
        let mut tagged = vec![0u8; 18];
        tagged[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        tagged[16..18].copy_from_slice(&0x0806u16.to_be_bytes());
        tagged.extend_from_slice(&f[14..]);
        assert!(parse_arp(&tagged).is_some());
        f.truncate(14);
        assert!(parse_arp(&f).is_none());
    }
    #[test]
    fn ipv4_parser_rejects_truncation_and_fragments() {
        let mut ip = vec![0u8; 28];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let f = ethernet(0x0800, &ip);
        assert!(parse_ipv4(&f, 14).is_some());
        assert!(parse_ipv4(&f[..30], 14).is_none());
        ip[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(parse_ipv4(&ethernet(0x0800, &ip), 14).is_none());
    }
    #[test]
    fn dhcp_discover_and_requested_ip_parse() {
        let mut b = vec![0u8; 240];
        b[0] = 1;
        b[1] = 1;
        b[2] = 6;
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend_from_slice(&[53, 1, 1, 255]);
        let mut udp = vec![0u8; 8];
        udp[..2].copy_from_slice(&68u16.to_be_bytes());
        udp[2..4].copy_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&b);
        let l = udp.len() as u16;
        udp[4..6].copy_from_slice(&l.to_be_bytes());
        let d = parse_dhcp(&udp).unwrap();
        assert_eq!(d.address, Ipv4Addr::UNSPECIFIED);
        let mut request = vec![0u8; 240];
        request[0] = 1;
        request[1] = 1;
        request[2] = 6;
        request[236..240].copy_from_slice(&[99, 130, 83, 99]);
        request.extend_from_slice(&[53, 1, 3, 50, 4, 169, 254, 7, 9, 255]);
        let mut udp_request = vec![0u8; 8];
        udp_request[..2].copy_from_slice(&68u16.to_be_bytes());
        udp_request[2..4].copy_from_slice(&67u16.to_be_bytes());
        udp_request.extend_from_slice(&request);
        let length = udp_request.len() as u16;
        udp_request[4..6].copy_from_slice(&length.to_be_bytes());
        let d = parse_dhcp(&udp_request).unwrap();
        assert_eq!(d.address, "169.254.7.9".parse::<Ipv4Addr>().unwrap());
        assert!(parse_dhcp(&udp_request[..20]).is_none());
    }
    #[test]
    fn ipv6_extension_nd_and_scope_are_parsed() {
        let mut p = vec![0u8; 40 + 8 + 24];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&32u16.to_be_bytes());
        p[6] = 60;
        p[7] = 255;
        p[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"ff02::1:ff00:2".parse::<Ipv6Addr>().unwrap().octets());
        p[40] = 58;
        p[41] = 0;
        p[48] = 135;
        p[56..72].copy_from_slice(&"fe80::2".parse::<Ipv6Addr>().unwrap().octets());
        let mut f = ethernet(0x86dd, &p);
        f.extend_from_slice(&[0xaa; 12]);
        let ip = parse_ipv6(&f, 14).unwrap();
        assert_eq!(ip.next_header, 58);
        assert_eq!(ip.payload_end, 14 + 40 + 32);
        assert_eq!(
            parse_valid_nd(ip, &f[ip.payload_offset..ip.payload_end])
                .unwrap()
                .0,
            135
        );
        assert!(parse_ipv6(&f[..40], 14).is_none());
        assert_eq!(
            format_ipv6_address("fe80::1".parse().unwrap(), "eth0"),
            "fe80::1%eth0"
        );
        assert_eq!(
            format_ipv6_address("2001:db8::1".parse().unwrap(), "eth0"),
            "2001:db8::1"
        );
        let mut bad_hop_limit = ip;
        bad_hop_limit.hop_limit = 64;
        assert!(parse_valid_nd(bad_hop_limit, &f[ip.payload_offset..ip.payload_end]).is_none());
        let mut bad_code = f[ip.payload_offset..ip.payload_end].to_vec();
        bad_code[1] = 1;
        assert!(parse_valid_nd(ip, &bad_code).is_none());
        let mut bad_kind = f[ip.payload_offset..ip.payload_end].to_vec();
        bad_kind[0] = 134;
        assert!(parse_valid_nd(ip, &bad_kind).is_none());
        let mut multicast_target = f[ip.payload_offset..ip.payload_end].to_vec();
        multicast_target[8..24].copy_from_slice(&"ff02::1".parse::<Ipv6Addr>().unwrap().octets());
        assert!(parse_valid_nd(ip, &multicast_target).is_none());
    }
    #[test]
    fn mdns_requires_multicast_destination_and_port() {
        let mut u = vec![0u8; 20];
        u[0..2].copy_from_slice(&5353u16.to_be_bytes());
        u[4..6].copy_from_slice(&20u16.to_be_bytes());
        assert!(is_mdns_v4(
            "192.0.2.1".parse().unwrap(),
            "224.0.0.251".parse().unwrap(),
            &u
        ));
        assert!(!is_mdns_v4(
            "192.0.2.1".parse().unwrap(),
            "224.0.0.252".parse().unwrap(),
            &u
        ));
        u[2..4].copy_from_slice(&5353u16.to_be_bytes());
        assert!(is_mdns_v6("ff02::fb".parse().unwrap(), &u));
    }
    #[test]
    fn passive_arp_and_link_local_gating_matrix() {
        let link_local: Ipv4Addr = "169.254.10.2".parse().unwrap();
        let global: Ipv4Addr = "192.0.2.10".parse().unwrap();
        for (passive_arp, link_local_enabled, allow_global, allow_link_local) in [
            (false, false, false, false),
            (true, false, true, false),
            (false, true, false, true),
            (true, true, true, true),
        ] {
            let options = DiscoverOptions {
                passive_arp,
                ipv4_link_local: link_local_enabled,
                ..DiscoverOptions::default()
            };
            assert_eq!(ipv4_arp_allowed(global, &options), allow_global);
            assert_eq!(ipv4_arp_allowed(link_local, &options), allow_link_local);
        }
    }

    #[test]
    fn passive_ipv6_and_link_local_gating_matrix_does_not_enable_global_sources() {
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        for (passive_ipv6, link_local_enabled, allow_global, allow_link_local) in [
            (false, false, false, false),
            (true, false, true, false),
            (false, true, false, true),
            (true, true, true, true),
        ] {
            let options = DiscoverOptions {
                passive_ipv6,
                ipv6_link_local: link_local_enabled,
                ..DiscoverOptions::default()
            };
            assert_eq!(ipv6_observation_allowed(global, &options), allow_global);
            assert_eq!(
                ipv6_observation_allowed(link_local, &options),
                allow_link_local
            );
        }
    }

    #[test]
    fn ipv4_special_sources_are_not_candidates() {
        let options = DiscoverOptions {
            passive_arp: true,
            ipv4_link_local: true,
            ..DiscoverOptions::default()
        };
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !ipv4_arp_allowed(address.parse().unwrap(), &options),
                "{address}"
            );
        }
        assert!(ipv4_arp_allowed("192.0.2.1".parse().unwrap(), &options));
        assert!(ipv4_arp_allowed("169.254.1.1".parse().unwrap(), &options));
    }
    #[test]
    fn sweep_reply_requires_reply_addressed_to_us() {
        let own = [0x02, 0, 0, 0, 0, 1];
        let mut frame = arp_frame(2, Ipv4Addr::new(192, 168, 127, 10), Ipv4Addr::UNSPECIFIED);
        frame[32..38].copy_from_slice(&own);
        let reply = parse_arp(&frame).unwrap();
        assert_eq!(reply.target_mac, own);
        assert!(is_sweep_reply(&reply, own));
        assert!(!is_sweep_reply(&reply, [0x02, 0, 0, 0, 0, 2]));
        let request = parse_arp(&arp_frame(
            1,
            Ipv4Addr::new(192, 168, 127, 10),
            Ipv4Addr::new(192, 168, 127, 1),
        ))
        .unwrap();
        assert!(!is_sweep_reply(&request, own));
    }

    #[test]
    fn sweep_targets_cover_board_defaults_and_respect_uplinks() {
        // Unconfigured direct cable: common board subnets, probes sent from 0.0.0.0.
        let targets = sweep_targets(&[], true, false, true);
        let rdk = targets
            .iter()
            .find(|(t, _)| *t == Ipv4Addr::new(192, 168, 127, 10))
            .unwrap();
        assert_eq!(rdk.1, Ipv4Addr::UNSPECIFIED);
        assert!(!targets
            .iter()
            .any(|(t, _)| t.octets()[3] == 0 || t.octets()[3] == 255));
        assert!(targets.len() < 8000);
        // Deep sweep adds all of 192.168/16 and 169.254.1-254.x without duplicates.
        let deep = sweep_targets(&[], true, true, true);
        assert!(deep
            .iter()
            .any(|(t, _)| *t == Ipv4Addr::new(192, 168, 213, 7)));
        assert!(deep
            .iter()
            .any(|(t, _)| *t == Ipv4Addr::new(169, 254, 33, 0)));
        assert!(!deep
            .iter()
            .any(|(t, _)| t.octets()[0] == 169 && t.octets()[2] == 0));
        let unique = deep
            .iter()
            .map(|(t, _)| *t)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), deep.len());
        // Own subnet uses the local address as sender and never targets ourselves.
        let local = Ipv4Addr::new(192, 168, 127, 1);
        let own = sweep_targets(&[(local, 24)], true, false, false);
        assert_eq!(own[0].1, local);
        assert!(!own.iter().any(|(t, _)| *t == local));
        // Uplink (default route): only our own subnet.
        let lan = sweep_targets(&[(Ipv4Addr::new(10, 3, 4, 5), 16)], false, true, true);
        assert_eq!(lan.len(), 253);
        assert!(lan.iter().all(|(t, _)| t.octets()[..3] == [10, 3, 4]));
    }

    #[test]
    fn nm_profile_is_manual_without_default_route() {
        let args = nm_profile_args("enp3s0", &["192.168.127.1/24".into()], true);
        let joined = args.join(" ");
        assert!(joined.starts_with(
            "connection add save no type ethernet con-name robolink-enp3s0 ifname enp3s0"
        ));
        assert!(joined.contains("ipv4.method manual"));
        assert!(joined.contains("ipv4.addresses 192.168.127.1/24"));
        assert!(joined.contains("ipv4.never-default yes"));
        let modify = nm_profile_args(
            "enp3s0",
            &["192.168.127.1/24".into(), "192.168.1.2/24".into()],
            false,
        );
        assert_eq!(&modify[..3], ["connection", "modify", "robolink-enp3s0"]);
        assert!(modify.contains(&"192.168.127.1/24,192.168.1.2/24".to_string()));
        assert_eq!(
            parse_nm_addresses("192.168.127.1/24, 192.168.1.2/24\n"),
            vec!["192.168.127.1/24", "192.168.1.2/24"]
        );
        assert!(parse_nm_addresses("\n").is_empty());
        assert!(nm_state_is_managed("100 (connected)"));
        assert!(nm_state_is_managed("30 (disconnected)"));
        assert!(!nm_state_is_managed("10 (unmanaged)"));
        assert!(!nm_state_is_managed(""));
    }

    #[test]
    fn default_route_interfaces_are_parsed_from_proc() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\nwlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\nenp3s0\t007FA8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let found = parse_default_route_interfaces(text);
        assert!(found.contains("wlp2s0"));
        assert!(!found.contains("enp3s0"));
    }

    #[test]
    fn discovery_json_contract_uses_camel_case_and_optional_reachability() {
        let row = ArpCandidate {
            interface: "enx0".into(),
            address: "192.0.2.3".into(),
            mac: "00:11:22:33:44:55".into(),
            source: "ARP".into(),
            confidence: "较高".into(),
            arp_reachable: Some(false),
        };
        let output = serde_json::to_value(DiscoveryResult {
            candidates: vec![row],
            skipped_interfaces: vec!["enx1".into()],
            warnings: vec![],
        })
        .unwrap();
        assert!(output.get("candidates").is_some());
        assert!(output.get("skippedInterfaces").is_some());
        assert!(output["candidates"][0].get("arpReachable").is_some());
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
