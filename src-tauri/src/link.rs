//! Finding a directly cabled robot without knowing its IPv4 address and without root.
//!
//! Every Linux interface that is up has an IPv6 link-local address (`fe80::…`) and answers pings
//! to the all-nodes group `ff02::1`. So: ping `ff02::1%<nic>` on each cabled wired NIC, read the
//! IPv6 neighbour table for the peers' addresses and MACs, ask mDNS who they are, and check for an
//! SSH server. After the user confirms the host name, log in over the link-local address, read the
//! robot's IPv4 on that port and give this PC an address in that subnet.

use crate::commands::{command_text, get_host_info, route_interface};
use crate::model::{normalize_mac, validate_ifname, validate_username, Target, TargetMove};
use crate::ssh;
use crate::state::AppState;
use serde::Serialize;
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tauri::State;
use uuid::Uuid;

/// Host names that identify a robot (as opposed to a switch, a camera or another PC).
const ROBOT_PREFIXES: &[&str] = &["hoson-robot-"];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkPeer {
    pub interface: String,
    pub link_local: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub ssh_open: bool,
    pub ssh_banner: Option<String>,
    pub is_robot: bool,
    pub known_target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkScan {
    pub interfaces: Vec<String>,
    pub skipped: Vec<String>,
    pub peers: Vec<LinkPeer>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkPrepared {
    pub target: Target,
    pub fingerprint: Option<String>,
    /// The robot's host key differs from the one pinned for this robot earlier.
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkLogin {
    /// "session" (already logged in), "key" (RoboLink key) or "password".
    pub via: String,
    pub key_installed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RobotIpv4 {
    pub hostname: String,
    pub device: Option<String>,
    /// IPv4/prefix on the robot port this cable is plugged into.
    pub cidrs: Vec<String>,
    /// Addresses on the robot's side that this PC must not take (its other ports, its neighbours).
    pub avoid: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkFinished {
    pub target: Target,
    pub via_ipv4: bool,
}

pub fn is_robot_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ROBOT_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn parse_link_local(value: &str) -> Result<Ipv6Addr, String> {
    let ip = value
        .split('%')
        .next()
        .unwrap_or(value)
        .parse::<Ipv6Addr>()
        .map_err(|_| "IPv6 链路本地地址格式无效".to_string())?;
    if !ip.is_unicast_link_local() {
        return Err("只支持 fe80:: 链路本地地址".into());
    }
    Ok(ip)
}

fn ifindex(interface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn default_route_interfaces() -> HashSet<String> {
    let text = command_text("ip", &["-4", "route", "show", "default"]).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let words = line.split_whitespace().collect::<Vec<_>>();
            words
                .windows(2)
                .find(|w| w[0] == "dev")
                .map(|w| w[1].to_string())
        })
        .collect()
}

/// This PC's own link-local addresses on the interface.
fn own_link_locals(interface: &str) -> HashSet<Ipv6Addr> {
    let text = command_text(
        "ip",
        &[
            "-6", "-o", "addr", "show", "dev", interface, "scope", "link",
        ],
    )
    .unwrap_or_default();
    text.split_whitespace()
        .filter_map(|word| word.split('/').next()?.parse::<Ipv6Addr>().ok())
        .filter(Ipv6Addr::is_unicast_link_local)
        .collect()
}

/// `64 bytes from fe80::c072:3dfc:5e34:87ce%enx00e04c3071f5: icmp_seq=1 …` → the address.
fn parse_ping_responders(text: &str) -> Vec<Ipv6Addr> {
    let mut found = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.split(" from ").nth(1) else {
            continue;
        };
        let word = rest.split_whitespace().next().unwrap_or("");
        let address = word.trim_end_matches(':').split('%').next().unwrap_or("");
        if let Ok(ip) = address.parse::<Ipv6Addr>() {
            if ip.is_unicast_link_local() && !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found
}

/// Link-local neighbours with their MACs from `ip -j -6 neigh show dev <nic>`.
fn parse_neighbors(rows: &[Value]) -> BTreeMap<Ipv6Addr, Option<String>> {
    let mut result = BTreeMap::new();
    for row in rows {
        let Some(ip) = row
            .get("dst")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
        else {
            continue;
        };
        if !ip.is_unicast_link_local() {
            continue;
        }
        let failed = row
            .get("state")
            .and_then(Value::as_array)
            .is_some_and(|states| {
                states
                    .iter()
                    .any(|s| matches!(s.as_str(), Some("FAILED" | "INCOMPLETE")))
            });
        if failed {
            continue;
        }
        let mac = row
            .get("lladdr")
            .and_then(Value::as_str)
            .and_then(normalize_mac);
        result.insert(ip, mac);
    }
    result
}

fn neighbors(interface: &str) -> BTreeMap<Ipv6Addr, Option<String>> {
    Command::new("ip")
        .args(["-j", "-6", "neigh", "show", "dev", interface])
        .output()
        .ok()
        .and_then(|out| serde_json::from_slice::<Vec<Value>>(&out.stdout).ok())
        .map(|rows| parse_neighbors(&rows))
        .unwrap_or_default()
}

/// Pings the all-nodes group on the interface (no root needed) and returns the peers that answered
/// or sit in the neighbour table, with their MACs.
fn link_peers(interface: &str) -> Vec<(Ipv6Addr, Option<String>)> {
    let target = format!("ff02::1%{interface}");
    let mut ping = Command::new("ping");
    ping.args(["-6", "-n", "-c", "3", "-i", "0.3", "-W", "1", &target])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    let mut responders = Vec::new();
    if let Ok(mut child) = ping.spawn() {
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() < Duration::from_secs(4) => {
                    thread::sleep(Duration::from_millis(50))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
        let mut text = String::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut text);
        }
        responders = parse_ping_responders(&text);
    }
    let own = own_link_locals(interface);
    let table = neighbors(interface);
    let mut peers: Vec<(Ipv6Addr, Option<String>)> = Vec::new();
    for ip in responders.iter().chain(table.keys()) {
        if own.contains(ip) || peers.iter().any(|(p, _)| p == ip) {
            continue;
        }
        peers.push((*ip, table.get(ip).cloned().flatten()));
    }
    peers.truncate(16);
    peers
}

/// Reverse name of an IPv6 address for a PTR query: `e.c.7.8…ip6.arpa`.
fn reverse_name(ip: Ipv6Addr) -> String {
    let mut parts = Vec::with_capacity(34);
    for byte in ip.octets().iter().rev() {
        parts.push(format!("{:x}", byte & 0x0f));
        parts.push(format!("{:x}", byte >> 4));
    }
    parts.push("ip6".into());
    parts.push("arpa".into());
    parts.join(".")
}

fn ptr_query(name: &str, unicast_response: bool) -> Vec<u8> {
    let mut packet = vec![0u8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, 12]);
    packet.extend_from_slice(if unicast_response {
        &[0x80, 1]
    } else {
        &[0, 1]
    });
    packet
}

/// Reads a (possibly compressed) DNS name at `offset`; returns the name and the offset after it.
fn read_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *packet.get(offset)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(offset + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let low = *packet.get(offset + 1)? as usize;
            end.get_or_insert(offset + 2);
            offset = ((len & 0x3f) << 8) | low;
            continue;
        }
        let label = packet.get(offset + 1..offset + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        offset += 1 + len;
    }
    None
}

/// The PTR answer for `name` in an mDNS response, if any.
fn parse_ptr_answer(packet: &[u8], name: &str) -> Option<String> {
    if packet.len() < 12 || packet[2] & 0x80 == 0 {
        return None;
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let records = u16::from_be_bytes([packet[6], packet[7]]) as usize
        + u16::from_be_bytes([packet[8], packet[9]]) as usize
        + u16::from_be_bytes([packet[10], packet[11]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = read_name(packet, offset)?.1 + 4;
    }
    for _ in 0..records.min(64) {
        let (owner, after) = read_name(packet, offset)?;
        let header = packet.get(after..after + 10)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = after + 10;
        if kind == 12 && owner.eq_ignore_ascii_case(name) {
            let (target, _) = read_name(packet, data)?;
            return clean_hostname(&target);
        }
        offset = data + length;
    }
    None
}

fn clean_hostname(value: &str) -> Option<String> {
    let name = value.trim().trim_end_matches('.');
    let name = name.strip_suffix(".local").unwrap_or(name);
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    valid.then(|| name.to_ascii_lowercase())
}

/// Asks the peer's mDNS responder (avahi) for the name behind its link-local address: one legacy
/// unicast query straight to the peer plus a multicast query, then `avahi-resolve` as a fallback.
fn mdns_hostname(ip: Ipv6Addr, interface: &str) -> Option<String> {
    let scope = ifindex(interface);
    let name = reverse_name(ip);
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut sockets = Vec::new();
    if let Ok(socket) = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)) {
        let _ = socket.send_to(
            &ptr_query(&name, false),
            SocketAddrV6::new(ip, 5353, 0, scope),
        );
        let _ = socket.send_to(
            &ptr_query(&name, true),
            SocketAddrV6::new("ff02::fb".parse().unwrap(), 5353, 0, scope),
        );
        sockets.push(socket);
    }
    // Plain multicast query from port 5353, for responders that ignore legacy unicast.
    if let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        let group: Ipv6Addr = "ff02::fb".parse().unwrap();
        let _ = socket.set_reuse_address(true);
        let _ = socket.set_reuse_port(true);
        let _ = socket.set_only_v6(true);
        let bound = socket
            .bind(&SockAddr::from(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                5353,
                0,
                0,
            )))
            .is_ok();
        if bound && socket.join_multicast_v6(&group, scope).is_ok() {
            let _ = socket.set_multicast_if_v6(scope);
            let socket: UdpSocket = socket.into();
            let _ = socket.send_to(
                &ptr_query(&name, false),
                SocketAddrV6::new(group, 5353, 0, scope),
            );
            sockets.push(socket);
        }
    }
    let mut buffer = [0u8; 9000];
    while Instant::now() < deadline && !sockets.is_empty() {
        for socket in &sockets {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(60)));
            if let Ok((len, _)) = socket.recv_from(&mut buffer) {
                if let Some(host) = parse_ptr_answer(&buffer[..len], &name) {
                    return Some(host);
                }
            }
        }
    }
    avahi_resolve(ip)
}

fn avahi_resolve(ip: Ipv6Addr) -> Option<String> {
    let mut child = Command::new("avahi-resolve")
        .args(["-a", &ip.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < Duration::from_secs(3) => {
                thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut text = String::new();
    child.stdout.take()?.read_to_string(&mut text).ok()?;
    clean_hostname(text.split_whitespace().nth(1)?)
}

/// Whether an SSH server answers on port 22 of the link-local address, and its banner.
fn ssh_banner(ip: Ipv6Addr, interface: &str) -> Option<String> {
    let address = SocketAddr::V6(SocketAddrV6::new(ip, 22, 0, ifindex(interface)));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(1500)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let mut buffer = [0u8; 256];
    let len = stream.read(&mut buffer).unwrap_or(0);
    let text = String::from_utf8_lossy(&buffer[..len]);
    let line = text.lines().next().unwrap_or("").trim();
    Some(if line.starts_with("SSH-") {
        line.chars().take(80).collect()
    } else {
        String::new()
    })
}

fn known_target(targets: &[Target], hostname: Option<&str>, mac: Option<&str>) -> Option<String> {
    hostname
        .and_then(|name| targets.iter().find(|t| t.hostname.as_deref() == Some(name)))
        .or_else(|| mac.and_then(|mac| targets.iter().find(|t| t.macs.iter().any(|m| m == mac))))
        .map(|t| t.id.clone())
}

/// Step 1–3 of the procedure: every cabled wired NIC, its peers, their names and SSH servers.
#[tauri::command(async)]
pub fn find_link_peers(state: State<'_, AppState>) -> Result<LinkScan, String> {
    let host = get_host_info()?;
    let uplinks = default_route_interfaces();
    let mut interfaces = Vec::new();
    let mut skipped = Vec::new();
    for iface in host.interfaces.iter().filter(|i| i.kind == "有线以太网") {
        if !iface.carrier {
            skipped.push(format!("{}：没有插网线", iface.name));
        } else if uplinks.contains(&iface.name) {
            skipped.push(format!("{}：这是本机上网的网口", iface.name));
        } else if validate_ifname(&iface.name).is_ok() {
            interfaces.push(iface.name.clone());
        }
    }
    let handles = interfaces
        .iter()
        .cloned()
        .map(|interface| {
            thread::spawn(move || {
                let peers = link_peers(&interface);
                let probes = peers
                    .into_iter()
                    .map(|(ip, mac)| {
                        let interface = interface.clone();
                        thread::spawn(move || {
                            let name_iface = interface.clone();
                            let name = thread::spawn(move || mdns_hostname(ip, &name_iface));
                            let banner = ssh_banner(ip, &interface);
                            let hostname = name.join().ok().flatten();
                            (interface, ip, mac, hostname, banner)
                        })
                    })
                    .collect::<Vec<_>>();
                probes
                    .into_iter()
                    .filter_map(|h| h.join().ok())
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let targets = state.load_targets().unwrap_or_default();
    let mut peers = Vec::new();
    for handle in handles {
        for (interface, ip, mac, hostname, banner) in handle.join().unwrap_or_default() {
            let is_robot = hostname.as_deref().is_some_and(is_robot_name);
            peers.push(LinkPeer {
                known_target_id: known_target(&targets, hostname.as_deref(), mac.as_deref()),
                interface,
                link_local: ip.to_string(),
                mac,
                hostname,
                ssh_open: banner.is_some(),
                ssh_banner: banner.filter(|b| !b.is_empty()),
                is_robot,
            });
        }
    }
    peers.sort_by_key(|p| (!p.is_robot, !p.ssh_open, p.hostname.is_none()));
    Ok(LinkScan {
        interfaces,
        skipped,
        peers,
    })
}

fn link_host(ip: Ipv6Addr, interface: &str) -> String {
    format!("{ip}%{interface}")
}

fn save_target(state: &AppState, target: &Target) -> Result<(), String> {
    let mut targets = state.load_targets()?;
    if let Some(entry) = targets.iter_mut().find(|t| t.id == target.id) {
        *entry = target.clone();
    } else {
        targets.push(target.clone());
    }
    state.save_targets(&targets)
}

/// Step 4 begins: the user confirmed the host name. Record the robot (by host name, then MAC) with
/// its link-local address as the SSH host, and pin its host key on first contact.
#[tauri::command(async)]
pub fn link_prepare(
    state: State<'_, AppState>,
    interface: String,
    link_local: String,
    mac: Option<String>,
    hostname: Option<String>,
    username: String,
) -> Result<LinkPrepared, String> {
    validate_ifname(&interface)?;
    let ip = parse_link_local(&link_local)?;
    let username = validate_username(&username)?;
    let hostname = hostname.as_deref().and_then(clean_hostname);
    let mac = mac.as_deref().and_then(normalize_mac);
    let targets = state.load_targets()?;
    let existing = known_target(&targets, hostname.as_deref(), mac.as_deref())
        .and_then(|id| targets.iter().find(|t| t.id == id).cloned());
    let mut target = existing.clone().unwrap_or_else(|| Target {
        id: Uuid::new_v4().to_string(),
        name: hostname
            .clone()
            .unwrap_or_else(|| format!("机器人 {}", mac.clone().unwrap_or_default())),
        host: String::new(),
        port: 22,
        username: username.clone(),
        macs: Vec::new(),
        interface: None,
        key_login: false,
        hostname: None,
    });
    if let Some(old) = &existing {
        ssh::drop_channel(&state, old);
        if old.username != username {
            target.key_login = false;
        }
    }
    target.host = link_host(ip, &interface);
    target.port = 22;
    target.username = username;
    target.interface = Some(interface);
    if hostname.is_some() {
        target.hostname = hostname;
    }
    if let Some(mac) = mac {
        if !target.macs.contains(&mac) {
            target.macs.push(mac);
        }
    }
    save_target(&state, &target)?;
    let status = ssh::host_key_status(&state, &target)?;
    if status.changed {
        return Ok(LinkPrepared {
            target,
            fingerprint: status.fingerprints.first().cloned(),
            changed: true,
        });
    }
    let fingerprint = status
        .fingerprints
        .iter()
        .find(|f| f.starts_with("ssh-ed25519"))
        .or(status.fingerprints.first())
        .cloned()
        .ok_or("没有读取到机器人的 SSH 主机密钥")?;
    if !status.trusted {
        // The user picked this robot by its host name; its key is pinned now and checked on every
        // later connection, whatever address the robot is reached at.
        ssh::trust_host_key(&state, &target, &fingerprint)?;
    }
    Ok(LinkPrepared {
        target,
        fingerprint: Some(fingerprint),
        changed: false,
    })
}

/// Logs in with RoboLink's key, or once with the password and then installs the key.
#[tauri::command(async)]
pub fn link_login(
    state: State<'_, AppState>,
    target_id: String,
    password: Option<String>,
) -> Result<LinkLogin, String> {
    let mut target = ssh::lookup_target(&state, &target_id)?;
    ssh::ensure_pinned(&state, &target)?;
    let via = if ssh::master_alive(&state, &target) {
        "session"
    } else if state.identity_file.is_file() && ssh::key_login(&state, &target) {
        "key"
    } else if let Some(password) = password.as_deref().filter(|p| !p.is_empty()) {
        ssh::password_login(&state, &target, password)?;
        "password"
    } else {
        return Err(format!(
            "{}第一次连接 {} 需要输入一次用户 {} 的登录密码，之后会改用 RoboLink 的密钥免密登录。",
            ssh::PASSWORD_MARK,
            target.name,
            target.username
        ));
    };
    let key_installed = if via == "key" {
        true
    } else {
        ssh::install_app_key(&state, &target).is_ok()
    };
    if key_installed && !target.key_login {
        target.key_login = true;
        save_target(&state, &target)?;
    }
    Ok(LinkLogin {
        via: via.into(),
        key_installed,
    })
}

fn robot_ipv4_script(link_local: Ipv6Addr) -> String {
    format!(
        r#"LL='{link_local}'
dev=$(ip -o -6 addr show 2>/dev/null | awk -v ll="$LL" '{{split($4,a,"/"); if (a[1]==ll) {{print $2; exit}}}}')
echo "HOST=$(hostname)"
echo "DEV=$dev"
[ -n "$dev" ] && ip -o -4 addr show dev "$dev" 2>/dev/null | awk '{{print "ADDR="$4}}'
ip -o -4 addr show 2>/dev/null | awk '{{print "ALL="$4}}'
ip -4 neigh show 2>/dev/null | awk '{{print "NEIGH="$1}}'
exit 0"#
    )
}

fn parse_robot_ipv4(text: &str) -> RobotIpv4 {
    let mut result = RobotIpv4 {
        hostname: String::new(),
        device: None,
        cidrs: Vec::new(),
        avoid: Vec::new(),
    };
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "HOST" => result.hostname = value.to_string(),
            "DEV" if !value.is_empty() => result.device = Some(value.to_string()),
            "ADDR" => {
                let ok = value
                    .split_once('/')
                    .and_then(|(ip, p)| Some((ip.parse::<Ipv4Addr>().ok()?, p.parse::<u8>().ok()?)))
                    .is_some_and(|(ip, p)| {
                        !ip.is_loopback() && !ip.is_link_local() && (8..=30).contains(&p)
                    });
                if ok && !result.cidrs.iter().any(|c| c == value) {
                    result.cidrs.push(value.to_string());
                }
            }
            "ALL" | "NEIGH" => {
                if let Some(ip) = value
                    .split('/')
                    .next()
                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                {
                    let text = ip.to_string();
                    if !result.avoid.contains(&text) && result.avoid.len() < 200 {
                        result.avoid.push(text);
                    }
                }
            }
            _ => {}
        }
    }
    result
}

/// Step 4: over the link-local login, which IPv4 does the robot have on the port this cable is in.
#[tauri::command(async)]
pub fn link_robot_ipv4(
    state: State<'_, AppState>,
    target_id: String,
    link_local: String,
) -> Result<RobotIpv4, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let ip = parse_link_local(&link_local)?;
    let output = ssh::remote_command(&state, &target, &robot_ipv4_script(ip))?;
    let info = parse_robot_ipv4(&output);
    if let Some(name) = clean_hostname(&info.hostname) {
        if target.hostname.as_deref() != Some(name.as_str()) {
            let mut updated = target.clone();
            updated.hostname = Some(name);
            save_target(&state, &updated)?;
        }
    }
    Ok(info)
}

/// Step 5/6: switch the robot to its IPv4 address once this PC has a route to it through the
/// cable and key login works there; otherwise keep the link-local address, which needs no root.
#[tauri::command(async)]
pub fn link_finish(
    state: State<'_, AppState>,
    target_id: String,
    ipv4: Option<String>,
) -> Result<LinkFinished, String> {
    let target = ssh::lookup_target(&state, &target_id)?;
    let Some(address) = ipv4
        .as_deref()
        .and_then(|value| value.split('/').next()?.parse::<Ipv4Addr>().ok())
    else {
        return Ok(LinkFinished {
            target,
            via_ipv4: false,
        });
    };
    let interface = target.interface.clone().unwrap_or_default();
    if !target.key_login || route_interface(&address.to_string()).as_deref() != Some(&interface) {
        return Ok(LinkFinished {
            target,
            via_ipv4: false,
        });
    }
    let mut candidate = target.clone();
    candidate.host = address.to_string();
    if !ssh::key_login(&state, &candidate) {
        return Ok(LinkFinished {
            target,
            via_ipv4: false,
        });
    }
    save_target(&state, &candidate)?;
    // The link-local master is no longer needed.
    ssh::drop_channel(&state, &target);
    Ok(LinkFinished {
        target: candidate,
        via_ipv4: true,
    })
}

/// Recovery without root: the robot's MAC answers on `ff02::1` again → its link-local address →
/// (with key login) its current IPv4. Uses IPv4 when this PC can route it over the cable, otherwise
/// the link-local address.
pub fn relocate_by_link_local(state: &AppState, target: &Target) -> Option<TargetMove> {
    let interface = target.interface.clone()?;
    if target.macs.is_empty() || validate_ifname(&interface).is_err() {
        return None;
    }
    let (ip, _) = link_peers(&interface)
        .into_iter()
        .find(|(_, mac)| mac.as_ref().is_some_and(|m| target.macs.contains(m)))?;
    let mut moved = target.clone();
    moved.host = link_host(ip, &interface);
    if target.key_login && ssh::key_login(state, &moved) {
        if let Ok(output) = ssh::remote_command(state, &moved, &robot_ipv4_script(ip)) {
            let info = parse_robot_ipv4(&output);
            if let Some(v4) = info.cidrs.first().and_then(|c| c.split('/').next()) {
                if route_interface(v4).as_deref() == Some(interface.as_str()) {
                    ssh::drop_channel(state, &moved);
                    moved.host = v4.to_string();
                }
            }
        }
    }
    if moved.host == target.host {
        return None;
    }
    save_target(state, &moved).ok()?;
    ssh::drop_channel(state, target);
    Some(TargetMove {
        target_id: target.id.clone(),
        name: target.name.clone(),
        old_host: target.host.clone(),
        new_host: moved.host,
        interface: Some(interface),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_output_yields_link_local_responders() {
        let text = "PING ff02::1%enx1(ff02::1%enx1) 56 data bytes\n64 bytes from fe80::1%enx1: icmp_seq=1 ttl=64 time=0.05 ms\n64 bytes from fe80::c072:3dfc:5e34:87ce%enx1: icmp_seq=1 ttl=64 time=0.6 ms\n64 bytes from fe80::c072:3dfc:5e34:87ce%enx1: icmp_seq=2 ttl=64 time=0.5 ms\n";
        let found = parse_ping_responders(text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].to_string(), "fe80::c072:3dfc:5e34:87ce");
    }

    #[test]
    fn neighbours_keep_link_local_with_mac() {
        let rows: Vec<Value> = serde_json::from_str(
            r#"[{"dst":"fe80::c072:3dfc:5e34:87ce","dev":"enx1","lladdr":"34:DF:20:0A:6D:9B","state":["STALE"]},
                {"dst":"2001:db8::1","dev":"enx1","lladdr":"34:df:20:0a:6d:9c","state":["REACHABLE"]},
                {"dst":"fe80::2","dev":"enx1","state":["FAILED"]}]"#,
        )
        .unwrap();
        let table = parse_neighbors(&rows);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.values().next().unwrap().as_deref(),
            Some("34:df:20:0a:6d:9b")
        );
    }

    #[test]
    fn reverse_name_and_ptr_answer_round_trip() {
        let ip: Ipv6Addr = "fe80::c072:3dfc:5e34:87ce".parse().unwrap();
        let name = reverse_name(ip);
        assert!(name.starts_with("e.c.7.8.4.3.e.5"));
        assert!(name.ends_with(".0.8.e.f.ip6.arpa"));
        // Response: header, the question echoed, one PTR answer using a compression pointer.
        let mut packet = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        let question = ptr_query(&name, false);
        packet.extend_from_slice(&question[12..]);
        packet.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10]);
        let target = b"\x18hoson-robot-20260417-001\x05local\x00";
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(target);
        assert_eq!(
            parse_ptr_answer(&packet, &name).as_deref(),
            Some("hoson-robot-20260417-001")
        );
        assert!(parse_ptr_answer(&packet[..20], &name).is_none());
    }

    #[test]
    fn robot_names_and_ipv4_report_are_parsed() {
        assert!(is_robot_name("hoson-robot-20260417-001"));
        assert!(!is_robot_name("wzc-ubuntu"));
        let info = parse_robot_ipv4(
            "HOST=hoson-robot-20260417-001\nDEV=enp4s0\nADDR=192.168.9.17/24\nALL=127.0.0.1/8\nALL=192.168.9.17/24\nALL=192.168.9.10/24\nNEIGH=192.168.9.21\n",
        );
        assert_eq!(info.device.as_deref(), Some("enp4s0"));
        assert_eq!(info.cidrs, vec!["192.168.9.17/24"]);
        assert!(info.avoid.contains(&"192.168.9.10".to_string()));
        assert!(info.avoid.contains(&"192.168.9.21".to_string()));
        assert!(robot_ipv4_script("fe80::1".parse().unwrap()).contains("LL='fe80::1'"));
    }
}
