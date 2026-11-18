//! "Get the robot an IPv4" wizard, run after the link-local login (`hoson@fe80::…%<nic>`).
//!
//! 1. Find the robot NIC that owns the link-local address.
//! 2. Read its IPv4, its NetworkManager connection and `ipv4.method`, and every robot subnet.
//! 3. method=auto: serve direct DHCP on this PC's port and poll the robot for up to 15 s.
//! 4. manual / inactive / DHCP timed out: after the user confirms, add a temporary address on the
//!    robot with `sudo -S ip addr add` (password over stdin only; NM profiles untouched).
//! 5. Cancelled or failed: keep using `fe80::…%<nic>` and write a `~/.ssh/config` alias.
//! 6. Verify over IPv4 and remember host name → IPv4, robot NIC, PC port, how it was obtained.
//!
//! Each step reports progress to the window as a `link-wizard` event.

use crate::commands::start_direct_dhcp;
use crate::link::{link_host, parse_link_local, save_target};
use crate::model::{validate_ifname, LinkRecord, Target};
use crate::ssh::{self, RemoteOptions};
use crate::state::AppState;
use serde::Serialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

const DHCP_WAIT: Duration = Duration::from_secs(15);
const DHCP_POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardEvent {
    pub target_id: String,
    pub step: u8,
    /// "running" | "done" | "skip" | "fail"
    pub status: String,
    pub text: String,
}

fn emit(app: &AppHandle, target_id: &str, step: u8, status: &str, text: impl Into<String>) {
    let _ = app.emit(
        "link-wizard",
        WizardEvent {
            target_id: target_id.into(),
            step,
            status: status.into(),
            text: text.into(),
        },
    );
}

/// What the robot told us about the NIC the cable is in.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RobotPort {
    pub hostname: String,
    pub device: Option<String>,
    /// IPv4/prefix on that NIC.
    pub cidrs: Vec<String>,
    /// NetworkManager is installed on the robot.
    pub nm: bool,
    /// Active connection on the NIC (`GENERAL.CONNECTION`), empty when none is active.
    pub connection: Option<String>,
    /// `ipv4.method` of the active connection, or of the profile bound to the NIC.
    pub method: Option<String>,
    /// Every IPv4 subnet on the robot, as (device, address, prefix).
    pub nets: Vec<(String, Ipv4Addr, u8)>,
    /// Addresses in the robot's ARP table (internal devices).
    pub neighbors: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    /// The NIC already has an IPv4: go to step 6.
    Existing,
    /// Active NM connection with method=auto: try direct DHCP.
    Dhcp,
    /// Needs a temporary address on the robot.
    Manual,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub port: RobotPort,
    pub plan: Plan,
    /// Why the plan was chosen, for the step text.
    pub reason: String,
    /// Addresses this PC must not take (robot addresses and its neighbours).
    pub avoid: Vec<String>,
}

fn robot_port_script(link_local: Ipv6Addr) -> String {
    format!(
        r#"LL='{link_local}'
dev=$(ip -o -6 addr show 2>/dev/null | awk -v ll="$LL" '{{split($4,a,"/"); if (a[1]==ll) {{print $2; exit}}}}')
echo "HOST=$(hostname)"
echo "DEV=$dev"
if [ -n "$dev" ]; then
  ip -o -4 addr show dev "$dev" 2>/dev/null | awk '{{print "ADDR="$4}}'
  if command -v nmcli >/dev/null 2>&1; then
    echo "NM=yes"
    conn=$(nmcli -g GENERAL.CONNECTION dev show "$dev" 2>/dev/null)
    echo "CONN=$conn"
    if [ -n "$conn" ]; then
      echo "METHOD=$(nmcli -g ipv4.method con show "$conn" 2>/dev/null)"
    else
      nmcli -t -f NAME con show 2>/dev/null | sed 's/\\:/:/g' | while IFS= read -r n; do
        [ "$(nmcli -g connection.interface-name con show "$n" 2>/dev/null)" = "$dev" ] && echo "PROFILE_METHOD=$(nmcli -g ipv4.method con show "$n" 2>/dev/null)"
      done
    fi
  fi
fi
ip -o -4 addr show 2>/dev/null | awk '{{print "NET="$2" "$4}}'
ip -4 neigh show 2>/dev/null | awk '{{print "NEIGH="$1}}'
exit 0"#
    )
}

fn parse_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = value.trim().split_once('/')?;
    let ip = ip.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok().filter(|p| *p <= 32)?;
    Some((ip, prefix))
}

/// An IPv4 that can carry the link: not loopback, not 169.254, a sane prefix.
fn usable(ip: Ipv4Addr, prefix: u8) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && (8..=30).contains(&prefix)
}

pub fn parse_robot_port(text: &str) -> RobotPort {
    let mut port = RobotPort::default();
    let mut profile_method = None;
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "HOST" => port.hostname = value.to_string(),
            "DEV" if !value.is_empty() => port.device = Some(value.to_string()),
            "ADDR" => {
                if parse_cidr(value).is_some_and(|(ip, p)| usable(ip, p))
                    && !port.cidrs.iter().any(|c| c == value)
                {
                    port.cidrs.push(value.to_string());
                }
            }
            "NM" => port.nm = true,
            "CONN" if !value.is_empty() && value != "--" => {
                port.connection = Some(value.to_string())
            }
            "METHOD" if !value.is_empty() => port.method = Some(value.to_string()),
            "PROFILE_METHOD" if !value.is_empty() && profile_method.is_none() => {
                profile_method = Some(value.to_string())
            }
            "NET" => {
                let mut parts = value.split_whitespace();
                if let (Some(dev), Some(Some((ip, p)))) =
                    (parts.next(), parts.next().map(parse_cidr))
                {
                    if !ip.is_loopback() {
                        port.nets.push((dev.to_string(), ip, p));
                    }
                }
            }
            "NEIGH" => {
                if let Ok(ip) = value.parse::<Ipv4Addr>() {
                    if !port.neighbors.contains(&ip) && port.neighbors.len() < 200 {
                        port.neighbors.push(ip);
                    }
                }
            }
            _ => {}
        }
    }
    if port.method.is_none() {
        port.method = profile_method;
    }
    port
}

/// Step 2's decision.
pub fn choose_plan(port: &RobotPort) -> (Plan, String) {
    let device = port.device.as_deref().unwrap_or("这个网口");
    if let Some(cidr) = port.cidrs.first() {
        return (Plan::Existing, format!("{device} 已有 {cidr}"));
    }
    if !port.nm {
        return (
            Plan::Manual,
            format!("{device} 没有 IPv4，机器人上没有 NetworkManager"),
        );
    }
    match (port.connection.as_deref(), port.method.as_deref()) {
        (Some(conn), Some("auto")) => (
            Plan::Dhcp,
            format!("{device} 没有 IPv4，连接「{conn}」是自动获取（DHCP）"),
        ),
        (Some(conn), Some(method)) => (
            Plan::Manual,
            format!("{device} 没有 IPv4，连接「{conn}」的 IPv4 方式是 {method}"),
        ),
        (Some(conn), None) => (
            Plan::Manual,
            format!("{device} 没有 IPv4，读不到连接「{conn}」的 IPv4 方式"),
        ),
        (None, _) => (
            Plan::Manual,
            format!("{device} 没有 IPv4，也没有已激活的连接"),
        ),
    }
}

pub fn avoid_list(port: &RobotPort) -> Vec<String> {
    let mut avoid: Vec<String> = port
        .nets
        .iter()
        .map(|(_, ip, _)| ip.to_string())
        .chain(port.neighbors.iter().map(Ipv4Addr::to_string))
        .collect();
    avoid.dedup();
    let mut seen = HashSet::new();
    avoid.retain(|a| seen.insert(a.clone()));
    avoid
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

pub fn overlaps(a: Ipv4Addr, ap: u8, b: Ipv4Addr, bp: u8) -> bool {
    let p = ap.min(bp);
    (u32::from(a) & mask(p)) == (u32::from(b) & mask(p))
}

/// A /24 for direct DHCP that overlaps neither this PC's subnets nor the robot's.
pub fn pick_dhcp_subnet(taken: &[(Ipv4Addr, u8)]) -> Option<(Ipv4Addr, u8)> {
    let candidates = (77..=99)
        .map(|c| Ipv4Addr::new(192, 168, c, 1))
        .chain((77..=99).map(|b| Ipv4Addr::new(10, b, 0, 1)))
        .chain((77..=90).map(|b| Ipv4Addr::new(172, 16, b, 1)));
    candidates
        .into_iter()
        .find(|ip| !taken.iter().any(|(t, p)| overlaps(*ip, 24, *t, *p)))
        .map(|ip| (ip, 24))
}

/// Candidate host addresses for the robot in `net`, middle of the range first (the PC takes the
/// top, DHCP pools and internal devices tend to sit low), skipping `exclude`.
pub fn robot_address_candidates(
    net: (Ipv4Addr, u8),
    exclude: &HashSet<Ipv4Addr>,
    limit: usize,
) -> Vec<Ipv4Addr> {
    let (ip, prefix) = net;
    if !(16..=30).contains(&prefix) {
        return Vec::new();
    }
    let base = u32::from(ip) & mask(prefix);
    let size = 1u32 << (32 - prefix as u32);
    let last = size - 2; // highest host number
    let mut order: Vec<u32> = Vec::new();
    for n in (100..=199).chain(20..=99).chain(2..=19) {
        if n <= last {
            order.push(n);
        }
    }
    if order.is_empty() {
        order.extend(1..=last);
    }
    order
        .into_iter()
        .map(|n| Ipv4Addr::from(base + n))
        .filter(|a| !exclude.contains(a))
        .take(limit)
        .collect()
}

/// This PC's IPv4 addresses, as (device, address, prefix).
fn pc_addresses() -> Vec<(String, Ipv4Addr, u8)> {
    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    parse_ip_o_addr(&output)
}

/// Parses `ip -o -4 addr show` lines: `3: enp4s0    inet 192.168.9.17/24 brd … scope global …`.
pub fn parse_ip_o_addr(text: &str) -> Vec<(String, Ipv4Addr, u8)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            parts.next()?;
            let dev = parts.next()?.split('@').next()?.to_string();
            let mut rest = parts.skip_while(|p| *p != "inet");
            rest.next()?;
            let (ip, prefix) = parse_cidr(rest.next()?)?;
            Some((dev, ip, prefix))
        })
        .collect()
}

fn pc_neighbors(interface: &str) -> HashSet<Ipv4Addr> {
    Command::new("ip")
        .args(["-4", "neigh", "show", "dev", interface])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.contains("FAILED") && !l.contains("INCOMPLETE"))
                .filter_map(|l| l.split_whitespace().next()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Something answers at `ip` through `interface` (unprivileged unicast ping).
fn answers(ip: Ipv4Addr, interface: &str) -> bool {
    Command::new("ping")
        .args([
            "-n",
            "-q",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            interface,
            &ip.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The target, reached at the robot's link-local address on `interface`.
fn link_target(
    state: &AppState,
    target_id: &str,
    link_local: &str,
) -> Result<(Target, Ipv6Addr, String), String> {
    let target = ssh::lookup_target(state, target_id)?;
    let ip = parse_link_local(link_local)?;
    let interface = target
        .interface
        .clone()
        .or_else(|| target.link.as_ref().map(|l| l.pc_interface.clone()))
        .ok_or("不知道机器人接在本机哪个网口")?;
    validate_ifname(&interface)?;
    let mut via = target.clone();
    via.host = link_host(ip, &interface);
    Ok((via, ip, interface))
}

fn read_port(state: &AppState, via: &Target, ip: Ipv6Addr) -> Result<RobotPort, String> {
    let output = ssh::remote_command(state, via, &robot_port_script(ip))?;
    Ok(parse_robot_port(&output))
}

/// Steps 1 and 2.
#[tauri::command(async)]
pub fn link_ipv4_probe(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    link_local: String,
) -> Result<ProbeResult, String> {
    emit(
        &app,
        &target_id,
        1,
        "running",
        "经链路本地地址查找机器人网卡…",
    );
    let (via, ip, _) = link_target(&state, &target_id, &link_local).inspect_err(|e| {
        emit(&app, &target_id, 1, "fail", e.clone());
    })?;
    let port = read_port(&state, &via, ip).inspect_err(|e| {
        emit(
            &app,
            &target_id,
            1,
            "fail",
            format!("读取机器人网卡失败：{e}"),
        );
    })?;
    let Some(device) = port.device.clone() else {
        let text = format!("机器人上没有找到持有 {ip} 的网卡");
        emit(&app, &target_id, 1, "fail", text.clone());
        return Err(text);
    };
    emit(
        &app,
        &target_id,
        1,
        "done",
        format!("网线接在机器人的 {device}"),
    );
    let (plan, reason) = choose_plan(&port);
    emit(&app, &target_id, 2, "done", reason.clone());
    if !port.hostname.is_empty() {
        let mut target = ssh::lookup_target(&state, &target_id)?;
        if target.hostname.as_deref() != Some(port.hostname.as_str()) {
            target.hostname = Some(port.hostname.clone());
            save_target(&state, &target)?;
        }
    }
    let avoid = avoid_list(&port);
    Ok(ProbeResult {
        port,
        plan,
        reason,
        avoid,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpOutcome {
    /// IPv4/prefix the robot got, or None after the wait.
    pub cidr: Option<String>,
    /// The DHCP server's address on this PC.
    pub server: Option<String>,
    pub reason: Option<String>,
}

/// Step 3: direct DHCP on this PC's port, polling the robot over the link-local address.
#[tauri::command(async)]
pub fn link_ipv4_dhcp(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    link_local: String,
) -> Result<DhcpOutcome, String> {
    let (via, ip, interface) = link_target(&state, &target_id, &link_local)?;
    let fail = |reason: String| {
        emit(&app, &target_id, 3, "fail", reason.clone());
        Ok(DhcpOutcome {
            cidr: None,
            server: None,
            reason: Some(reason),
        })
    };
    let port = read_port(&state, &via, ip)?;
    let mut taken: Vec<(Ipv4Addr, u8)> = pc_addresses()
        .into_iter()
        .map(|(_, ip, p)| (ip, p))
        .collect();
    taken.extend(port.nets.iter().map(|(_, ip, p)| (*ip, *p)));
    let Some((server, prefix)) = pick_dhcp_subnet(&taken) else {
        return fail("找不到一个和本机、机器人都不重叠的网段".into());
    };
    let wanted = format!("{server}/{prefix}");
    emit(
        &app,
        &target_id,
        3,
        "running",
        format!("在本机 {interface} 上用 {wanted} 启动直连 DHCP（会请求一次系统授权）…"),
    );
    let status = match start_direct_dhcp(interface.clone(), wanted) {
        Ok(list) => list,
        Err(e) => return fail(format!("直连 DHCP 没有启动：{e}")),
    };
    let server_cidr = status
        .iter()
        .find(|s| s.interface == interface && s.running)
        .map(|s| s.cidr.clone());
    let Some(server_cidr) = server_cidr else {
        return fail("直连 DHCP 没有运行".into());
    };
    let started = Instant::now();
    while started.elapsed() < DHCP_WAIT {
        thread::sleep(DHCP_POLL);
        let left = DHCP_WAIT.saturating_sub(started.elapsed()).as_secs();
        emit(
            &app,
            &target_id,
            3,
            "running",
            format!("直连 DHCP（{server_cidr}）已启动，等待机器人领取地址…还剩约 {left} 秒"),
        );
        if let Ok(now) = read_port(&state, &via, ip) {
            if let Some(cidr) = now.cidrs.first() {
                emit(
                    &app,
                    &target_id,
                    3,
                    "done",
                    format!("机器人通过 DHCP 拿到 {cidr}"),
                );
                return Ok(DhcpOutcome {
                    cidr: Some(cidr.clone()),
                    server: Some(server_cidr),
                    reason: None,
                });
            }
        }
    }
    let reason = format!("等了 {} 秒，机器人没有领取地址", DHCP_WAIT.as_secs());
    emit(&app, &target_id, 3, "fail", reason.clone());
    Ok(DhcpOutcome {
        cidr: None,
        server: Some(server_cidr),
        reason: Some(reason),
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempProposal {
    pub hostname: String,
    pub device: String,
    /// Address to add on the robot, IPv4/prefix.
    pub cidr: String,
    /// The PC port already has an address in that subnet (otherwise one is added in step 6).
    pub pc_has_subnet: bool,
}

/// Pick the subnet for a temporary robot address: this PC port's own subnet when it does not
/// collide with any robot subnet, otherwise a fresh /24.
pub fn temp_subnet(
    pc_port: &[(Ipv4Addr, u8)],
    pc_all: &[(Ipv4Addr, u8)],
    robot_nets: &[(Ipv4Addr, u8)],
) -> Option<((Ipv4Addr, u8), bool)> {
    if let Some(net) = pc_port.iter().copied().find(|(ip, p)| {
        usable(*ip, *p)
            && (16..=30).contains(p)
            && !robot_nets.iter().any(|(r, rp)| overlaps(*ip, *p, *r, *rp))
    }) {
        return Some((net, true));
    }
    let mut taken = pc_all.to_vec();
    taken.extend_from_slice(robot_nets);
    pick_dhcp_subnet(&taken).map(|net| (net, false))
}

/// Step 4, before the dialog: which address would be added.
#[tauri::command(async)]
pub fn link_ipv4_propose(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    link_local: String,
) -> Result<TempProposal, String> {
    emit(&app, &target_id, 4, "running", "挑选一个空闲地址…");
    let (via, ip, interface) = link_target(&state, &target_id, &link_local)?;
    let port = read_port(&state, &via, ip)?;
    let device = port
        .device
        .clone()
        .ok_or("机器人上没有找到这根网线对应的网卡")?;
    let all = pc_addresses();
    let pc_port: Vec<_> = all
        .iter()
        .filter(|(d, _, _)| *d == interface)
        .map(|(_, ip, p)| (*ip, *p))
        .collect();
    let pc_all: Vec<_> = all.iter().map(|(_, ip, p)| (*ip, *p)).collect();
    let robot_nets: Vec<_> = port.nets.iter().map(|(_, ip, p)| (*ip, *p)).collect();
    let ((net, prefix), pc_has_subnet) =
        temp_subnet(&pc_port, &pc_all, &robot_nets).ok_or("找不到可用的网段")?;
    let mut exclude: HashSet<Ipv4Addr> = all.iter().map(|(_, ip, _)| *ip).collect();
    exclude.extend(port.nets.iter().map(|(_, ip, _)| *ip));
    exclude.extend(port.neighbors.iter().copied());
    exclude.extend(pc_neighbors(&interface));
    let mut chosen = None;
    for candidate in robot_address_candidates((net, prefix), &exclude, 6) {
        // Only probe when this PC can reach the subnet through the cable.
        if !pc_has_subnet || !answers(candidate, &interface) {
            chosen = Some(candidate);
            break;
        }
    }
    let address = chosen.ok_or("这个网段里没找到空闲地址")?;
    let cidr = format!("{address}/{prefix}");
    let hostname = if port.hostname.is_empty() {
        via.name.clone()
    } else {
        port.hostname.clone()
    };
    emit(
        &app,
        &target_id,
        4,
        "running",
        format!("等待确认：在 {hostname} 的 {device} 上临时添加 {cidr}"),
    );
    Ok(TempProposal {
        hostname,
        device,
        cidr,
        pc_has_subnet,
    })
}

fn validate_temp_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    parse_cidr(cidr)
        .filter(|(ip, p)| usable(*ip, *p) && (16..=30).contains(p))
        .ok_or_else(|| "临时地址格式无效".to_string())
}

/// Step 4: `sudo -S ip addr add` on the robot. The password goes to ssh's stdin only.
#[tauri::command(async)]
pub fn link_ipv4_temp_add(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    link_local: String,
    device: String,
    cidr: String,
    sudo_password: String,
) -> Result<String, String> {
    let (via, ip, interface) = link_target(&state, &target_id, &link_local)?;
    validate_ifname(&device)?;
    validate_temp_cidr(&cidr)?;
    emit(
        &app,
        &target_id,
        4,
        "running",
        format!("在机器人 {device} 上添加 {cidr}…"),
    );
    let script = format!("ip addr add {cidr} dev {device}");
    let result = ssh::remote_command_with(
        &state,
        &via,
        &script,
        RemoteOptions {
            sudo_password: Some(&sudo_password),
            ..Default::default()
        },
    );
    if let Err(e) = result {
        // "File exists": already there from an earlier attempt.
        if !e.contains("File exists") {
            emit(
                &app,
                &target_id,
                4,
                "fail",
                format!("添加失败：{}", strip_mark(&e)),
            );
            return Err(e);
        }
    }
    let port = read_port(&state, &via, ip)?;
    if !port.cidrs.iter().any(|c| c == &cidr) {
        let text = format!("命令执行了，但 {device} 上没有看到 {cidr}");
        emit(&app, &target_id, 4, "fail", text.clone());
        return Err(text);
    }
    let mut target = ssh::lookup_target(&state, &target_id)?;
    let mut record = target.link.clone().unwrap_or_else(|| LinkRecord {
        link_local: ip.to_string(),
        pc_interface: interface.clone(),
        robot_device: Some(device.clone()),
        ipv4: None,
        source: "temporary".into(),
        temp_cidr: None,
        ssh_alias: None,
    });
    record.link_local = ip.to_string();
    record.pc_interface = interface;
    record.robot_device = Some(device.clone());
    record.temp_cidr = Some(cidr.clone());
    target.link = Some(record);
    save_target(&state, &target)?;
    emit(
        &app,
        &target_id,
        4,
        "done",
        format!("已在 {device} 上临时添加 {cidr}（机器人重启后失效）"),
    );
    Ok(cidr)
}

fn strip_mark(text: &str) -> String {
    text.strip_prefix(ssh::SUDO_MARK)
        .unwrap_or(text)
        .to_string()
}

/// Undo step 4: `sudo ip addr del` on the robot, over the link-local address. If the target was
/// using that address it switches back to the link-local address first.
#[tauri::command(async)]
pub fn link_ipv4_temp_remove(
    state: State<'_, AppState>,
    target_id: String,
    sudo_password: String,
) -> Result<Target, String> {
    let mut target = ssh::lookup_target(&state, &target_id)?;
    let record = target.link.clone().ok_or("没有记录这台机器人的直连信息")?;
    let cidr = record.temp_cidr.clone().ok_or("没有需要撤销的临时地址")?;
    let device = record
        .robot_device
        .clone()
        .ok_or("不知道临时地址在哪个网卡上")?;
    validate_ifname(&device)?;
    validate_temp_cidr(&cidr)?;
    let (via, _, _) = link_target(&state, &target_id, &record.link_local)?;
    let script = format!("ip addr del {cidr} dev {device} 2>&1 | grep -v 'Cannot assign' ; true");
    ssh::remote_command_with(
        &state,
        &via,
        &script,
        RemoteOptions {
            sudo_password: Some(&sudo_password),
            ..Default::default()
        },
    )?;
    let address = cidr.split('/').next().unwrap_or_default();
    if target.host == address {
        ssh::drop_channel(&state, &target);
        target.host = via.host.clone();
    }
    let mut record = record;
    record.temp_cidr = None;
    if record.source == "temporary" {
        record.source = "ipv6".into();
        record.ipv4 = None;
    }
    target.link = Some(record);
    save_target(&state, &target)?;
    Ok(target)
}

/// The `Host` block RoboLink keeps in ~/.ssh/config for one robot.
pub fn ssh_config_block(alias: &str, link_host: &str, user: &str, identity: &str) -> String {
    format!(
        "# >>> RoboLink {alias}\nHost {alias}\n    HostName {link_host}\n    User {user}\n    IdentityFile {identity}\n# <<< RoboLink {alias}\n"
    )
}

/// Replaces this alias's block in `config`, or appends it.
pub fn upsert_ssh_config(config: &str, alias: &str, block: &str) -> String {
    let begin = format!("# >>> RoboLink {alias}\n");
    let end = format!("# <<< RoboLink {alias}\n");
    if let Some(start) = config.find(&begin) {
        if let Some(stop) = config[start..].find(&end) {
            let stop = start + stop + end.len();
            return format!("{}{}{}", &config[..start], block, &config[stop..]);
        }
    }
    let mut out = config.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(block);
    out
}

/// `hoson-robot-20260907-002.local` → `hoson-robot-20260907-002`; only characters safe in a Host line.
pub fn alias_for(hostname: &str) -> Option<String> {
    let short = hostname
        .trim()
        .trim_end_matches(".local")
        .trim_end_matches('.');
    let short = short.split('.').next().unwrap_or(short);
    (!short.is_empty()
        && short.len() <= 63
        && short
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then(|| short.to_string())
}

fn write_ssh_alias(alias: &str, block: &str) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let home = dirs::home_dir().ok_or("找不到用户主目录")?;
    let dir = home.join(".ssh");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("无法创建 ~/.ssh：{e}"))?;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = dir.join("config");
    let existed = path.exists();
    let current = if existed {
        std::fs::read_to_string(&path).map_err(|e| format!("无法读取 ~/.ssh/config：{e}"))?
    } else {
        String::new()
    };
    let updated = upsert_ssh_config(&current, alias, block);
    if updated != current {
        write_atomic(&path, &updated)?;
        if !existed {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(path.to_string_lossy().into_owned())
}

fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("robolink-tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("无法写入 ~/.ssh/config：{e}"))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(
            &tmp,
            std::fs::Permissions::from_mode(meta.permissions().mode()),
        );
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("无法写入 ~/.ssh/config：{e}"))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6Fallback {
    pub target: Target,
    pub alias: Option<String>,
    pub config_path: Option<String>,
    /// Ready-to-copy examples (scp/rsync need brackets around the address).
    pub ssh: String,
    pub scp: String,
    pub rsync: String,
}

/// Step 5: keep using the link-local address and give scripts a host-name alias for it.
#[tauri::command(async)]
pub fn link_use_ipv6(
    app: AppHandle,
    state: State<'_, AppState>,
    target_id: String,
    link_local: String,
) -> Result<Ipv6Fallback, String> {
    let (via, ip, interface) = link_target(&state, &target_id, &link_local)?;
    let mut target = ssh::lookup_target(&state, &target_id)?;
    if target.host != via.host {
        ssh::drop_channel(&state, &target);
        target.host = via.host.clone();
    }
    let hostname = target
        .hostname
        .clone()
        .unwrap_or_else(|| target.name.clone());
    let alias = alias_for(&hostname);
    let identity = state.identity_file.to_string_lossy().into_owned();
    let mut config_path = None;
    if let Some(alias) = &alias {
        let block = ssh_config_block(alias, &via.host, &target.username, &identity);
        match write_ssh_alias(alias, &block) {
            Ok(path) => config_path = Some(path),
            Err(e) => emit(
                &app,
                &target_id,
                5,
                "running",
                format!("没写入 ~/.ssh/config：{e}"),
            ),
        }
    }
    let mut record = target.link.clone().unwrap_or_else(|| LinkRecord {
        link_local: ip.to_string(),
        pc_interface: interface.clone(),
        robot_device: None,
        ipv4: None,
        source: "ipv6".into(),
        temp_cidr: None,
        ssh_alias: None,
    });
    record.link_local = ip.to_string();
    record.pc_interface = interface.clone();
    record.source = "ipv6".into();
    record.ssh_alias = config_path.as_ref().and(alias.clone());
    target.link = Some(record);
    save_target(&state, &target)?;
    let user = &target.username;
    let bracket = format!("{user}@[{ip}%{interface}]");
    let fallback = Ipv6Fallback {
        ssh: match &alias {
            Some(a) if config_path.is_some() => format!("ssh {a}"),
            _ => format!("ssh {user}@{ip}%{interface}"),
        },
        scp: format!("scp <文件> {bracket}:~/"),
        rsync: format!("rsync -av -e ssh <目录>/ {bracket}:~/<目录>/"),
        alias: record_alias(&target),
        config_path,
        target,
    };
    emit(
        &app,
        &target_id,
        5,
        "done",
        match &fallback.alias {
            Some(a) => format!("改用 IPv6 链路本地地址，脚本里可以直接写 ssh {a}"),
            None => "改用 IPv6 链路本地地址".to_string(),
        },
    );
    Ok(fallback)
}

fn record_alias(target: &Target) -> Option<String> {
    target.link.as_ref().and_then(|l| l.ssh_alias.clone())
}

/// Step 6 bookkeeping, called by link_finish once IPv4 works (or not).
pub fn remember(
    target: &mut Target,
    link_local: Option<&str>,
    robot_device: Option<String>,
    ipv4: Option<String>,
    source: &str,
) {
    let interface = target.interface.clone().unwrap_or_default();
    let previous = target.link.clone();
    let link_local = link_local
        .map(str::to_string)
        .or_else(|| previous.as_ref().map(|l| l.link_local.clone()))
        .unwrap_or_default();
    target.link = Some(LinkRecord {
        link_local,
        pc_interface: interface,
        robot_device: robot_device
            .or_else(|| previous.as_ref().and_then(|l| l.robot_device.clone())),
        ipv4,
        source: source.to_string(),
        temp_cidr: previous.as_ref().and_then(|l| l.temp_cidr.clone()),
        ssh_alias: previous.as_ref().and_then(|l| l.ssh_alias.clone()),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT_AUTO: &str = "HOST=hoson-robot-20260907-002\nDEV=enp4s0\nNM=yes\nCONN=Wired connection 2\nMETHOD=auto\nNET=enp7s0 192.168.9.10/24\nNET=wlan0 192.168.11.50/24\nNET=lo 127.0.0.1/8\nNEIGH=192.168.9.21\nNEIGH=192.168.9.21\n";

    #[test]
    fn parses_port_report() {
        let port = parse_robot_port(PORT_AUTO);
        assert_eq!(port.hostname, "hoson-robot-20260907-002");
        assert_eq!(port.device.as_deref(), Some("enp4s0"));
        assert!(port.cidrs.is_empty());
        assert!(port.nm);
        assert_eq!(port.connection.as_deref(), Some("Wired connection 2"));
        assert_eq!(port.method.as_deref(), Some("auto"));
        assert_eq!(port.nets.len(), 2);
        assert_eq!(port.neighbors, vec![Ipv4Addr::new(192, 168, 9, 21)]);
        assert_eq!(
            avoid_list(&port),
            vec!["192.168.9.10", "192.168.11.50", "192.168.9.21"]
        );
    }

    #[test]
    fn port_with_address_and_link_local_only_entries() {
        let port = parse_robot_port(
            "HOST=r\nDEV=enp4s0\nADDR=192.168.9.17/24\nADDR=169.254.3.3/16\nNM=yes\nCONN=c\nMETHOD=manual\n",
        );
        assert_eq!(port.cidrs, vec!["192.168.9.17/24"]);
        assert_eq!(choose_plan(&port).0, Plan::Existing);
    }

    #[test]
    fn plan_follows_nm_method_and_activation() {
        let mut port = parse_robot_port(PORT_AUTO);
        assert_eq!(choose_plan(&port).0, Plan::Dhcp);
        port.method = Some("manual".into());
        assert_eq!(choose_plan(&port).0, Plan::Manual);
        // Inactive connection: the profile's method is known but nothing is active.
        let inactive = parse_robot_port("HOST=r\nDEV=enp4s0\nNM=yes\nCONN=\nPROFILE_METHOD=auto\n");
        assert_eq!(inactive.connection, None);
        assert_eq!(inactive.method.as_deref(), Some("auto"));
        assert_eq!(choose_plan(&inactive).0, Plan::Manual);
        let no_nm = parse_robot_port("HOST=r\nDEV=enp4s0\n");
        assert_eq!(choose_plan(&no_nm).0, Plan::Manual);
        // nmcli prints "--" for "no connection" in some versions.
        let dashes = parse_robot_port("HOST=r\nDEV=enp4s0\nNM=yes\nCONN=--\n");
        assert_eq!(dashes.connection, None);
    }

    #[test]
    fn parses_ip_o_addr() {
        let text = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n3: enx00e04c3071f5    inet 192.168.77.1/24 brd 192.168.77.255 scope global noprefixroute enx00e04c3071f5\\       valid_lft forever\n5: veth0@if4    inet 10.1.0.1/16 scope global veth0\n";
        let rows = parse_ip_o_addr(text);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[1],
            ("enx00e04c3071f5".into(), Ipv4Addr::new(192, 168, 77, 1), 24)
        );
        assert_eq!(rows[2].0, "veth0");
    }

    #[test]
    fn dhcp_subnet_avoids_pc_and_robot_nets() {
        let taken = [
            (Ipv4Addr::new(192, 168, 77, 1), 24),
            (Ipv4Addr::new(192, 168, 78, 9), 24),
            (Ipv4Addr::new(192, 168, 11, 5), 24),
        ];
        assert_eq!(
            pick_dhcp_subnet(&taken),
            Some((Ipv4Addr::new(192, 168, 79, 1), 24))
        );
        // A /16 on the PC rules out every 192.168.x candidate.
        let wide = [(Ipv4Addr::new(192, 168, 0, 1), 16)];
        assert_eq!(
            pick_dhcp_subnet(&wide),
            Some((Ipv4Addr::new(10, 77, 0, 1), 24))
        );
    }

    #[test]
    fn robot_address_skips_taken_and_internal_hosts() {
        let mut exclude = HashSet::new();
        exclude.insert(Ipv4Addr::new(192, 168, 9, 100));
        exclude.insert(Ipv4Addr::new(192, 168, 9, 101));
        let picks = robot_address_candidates((Ipv4Addr::new(192, 168, 9, 17), 24), &exclude, 3);
        assert_eq!(
            picks,
            vec![
                Ipv4Addr::new(192, 168, 9, 102),
                Ipv4Addr::new(192, 168, 9, 103),
                Ipv4Addr::new(192, 168, 9, 104)
            ]
        );
        assert!(!picks.contains(&Ipv4Addr::new(192, 168, 9, 10)));
        // Small subnets still get hosts, never network/broadcast.
        let small = robot_address_candidates((Ipv4Addr::new(10, 0, 0, 1), 29), &HashSet::new(), 10);
        assert_eq!(small.first(), Some(&Ipv4Addr::new(10, 0, 0, 2)));
        assert!(small
            .iter()
            .all(|a| a.octets()[3] >= 1 && a.octets()[3] <= 6));
        assert!(
            robot_address_candidates((Ipv4Addr::new(10, 0, 0, 1), 8), &HashSet::new(), 3)
                .is_empty()
        );
    }

    #[test]
    fn temp_subnet_prefers_pc_port_unless_robot_uses_it() {
        let pc_port = [(Ipv4Addr::new(192, 168, 77, 1), 24)];
        let pc_all = [
            (Ipv4Addr::new(192, 168, 77, 1), 24),
            (Ipv4Addr::new(192, 168, 11, 2), 24),
        ];
        let robot = [(Ipv4Addr::new(192, 168, 9, 10), 24)];
        assert_eq!(
            temp_subnet(&pc_port, &pc_all, &robot),
            Some(((Ipv4Addr::new(192, 168, 77, 1), 24), true))
        );
        // The robot already has 192.168.77.x on another NIC: a fresh subnet instead.
        let robot = [(Ipv4Addr::new(192, 168, 77, 10), 24)];
        assert_eq!(
            temp_subnet(&pc_port, &pc_all, &robot),
            Some(((Ipv4Addr::new(192, 168, 78, 1), 24), false))
        );
        // No address on the PC port (or only 169.254): fresh subnet.
        let ll = [(Ipv4Addr::new(169, 254, 1, 1), 16)];
        assert!(!temp_subnet(&ll, &pc_all, &[]).unwrap().1);
    }

    #[test]
    fn ssh_config_block_is_replaced_in_place() {
        let block = ssh_config_block(
            "hoson-robot-1",
            "fe80::1%enx0",
            "hoson",
            "/home/u/.config/robot-link-console/id_ed25519",
        );
        let start = "Host work\n    User me\n";
        let once = upsert_ssh_config(start, "hoson-robot-1", &block);
        assert!(once.starts_with(start));
        assert!(once.contains("HostName fe80::1%enx0"));
        let newer = ssh_config_block("hoson-robot-1", "fe80::2%enx0", "hoson", "/k");
        let twice = upsert_ssh_config(&once, "hoson-robot-1", &newer);
        assert_eq!(twice.matches("Host hoson-robot-1").count(), 1);
        assert!(twice.contains("fe80::2%enx0") && !twice.contains("fe80::1%enx0"));
        assert!(twice.starts_with(start));
        assert_eq!(upsert_ssh_config("", "a", "B\n"), "B\n");
    }

    #[test]
    fn aliases_are_short_safe_host_names() {
        assert_eq!(
            alias_for("hoson-robot-20260907-002.local").as_deref(),
            Some("hoson-robot-20260907-002")
        );
        assert_eq!(alias_for("bad name"), None);
        assert_eq!(alias_for(""), None);
    }

    #[test]
    fn temp_cidr_validation() {
        assert!(validate_temp_cidr("192.168.77.100/24").is_ok());
        assert!(validate_temp_cidr("192.168.77.100/24; reboot").is_err());
        assert!(validate_temp_cidr("169.254.1.1/16").is_err());
        assert!(validate_temp_cidr("10.0.0.1/8").is_err());
    }

    #[test]
    fn overlap_math() {
        assert!(overlaps(
            Ipv4Addr::new(192, 168, 9, 1),
            24,
            Ipv4Addr::new(192, 168, 9, 200),
            24
        ));
        assert!(!overlaps(
            Ipv4Addr::new(192, 168, 9, 1),
            24,
            Ipv4Addr::new(192, 168, 10, 1),
            24
        ));
        assert!(overlaps(
            Ipv4Addr::new(10, 0, 0, 1),
            8,
            Ipv4Addr::new(10, 9, 9, 9),
            24
        ));
    }
}
