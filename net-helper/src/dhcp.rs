use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const STATE_DIR: &str = "/run/robolink-dhcp";
const DNSMASQ: &str = "/usr/sbin/dnsmasq";
const UDP_PORT_DHCP: u16 = 67;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpStatus {
    pub interface: String,
    pub cidr: String,
    pub running: bool,
    pub owned: bool,
    pub message: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DhcpRecord {
    interface: String,
    cidr: String,
    uid: u32,
    id: String,
    pid: u32,
    start_time: u64,
    config_path: String,
    log_path: String,
    address_added: bool,
}

struct StateLock {
    _file: File,
}

impl StateLock {
    fn acquire() -> Result<Self, String> {
        ensure_state_dir()?;
        let path = Path::new(STATE_DIR).join("lifecycle.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| format!("无法打开 DHCP 生命周期锁：{e}"))?;
        validate_root_file(&file, &path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!(
                "无法锁定 DHCP 生命周期：{}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { _file: file })
    }
}

pub fn run(action: &str, args: Vec<String>) -> Result<(), String> {
    let uid = requesting_uid()?;
    let _lock = StateLock::acquire()?;
    let rows = match action {
        "dhcp-start" => {
            if args.len() != 2 {
                return Err("用法：dhcp-start IF CIDR".into());
            }
            start(&args[0], &args[1], uid)?;
            statuses(uid)?
        }
        "dhcp-stop" => {
            if args.len() != 1 {
                return Err("用法：dhcp-stop IF".into());
            }
            stop(&args[0], uid)?;
            statuses(uid)?
        }
        "dhcp-status" => {
            if !args.is_empty() {
                return Err("用法：dhcp-status".into());
            }
            statuses(uid)?
        }
        _ => return Err("不支持的 DHCP 操作".into()),
    };
    println!(
        "{}",
        serde_json::to_string(&rows).map_err(|e| e.to_string())?
    );
    Ok(())
}

pub fn lease_candidates(interfaces: &[String]) -> Result<Vec<super::ArpCandidate>, String> {
    let uid = requesting_uid()?;
    let selected = interfaces
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    for interface in &selected {
        super::validate_ifname(interface)?;
    }
    if selected.is_empty() {
        return Ok(Vec::new());
    }
    ensure_state_dir()?;
    let mut candidates = Vec::new();
    for entry in
        fs::read_dir(STATE_DIR).map_err(|error| format!("无法读取 DHCP 状态目录：{error}"))?
    {
        let entry = entry.map_err(|error| format!("读取 DHCP 状态目录失败：{error}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let mut record = read_record(&path)?;
        if record.uid != uid || !selected.contains(&record.interface) {
            continue;
        }
        if resolve_record_process(&mut record, &path)?.is_none() {
            continue;
        }
        let log_path = Path::new(&record.log_path);
        let contents = read_private_log_tail(log_path)?;
        for (address, mac) in parse_dhcp_ack_log(&contents, &record.interface, &record.cidr) {
            if candidates.len() >= 256 {
                return Ok(candidates);
            }
            candidates.push(super::ArpCandidate {
                interface: record.interface.clone(),
                address: address.to_string(),
                mac: mac_to_string(mac),
                source: "本应用DHCPACK日志缓存，需重新验证".into(),
                confidence: "低".into(),
                arp_reachable: None,
            });
        }
    }
    Ok(candidates)
}

fn read_private_log_tail(path: &Path) -> Result<String, String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|error| format!("无法检查 DHCP 专属日志 {}：{error}", path.display()))?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
    {
        return Err(format!("DHCP 专属日志 {} 权限或类型不安全", path.display()));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("无法打开 DHCP 专属日志：{error}"))?;
    validate_root_file(&file, path)?;
    let length = file
        .metadata()
        .map_err(|error| format!("无法检查 DHCP 专属日志长度：{error}"))?
        .len();
    const MAX_LOG_TAIL: u64 = 64 * 1024;
    let offset = length.saturating_sub(MAX_LOG_TAIL);
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("无法定位 DHCP 专属日志尾部：{error}"))?;
    let mut bytes = Vec::with_capacity(length.min(MAX_LOG_TAIL) as usize);
    file.take(MAX_LOG_TAIL)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("无法读取 DHCP 专属日志尾部：{error}"))?;
    if offset != 0 {
        if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=newline);
        } else {
            bytes.clear();
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_dhcp_ack_log(contents: &str, interface: &str, cidr: &str) -> Vec<(Ipv4Addr, [u8; 6])> {
    let Ok((local, _)) = parse_private_dhcp_cidr(cidr) else {
        return Vec::new();
    };
    let expected = format!("DHCPACK({interface})");
    let mut result = Vec::new();
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || fields[0] != expected {
            continue;
        }
        let Ok(address) = fields[1].parse::<Ipv4Addr>() else {
            continue;
        };
        let octets = address.octets();
        if octets[..3] != local.octets()[..3]
            || octets[3] == 0
            || octets[3] == 255
            || address == local
        {
            continue;
        }
        let Some(mac) = super::parse_mac(fields[2]) else {
            continue;
        };
        if !valid_unicast_mac(mac) || result.len() >= 256 {
            continue;
        }
        if !result
            .iter()
            .any(|(ip, existing_mac)| *ip == address && *existing_mac == mac)
        {
            result.push((address, mac));
        }
    }
    result
}

fn valid_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0
}

fn mac_to_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn requesting_uid() -> Result<u32, String> {
    if let Some(value) = env::var_os("PKEXEC_UID") {
        let text = value.to_str().ok_or("PKEXEC_UID 不是有效的数字 UID")?;
        return parse_uid(text).ok_or_else(|| "PKEXEC_UID 不是有效的数字 UID".into());
    }
    if let Some(value) = env::var_os("SUDO_UID") {
        let text = value.to_str().ok_or("SUDO_UID 不是有效的数字 UID")?;
        return parse_uid(text).ok_or_else(|| "SUDO_UID 不是有效的数字 UID".into());
    }
    Ok(unsafe { libc::geteuid() })
}

fn parse_uid(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok()
}

fn validate_interface(interface: &str) -> Result<(), String> {
    super::physical_ethernet(interface, true)
}

fn parse_private_dhcp_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, prefix) = super::parse_cidr(cidr)?;
    if prefix != 24 || !is_rfc1918(address) {
        return Err("DHCP 仅支持 RFC1918 私有 IPv4 地址及 /24 子网".into());
    }
    let last = address.octets()[3];
    if !(1..=9).contains(&last) && !(201..=254).contains(&last) {
        return Err(
            "为避免 DHCP 地址池冲突，本机地址必须位于 .1–.9 或 .201–.254；地址池固定为 .10–.200"
                .into(),
        );
    }
    Ok((address, prefix))
}

fn is_rfc1918(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

fn build_dnsmasq_config(interface: &str, local: Ipv4Addr, id: &str) -> String {
    let [a, b, c, _] = local.octets();
    format!(
        // dhcp-authoritative: the board may still hold a lease from another network and ask for that
        // old address. Without this dnsmasq silently ignores the INIT-REBOOT request, so the board
        // never gets an address even though the server is running. dhcp-broadcast: a client without
        // an address cannot always receive a unicast reply on this point-to-point link.
        "# robolink-id={id}\nport=0\ninterface={interface}\nbind-interfaces\ndhcp-authoritative\ndhcp-broadcast\ndhcp-range={a}.{b}.{c}.10,{a}.{b}.{c}.200,255.255.255.0,1h\ndhcp-option=3\ndhcp-option=6\nleasefile-ro\nlog-dhcp\nlog-facility=-\nuser=nobody\n"
    )
}

fn start(interface: &str, cidr: &str, uid: u32) -> Result<DhcpStatus, String> {
    validate_interface(interface)?;
    let (local, prefix) = parse_private_dhcp_cidr(cidr)?;
    if !Path::new(DNSMASQ).is_file() {
        return Err("未安装 /usr/sbin/dnsmasq；请安装 dnsmasq-base 后重试".into());
    }
    let state_path = record_path(uid, interface);
    if state_path.exists() {
        let mut record = read_record(&state_path)?;
        if let Some(running) = record_status(&mut record, &state_path)? {
            if running.running {
                return Ok(running);
            }
        }
        return Err("此网口有尚未清理的 DHCP 所有权记录；请先执行停止，再重新启动".into());
    }

    check_no_dhcp_listener()?;
    check_nm_shared(interface)?;
    let addresses = super::all_ipv4_addresses()?;
    if let Some((dev, _, _)) = addresses.iter().find(|(_, ip, _)| *ip == local) {
        return Err(format!(
            "本机 IPv4 {local} 已由网卡 {dev} 使用；DHCP 不会接管已有地址。"
        ));
    }
    for (dev, address, bits) in &addresses {
        if super::networks_overlap(local, prefix, *address, *bits) {
            return Err(format!(
                "新 DHCP 子网与网卡 {dev} 上现有地址 {address}/{bits} 重叠；未修改网络。"
            ));
        }
    }
    super::check_route_conflicts(interface, local, prefix)?;
    if super::duplicate_address_probe(interface, local)? {
        return Err(format!(
            "检测到其他设备正在使用候选本机地址 {local}；没有启动 DHCP。"
        ));
    }

    let id = new_id()?;
    let config_path = Path::new(STATE_DIR).join(format!("{id}.conf"));
    let log_path = Path::new(STATE_DIR).join(format!("{id}.log"));
    let config_text = build_dnsmasq_config(interface, local, &id);
    create_private_file(&config_path, config_text.as_bytes())?;
    let mut record = DhcpRecord {
        interface: interface.into(),
        cidr: cidr.into(),
        uid,
        id: id.clone(),
        pid: 0,
        start_time: 0,
        config_path: config_path.to_string_lossy().into_owned(),
        log_path: log_path.to_string_lossy().into_owned(),
        address_added: true,
    };
    if let Err(error) = write_record(&state_path, &record) {
        remove_file_if_exists(&config_path)?;
        return Err(error);
    }

    let cidr_arg = format!("{local}/{prefix}");
    // On an interface NetworkManager manages, a raw `ip address add` is flushed whenever NM
    // reactivates the port, which silently cut the board off; use RoboLink's in-memory NM profile.
    let added = if super::nm_manages(interface) {
        super::nm_add_address(interface, &cidr_arg)
            .map_err(|e| format!("添加临时 DHCP 本机地址失败：{e}"))
    } else {
        match super::ip_command(&["address", "add", &cidr_arg, "dev", interface]) {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(format!(
                "添加临时 DHCP 本机地址失败：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => Err(error),
        }
    };
    if let Err(detail) = added {
        record.address_added = false;
        let cleanup = cleanup_record(&mut record, &state_path)
            .err()
            .into_iter()
            .collect();
        return Err(append_cleanup(detail, cleanup));
    }

    let log = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log_path)
    {
        Ok(file) => file,
        Err(error) => {
            return rollback_start(
                &record,
                &state_path,
                format!("无法创建 DHCP 日志文件：{error}"),
            )
        }
    };
    let mut child = match Command::new(DNSMASQ)
        .arg(format!("--conf-file={}", record.config_path))
        .arg("--keep-in-foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return rollback_start(&record, &state_path, format!("无法启动 dnsmasq：{error}"))
        }
    };

    record.pid = child.id();
    match process_start_time(record.pid) {
        Ok(Some(value)) => record.start_time = value,
        Ok(None) => {}
        Err(error) => {
            let mut cleanup = Vec::new();
            if let Err(e) = child.kill() {
                cleanup.push(format!("终止刚启动的 dnsmasq 失败：{e}"));
            }
            if let Err(e) = child.wait() {
                cleanup.push(format!("等待 dnsmasq 退出失败：{e}"));
            }
            if cleanup.is_empty() {
                return rollback_start(&record, &state_path, error);
            }
            return Err(append_cleanup(error, cleanup));
        }
    }
    if record.start_time != 0 {
        if let Err(error) = write_record(&state_path, &record) {
            let cleanup = stop_owned_process(&mut record, &state_path, Duration::from_secs(3));
            if cleanup.is_ok() {
                return rollback_start(&record, &state_path, error);
            }
            return Err(append_cleanup(error, vec![cleanup.unwrap_err()]));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut launch_error = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let detail = fs::read_to_string(&log_path).unwrap_or_default();
                launch_error = Some(format!("dnsmasq 启动失败（{status}）：{}", detail.trim()));
                break;
            }
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                launch_error = Some(format!("无法确认 dnsmasq 启动状态：{error}"));
                break;
            }
        }
    }
    if let Some(error) = launch_error {
        return rollback_start(&record, &state_path, error);
    }
    if record.start_time == 0 {
        return rollback_start(&record, &state_path, "dnsmasq 启动后进程已退出".into());
    }
    if let Err(error) = write_record(&state_path, &record) {
        let cleanup = stop_owned_process(&mut record, &state_path, Duration::from_secs(3));
        if let Err(cleanup_error) = cleanup {
            return Err(append_cleanup(error, vec![cleanup_error]));
        }
        return rollback_start(&record, &state_path, error);
    }
    Ok(status_for(
        &record,
        true,
        true,
        "DHCP 服务已启动；未启用互联网共享，未设置网关或 DNS。",
    ))
}

fn rollback_start(
    record: &DhcpRecord,
    state_path: &Path,
    cause: String,
) -> Result<DhcpStatus, String> {
    let mut record = record.clone();
    let mut cleanup = Vec::new();
    if let Err(error) = stop_owned_process(&mut record, state_path, Duration::from_secs(3)) {
        cleanup.push(error);
    }
    if !cleanup.is_empty() {
        return Err(append_cleanup(cause, cleanup));
    }
    if let Err(error) = cleanup_record(&mut record, state_path) {
        cleanup.push(error);
    }
    Err(append_cleanup(cause, cleanup))
}

fn stop(interface: &str, uid: u32) -> Result<DhcpStatus, String> {
    super::validate_ifname(interface)?;
    let path = record_path(uid, interface);
    if !path.exists() {
        return Ok(DhcpStatus {
            interface: interface.into(),
            cidr: String::new(),
            running: false,
            owned: false,
            message: "此用户没有该网口的 DHCP 服务记录；未停止任何系统服务。".into(),
            id: String::new(),
        });
    }
    let mut record = read_record(&path)?;
    if record.uid != uid || record.interface != interface {
        return Err("DHCP 所有权记录与请求用户或网卡不匹配".into());
    }
    stop_owned_process(&mut record, &path, Duration::from_secs(3))?;
    cleanup_record(&mut record, &path).map_err(|error| {
        append_cleanup(
            "DHCP 进程已停止，但清理未全部完成；所有权记录已保留，可重试停止".into(),
            vec![error],
        )
    })?;
    Ok(status_for(
        &record,
        false,
        false,
        "DHCP 服务已停止；仅清理本应用记录的服务、配置和地址。",
    ))
}

fn cleanup_record(record: &mut DhcpRecord, state_path: &Path) -> Result<(), String> {
    cleanup_record_with(
        record,
        state_path,
        remove_owned_address,
        write_record,
        remove_file_if_exists,
    )
}

fn cleanup_record_with<A, P, F>(
    record: &mut DhcpRecord,
    state_path: &Path,
    mut remove_address: A,
    mut persist: P,
    mut remove_file: F,
) -> Result<(), String>
where
    A: FnMut(&DhcpRecord) -> Result<(), String>,
    P: FnMut(&Path, &DhcpRecord) -> Result<(), String>,
    F: FnMut(&Path) -> Result<(), String>,
{
    if record.address_added {
        remove_address(record)?;
        record.address_added = false;
    }
    persist(state_path, record).map_err(|error| {
        format!(
            "地址已确认移除/未添加，但无法持久化 addressAdded=false；保留所有记录和文件：{error}"
        )
    })?;
    let mut failures = Vec::new();
    for path in [Path::new(&record.config_path), Path::new(&record.log_path)] {
        if let Err(error) = remove_file(path) {
            failures.push(error);
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "清理配置或日志失败，所有权记录已保留：{}",
            failures.join("；")
        ));
    }
    remove_file(state_path).map_err(|error| format!("清理所有权记录失败：{error}"))
}

fn validate_record_config(record: &DhcpRecord) -> Result<(), String> {
    let path = Path::new(&record.config_path);
    let meta = fs::symlink_metadata(path)
        .map_err(|error| format!("无法检查 DHCP 专属配置 {}：{error}", path.display()))?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
    {
        return Err(format!("DHCP 专属配置 {} 权限或类型不安全", path.display()));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("无法打开 DHCP 专属配置：{error}"))?;
    validate_root_file(&file, path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| format!("无法读取 DHCP 专属配置：{error}"))?;
    let (address, _) = parse_private_dhcp_cidr(&record.cidr)?;
    let expected = build_dnsmasq_config(&record.interface, address, &record.id);
    // Accept a record created by the previous release (without authoritative/broadcast) so an
    // in-flight DHCP server can still be inspected and cleaned up after upgrading.
    let legacy = expected.replacen("dhcp-authoritative\ndhcp-broadcast\n", "", 1);
    if contents != expected && contents != legacy {
        return Err("DHCP 专属配置与所有权记录/UUID 不匹配；拒绝恢复进程身份".into());
    }
    Ok(())
}

fn statuses(uid: u32) -> Result<Vec<DhcpStatus>, String> {
    let mut result = Vec::new();
    for entry in fs::read_dir(STATE_DIR).map_err(|e| format!("无法读取 DHCP 状态目录：{e}"))?
    {
        let entry = entry.map_err(|e| format!("读取 DHCP 状态目录失败：{e}"))?;
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let mut record = read_record(&path)?;
        if record.uid != uid {
            continue;
        }
        let running = resolve_record_process(&mut record, &path)?.is_some();
        let message = if running {
            "DHCP 服务正在运行；未启用互联网共享，未设置网关或 DNS。"
        } else {
            "DHCP 进程已退出但所有权记录仍保留；可从 GUI 停止以清理本应用地址和文件。"
        };
        result.push(status_for(&record, running, true, message));
    }
    result.sort_by(|a, b| a.interface.cmp(&b.interface));
    Ok(result)
}

fn record_status(record: &mut DhcpRecord, state_path: &Path) -> Result<Option<DhcpStatus>, String> {
    let running = resolve_record_process(record, state_path)?.is_some();
    Ok(Some(status_for(
        record,
        running,
        true,
        if running {
            "DHCP 服务正在运行；未启用互联网共享，未设置网关或 DNS。"
        } else {
            "DHCP 进程已退出但所有权记录仍保留；请停止以清理后再启动。"
        },
    )))
}

fn status_for(record: &DhcpRecord, running: bool, owned: bool, message: &str) -> DhcpStatus {
    DhcpStatus {
        interface: record.interface.clone(),
        cidr: record.cidr.clone(),
        running,
        owned,
        message: message.into(),
        id: record.id.clone(),
    }
}

fn record_path(uid: u32, interface: &str) -> PathBuf {
    Path::new(STATE_DIR).join(format!("{uid}-{interface}.json"))
}

fn new_id() -> Result<String, String> {
    let text = fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map_err(|e| format!("无法生成 DHCP 独立 ID：{e}"))?;
    let value = text.trim();
    if value.len() != 36 || !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err("内核返回的 DHCP ID 格式无效".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn ensure_state_dir() -> Result<(), String> {
    let path = Path::new(STATE_DIR);
    if !path.exists() {
        match fs::create_dir(path) {
            Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("无法保护 DHCP 状态目录：{e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("无法创建 DHCP 状态目录：{e}")),
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|e| format!("无法检查 DHCP 状态目录：{e}"))?;
    if meta.file_type().is_symlink()
        || !meta.is_dir()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
    {
        return Err(
            "/run/robolink-dhcp 必须是 root 所有且不可被 group/world 写入的真实目录".into(),
        );
    }
    Ok(())
}

fn validate_root_file(file: &File, path: &Path) -> Result<(), String> {
    let meta = file
        .metadata()
        .map_err(|e| format!("无法检查 {}：{e}", path.display()))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} 必须是 root 所有、权限不宽于 0600 的普通文件",
            path.display()
        ));
    }
    Ok(())
}

fn create_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("无法创建 {}：{e}", path.display()))?;
    validate_root_file(&file, path)?;
    file.write_all(data)
        .map_err(|e| format!("写入 {} 失败：{e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("同步 {} 失败：{e}", path.display()))
}

fn write_record(path: &Path, record: &DhcpRecord) -> Result<(), String> {
    let temp = Path::new(STATE_DIR).join(format!(".{}.{}.tmp", record.id, std::process::id()));
    let bytes = serde_json::to_vec(record).map_err(|e| format!("编码 DHCP 所有权记录失败：{e}"))?;
    create_private_file(&temp, &bytes)?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = remove_file_if_exists(&temp);
        return Err(format!("原子更新 DHCP 所有权记录失败：{error}"));
    }
    Ok(())
}

fn read_record(path: &Path) -> Result<DhcpRecord, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("无法检查 DHCP 所有权记录：{e}"))?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
    {
        return Err(format!(
            "DHCP 所有权记录 {} 权限或类型不安全",
            path.display()
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("无法读取 DHCP 所有权记录：{e}"))?;
    validate_root_file(&file, path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("读取 DHCP 所有权记录失败：{e}"))?;
    let record: DhcpRecord =
        serde_json::from_slice(&bytes).map_err(|e| format!("DHCP 所有权记录格式无效：{e}"))?;
    if !valid_record(&record) || path != record_path(record.uid, &record.interface) {
        return Err("DHCP 所有权记录字段无效".into());
    }
    Ok(record)
}

fn valid_record(record: &DhcpRecord) -> bool {
    super::validate_ifname(&record.interface).is_ok()
        && parse_private_dhcp_cidr(&record.cidr).is_ok()
        && record.id.len() == 36
        && record
            .id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
        && record.config_path
            == Path::new(STATE_DIR)
                .join(format!("{}.conf", record.id))
                .to_string_lossy()
        && record.log_path
            == Path::new(STATE_DIR)
                .join(format!("{}.log", record.id))
                .to_string_lossy()
        && record.pid <= i32::MAX as u32
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink()
                || !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o077 != 0
            {
                return Err(format!("拒绝删除类型或权限不安全的文件 {}", path.display()));
            }
            fs::remove_file(path).map_err(|e| format!("删除 {} 失败：{e}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("检查 {} 失败：{error}", path.display())),
    }
}

fn remove_owned_address(record: &DhcpRecord) -> Result<(), String> {
    let (address, prefix) = parse_private_dhcp_cidr(&record.cidr)?;
    if super::nm_remove_address(&record.interface, &format!("{address}/{prefix}"))? {
        return Ok(());
    }
    let current = super::all_ipv4_addresses()?;
    let exact = current
        .iter()
        .any(|(dev, ip, bits)| dev == &record.interface && *ip == address && *bits == prefix);
    if !exact {
        return Ok(());
    }
    let cidr = format!("{address}/{prefix}");
    let output = super::ip_command(&["address", "del", &cidr, "dev", &record.interface])?;
    if !output.status.success() {
        return Err(format!(
            "移除本应用登记地址 {cidr} 失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn process_start_time(pid: u32) -> Result<Option<u64>, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Ok(None);
    }
    let path = format!("/proc/{pid}/stat");
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("无法核验 dnsmasq 进程启动时间：{error}")),
    };
    let close = text.rfind(')').ok_or("/proc PID stat 格式无效")?;
    let fields = text[close + 1..].split_whitespace().collect::<Vec<_>>();
    let value = fields
        .get(19)
        .ok_or("/proc PID stat 缺少 starttime")?
        .parse::<u64>()
        .map_err(|_| "/proc PID starttime 无效")?;
    Ok(Some(value))
}

fn process_identity_matches(
    record: &DhcpRecord,
    observed_start: Option<u64>,
    exe: &str,
    argv: &[String],
) -> bool {
    observed_start == Some(record.start_time)
        && record.pid != 0
        && exe == DNSMASQ
        && argv.len() == 3
        && argv[0] == DNSMASQ
        && argv[1] == format!("--conf-file={}", record.config_path)
        && argv[2] == "--keep-in-foreground"
}

fn read_process_identity(pid: u32) -> Result<Option<(u64, String, Vec<String>)>, String> {
    let start_before = match process_start_time(pid)? {
        Some(value) => value,
        None => return Ok(None),
    };
    let exe = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("无法核验 DHCP 进程可执行文件：{error}")),
    };
    if exe != DNSMASQ {
        let Some(start_after) = process_start_time(pid)? else {
            return Ok(None);
        };
        return Ok((start_before == start_after).then_some((start_after, exe, Vec::new())));
    }
    let cmdline = match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("无法核验 DHCP 进程参数：{error}")),
    };
    let argv = cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>();
    let Some(start_after) = process_start_time(pid)? else {
        return Ok(None);
    };
    Ok((start_before == start_after).then_some((start_after, exe, argv)))
}

fn exact_record_process(record: &DhcpRecord, identity: &(u32, u64)) -> Result<bool, String> {
    let Some((observed_start, exe, argv)) = read_process_identity(identity.0)? else {
        return Ok(false);
    };
    Ok(identity.1 == observed_start
        && record.pid == identity.0
        && process_identity_matches(record, Some(observed_start), &exe, &argv))
}

fn resolve_record_process(
    record: &mut DhcpRecord,
    state_path: &Path,
) -> Result<Option<(u32, u64)>, String> {
    if !valid_record(record) || state_path != record_path(record.uid, &record.interface) {
        return Err("DHCP 所有权记录与 UID/网卡/文件路径不一致；拒绝进程恢复或网络清理".into());
    }
    validate_record_config(record)?;
    if record.pid != 0 && record.start_time != 0 {
        let observed = process_start_time(record.pid)?;
        if observed != Some(record.start_time) {
            // Do not inspect /proc/<pid>/exe after detecting PID reuse.
            return Ok(None);
        }
        let identity = (record.pid, record.start_time);
        if exact_record_process(record, &identity)? {
            return Ok(Some(identity));
        }
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir("/proc")
        .map_err(|error| format!("无法扫描 /proc 恢复 dnsmasq 身份：{error}"))?
    {
        let entry = entry.map_err(|error| format!("扫描 /proc 失败：{error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == 0 || pid > i32::MAX as u32 {
            continue;
        }
        let Some((start_time, exe, argv)) = read_process_identity(pid)? else {
            continue;
        };
        if exe == DNSMASQ
            && argv.len() == 3
            && argv[0] == DNSMASQ
            && argv[1] == format!("--conf-file={}", record.config_path)
            && argv[2] == "--keep-in-foreground"
        {
            matches.push((pid, start_time));
        }
    }
    match matches.as_slice() {
        [] => Ok(None),
        [identity] => {
            record.pid = identity.0;
            record.start_time = identity.1;
            write_record(state_path, record).map_err(|error| {
                format!("已找到唯一匹配的 dnsmasq，但无法持久化恢复身份，拒绝后续清理：{error}")
            })?;
            Ok(Some(*identity))
        }
        _ => Err(format!(
            "发现 {} 个进程匹配此 DHCP 专属配置；拒绝猜测、停止或清理网络",
            matches.len()
        )),
    }
}

fn stop_owned_process(
    record: &mut DhcpRecord,
    state_path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let Some(identity) = resolve_record_process(record, state_path)? else {
        return Ok(());
    };
    if !exact_record_process(record, &identity)? {
        return Ok(());
    }
    if !signal_record_process(record, &identity)? {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !exact_record_process(record, &identity)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    if exact_record_process(record, &identity)? {
        Err("dnsmasq 未及时退出；保留其配置、地址及所有权记录，没有强制杀进程".into())
    } else {
        Ok(())
    }
}

fn signal_record_process(record: &DhcpRecord, identity: &(u32, u64)) -> Result<bool, String> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.0 as libc::pid_t, 0) };
    if pidfd < 0 {
        return Err(format!(
            "无法安全打开本应用 dnsmasq 的 pidfd；拒绝按 PID 发送信号：{}",
            std::io::Error::last_os_error()
        ));
    }
    if !exact_record_process(record, identity)? {
        unsafe { libc::close(pidfd as libc::c_int) };
        return Ok(false);
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd as libc::c_int,
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    let error = (result < 0).then(std::io::Error::last_os_error);
    unsafe { libc::close(pidfd as libc::c_int) };
    if let Some(error) = error {
        if !exact_record_process(record, identity)? {
            return Ok(false);
        }
        return Err(format!("无法停止本应用登记的 dnsmasq：{error}"));
    }
    Ok(true)
}

fn parse_udp_port_conflict(contents: &str, port: u16) -> bool {
    contents.lines().skip(1).any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields
            .get(1)
            .and_then(|local| local.rsplit_once(':'))
            .and_then(|(_, hex_port)| u16::from_str_radix(hex_port, 16).ok())
            == Some(port)
    })
}

fn check_no_dhcp_listener() -> Result<(), String> {
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("无法检查 {path} 中的 DHCP 端口占用：{e}"))?;
        if parse_udp_port_conflict(&contents, UDP_PORT_DHCP) {
            return Err(format!(
                "检测到现有 UDP/67 DHCP 服务（{path}）；为保护现有服务，未启动 dnsmasq。"
            ));
        }
    }
    Ok(())
}

fn check_nm_shared(interface: &str) -> Result<(), String> {
    let nmcli = ["/usr/bin/nmcli", "/bin/nmcli"]
        .iter()
        .find(|p| Path::new(p).is_file());
    if nmcli.is_none() {
        if Path::new("/run/NetworkManager").exists() {
            return Err("NetworkManager 正在运行但 nmcli 不可用，无法确认连接是否启用了 shared；为安全起见未启动 DHCP。".into());
        }
        return Ok(());
    }
    let device = Command::new(nmcli.unwrap())
        .args(["-g", "GENERAL.CON-UUID", "device", "show", interface])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("无法查询 NetworkManager 活动连接：{e}"))?;
    if !device.status.success() {
        if Path::new("/run/NetworkManager").exists() {
            return Err(format!(
                "无法确认 {interface} 的 NetworkManager 活动连接：{}",
                String::from_utf8_lossy(&device.stderr).trim()
            ));
        }
        return Ok(());
    }
    let uuid = String::from_utf8_lossy(&device.stdout).trim().to_string();
    if uuid.is_empty() || uuid == "--" {
        return Ok(());
    }
    if uuid.len() != 36 || !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err("NetworkManager 返回了格式无效的活动连接 UUID；为安全起见未启动 DHCP。".into());
    }
    let connection = Command::new(nmcli.unwrap())
        .args(["-g", "ipv4.method", "connection", "show", "uuid", &uuid])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("无法查询 NetworkManager IPv4 配置：{e}"))?;
    if !connection.status.success() {
        if Path::new("/run/NetworkManager").exists() {
            return Err(format!(
                "无法确认 {interface} 的 NetworkManager IPv4 分享模式：{}",
                String::from_utf8_lossy(&connection.stderr).trim()
            ));
        }
        return Ok(());
    }
    if String::from_utf8_lossy(&connection.stdout).trim() == "shared" {
        return Err(format!(
            "NetworkManager 已将 {interface} 配置为 shared；请先关闭其共享，避免 DHCP 服务冲突。"
        ));
    }
    Ok(())
}

fn append_cleanup(cause: String, cleanup: Vec<String>) -> String {
    if cleanup.is_empty() {
        cause
    } else {
        format!("{cause}；清理也有错误：{}", cleanup.join("；"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_config_never_advertises_router_or_dns_servers() {
        let config = build_dnsmasq_config(
            "enx123",
            Ipv4Addr::new(192, 168, 50, 3),
            "12345678-1234-1234-1234-123456789abc",
        );
        assert!(config.contains("robolink-id=12345678-1234-1234-1234-123456789abc"));
        assert!(config.lines().any(|line| line == "port=0"));
        assert!(config.lines().any(|line| line == "interface=enx123"));
        assert!(config.lines().any(|line| line == "bind-interfaces"));
        assert!(config
            .lines()
            .any(|line| line == "dhcp-range=192.168.50.10,192.168.50.200,255.255.255.0,1h"));
        assert!(config.lines().any(|line| line == "dhcp-option=3"));
        assert!(config.lines().any(|line| line == "dhcp-option=6"));
        assert!(config.lines().any(|line| line == "leasefile-ro"));
        assert!(config.lines().any(|line| line == "log-dhcp"));
        assert!(config.lines().any(|line| line == "log-facility=-"));
        assert!(!config.contains("leasefile="));
        assert!(!config.contains("net:") && !config.contains("enable-ra"));
        assert!(!config
            .lines()
            .any(|line| line.starts_with("dhcp-option=3,")));
        assert!(!config
            .lines()
            .any(|line| line.starts_with("dhcp-option=6,")));
    }

    #[test]
    fn only_private_slash24_with_host_outside_the_pool_is_accepted() {
        for cidr in [
            "10.0.0.1/24",
            "172.16.3.9/24",
            "172.31.3.201/24",
            "192.168.8.254/24",
        ] {
            assert!(parse_private_dhcp_cidr(cidr).is_ok(), "{cidr}");
        }
        for cidr in [
            "8.8.8.1/24",
            "172.15.1.1/24",
            "172.32.1.1/24",
            "192.167.1.1/24",
            "192.168.1.1/23",
            "192.168.1.10/24",
            "192.168.1.200/24",
            "192.168.1.255/24",
        ] {
            assert!(parse_private_dhcp_cidr(cidr).is_err(), "{cidr}");
        }
    }

    #[test]
    fn uid_parser_rejects_non_decimal_and_overflow() {
        assert_eq!(parse_uid("1000"), Some(1000));
        for value in ["", "-1", "+1", " 1", "1 ", "1x", "4294967296"] {
            assert_eq!(parse_uid(value), None, "{value:?}");
        }
    }

    #[test]
    fn pid_ownership_requires_pid_starttime_executable_and_exact_config_argument() {
        let record = DhcpRecord {
            interface: "enx123".into(),
            cidr: "192.168.2.1/24".into(),
            uid: 1000,
            id: "12345678-1234-1234-1234-123456789abc".into(),
            pid: 321,
            start_time: 999,
            config_path: "/run/robolink-dhcp/12345678-1234-1234-1234-123456789abc.conf".into(),
            log_path: "/run/robolink-dhcp/12345678-1234-1234-1234-123456789abc.log".into(),
            address_added: true,
        };
        let argv = vec![
            DNSMASQ.into(),
            format!("--conf-file={}", record.config_path),
            "--keep-in-foreground".into(),
        ];
        assert!(process_identity_matches(&record, Some(999), DNSMASQ, &argv));
        assert!(!process_identity_matches(
            &record,
            Some(998),
            DNSMASQ,
            &argv
        ));
        assert!(!process_identity_matches(
            &record,
            Some(999),
            "/usr/bin/other",
            &argv
        ));
        assert!(!process_identity_matches(
            &record,
            Some(999),
            DNSMASQ,
            &[
                DNSMASQ.into(),
                "--conf-file=/tmp/unrelated".into(),
                "--keep-in-foreground".into()
            ]
        ));
    }

    #[test]
    fn failed_address_removal_preserves_journal_and_all_files() {
        let mut record = DhcpRecord {
            interface: "enx123".into(),
            cidr: "192.168.2.1/24".into(),
            uid: 1000,
            id: "12345678-1234-1234-1234-123456789abc".into(),
            pid: 0,
            start_time: 0,
            config_path: "/run/robolink-dhcp/12345678-1234-1234-1234-123456789abc.conf".into(),
            log_path: "/run/robolink-dhcp/12345678-1234-1234-1234-123456789abc.log".into(),
            address_added: true,
        };
        let mut file_removals = Vec::new();
        let mut persists = 0;
        let result = cleanup_record_with(
            &mut record,
            Path::new("/run/robolink-dhcp/1000-enx123.json"),
            |_| Err("injected ip address removal failure".into()),
            |_, _| {
                persists += 1;
                Ok(())
            },
            |path| {
                file_removals.push(path.to_path_buf());
                Ok(())
            },
        );
        assert!(result
            .unwrap_err()
            .contains("injected ip address removal failure"));
        assert!(record.address_added);
        assert_eq!(persists, 0);
        assert!(
            file_removals.is_empty(),
            "config, log, and state journal must remain"
        );
    }

    #[test]
    fn cleared_address_is_persisted_before_any_cleanup_file_is_removed() {
        use std::cell::RefCell;

        let mut record = DhcpRecord {
            interface: "enx123".into(),
            cidr: "192.168.2.1/24".into(),
            uid: 1000,
            id: "12345678-1234-1234-1234-123456789abc".into(),
            pid: 0,
            start_time: 0,
            config_path: "/run/robolink-dhcp/12345678-1234-1234-1234-123456789abc.conf".into(),
            log_path: "/run/robolink-dhcp/12345678-1234-1234-1234-123456789abc.log".into(),
            address_added: true,
        };
        let steps = RefCell::new(Vec::new());
        cleanup_record_with(
            &mut record,
            Path::new("/run/robolink-dhcp/1000-enx123.json"),
            |_| {
                steps.borrow_mut().push("remove-address".to_string());
                Ok(())
            },
            |_, persisted| {
                assert!(!persisted.address_added);
                steps
                    .borrow_mut()
                    .push("persist-addressAdded-false".to_string());
                Ok(())
            },
            |path| {
                steps
                    .borrow_mut()
                    .push(path.file_name().unwrap().to_string_lossy().into_owned());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            steps.into_inner(),
            [
                "remove-address",
                "persist-addressAdded-false",
                "12345678-1234-1234-1234-123456789abc.conf",
                "12345678-1234-1234-1234-123456789abc.log",
                "1000-enx123.json",
            ]
        );
    }

    #[test]
    fn dhcp_ack_log_parser_rejects_bad_ip_interface_mac_and_truncated_rows() {
        let log = concat!(
            "DHCPACK(enx123) 192.168.2.44 02:11:22:33:44:55 robot\n",
            "DHCPACK(enx123) 192.168.3.44 02:11:22:33:44:56 other-subnet\n",
            "DHCPACK(other0) 192.168.2.45 02:11:22:33:44:57 wrong-interface\n",
            "DHCPACK(enx123) 192.168.2.46 01:11:22:33:44:58 multicast-mac\n",
            "DHCPACK(enx123) 999.168.2.47 02:11:22:33:44:59 bad-ip\n",
            "DHCPACK(enx123) 192.168.2.48 02:11:22:33\n",
            "DHCPACK(enx123) 192.168.2.1 02:11:22:33:44:60 local-ip\n",
            "DHCPACK(enx123) 192.168.2.49 02:11:22:33:44:61 robot-2\n",
        );
        let parsed = parse_dhcp_ack_log(log, "enx123", "192.168.2.1/24");
        assert_eq!(
            parsed,
            vec![
                (Ipv4Addr::new(192, 168, 2, 44), [2, 17, 34, 51, 68, 85]),
                (Ipv4Addr::new(192, 168, 2, 49), [2, 17, 34, 51, 68, 97])
            ]
        );
    }

    #[test]
    fn udp_conflict_parser_handles_ipv4_and_ipv6_proc_rows() {
        let ipv4 = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n  42: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 123";
        assert!(parse_udp_port_conflict(ipv4, 67));
        assert!(!parse_udp_port_conflict(ipv4, 68));
        let ipv6 = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n  14: 00000000000000000000000000000000:0043 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 456";
        assert!(parse_udp_port_conflict(ipv6, 67));
    }
}
