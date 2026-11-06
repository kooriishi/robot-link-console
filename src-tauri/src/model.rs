use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetDraft {
    pub id: Option<String>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInterface {
    pub name: String,
    pub kind: String,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub carrier: bool,
    pub state: String,
    pub mtu: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub interfaces: Vec<HostInterface>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredHost {
    pub address: String,
    pub interface: String,
    pub mac: String,
    pub port: u16,
    pub port_open: bool,
    pub route_ready: bool,
    pub source: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyStatus {
    pub fingerprints: Vec<String>,
    pub pinned_fingerprints: Vec<String>,
    pub trusted: bool,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteOverview {
    pub hostname: String,
    pub uptime: String,
    pub load: String,
    pub memory_total_kb: Option<u64>,
    pub memory_available_kb: Option<u64>,
    pub temperature_c: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub active: String,
    pub sub_state: String,
    pub enabled: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiNetwork {
    pub in_use: bool,
    pub ssid: String,
    pub signal: u8,
    pub security: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDevice {
    pub device: String,
    pub kind: String,
    pub state: String,
    pub connection: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteNetwork {
    pub supported: bool,
    pub wifi_enabled: bool,
    pub devices: Vec<NetworkDevice>,
    pub wifi_networks: Vec<WifiNetwork>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluetoothDevice {
    pub address: String,
    pub name: String,
    pub paired: bool,
    pub connected: bool,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BluetoothSnapshot {
    pub available: bool,
    pub powered: bool,
    pub adapter: String,
    pub devices: Vec<BluetoothDevice>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioDevice {
    pub name: String,
    pub description: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioSnapshot {
    pub available: bool,
    pub sinks: Vec<AudioDevice>,
    pub sources: Vec<AudioDevice>,
    pub alsa_playback: Vec<AudioDevice>,
    pub alsa_capture: Vec<AudioDevice>,
    pub default_sink_volume: Option<u8>,
    pub default_source_volume: Option<u8>,
    pub note: Option<String>,
}

pub fn validate_host(value: &str) -> Result<String, String> {
    let host = value.trim().trim_matches(['[', ']']);
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('-')
        || host.contains(['\n', '\r', '\0', '/', '\\', '@', ' '])
    {
        return Err("主机名/IP 格式无效".into());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !valid {
        return Err("主机名仅允许字母、数字、点和连字符；IPv6 地址请使用标准格式".into());
    }
    Ok(host.to_ascii_lowercase())
}

pub fn validate_username(value: &str) -> Result<String, String> {
    let username = value.trim();
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        || username.starts_with('-')
    {
        return Err("用户名仅允许字母、数字、点、下划线和连字符".into());
    }
    Ok(username.to_string())
}

pub fn validate_ifname(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 15
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':')
    {
        return Err("网卡名称格式无效".into());
    }
    Ok(())
}

pub fn validate_service_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 160
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'_'
                || b == b'.'
                || b == b'@'
                || b == b':'
                || b == b'-'
        })
        || value.starts_with('-')
    {
        return Err("systemd 服务名称格式无效".into());
    }
    Ok(())
}

pub fn validate_mac(value: &str) -> Result<(), String> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("蓝牙设备地址格式无效".into());
    }
    Ok(())
}

pub fn validate_wifi_ssid(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 || value.chars().any(|c| c.is_control()) {
        return Err("Wi-Fi 名称为空、过长或包含控制字符".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_direct_link_hosts_and_domains() {
        assert_eq!(validate_host("192.168.7.2").unwrap(), "192.168.7.2");
        assert_eq!(validate_host("robot-r2.local").unwrap(), "robot-r2.local");
        assert_eq!(validate_host("[2001:db8::1]").unwrap(), "2001:db8::1");
    }

    #[test]
    fn rejects_shell_and_option_injection() {
        assert!(validate_host("-oProxyCommand=bad").is_err());
        assert!(validate_host("robot;touch /tmp/x").is_err());
        assert!(validate_username("robot$(id)").is_err());
        assert!(validate_service_name("foo; reboot").is_err());
    }

    #[test]
    fn allows_systemd_template_units_and_wifi_control_characters_are_rejected() {
        assert!(validate_service_name("ros2@robot.service").is_ok());
        assert!(validate_wifi_ssid("robot\nmalicious").is_err());
        assert!(validate_mac("AA:BB:CC:12:34:56").is_ok());
    }
}
