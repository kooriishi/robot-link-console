use crate::model::Target;
use crate::ssh::TerminalSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostPin {
    pub target_key: String,
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub key_algorithm: String,
    pub known_hosts_lines: Vec<String>,
}

pub struct AppState {
    pub config_dir: PathBuf,
    pub targets_file: PathBuf,
    pub pins_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub sessions: Mutex<HashMap<String, TerminalSession>>,
    persistence_lock: Mutex<()>,
}

impl AppState {
    pub fn new() -> Result<Self, String> {
        let base = dirs::config_dir()
            .or_else(dirs::home_dir)
            .ok_or("找不到用户配置目录")?;
        let config_dir = base.join("robot-link-console");
        fs::create_dir_all(&config_dir).map_err(|e| format!("无法创建配置目录：{e}"))?;
        set_private_permissions(&config_dir, true)?;
        Ok(Self {
            targets_file: config_dir.join("targets.json"),
            pins_file: config_dir.join("host-pins.json"),
            known_hosts_file: config_dir.join("known_hosts"),
            config_dir,
            sessions: Mutex::new(HashMap::new()),
            persistence_lock: Mutex::new(()),
        })
    }

    pub fn load_targets(&self) -> Result<Vec<Target>, String> {
        read_json(&self.targets_file)
    }

    pub fn save_targets(&self, targets: &[Target]) -> Result<(), String> {
        let _guard = self
            .persistence_lock
            .lock()
            .map_err(|_| "配置写入锁不可用".to_string())?;
        write_json_atomic(&self.targets_file, targets)
    }

    pub fn load_pins(&self) -> Result<Vec<HostPin>, String> {
        read_json(&self.pins_file)
    }

    pub fn save_pins(&self, pins: &[HostPin]) -> Result<(), String> {
        let _guard = self
            .persistence_lock
            .lock()
            .map_err(|_| "配置写入锁不可用".to_string())?;
        write_json_atomic(&self.pins_file, pins)?;
        let contents = pins
            .iter()
            .flat_map(|p| p.known_hosts_lines.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        write_bytes_atomic(
            &self.known_hosts_file,
            if contents.is_empty() {
                String::new()
            } else {
                format!("{contents}\n")
            }
            .as_bytes(),
        )
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T, String> {
    if !path.exists() {
        return serde_json::from_slice(b"[]").map_err(|e| e.to_string());
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("读取配置失败：{e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("配置路径不是普通文件，已拒绝读取".into());
    }
    let bytes = fs::read(path).map_err(|e| format!("读取配置失败：{e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("配置文件格式错误：{e}"))
}

fn write_json_atomic<T: Serialize + ?Sized>(path: &PathBuf, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    let mut tmp = path.clone();
    tmp.set_extension(format!("tmp-{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("写入配置失败：{e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("写入配置失败：{e}"))?;
        file.sync_all().map_err(|e| format!("同步配置失败：{e}"))?;
    }
    #[cfg(not(unix))]
    fs::write(&tmp, bytes).map_err(|e| format!("写入配置失败：{e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("替换配置文件失败：{e}"))?;
    set_private_permissions(path, false)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &PathBuf, is_dir: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if is_dir { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("设置文件权限失败：{e}"))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &PathBuf, _is_dir: bool) -> Result<(), String> {
    Ok(())
}
