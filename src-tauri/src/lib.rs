mod commands;
mod desktop;
mod model;
mod ssh;
mod state;

use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state = AppState::new().map_err(std::io::Error::other)?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_host_info,
            commands::list_targets,
            commands::save_target,
            commands::delete_target,
            commands::get_host_key_status,
            commands::trust_host_key,
            commands::forget_host_key,
            commands::ssh_connection_ready,
            commands::scan_direct_interface,
            commands::scan_direct_interfaces,
            commands::discover_direct_devices,
            commands::get_dhcp_status,
            commands::start_direct_dhcp,
            commands::stop_direct_dhcp,
            commands::list_owned_network_addresses,
            commands::add_temporary_network_address,
            commands::remove_owned_network_address,
            commands::cleanup_session_network_addresses,
            commands::cleanup_owned_network_addresses,
            commands::get_remote_overview,
            commands::list_services,
            commands::service_action,
            commands::get_remote_network,
            commands::scan_remote_wifi,
            commands::set_remote_wifi_radio,
            commands::start_wifi_connect,
            commands::connect_remote_wifi,
            commands::get_bluetooth_snapshot,
            commands::scan_bluetooth,
            commands::set_bluetooth_power,
            commands::bluetooth_action,
            commands::get_audio_snapshot,
            commands::set_audio_default,
            commands::set_audio_volume,
            commands::play_test_audio,
            commands::open_ssh_terminal,
            commands::send_terminal_input,
            commands::resize_terminal,
            commands::close_ssh_terminal,
            desktop::check_remote_desktop,
            desktop::install_remote_desktop,
            desktop::start_remote_desktop,
            desktop::stop_remote_desktop
        ])
        .run(tauri::generate_context!())
        .expect("启动 RoboLink 桌面程序失败");
}
