mod commands;
mod desktop;
mod link;
mod link_ipv4;
mod model;
mod ssh;
mod state;

use state::AppState;
use tauri::Manager;

pub fn askpass_main(socket: &str) -> ! {
    ssh::askpass_main(socket)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state = AppState::new().map_err(std::io::Error::other)?;
            // Host-key pins used to be stored per address; they now belong to the device.
            if let Err(error) = ssh::migrate_pins(&state) {
                eprintln!("RoboLink: 迁移主机指纹失败：{error}");
            }
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
            commands::get_channel_status,
            link::find_link_peers,
            link::link_prepare,
            link::link_login,
            link::link_robot_ipv4,
            link::link_finish,
            link_ipv4::link_ipv4_probe,
            link_ipv4::link_ipv4_dhcp,
            link_ipv4::link_ipv4_propose,
            link_ipv4::link_ipv4_temp_add,
            link_ipv4::link_ipv4_temp_remove,
            link_ipv4::link_use_ipv6,
            commands::drop_channel,
            commands::set_key_login,
            commands::sync_targets_with_discovery,
            commands::relocate_target,
            commands::auto_direct_address,
            commands::power_action,
            commands::collect_diagnostics,
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
