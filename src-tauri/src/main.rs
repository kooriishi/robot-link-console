#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // RoboLink doubles as ssh's SSH_ASKPASS helper for the one-time password login.
    if let Ok(socket) = std::env::var("ROBOLINK_ASKPASS") {
        robot_link_console_lib::askpass_main(&socket);
    }
    robot_link_console_lib::run()
}
