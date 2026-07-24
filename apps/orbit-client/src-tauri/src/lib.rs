use std::fs;

use tauri::Manager;

mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            fs::create_dir_all(&app_data)?;
            let default_sync_root = app
                .path()
                .document_dir()
                .unwrap_or_else(|_| app_data.clone())
                .join("Orbit");
            app.manage(commands::ClientState::new(
                app_data.join("orbit.toml"),
                default_sync_root,
            ));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::load_snapshot,
            commands::initialize_node,
            commands::start_service,
            commands::stop_service,
            commands::sync_now,
            commands::add_peer,
            commands::add_peer_from_invite,
            commands::switch_workspace_from_invite,
            commands::revoke_peer,
            commands::save_settings,
            commands::create_invite,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
