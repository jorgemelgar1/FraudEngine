// Hide the extra console window on Windows when launched outside a terminal.
// In debug builds (cargo tauri dev) the console is kept so we can see logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    cubo_fraud_engine_lib::run()
}
