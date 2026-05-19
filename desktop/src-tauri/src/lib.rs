use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;

/// Run the bundled fraud-engine-sidecar against a CSV file path and return
/// the parsed JSON findings.
///
/// Why we stream events instead of using `.output().await`:
/// the sidecar can emit ~MBs of JSON for a large CSV. `.output()` collects
/// everything in memory and is fine for our sizes, but streaming lets the
/// UI react if we ever want a progress bar later. Stdout chunks are
/// concatenated; we parse the full payload at the end so we don't lose
/// data even if Python writes the JSON across multiple flushes.
///
/// `watchlist_json` (optional): if provided, written to a tempfile and
/// passed to the sidecar via `--watchlist`. The sidecar reads it the same
/// way analyze.py expects in CLI mode. The tempfile is cleaned up after
/// the sidecar exits regardless of success.
#[tauri::command]
async fn analyze_csv(
    app: tauri::AppHandle,
    csv_path: String,
    watchlist_json: Option<String>,
) -> Result<serde_json::Value, String> {
    // Stage the watchlist into a tempfile if the JS side gave us one.
    // PID is unique-enough since the desktop app runs as a single process
    // and we delete the tempfile right after the sidecar finishes.
    let watchlist_path: Option<std::path::PathBuf> = if let Some(wl) = watchlist_json {
        let tmp = std::env::temp_dir()
            .join(format!("cubo-watchlist-{}.json", std::process::id()));
        std::fs::write(&tmp, wl)
            .map_err(|e| format!("Failed to write watchlist tempfile: {e}"))?;
        Some(tmp)
    } else {
        None
    };

    let mut args: Vec<String> = vec![csv_path.clone()];
    if let Some(wl) = &watchlist_path {
        args.push("--watchlist".to_string());
        args.push(wl.to_string_lossy().to_string());
    }

    let sidecar = app
        .shell()
        .sidecar("fraud-engine-sidecar")
        .map_err(|e| format!("Failed to locate sidecar binary: {e}"))?
        .args(&args);

    let (mut rx, _child) = sidecar
        .spawn()
        .map_err(|e| format!("Failed to spawn sidecar: {e}"))?;

    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    let mut exit_code: Option<i32> = None;

    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stdout(line) => stdout_buf.extend_from_slice(&line),
            CommandEvent::Stderr(line) => stderr_buf.extend_from_slice(&line),
            CommandEvent::Terminated(payload) => exit_code = payload.code,
            _ => {}
        }
    }

    // Always remove the tempfile even on failure — it can contain a snapshot
    // of the watchlist (cardholder fingerprints etc.) that we don't want
    // lingering on disk.
    if let Some(wl) = watchlist_path {
        let _ = std::fs::remove_file(wl);
    }

    let stdout_str = String::from_utf8_lossy(&stdout_buf);
    let stderr_str = String::from_utf8_lossy(&stderr_buf);

    if stdout_str.trim().is_empty() {
        return Err(format!(
            "Sidecar produced no output (exit={:?}). stderr:\n{}",
            exit_code, stderr_str
        ));
    }

    serde_json::from_str(&stdout_str).map_err(|e| {
        format!(
            "Could not parse sidecar JSON (exit={:?}): {e}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            exit_code, stdout_str, stderr_str
        )
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use tauri::Manager;

    tauri::Builder::default()
        // Single-instance must come BEFORE deep-link so it can intercept
        // a second launch (carrying the OAuth callback URL) and forward
        // the URL to the already-running app instead of spawning a fresh
        // process. Without this, every deep link spawned a new copy of
        // the app, leaving the original login window stranded.
        //
        // The callback fires inside the FIRST (already-running) instance
        // when Windows tries to launch a second one. We just refocus the
        // window; tauri-plugin-deep-link's `deep-link` feature flag on
        // single-instance handles converting argv into an onOpenUrl event.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|_app| {
            // In production the installer (.msi/.exe) writes the URL scheme
            // into the Windows registry under HKCU\Software\Classes. In
            // `tauri dev` we ship no installer, so we have to register the
            // scheme ourselves on first launch — otherwise Windows doesn't
            // know that `cubo-fraud-engine://...` URLs should route back to
            // this running process, and the browser shows a blank page
            // after Supabase finishes OAuth.
            //
            // The registry write is per-user (no admin needed) and persists
            // across runs, so this is effectively a one-time setup that
            // re-runs idempotently on every dev launch.
            //
            // `_app` underscore prefix: the closure parameter is unused on
            // Windows release builds (the cfg below is false there), and
            // the unused-variables lint would warn without the prefix.
            #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                match _app.deep_link().register_all() {
                    Ok(_)  => eprintln!("[deep-link] URL schemes registered with the OS"),
                    Err(e) => eprintln!("[deep-link] FAILED to register URL schemes: {e}"),
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![analyze_csv])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
