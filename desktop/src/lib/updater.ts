import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

// State machine the UI follows for the auto-update flow. We keep the
// detected `Update` handle in a module-scoped variable rather than in
// React state because the handle isn't serializable / safe to pass
// through React's reconciler.

export type UpdateState =
  | { status: 'idle' }
  | { status: 'checking' }
  | { status: 'up-to-date' }
  | { status: 'available'; version: string; notes?: string }
  | { status: 'downloading' }
  | { status: 'installing' }
  | { status: 'error'; message: string };

let _pending: Update | null = null;

// Check the configured GitHub Releases endpoint for a newer version.
// Returns the resulting state. Silent network failures resolve to 'error'
// rather than throwing; the caller decides whether to surface them.
//
// We treat "could not check" as different from "no update" so the UI can
// stay quiet when offline (an error here just means we couldn't reach
// GitHub right now — the user already has a working app version).
export async function checkForUpdate(): Promise<UpdateState> {
  try {
    const update = await check();
    if (!update) {
      _pending = null;
      return { status: 'up-to-date' };
    }
    _pending = update;
    return {
      status:  'available',
      version: update.version,
      notes:   update.body || undefined,
    };
  } catch (e) {
    _pending = null;
    return {
      status: 'error',
      message: e instanceof Error ? e.message : String(e),
    };
  }
}

// Download + install the previously-detected update, then relaunch.
// Throws if checkForUpdate hasn't been called or returned 'available'.
// The relaunch happens after install completes; the app process exits
// and a fresh one starts on the new version.
export async function installAvailableUpdate(): Promise<void> {
  if (!_pending) {
    throw new Error('No hay ninguna actualización pendiente para instalar.');
  }
  await _pending.downloadAndInstall();
  await relaunch();
}
