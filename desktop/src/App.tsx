import { useCallback, useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

import { supabase } from './lib/supabase';
import { signInWithGoogle, registerOAuthCallbackHandler } from './lib/auth';
import { pendingCount } from './lib/findings';
import { drainSyncQueue } from './lib/sync';
import { getSyncQueue } from './lib/offline';
import {
  checkForUpdate,
  installAvailableUpdate,
  type UpdateState,
} from './lib/updater';
import { Header, type View } from './components/Header';
import { LoginScreen } from './components/LoginScreen';
import { Analyzer } from './pages/Analyzer';
import { Pendientes } from './pages/Pendientes';
import { Historial } from './pages/Historial';
import { Indicadores } from './pages/Indicadores';

// App is the shell: it owns auth state, the active view, online/offline
// status, and the pending-count + sync-queue badges in the header. Each
// page component is self-contained and gets only what it needs.
export default function App() {
  // undefined = checking; null = logged out; Session = logged in.
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [authError, setAuthError] = useState('');
  const [signingIn, setSigningIn] = useState(false);

  const [view, setView] = useState<View>('analyzer');
  const [pendingCnt, setPendingCnt] = useState<number | null>(null);
  const [updateState, setUpdateState] = useState<UpdateState>({ status: 'idle' });

  // Network state — defaults to true and tracks browser online/offline
  // events. We treat `online` as a hint, not a guarantee; actual operations
  // still catch network errors and queue locally if they fail.
  const [online, setOnline] = useState<boolean>(
    typeof navigator !== 'undefined' ? navigator.onLine : true,
  );
  const [queueSize, setQueueSize] = useState(0);
  const [draining, setDraining] = useState(false);

  // Hydrate session + subscribe to changes once at mount.
  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session));

    const { data: sub } = supabase.auth.onAuthStateChange((_event, sess) => {
      setSession(sess);
    });

    let unlisten: (() => void) | undefined;
    registerOAuthCallbackHandler((result) => {
      setSigningIn(false);
      if (result.ok) {
        setAuthError('');
      } else {
        setAuthError(result.reason);
      }
    }).then((fn) => { unlisten = fn; });

    return () => {
      sub.subscription.unsubscribe();
      unlisten?.();
    };
  }, []);

  // Track browser online/offline events. These are heuristics — Windows
  // fires `online` as soon as a network interface is up, even before DNS
  // works — so the drain logic still catches its own failures and bails
  // gracefully if the network turns out to not actually be usable.
  useEffect(() => {
    const up   = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener('online', up);
    window.addEventListener('offline', down);
    return () => {
      window.removeEventListener('online', up);
      window.removeEventListener('offline', down);
    };
  }, []);

  // Refresh the queue size badge. Called after every relevant transition:
  // queue grows (a run was queued offline), queue shrinks (drain succeeded),
  // app boot, login.
  const refreshQueueSize = useCallback(async () => {
    try {
      const q = await getSyncQueue();
      setQueueSize(q.length);
    } catch {
      // Store load failures shouldn't break the UI — just leave the
      // previous count visible.
    }
  }, []);

  useEffect(() => { refreshQueueSize(); }, [refreshQueueSize, session]);

  // Refresh the pending-Critical-findings count whenever auth changes or a
  // child page tells us something moved.
  const refreshPendingCount = useCallback(async () => {
    if (!session) {
      setPendingCnt(null);
      return;
    }
    try {
      setPendingCnt(await pendingCount());
    } catch {
      // Best-effort — leave previous value visible.
    }
  }, [session]);

  useEffect(() => { refreshPendingCount(); }, [refreshPendingCount]);

  // One-shot update check at app startup. Re-runs if the user signs out
  // and back in (rare but harmless). We only show UI for 'available' and
  // 'installing' — silence 'up-to-date' and 'error' so an offline user
  // doesn't see a spurious "couldn't check" notification every launch.
  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    checkForUpdate().then((state) => {
      if (!cancelled) setUpdateState(state);
    });
    return () => { cancelled = true; };
  }, [session]);

  async function handleInstallUpdate() {
    setUpdateState({ status: 'installing' });
    try {
      await installAvailableUpdate(); // app process exits before this resolves
    } catch (e) {
      setUpdateState({
        status: 'error',
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  // Drain handler — used both by the auto-drain on reconnect AND by the
  // "Sincronizar pendientes" button in the header. Re-entry-safe via the
  // `draining` flag.
  const handleDrain = useCallback(async () => {
    if (draining) return;
    setDraining(true);
    try {
      const result = await drainSyncQueue();
      setQueueSize(result.remaining);
      // A successful drain might have added findings to Supabase that the
      // /pendientes badge cares about.
      refreshPendingCount();
    } catch {
      // The drain swallows its own per-item errors; getting here means a
      // bigger failure (e.g., store I/O). Leave queueSize as-is.
    } finally {
      setDraining(false);
    }
  }, [draining, refreshPendingCount]);

  // Auto-drain when the network comes back AND there's work waiting. We
  // depend on `queueSize` so we don't fire on initial mount with an empty
  // queue (no-op but wasteful).
  useEffect(() => {
    if (online && session && queueSize > 0 && !draining) {
      handleDrain();
    }
  }, [online, session, queueSize, draining, handleDrain]);

  async function handleSignIn() {
    setAuthError('');
    setSigningIn(true);
    try {
      await signInWithGoogle();
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : String(e));
      setSigningIn(false);
    }
  }

  // Booting flash.
  if (session === undefined) {
    return <div className="app boot">Cargando…</div>;
  }

  // Not logged in.
  if (session === null) {
    return (
      <LoginScreen
        signingIn={signingIn}
        error={authError}
        onSignIn={handleSignIn}
      />
    );
  }

  return (
    <div className="app">
      <Header
        view={view}
        setView={setView}
        email={session.user.email || ''}
        pendingCount={pendingCnt}
        online={online}
        queueSize={queueSize}
        draining={draining}
        onSyncNow={handleDrain}
        updateState={updateState}
        onInstallUpdate={handleInstallUpdate}
      />
      {view === 'analyzer' && (
        <Analyzer
          session={session}
          online={online}
          onRunCompleted={() => {
            refreshPendingCount();
            refreshQueueSize();
          }}
        />
      )}
      {view === 'pendientes' && (
        <Pendientes session={session} online={online} onChanged={refreshPendingCount} />
      )}
      {view === 'historial' && (
        <Historial session={session} online={online} onChanged={refreshPendingCount} />
      )}
      {view === 'indicadores' && (
        <Indicadores session={session} online={online} />
      )}
    </div>
  );
}
