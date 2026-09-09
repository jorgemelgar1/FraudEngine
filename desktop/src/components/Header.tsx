import { signOut } from '../lib/auth';
import { pendingSyncCount } from '../lib/offline';
import type { UpdateState } from '../lib/updater';

export type View = 'analyzer' | 'pendientes' | 'historial' | 'indicadores' | 'runner';

export function Header({
  view, setView, email, pendingCount,
  online, queueSize, draining, onSyncNow,
  updateState, onInstallUpdate, runnerAlert,
}: {
  view: View;
  setView: (v: View) => void;
  email: string;
  pendingCount: number | null;
  online: boolean;
  queueSize: number;
  draining: boolean;
  onSyncNow: () => void;
  updateState: UpdateState;
  onInstallUpdate: () => void;
  // True when a country has gone quiet. The tab sits last because it is the
  // least-visited one; the dot is what pulls the eye on the day it matters.
  runnerAlert: boolean;
}) {
  const showUpdatePill =
    updateState.status === 'available' || updateState.status === 'installing';
  return (
    <header className="header">
      <img
        src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo.png"
        alt="Cubo"
        className="logo"
      />
      <span className="product">Fraud Engine</span>

      <nav className="nav">
        <NavButton active={view === 'analyzer'}   onClick={() => setView('analyzer')}>
          Analizar
        </NavButton>
        <NavButton active={view === 'pendientes'} onClick={() => setView('pendientes')}>
          Pendientes
          {pendingCount !== null && pendingCount > 0 && (
            <span className="pending-badge">{pendingCount}</span>
          )}
        </NavButton>
        <NavButton active={view === 'historial'} onClick={() => setView('historial')}>
          Historial
        </NavButton>
        <NavButton active={view === 'indicadores'} onClick={() => setView('indicadores')}>
          Indicadores
        </NavButton>
        <NavButton active={view === 'runner'} onClick={() => setView('runner')}>
          Runner
          {runnerAlert && (
            <span
              className="runner-alert-dot"
              title="Un país lleva demasiado tiempo sin correr"
            />
          )}
        </NavButton>
      </nav>

      {/* Status cluster — pushed to the right via margin-left:auto on the
          first member. Order: update available (rare, takes precedence),
          queue (if any), connection dot, email, sign out. */}
      {showUpdatePill && (
        <button
          className="update-pill"
          onClick={onInstallUpdate}
          disabled={updateState.status === 'installing'}
          title="Reinstala la app con la nueva versión y reinicia."
        >
          {updateState.status === 'installing'
            ? 'Instalando actualización…'
            : `Actualización disponible · v${(updateState as { version: string }).version}`}
        </button>
      )}
      {queueSize > 0 && (
        <button
          className="sync-pill"
          onClick={onSyncNow}
          disabled={draining || !online}
          title={
            !online
              ? 'Sin conexión — se sincronizará automáticamente al volver'
              : draining ? 'Sincronizando…' : 'Sincronizar ahora'
          }
        >
          {draining
            ? 'Sincronizando…'
            : `${queueSize} pendiente${queueSize === 1 ? '' : 's'} de sincronizar`}
        </button>
      )}

      <span
        className={`status-dot ${online ? 'online' : 'offline'}`}
        title={online ? 'En línea' : 'Sin conexión'}
      />
      <span className="user-badge">{email}</span>
      <button
        className="btn ghost small"
        onClick={async () => {
          // Signing out wipes the local caches, and one of them holds runs
          // that never reached Supabase. Say so before destroying them.
          const pending = await pendingSyncCount();
          if (
            pending > 0 &&
            !confirm(
              `Hay ${pending} análisis sin subir. Al cerrar sesión se ` +
              `borran de este equipo y no se pueden recuperar. ¿Cerrar sesión?`,
            )
          ) {
            return;
          }
          await signOut();
        }}
      >
        Cerrar sesión
      </button>
    </header>
  );
}

function NavButton({
  active, onClick, children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      className={`nav-btn ${active ? 'active' : ''}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}
