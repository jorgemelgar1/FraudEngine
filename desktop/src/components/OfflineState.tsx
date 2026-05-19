// Shared "this view needs internet" empty state. Rendered by Pendientes and
// Historial when the app is offline OR when their fetch fails with a network
// error even though navigator.onLine claimed we were up.
export function OfflineState({
  title, onRetry, disabled,
}: {
  title: string;
  onRetry: () => void;
  disabled: boolean;
}) {
  return (
    <main className="main">
      <div className="card centered offline-state">
        <img
          src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo%20Holmes.png"
          alt="Cubo Holmes"
          className="mascot"
        />
        <h2>{title}</h2>
        <p className="muted">
          Esta sección requiere conexión a internet — los datos viven en
          Supabase. Cuando vuelvas a estar en línea, se cargará
          automáticamente. También puedes intentarlo manualmente.
        </p>
        <button className="btn" onClick={onRetry} disabled={disabled}>
          Reintentar
        </button>
        <p className="hint">
          La pestaña <strong>Analizar</strong> sí funciona sin conexión si
          tienes una watchlist en caché — los resultados se guardan en una
          cola local y se sincronizan al volver.
        </p>
      </div>
    </main>
  );
}
