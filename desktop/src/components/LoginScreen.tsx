export function LoginScreen({
  signingIn, error, onSignIn,
}: {
  signingIn: boolean;
  error: string;
  onSignIn: () => void;
}) {
  return (
    <div className="app login">
      <div className="login-card">
        <img
          src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo%20Holmes.png"
          alt="Cubo Holmes"
          className="mascot"
        />
        <img
          src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo.png"
          alt="Cubo"
          className="logo big"
        />
        <h1>Fraud Engine</h1>
        <p className="muted">Versión escritorio</p>
        <p className="hint">
          Inicia sesión con tu cuenta de Google de Cubo Pago.
          Se abrirá tu navegador para completar la autenticación.
        </p>

        {error && <div className="error-banner">{error}</div>}

        <button className="btn primary" onClick={onSignIn} disabled={signingIn}>
          {signingIn ? 'Esperando autenticación…' : 'Iniciar sesión con Google'}
        </button>

        {signingIn && (
          <p className="hint">
            Si la ventana del navegador no apareció, búscala en la barra de tareas.
            Vuelve aquí después de elegir tu cuenta.
          </p>
        )}
      </div>
    </div>
  );
}
