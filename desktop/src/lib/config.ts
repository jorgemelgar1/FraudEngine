// Vite inlines VITE_-prefixed env vars at BUILD time. In dev these come from
// desktop/.env.local; in production they're baked into the bundled JS at
// `npm run tauri build` time. All three values are public (anon key is
// designed to be shipped in client code; RLS policies are what enforce
// access control).
//
// We intentionally fail loud if the values are missing — a desktop build
// without Supabase config is non-functional and there's no graceful fallback.
function required(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(
      `Missing required env var ${name}. ` +
      `Did you create desktop/.env.local from .env.example?`,
    );
  }
  return value;
}

export const SUPABASE_URL = required('VITE_SUPABASE_URL', import.meta.env.VITE_SUPABASE_URL);
export const SUPABASE_ANON_KEY = required('VITE_SUPABASE_ANON_KEY', import.meta.env.VITE_SUPABASE_ANON_KEY);
export const ALLOWED_EMAIL_DOMAIN = (
  import.meta.env.VITE_ALLOWED_EMAIL_DOMAIN || 'cubopago.com'
).toLowerCase();

// OAuth callback URL — must match what's configured in Supabase's
// "Redirect URLs" allow list. Custom scheme `cubo-fraud-engine://` is
// registered by tauri-plugin-deep-link so the OS routes the callback
// back to the running desktop app.
export const OAUTH_REDIRECT_URL = 'cubo-fraud-engine://auth/callback';
