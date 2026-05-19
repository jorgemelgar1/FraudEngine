import { open as openUrl } from '@tauri-apps/plugin-shell';
import { onOpenUrl } from '@tauri-apps/plugin-deep-link';
import { supabase } from './supabase';
import { ALLOWED_EMAIL_DOMAIN, OAUTH_REDIRECT_URL } from './config';

// Two-step PKCE OAuth flow for desktop:
//   1. Ask Supabase to construct the provider URL (skipBrowserRedirect: true
//      so we get the URL string back instead of being navigated). Pass our
//      custom `cubo-fraud-engine://` redirect so Supabase will bounce here
//      after Google auth completes.
//   2. Open that URL in the user's default system browser via Tauri's
//      shell:open-url permission. The browser handles Google login.
//   3. Once Google returns the user to Supabase, Supabase redirects to
//      `cubo-fraud-engine://auth/callback?code=...`. The OS routes that
//      to our running app via tauri-plugin-deep-link, which fires the
//      `onOpenUrl` handler set up below.
//   4. We extract the `code`, call exchangeCodeForSession to mint the
//      session, and the Supabase client persists it.
export async function signInWithGoogle(): Promise<void> {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: OAUTH_REDIRECT_URL,
      skipBrowserRedirect: true,
      // Pre-filter Google's account picker to the Cubo Workspace. Same
      // trick the Vercel login uses — saves a click for the common case
      // and gently nudges users with non-Cubo Google accounts toward
      // logging into Cubo first.
      queryParams: { hd: ALLOWED_EMAIL_DOMAIN },
    },
  });
  if (error) throw error;
  if (!data?.url) throw new Error('Supabase did not return an OAuth URL');
  await openUrl(data.url);
}

// Register a single deep-link listener for the OAuth callback. Called
// once at app startup. Tauri keeps the listener alive for the app's
// lifetime; we return the unlisten function for completeness even though
// we don't currently unsubscribe before app exit.
export async function registerOAuthCallbackHandler(
  onResult: (result: { ok: true; email: string } | { ok: false; reason: string }) => void,
): Promise<() => void> {
  return onOpenUrl(async (urls) => {
    for (const raw of urls) {
      if (!raw.startsWith('cubo-fraud-engine://auth/callback')) continue;

      // Parse query params off the URL. URL constructor handles custom
      // schemes fine in modern browsers.
      let url: URL;
      try {
        url = new URL(raw);
      } catch {
        onResult({ ok: false, reason: 'URL inválido en el callback de OAuth' });
        continue;
      }

      const code = url.searchParams.get('code');
      const errParam = url.searchParams.get('error_description') || url.searchParams.get('error');
      if (errParam) {
        onResult({ ok: false, reason: errParam });
        continue;
      }
      if (!code) {
        onResult({ ok: false, reason: 'Callback sin código de autorización' });
        continue;
      }

      const { data, error } = await supabase.auth.exchangeCodeForSession(code);
      if (error || !data?.user) {
        onResult({ ok: false, reason: error?.message || 'No se pudo crear la sesión' });
        continue;
      }

      // Defense-in-depth domain check (same as the Vercel app/auth/callback
      // route): even though Supabase's `hd=` hint nudges users to the right
      // account, a determined user could still sign in with a personal
      // Google account. We catch that here and sign them out immediately.
      const email = (data.user.email || '').toLowerCase();
      const parts = email.split('@');
      if (parts.length !== 2 || parts[1] !== ALLOWED_EMAIL_DOMAIN) {
        await supabase.auth.signOut();
        onResult({
          ok: false,
          reason: `Ese dominio de email no está autorizado. Usa tu cuenta @${ALLOWED_EMAIL_DOMAIN}.`,
        });
        continue;
      }

      onResult({ ok: true, email });
    }
  });
}

export async function signOut(): Promise<void> {
  await supabase.auth.signOut();
}
