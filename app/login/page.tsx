'use client';

import { Suspense, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="container" style={{ paddingTop: '5rem' }} />}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const search = useSearchParams();
  const initialError =
    search.get('error') === 'domain'
      ? 'That email domain is not authorized. Please use your Cubo Pago Google account.'
      : search.get('error') === 'callback'
      ? 'Sign-in failed. Please try again.'
      : '';

  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState(initialError);

  async function signInWithGoogle() {
    setError('');
    setSigningIn(true);
    const supabase = createClient();
    const { error: err } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`,
        queryParams: {
          // Pre-filter Google's account picker to Cubo Workspace accounts only.
          // (Defense in depth — middleware also enforces the domain.)
          hd: 'cubopago.com',
        },
      },
    });
    if (err) {
      setError(err.message);
      setSigningIn(false);
    }
    // On success, the browser navigates away to Google.
  }

  return (
    <div className="container" style={{ maxWidth: 440, paddingTop: '5rem' }}>
      <div className="card">
        <h1 style={{ marginTop: 0 }}>Cubo Fraud Engine</h1>
        <p className="muted">Sign in with your Cubo Pago Google account.</p>

        {error && <div className="error">{error}</div>}

        <button
          onClick={signInWithGoogle}
          disabled={signingIn}
          className="btn"
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.7rem',
            background: 'white',
            color: '#1f2937',
          }}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">
            <path
              fill="#4285F4"
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            />
            <path
              fill="#34A853"
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            />
            <path
              fill="#FBBC05"
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"
            />
            <path
              fill="#EA4335"
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
            />
          </svg>
          {signingIn ? 'Redirecting to Google…' : 'Sign in with Google'}
        </button>
      </div>
    </div>
  );
}
