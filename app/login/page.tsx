'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

export default function LoginPage() {
  const search = useSearchParams();
  const initialError =
    search.get('error') === 'domain'
      ? 'That email domain is not authorized. Please use your Cubo Pago email.'
      : '';

  const [email, setEmail] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(initialError);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setSending(true);

    const supabase = createClient();
    const { error: err } = await supabase.auth.signInWithOtp({
      email,
      options: { emailRedirectTo: `${window.location.origin}/auth/callback` },
    });

    setSending(false);
    if (err) {
      setError(err.message);
      return;
    }
    setSent(true);
  }

  return (
    <div className="container" style={{ maxWidth: 440, paddingTop: '5rem' }}>
      <div className="card">
        <h1 style={{ marginTop: 0 }}>Cubo Fraud Engine</h1>
        <p className="muted">Sign in with your Cubo Pago email to continue.</p>

        {error && <div className="error">{error}</div>}

        {sent ? (
          <div>
            <p className="success">
              Check your inbox — we sent a sign-in link to <strong>{email}</strong>.
            </p>
            <p className="muted">You can close this tab; the link will sign you in.</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <label htmlFor="email" style={{ display: 'block', marginBottom: '0.4rem' }}>
              Work email
            </label>
            <input
              id="email"
              type="email"
              required
              autoFocus
              className="input"
              placeholder="you@cubopago.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <button
              type="submit"
              className="btn"
              disabled={sending || !email}
              style={{ marginTop: '1rem', width: '100%' }}
            >
              {sending ? 'Sending link...' : 'Send sign-in link'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
