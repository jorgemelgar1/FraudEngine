import { createClient } from '@supabase/supabase-js';
import { SUPABASE_URL, SUPABASE_ANON_KEY } from './config';

// PKCE is the secure OAuth flow for native apps — the desktop app generates
// a one-time code challenge, Supabase verifies it, and the code exchange
// can only happen on the same device. localStorage persistence keeps the
// session across app restarts (Tauri's WebView has a persistent storage
// scope per identifier, so localStorage survives between launches).
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    flowType: 'pkce',
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: false, // we handle the callback manually via deep link
  },
});
