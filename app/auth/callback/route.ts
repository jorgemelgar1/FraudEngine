import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { ALLOWED_EMAIL_DOMAIN } from '@/lib/config';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');

  if (!code) {
    return NextResponse.redirect(`${origin}/login?error=callback`);
  }

  const supabase = await createClient();
  const { data, error } = await supabase.auth.exchangeCodeForSession(code);

  if (error || !data?.user) {
    return NextResponse.redirect(`${origin}/login?error=callback`);
  }

  // Validate the email domain BEFORE letting the session continue.
  // exchangeCodeForSession has already set the session cookie at this point,
  // so a non-Cubo OAuth account would briefly hold a valid session — until
  // middleware caught them on the next page load. Catching it here closes
  // that window and signs them out before they can act on the session.
  const email = (data.user.email || '').toLowerCase();
  const parts = email.split('@');
  if (parts.length !== 2 || parts[1] !== ALLOWED_EMAIL_DOMAIN) {
    await supabase.auth.signOut();
    return NextResponse.redirect(`${origin}/login?error=domain`);
  }

  return NextResponse.redirect(`${origin}/`);
}
