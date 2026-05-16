// Single source of truth for the email-domain restriction on the TypeScript
// side (middleware, OAuth callback, login page). The Python serverless
// function reads ALLOWED_EMAIL_DOMAIN directly from os.environ — duplication
// across the language boundary is unavoidable, but inside TS we resolve
// here so the fallback ('cubopago.com') and the lowercasing live in one
// place and can't drift between files.
//
// Resolution order:
//   1. ALLOWED_EMAIL_DOMAIN              — server-only, authoritative
//   2. NEXT_PUBLIC_ALLOWED_EMAIL_DOMAIN  — inlined at build time, also used
//                                          by the login page to hint the
//                                          Google account picker
//   3. 'cubopago.com'                    — default for first-run deploys
//
// In client bundles, (1) is undefined (not exposed to the browser) so we
// fall through to (2). On the server both are visible; setting them to the
// same value in Vercel is the recommended setup.
export const ALLOWED_EMAIL_DOMAIN = (
  process.env.ALLOWED_EMAIL_DOMAIN ||
  process.env.NEXT_PUBLIC_ALLOWED_EMAIL_DOMAIN ||
  'cubopago.com'
).toLowerCase();
